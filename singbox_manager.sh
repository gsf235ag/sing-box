#!/bin/bash

# sing-box多协议管理脚本
# 支持VLESS Reality、Hysteria2等协议

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
SING_BOX_DIR="/etc/sing-box"
CONFIG_FILE="$SING_BOX_DIR/config.json"
SERVICE_FILE="/etc/systemd/system/sing-box.service"
BINARY_PATH="/usr/local/bin/sing-box"
LOG_FILE="/var/log/sing-box.log"

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 请以root权限运行此脚本${NC}"
        exit 1
    fi
}

# 获取系统架构
get_arch() {
    arch=$(uname -m)
    case $arch in
        x86_64)
            echo "amd64"
            ;;
        aarch64)
            echo "arm64"
            ;;
        armv7l)
            echo "armv7"
            ;;
        *)
            echo -e "${RED}不支持的架构: $arch${NC}"
            exit 1
            ;;
    esac
}

# 检测系统
detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        echo "centos"
    elif [[ -f /etc/lsb-release ]]; then
        echo "ubuntu"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# 安装依赖
install_dependencies() {
    os=$(detect_os)
    case $os in
        "centos")
            yum update -y
            yum install -y curl wget unzip jq openssl bind-utils
            ;;
        "ubuntu"|"debian")
            apt-get update
            apt-get install -y curl wget unzip jq openssl dnsutils
            ;;
        *)
            echo -e "${RED}不支持的操作系统${NC}"
            exit 1
            ;;
    esac
}

# 下载并安装sing-box
install_sing_box() {
    echo -e "${BLUE}正在下载并安装sing-box...${NC}"
    
    arch=$(get_arch)
    latest_version=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/^v//')
    
    download_url="https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/sing-box-${latest_version}-linux-${arch}.tar.gz"
    
    cd /tmp
    wget -O sing-box.tar.gz "$download_url"
    tar -xzf sing-box.tar.gz
    
    # 找到解压后的文件夹
    extracted_dir=$(find . -maxdepth 1 -type d -name "sing-box-*" | head -1)
    cp "${extracted_dir}/sing-box" "$BINARY_PATH"
    chmod +x "$BINARY_PATH"
    
    rm -rf sing-box.tar.gz "$extracted_dir"
    
    echo -e "${GREEN}sing-box安装完成，版本: ${latest_version}${NC}"
}

# 生成UUID
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# 生成随机密码
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-16
}

# 生成私钥和公钥
generate_reality_keys() {
    key_pair=$("$BINARY_PATH" generate reality-keypair)
    private_key=$(echo "$key_pair" | grep "PrivateKey:" | awk '{print $2}')
    public_key=$(echo "$key_pair" | grep "PublicKey:" | awk '{print $2}')
    echo "$private_key $public_key"
}

# 获取服务器IP
get_server_ip() {
    curl -s4 ifconfig.me || curl -s4 icanhazip.com || curl -s4 ipinfo.io/ip
}

# 验证域名解析
verify_domain_resolution() {
    local domain=$1
    local server_ip=$2
    
    # 尝试多种方法获取域名解析的IP
    local resolved_ip=""
    
    # 方法1: 使用dig命令
    if command -v dig &> /dev/null; then
        resolved_ip=$(dig +short "$domain" | head -1)
    fi
    
    # 方法2: 使用nslookup命令
    if [[ -z "$resolved_ip" ]] && command -v nslookup &> /dev/null; then
        resolved_ip=$(nslookup "$domain" | grep -A1 "Name:" | tail -1 | awk '{print $2}')
    fi
    
    # 方法3: 使用host命令
    if [[ -z "$resolved_ip" ]] && command -v host &> /dev/null; then
        resolved_ip=$(host "$domain" | grep "has address" | head -1 | awk '{print $NF}')
    fi
    
    # 方法4: 使用curl查询
    if [[ -z "$resolved_ip" ]]; then
        resolved_ip=$(curl -s "https://dns.google/resolve?name=$domain&type=A" | jq -r '.Answer[0].data' 2>/dev/null)
    fi
    
    # 如果所有方法都失败，返回空字符串
    if [[ -z "$resolved_ip" ]]; then
        echo -e "${YELLOW}警告: 无法解析域名 $domain，请确保域名正确且已正确解析${NC}"
        return 1
    fi
    
    # 比较解析的IP和服务器IP
    if [[ "$resolved_ip" != "$server_ip" ]]; then
        echo -e "${YELLOW}警告: 域名 $domain 解析的IP ($resolved_ip) 与服务器IP ($server_ip) 不匹配${NC}"
        echo -e "${YELLOW}这可能会导致证书申请失败或连接问题${NC}"
        return 1
    fi
    
    echo -e "${GREEN}域名解析验证成功: $domain -> $resolved_ip${NC}"
    return 0
}

# 验证端口
validate_port() {
    local port=$1
    if [[ ! $port =~ ^[0-9]+$ ]] || [[ $port -lt 1 ]] || [[ $port -gt 65535 ]]; then
        echo -e "${RED}错误: 端口必须是1-65535之间的数字${NC}"
        return 1
    fi
    return 0
}

# 获取自定义端口
get_custom_port() {
    local default_port=$1
    local protocol_name=$2
    
    while true; do
        read -p "请输入${protocol_name}端口 (默认: $default_port): " port
        if [[ -z "$port" ]]; then
            port=$default_port
        fi
        
        if validate_port "$port"; then
            echo "$port"
            break
        fi
    done
}

# 创建systemd服务
create_systemd_service() {
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

# 创建配置目录
create_config_dir() {
    mkdir -p "$SING_BOX_DIR"
}

# VLESS Reality配置
install_vless_reality() {
    echo -e "${BLUE}正在安装VLESS Reality...${NC}"
    
    # 获取自定义端口
    port=$(get_custom_port 443 "VLESS Reality")
    
    uuid=$(generate_uuid)
    short_id=$(openssl rand -hex 8)
    keys=$(generate_reality_keys)
    private_key=$(echo $keys | awk '{print $1}')
    public_key=$(echo $keys | awk '{print $2}')
    server_ip=$(get_server_ip)
    
    # 保存密钥对到文件
    echo "PrivateKey: $private_key" > "$SING_BOX_DIR/reality_keys.txt"
    echo "PublicKey: $public_key" >> "$SING_BOX_DIR/reality_keys.txt"
    
    create_config_dir
    
    cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $port,
      "users": [
        {
          "uuid": "$uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "itunes.apple.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "itunes.apple.com",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": [
            "$short_id"
          ]
        }
      }
    }
  ]
}
EOF

    create_systemd_service
    systemctl enable sing-box
    systemctl start sing-box
    
    echo -e "${GREEN}VLESS Reality安装完成！${NC}"
    echo -e "${YELLOW}客户端配置:${NC}"
    echo "vless://$uuid@$server_ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#VLESS-Reality"
}

# Hysteria2配置
install_hysteria2() {
    echo -e "${BLUE}正在安装Hysteria2...${NC}"
    
    # 获取自定义端口
    port=$(get_custom_port 8443 "Hysteria2")
    
    # 选择证书类型
    echo -e "${CYAN}请选择证书类型:${NC}"
    echo -e "${GREEN}1.${NC} Let's Encrypt 自动证书 (推荐，需要域名)"
    echo -e "${GREEN}2.${NC} 自签名证书 (无需域名)"
    read -p "请选择 [1-2]: " cert_choice
    
    case $cert_choice in
        1)
            # Let's Encrypt 证书
            read -p "请输入您的域名 (例如: example.com): " domain
            if [[ -z "$domain" ]]; then
                echo -e "${RED}错误: 域名不能为空${NC}"
                return 1
            fi
            
            # 验证域名解析
            echo -e "${BLUE}正在验证域名解析...${NC}"
            server_ip=$(get_server_ip)
            
            if ! verify_domain_resolution "$domain" "$server_ip"; then
                read -p "是否继续? (y/n): " continue_choice
                if [[ $continue_choice != "y" && $continue_choice != "Y" ]]; then
                    return 1
                fi
            fi
            
            password=$(generate_password)
            
            create_config_dir
            
            cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE"
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": $port,
      "users": [
        {
          "password": "$password"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "server_name": "$domain",
        "acme": {
          "domain": "$domain",
          "data_directory": "/etc/sing-box/acme",
          "default_server_name": "$domain"
        }
      }
    }
  ]
}
EOF

            create_systemd_service
            systemctl enable sing-box
            systemctl start sing-box
            
            echo -e "${GREEN}Hysteria2安装完成！${NC}"
            echo -e "${YELLOW}客户端配置:${NC}"
            echo "hy2://$password@$domain:$port#Hysteria2"
            ;;
        2)
            # 自签名证书
            password=$(generate_password)
            server_ip=$(get_server_ip)
            
            create_config_dir
            
            cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE"
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": $port,
      "users": [
        {
          "password": "$password"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "/etc/sing-box/cert.pem",
        "key_path": "/etc/sing-box/key.pem"
      }
    }
  ]
}
EOF

            # 生成自签名证书
            openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
                -keyout "$SING_BOX_DIR/key.pem" -out "$SING_BOX_DIR/cert.pem" -days 3650 \
                -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=hy2.example.com"

            create_systemd_service
            systemctl enable sing-box
            systemctl start sing-box
            
            echo -e "${GREEN}Hysteria2安装完成！${NC}"
            echo -e "${YELLOW}客户端配置:${NC}"
            echo "hy2://$password@$server_ip:$port/?insecure=1#Hysteria2"
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            return 1
            ;;
    esac
}

# 混合模式配置
install_mixed_protocols() {
    echo -e "${BLUE}正在安装混合协议模式...${NC}"
    
    # 获取自定义端口
    vless_port=$(get_custom_port 443 "VLESS Reality")
    hy2_port=$(get_custom_port 8443 "Hysteria2")
    
    # 选择Hysteria2证书类型
    echo -e "${CYAN}请选择Hysteria2证书类型:${NC}"
    echo -e "${GREEN}1.${NC} Let's Encrypt 自动证书 (推荐，需要域名)"
    echo -e "${GREEN}2.${NC} 自签名证书 (无需域名)"
    read -p "请选择 [1-2]: " cert_choice
    
    case $cert_choice in
        1)
            # Let's Encrypt 证书
            read -p "请输入您的域名 (例如: example.com): " domain
            if [[ -z "$domain" ]]; then
                echo -e "${RED}错误: 域名不能为空${NC}"
                return 1
            fi
            
            # 验证域名解析
            echo -e "${BLUE}正在验证域名解析...${NC}"
            server_ip=$(get_server_ip)
            
            if ! verify_domain_resolution "$domain" "$server_ip"; then
                read -p "是否继续? (y/n): " continue_choice
                if [[ $continue_choice != "y" && $continue_choice != "Y" ]]; then
                    return 1
                fi
            fi
            
            # VLESS Reality
            vless_uuid=$(generate_uuid)
            vless_short_id=$(openssl rand -hex 8)
            keys=$(generate_reality_keys)
            private_key=$(echo $keys | awk '{print $1}')
            public_key=$(echo $keys | awk '{print $2}')
            
            # Hysteria2
            hy2_password=$(generate_password)
            
            create_config_dir
            
            # 保存密钥对到文件
            echo "PrivateKey: $private_key" > "$SING_BOX_DIR/reality_keys.txt"
            echo "PublicKey: $public_key" >> "$SING_BOX_DIR/reality_keys.txt"
            
            cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $vless_port,
      "users": [
        {
          "uuid": "$vless_uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "itunes.apple.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "itunes.apple.com",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": [
            "$vless_short_id"
          ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": $hy2_port,
      "users": [
        {
          "password": "$hy2_password"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "server_name": "$domain",
        "acme": {
          "domain": "$domain",
          "data_directory": "/etc/sing-box/acme",
          "default_server_name": "$domain"
        }
      }
    }
  ]
}
EOF

            create_systemd_service
            systemctl enable sing-box
            systemctl start sing-box
            
            echo -e "${GREEN}混合协议模式安装完成！${NC}"
            echo -e "${YELLOW}客户端配置:${NC}"
            echo
            echo "VLESS Reality:"
            echo "vless://$vless_uuid@$server_ip:$vless_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=$public_key&sid=$vless_short_id&type=tcp&headerType=none#VLESS-Reality"
            echo
            echo "Hysteria2:"
            echo "hy2://$hy2_password@$domain:$hy2_port#Hysteria2"
            ;;
        2)
            # 自签名证书
            server_ip=$(get_server_ip)
            
            # VLESS Reality
            vless_uuid=$(generate_uuid)
            vless_short_id=$(openssl rand -hex 8)
            keys=$(generate_reality_keys)
            private_key=$(echo $keys | awk '{print $1}')
            public_key=$(echo $keys | awk '{print $2}')
            
            # Hysteria2
            hy2_password=$(generate_password)
            
            create_config_dir
            
            # 保存密钥对到文件
            echo "PrivateKey: $private_key" > "$SING_BOX_DIR/reality_keys.txt"
            echo "PublicKey: $public_key" >> "$SING_BOX_DIR/reality_keys.txt"
            
            cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE"
    },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $vless_port,
      "users": [
        {
          "uuid": "$vless_uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "itunes.apple.com",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "itunes.apple.com",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": [
            "$vless_short_id"
          ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": $hy2_port,
      "users": [
        {
          "password": "$hy2_password"
        }
      ],
      "tls": {
        "enabled": true,
        "alpn": [
          "h3"
        ],
        "certificate_path": "/etc/sing-box/cert.pem",
        "key_path": "/etc/sing-box/key.pem"
      }
    }
  ]
}
EOF

            # 生成自签名证书
            openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) \
                -keyout "$SING_BOX_DIR/key.pem" -out "$SING_BOX_DIR/cert.pem" -days 3650 \
                -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=hy2.example.com"

            create_systemd_service
            systemctl enable sing-box
            systemctl start sing-box
            
            echo -e "${GREEN}混合协议模式安装完成！${NC}"
            echo -e "${YELLOW}客户端配置:${NC}"
            echo
            echo "VLESS Reality:"
            echo "vless://$vless_uuid@$server_ip:$vless_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=$public_key&sid=$vless_short_id&type=tcp&headerType=none#VLESS-Reality"
            echo
            echo "Hysteria2:"
            echo "hy2://$hy2_password@$server_ip:$hy2_port/?insecure=1#Hysteria2"
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            return 1
            ;;
    esac
}

# 查看配置
show_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}未找到配置文件${NC}"
        return
    fi
    
    echo -e "${BLUE}当前配置信息:${NC}"
    server_ip=$(get_server_ip)
    
    # 检查配置文件中的协议类型
    if grep -q '"type": "vless"' "$CONFIG_FILE"; then
        echo -e "${GREEN}检测到VLESS Reality协议${NC}"
        uuid=$(jq -r '.inbounds[] | select(.type=="vless") | .users[0].uuid' "$CONFIG_FILE")
        port=$(jq -r '.inbounds[] | select(.type=="vless") | .listen_port' "$CONFIG_FILE")
        short_id=$(jq -r '.inbounds[] | select(.type=="vless") | .tls.reality.short_id[0]' "$CONFIG_FILE")
        
        # 尝试从reality_keys.txt文件获取公钥
        if [[ -f "$SING_BOX_DIR/reality_keys.txt" ]]; then
            public_key=$(cat "$SING_BOX_DIR/reality_keys.txt" | cut -d' ' -f2)
        else
            # 如果没有reality_keys.txt文件，尝试从sing-box生成
            echo -e "${YELLOW}正在生成Reality密钥对...${NC}"
            key_pair=$("$BINARY_PATH" generate reality-keypair 2>/dev/null)
            if [[ $? -eq 0 ]]; then
                public_key=$(echo "$key_pair" | grep "PublicKey:" | awk '{print $2}')
                # 保存密钥对到文件
                echo "$key_pair" > "$SING_BOX_DIR/reality_keys.txt"
            else
                echo -e "${RED}无法生成Reality密钥对，请手动配置${NC}"
                return 1
            fi
        fi
        
        if [[ -n "$public_key" && -n "$short_id" ]]; then
            echo "vless://$uuid@$server_ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#VLESS-Reality"
        else
            echo -e "${RED}VLESS Reality配置信息不完整${NC}"
        fi
    fi
    
    if grep -q '"type": "hysteria2"' "$CONFIG_FILE"; then
        echo -e "${GREEN}检测到Hysteria2协议${NC}"
        password=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .users[0].password' "$CONFIG_FILE")
        port=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .listen_port' "$CONFIG_FILE")
        domain=$(jq -r '.inbounds[] | select(.type=="hysteria2") | .tls.server_name' "$CONFIG_FILE" 2>/dev/null)
        
        if [[ -n "$domain" && "$domain" != "null" ]]; then
            echo "hy2://$password@$domain:$port#Hysteria2"
        else
            echo "hy2://$password@$server_ip:$port/?insecure=1#Hysteria2"
        fi
    fi
}

# 启动服务
start_service() {
    if systemctl is-active --quiet sing-box; then
        echo -e "${YELLOW}服务已经在运行${NC}"
    else
        systemctl start sing-box
        echo -e "${GREEN}服务启动成功${NC}"
    fi
}

# 停止服务
stop_service() {
    if systemctl is-active --quiet sing-box; then
        systemctl stop sing-box
        echo -e "${GREEN}服务停止成功${NC}"
    else
        echo -e "${YELLOW}服务未运行${NC}"
    fi
}

# 重启服务
restart_service() {
    systemctl restart sing-box
    echo -e "${GREEN}服务重启成功${NC}"
}

# 查看服务状态
show_status() {
    echo -e "${BLUE}服务状态:${NC}"
    systemctl status sing-box --no-pager
}

# 查看日志
show_logs() {
    echo -e "${BLUE}服务日志:${NC}"
    if [[ -f "$LOG_FILE" ]]; then
        tail -50 "$LOG_FILE"
    else
        journalctl -u sing-box -n 50 --no-pager
    fi
}

# 启用开机自启
enable_auto_start() {
    systemctl enable sing-box
    echo -e "${GREEN}开机自启已启用${NC}"
}

# 禁用开机自启
disable_auto_start() {
    systemctl disable sing-box
    echo -e "${GREEN}开机自启已禁用${NC}"
}

# 卸载
uninstall() {
    echo -e "${RED}确定要卸载sing-box吗? (y/n)${NC}"
    read -r confirm
    if [[ $confirm == "y" || $confirm == "Y" ]]; then
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        rm -f "$BINARY_PATH"
        rm -rf "$SING_BOX_DIR"
        systemctl daemon-reload
        echo -e "${GREEN}卸载完成${NC}"
    fi
}

# 获取服务状态
get_service_status() {
    if [[ ! -f "$BINARY_PATH" ]]; then
        echo "未安装"
    elif systemctl is-active --quiet sing-box; then
        echo "运行中"
    else
        echo "已停止"
    fi
}

# 显示菜单
show_menu() {
    clear
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}      sing-box 多协议管理脚本${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo
    echo -e "${GREEN}1.${NC} 搭建 VLESS Reality XTLS RPRX Vision"
    echo -e "${GREEN}2.${NC} 搭建 Hysteria2"
    echo -e "${GREEN}3.${NC} 搭建混合协议 (VLESS+Hysteria2)"
    echo -e "${GREEN}4.${NC} 查看已安装协议和节点配置"
    echo -e "${BLUE}5.${NC} 启动后端"
    echo -e "${BLUE}6.${NC} 关闭后端"
    echo -e "${BLUE}7.${NC} 重启后端"
    echo -e "${BLUE}8.${NC} 查看后端状态"
    echo -e "${BLUE}9.${NC} 查看服务日志"
    echo -e "${YELLOW}10.${NC} 设置开机自启动"
    echo -e "${YELLOW}11.${NC} 关闭开机自启动"
    echo -e "${RED}12.${NC} 卸载"
    echo -e "${PURPLE}0.${NC} 退出"
    echo
    status=$(get_service_status)
    case $status in
        "未安装")
            echo -e "${RED}状态: $status${NC}"
            ;;
        "运行中")
            echo -e "${GREEN}状态: $status${NC}"
            ;;
        "已停止")
            echo -e "${YELLOW}状态: $status${NC}"
            ;;
    esac
    echo
}

# 主函数
main() {
    check_root
    
    while true; do
        show_menu
        read -p "请选择操作 [0-12]: " choice
        
        case $choice in
            1)
                install_dependencies
                install_sing_box
                install_vless_reality
                ;;
            2)
                install_dependencies
                install_sing_box
                install_hysteria2
                ;;
            3)
                install_dependencies
                install_sing_box
                install_mixed_protocols
                ;;
            4)
                show_config
                ;;
            5)
                start_service
                ;;
            6)
                stop_service
                ;;
            7)
                restart_service
                ;;
            8)
                show_status
                ;;
            9)
                show_logs
                ;;
            10)
                enable_auto_start
                ;;
            11)
                disable_auto_start
                ;;
            12)
                uninstall
                ;;
            0)
                echo -e "${GREEN}感谢使用！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请重试${NC}"
                ;;
        esac
        
        echo
        read -p "按回车键继续..." -r
    done
}

# 运行主函数
main "$@"