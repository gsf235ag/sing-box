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

# 检查端口是否已在当前配置中被使用
is_port_used_in_config() {
    local port=$1
    if [[ ! -f "$CONFIG_FILE" ]] || ! command -v jq &> /dev/null; then
        return 1
    fi
    jq -e --argjson port "$port" '.inbounds[]? | select(.listen_port == $port)' "$CONFIG_FILE" > /dev/null 2>&1
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
            if is_port_used_in_config "$port"; then
                echo -e "${YELLOW}警告: 端口 ${port} 已被已安装协议使用，请更换端口${NC}"
            else
                echo "$port"
                break
            fi
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

# 使配置生效
apply_service_changes() {
    create_systemd_service
    systemctl enable sing-box
    if systemctl is-active --quiet sing-box; then
        systemctl restart sing-box
    else
        systemctl start sing-box
    fi
}

# 创建配置目录
create_config_dir() {
    mkdir -p "$SING_BOX_DIR"
}

# 初始化配置文件（多协议共存）
init_config_file() {
    create_config_dir
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE"
  },
  "inbounds": []
}
EOF
        return
    fi

    if ! jq empty "$CONFIG_FILE" > /dev/null 2>&1; then
        cp "$CONFIG_FILE" "${CONFIG_FILE}.bak.$(date +%s)"
        cat > "$CONFIG_FILE" << EOF
{
  "log": {
    "level": "info",
    "output": "$LOG_FILE"
  },
  "inbounds": []
}
EOF
        echo -e "${YELLOW}警告: 原配置文件不是有效JSON，已备份并重新初始化${NC}"
    fi
}

# 合并入站配置（按tag覆盖，支持多协议共存）
upsert_inbound() {
    local inbound_json=$1
    local tmp_file

    init_config_file
    tmp_file=$(mktemp)

    jq --arg log_file "$LOG_FILE" --argjson inbound "$inbound_json" '
      .log = (.log // {"level":"info","output":$log_file}) |
      .inbounds = (((.inbounds // []) | map(select(.tag != $inbound.tag))) + [$inbound])
    ' "$CONFIG_FILE" > "$tmp_file"

    mv "$tmp_file" "$CONFIG_FILE"
}

# 生成自签名证书（ECDSA）
generate_self_signed_cert() {
    create_config_dir
    openssl ecparam -name prime256v1 -genkey -noout -out "$SING_BOX_DIR/key.pem"
    openssl req -new -x509 -key "$SING_BOX_DIR/key.pem" -out "$SING_BOX_DIR/cert.pem" -days 3650 \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=Organizational Unit/CN=sing-box.local"
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
    
    create_config_dir
    
    # 保存密钥对到文件
    echo "PrivateKey: $private_key" > "$SING_BOX_DIR/reality_keys.txt"
    echo "PublicKey: $public_key" >> "$SING_BOX_DIR/reality_keys.txt"
    inbound_json=$(cat << EOF
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
EOF
)
    upsert_inbound "$inbound_json"
    apply_service_changes
    
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
            inbound_json=$(cat << EOF
{
  "type": "hysteria2",
  "tag": "hy2-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "name": "hy2-user",
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
EOF
)
            upsert_inbound "$inbound_json"
            apply_service_changes
            
            echo -e "${GREEN}Hysteria2安装完成！${NC}"
            echo -e "${YELLOW}客户端配置:${NC}"
            echo "hy2://$password@$domain:$port#Hysteria2"
            ;;
        2)
            # 自签名证书
            password=$(generate_password)
            server_ip=$(get_server_ip)
            generate_self_signed_cert
            inbound_json=$(cat << EOF
{
  "type": "hysteria2",
  "tag": "hy2-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "name": "hy2-user",
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
EOF
)
            upsert_inbound "$inbound_json"
            apply_service_changes
            
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

# SOCKS5配置
install_socks5() {
    echo -e "${BLUE}正在安装SOCKS5...${NC}"

    port=$(get_custom_port 1080 "SOCKS5")
    read -p "请输入SOCKS5用户名 (默认: admin): " username
    read -p "请输入SOCKS5密码 (留空自动生成): " password
    username=${username:-admin}
    password=${password:-$(generate_password)}
    server_ip=$(get_server_ip)

    inbound_json=$(cat << EOF
{
  "type": "socks",
  "tag": "socks-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "username": "$username",
      "password": "$password"
    }
  ]
}
EOF
)
    upsert_inbound "$inbound_json"
    apply_service_changes

    echo -e "${GREEN}SOCKS5安装完成！${NC}"
    echo -e "${YELLOW}客户端配置:${NC}"
    echo "socks5://$username:$password@$server_ip:$port"
}

# Shadowsocks配置
install_shadowsocks() {
    echo -e "${BLUE}正在安装Shadowsocks...${NC}"

    port=$(get_custom_port 8388 "Shadowsocks")
    read -p "请输入加密方法 (默认: aes-128-gcm): " method
    read -p "请输入Shadowsocks密码 (留空自动生成): " password
    method=${method:-aes-128-gcm}
    password=${password:-$(generate_password)}
    server_ip=$(get_server_ip)

    inbound_json=$(cat << EOF
{
  "type": "shadowsocks",
  "tag": "ss-in",
  "listen": "::",
  "listen_port": $port,
  "method": "$method",
  "password": "$password"
}
EOF
)
    upsert_inbound "$inbound_json"
    apply_service_changes

    ss_credential=$(printf "%s" "${method}:${password}" | base64 | tr -d '\n')
    echo -e "${GREEN}Shadowsocks安装完成！${NC}"
    echo -e "${YELLOW}客户端配置:${NC}"
    echo "ss://$ss_credential@$server_ip:$port#Shadowsocks"
}

# AnyTLS配置
install_anytls() {
    echo -e "${BLUE}正在安装AnyTLS...${NC}"

    port=$(get_custom_port 16999 "AnyTLS")
    read -p "请输入AnyTLS用户名 (默认: anytls-user): " username
    read -p "请输入AnyTLS密码 (留空自动生成): " password
    username=${username:-anytls-user}
    password=${password:-$(generate_password)}
    server_ip=$(get_server_ip)

    echo -e "${CYAN}请选择证书类型:${NC}"
    echo -e "${GREEN}1.${NC} Let's Encrypt 自动证书 (推荐，需要域名)"
    echo -e "${GREEN}2.${NC} 自签名证书 (无需域名)"
    read -p "请选择 [1-2]: " cert_choice

    case $cert_choice in
        1)
            read -p "请输入您的域名 (例如: example.com): " domain
            if [[ -z "$domain" ]]; then
                echo -e "${RED}错误: 域名不能为空${NC}"
                return 1
            fi

            echo -e "${BLUE}正在验证域名解析...${NC}"
            if ! verify_domain_resolution "$domain" "$server_ip"; then
                read -p "是否继续? (y/n): " continue_choice
                if [[ $continue_choice != "y" && $continue_choice != "Y" ]]; then
                    return 1
                fi
            fi

            inbound_json=$(cat << EOF
{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "name": "$username",
      "password": "$password"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$domain",
    "acme": {
      "domain": "$domain",
      "data_directory": "/etc/sing-box/acme",
      "default_server_name": "$domain"
    }
  }
}
EOF
)
            upsert_inbound "$inbound_json"
            apply_service_changes

            echo -e "${GREEN}AnyTLS安装完成！${NC}"
            echo -e "${YELLOW}客户端配置:${NC}"
            echo "anytls://$username:$password@$domain:$port#AnyTLS"
            ;;
        2)
            generate_self_signed_cert
            inbound_json=$(cat << EOF
{
  "type": "anytls",
  "tag": "anytls-in",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "name": "$username",
      "password": "$password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "/etc/sing-box/cert.pem",
    "key_path": "/etc/sing-box/key.pem"
  }
}
EOF
)
            upsert_inbound "$inbound_json"
            apply_service_changes

            echo -e "${GREEN}AnyTLS安装完成！${NC}"
            echo -e "${YELLOW}客户端配置:${NC}"
            echo "anytls://$username:$password@$server_ip:$port?insecure=1#AnyTLS"
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            return 1
            ;;
    esac
}

# 查看配置
show_config() {
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}缺少依赖: jq，请先执行任意“搭建协议”完成依赖安装${NC}"
        return
    fi
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo -e "${RED}未找到配置文件${NC}"
        return
    fi
    if ! jq empty "$CONFIG_FILE" > /dev/null 2>&1; then
        echo -e "${RED}配置文件JSON格式无效，请先修复: $CONFIG_FILE${NC}"
        return
    fi
    
    echo -e "${BLUE}当前配置信息:${NC}"
    local server_ip found public_key
    server_ip=$(get_server_ip)
    found=0

    if [[ -f "$SING_BOX_DIR/reality_keys.txt" ]]; then
        public_key=$(grep '^PublicKey:' "$SING_BOX_DIR/reality_keys.txt" | awk '{print $2}')
    else
        public_key=""
    fi

    while IFS= read -r inbound_b64; do
        local inbound_json type port
        inbound_json=$(echo "$inbound_b64" | base64 -d)
        type=$(echo "$inbound_json" | jq -r '.type')
        port=$(echo "$inbound_json" | jq -r '.listen_port // "N/A"')
        found=1

        case "$type" in
            vless)
                local uuid short_id
                uuid=$(echo "$inbound_json" | jq -r '.users[0].uuid // ""')
                short_id=$(echo "$inbound_json" | jq -r '.tls.reality.short_id[0] // ""')
                echo -e "${GREEN}检测到VLESS Reality协议${NC}"
                if [[ -n "$public_key" && -n "$short_id" && -n "$uuid" ]]; then
                    echo "vless://$uuid@$server_ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#VLESS-Reality"
                else
                    echo -e "${YELLOW}VLESS Reality公钥或short_id缺失，请检查 $SING_BOX_DIR/reality_keys.txt${NC}"
                fi
                ;;
            hysteria2)
                local password domain
                password=$(echo "$inbound_json" | jq -r '.users[0].password // ""')
                domain=$(echo "$inbound_json" | jq -r '.tls.server_name // ""')
                echo -e "${GREEN}检测到Hysteria2协议${NC}"
                if [[ -n "$domain" ]]; then
                    echo "hy2://$password@$domain:$port#Hysteria2"
                else
                    echo "hy2://$password@$server_ip:$port/?insecure=1#Hysteria2"
                fi
                ;;
            socks)
                local username password
                username=$(echo "$inbound_json" | jq -r '.users[0].username // ""')
                password=$(echo "$inbound_json" | jq -r '.users[0].password // ""')
                echo -e "${GREEN}检测到SOCKS5协议${NC}"
                echo "socks5://$username:$password@$server_ip:$port"
                ;;
            shadowsocks)
                local method password ss_credential
                method=$(echo "$inbound_json" | jq -r '.method // ""')
                password=$(echo "$inbound_json" | jq -r '.password // ""')
                echo -e "${GREEN}检测到Shadowsocks协议${NC}"
                ss_credential=$(printf "%s" "${method}:${password}" | base64 | tr -d '\n')
                echo "ss://$ss_credential@$server_ip:$port#Shadowsocks"
                ;;
            anytls)
                local username password domain
                username=$(echo "$inbound_json" | jq -r '.users[0].name // ""')
                password=$(echo "$inbound_json" | jq -r '.users[0].password // ""')
                domain=$(echo "$inbound_json" | jq -r '.tls.server_name // ""')
                echo -e "${GREEN}检测到AnyTLS协议${NC}"
                if [[ -n "$domain" ]]; then
                    echo "anytls://$username:$password@$domain:$port#AnyTLS"
                else
                    echo "anytls://$username:$password@$server_ip:$port?insecure=1#AnyTLS"
                fi
                ;;
        esac
        echo
    done < <(jq -r '.inbounds[]? | @base64' "$CONFIG_FILE")

    if [[ $found -eq 0 ]]; then
        echo -e "${YELLOW}当前未安装任何协议${NC}"
    fi
}

# 协议显示名称
get_protocol_display_name() {
    local type=$1
    local reality_enabled=$2

    case "$type" in
        "vless")
            if [[ "$reality_enabled" == "true" ]]; then
                echo "VLESS-REALITY"
            else
                echo "VLESS"
            fi
            ;;
        "hysteria2")
            echo "Hysteria2"
            ;;
        "shadowsocks")
            echo "Shadowsocks"
            ;;
        "socks")
            echo "SOCKS5"
            ;;
        "anytls")
            echo "AnyTLS"
            ;;
        *)
            echo "$type" | tr '[:lower:]' '[:upper:]'
            ;;
    esac
}

# 通过tag获取分享链接
get_share_link_by_tag() {
    local tag=$1
    local inbound_json type server_ip
    inbound_json=$(jq -c --arg tag "$tag" '.inbounds[]? | select(.tag == $tag)' "$CONFIG_FILE" 2>/dev/null)
    if [[ -z "$inbound_json" ]]; then
        return 1
    fi

    type=$(echo "$inbound_json" | jq -r '.type // ""')
    server_ip=$(get_server_ip)

    case "$type" in
        "vless")
            local uuid short_id public_key
            uuid=$(echo "$inbound_json" | jq -r '.users[0].uuid // ""')
            short_id=$(echo "$inbound_json" | jq -r '.tls.reality.short_id[0] // ""')
            if [[ -f "$SING_BOX_DIR/reality_keys.txt" ]]; then
                public_key=$(grep '^PublicKey:' "$SING_BOX_DIR/reality_keys.txt" | awk '{print $2}')
            fi
            if [[ -n "$uuid" && -n "$short_id" && -n "$public_key" ]]; then
                local port
                port=$(echo "$inbound_json" | jq -r '.listen_port // "443"')
                echo "vless://$uuid@$server_ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#VLESS-Reality"
                return 0
            fi
            ;;
        "hysteria2")
            local hy2_password hy2_domain hy2_port
            hy2_password=$(echo "$inbound_json" | jq -r '.users[0].password // ""')
            hy2_domain=$(echo "$inbound_json" | jq -r '.tls.server_name // ""')
            hy2_port=$(echo "$inbound_json" | jq -r '.listen_port // "8443"')
            if [[ -n "$hy2_domain" ]]; then
                echo "hy2://$hy2_password@$hy2_domain:$hy2_port#Hysteria2"
            else
                echo "hy2://$hy2_password@$server_ip:$hy2_port/?insecure=1#Hysteria2"
            fi
            return 0
            ;;
        "socks")
            local socks_user socks_pass socks_port
            socks_user=$(echo "$inbound_json" | jq -r '.users[0].username // ""')
            socks_pass=$(echo "$inbound_json" | jq -r '.users[0].password // ""')
            socks_port=$(echo "$inbound_json" | jq -r '.listen_port // "1080"')
            echo "socks5://$socks_user:$socks_pass@$server_ip:$socks_port"
            return 0
            ;;
        "shadowsocks")
            local ss_method ss_pass ss_port ss_credential
            ss_method=$(echo "$inbound_json" | jq -r '.method // ""')
            ss_pass=$(echo "$inbound_json" | jq -r '.password // ""')
            ss_port=$(echo "$inbound_json" | jq -r '.listen_port // "8388"')
            ss_credential=$(printf "%s" "${ss_method}:${ss_pass}" | base64 | tr -d '\n')
            echo "ss://$ss_credential@$server_ip:$ss_port#Shadowsocks"
            return 0
            ;;
        "anytls")
            local any_user any_pass any_domain any_port
            any_user=$(echo "$inbound_json" | jq -r '.users[0].name // ""')
            any_pass=$(echo "$inbound_json" | jq -r '.users[0].password // ""')
            any_domain=$(echo "$inbound_json" | jq -r '.tls.server_name // ""')
            any_port=$(echo "$inbound_json" | jq -r '.listen_port // "16999"')
            if [[ -n "$any_domain" ]]; then
                echo "anytls://$any_user:$any_pass@$any_domain:$any_port#AnyTLS"
            else
                echo "anytls://$any_user:$any_pass@$server_ip:$any_port?insecure=1#AnyTLS"
            fi
            return 0
            ;;
    esac
    return 1
}

# 查看协议配置（二级菜单）
protocol_config_menu() {
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}缺少依赖: jq${NC}"
        return
    fi
    if [[ ! -f "$CONFIG_FILE" ]] || ! jq empty "$CONFIG_FILE" > /dev/null 2>&1; then
        echo -e "${YELLOW}未检测到有效配置${NC}"
        return
    fi

    while true; do
        local protocols=()
        local display_protocols=()
        mapfile -t protocols < <(jq -r '.inbounds[]? | "\(.tag)|\(.type)|\(.listen_port // "N/A")|\(.tls.reality.enabled // false)"' "$CONFIG_FILE")

        clear
        echo -e "${CYAN}查看协议配置${NC}"
        echo "  已安装协议配置"
        echo "─────────────────────────────────────────────"
        echo "  Xray 协议 (vless-reality 服务):"

        local idx=1
        local shown=0
        local row tag type port reality_enabled name
        for row in "${protocols[@]}"; do
            IFS='|' read -r tag type port reality_enabled <<< "$row"
            if [[ "$type" == "vless" ]]; then
                name=$(get_protocol_display_name "$type" "$reality_enabled")
                echo "    ${idx}) ${name} - 端口: ${port}"
                display_protocols+=("$row")
                shown=1
                idx=$((idx + 1))
            fi
        done

        for row in "${protocols[@]}"; do
            IFS='|' read -r tag type port reality_enabled <<< "$row"
            if [[ "$type" != "vless" ]]; then
                name=$(get_protocol_display_name "$type" "$reality_enabled")
                echo "    ${idx}) ${name} - 端口: ${port}"
                display_protocols+=("$row")
                shown=1
                idx=$((idx + 1))
            fi
        done

        if [[ $shown -eq 0 ]]; then
            echo "    暂无已安装协议"
        fi

        echo
        echo "─────────────────────────────────────────────"
        echo "  输入序号查看详细配置/链接/二维码"
        echo "  a) 一键展示所有分享链接"
        echo "  0) 返回"
        echo "─────────────────────────────────────────────"
        read -p "  请选择 [0-$((idx-1))/a]: " sub_choice

        if [[ "$sub_choice" == "0" ]]; then
            return
        elif [[ "$sub_choice" == "a" || "$sub_choice" == "A" ]]; then
            echo
            show_config
            echo
            read -p "按回车键继续..." -r
        elif [[ "$sub_choice" =~ ^[0-9]+$ ]] && (( sub_choice >= 1 && sub_choice < idx )); then
            local selected_row selected_tag selected_type selected_port selected_reality link
            selected_row="${display_protocols[$((sub_choice - 1))]}"
            IFS='|' read -r selected_tag selected_type selected_port selected_reality <<< "$selected_row"
            name=$(get_protocol_display_name "$selected_type" "$selected_reality")
            echo
            echo "协议名称: $name"
            echo "监听端口: $selected_port"
            echo "协议标签: $selected_tag"
            link=$(get_share_link_by_tag "$selected_tag" || true)
            if [[ -n "$link" ]]; then
                echo "分享链接: $link"
                if command -v qrencode &> /dev/null; then
                    echo "二维码:"
                    qrencode -t UTF8 "$link"
                else
                    echo "二维码: 未安装 qrencode，暂不显示"
                fi
            else
                echo "分享链接: 暂无法生成"
            fi
            echo
            read -p "按回车键继续..." -r
        else
            echo -e "${RED}无效选择${NC}"
            sleep 1
        fi
    done
}

# 卸载指定协议（二级菜单）
uninstall_protocol_menu() {
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}缺少依赖: jq${NC}"
        return
    fi
    if [[ ! -f "$CONFIG_FILE" ]] || ! jq empty "$CONFIG_FILE" > /dev/null 2>&1; then
        echo -e "${YELLOW}未检测到有效配置${NC}"
        return
    fi

    while true; do
        local protocols=()
        mapfile -t protocols < <(jq -r '.inbounds[]? | "\(.tag)|\(.type)|\(.listen_port // "N/A")|\(.tls.reality.enabled // false)"' "$CONFIG_FILE")

        clear
        echo -e "${CYAN}卸载指定协议${NC}"
        echo "  卸载指定协议"
        echo "─────────────────────────────────────────────"
        echo "  已安装的协议:"

        if [[ ${#protocols[@]} -eq 0 ]]; then
            echo "    暂无已安装协议"
            echo
            echo "  0) 返回"
            echo "─────────────────────────────────────────────"
            read -p "  选择要卸载的协议 [0]: " choice
            return
        fi

        local i=1 row tag type port reality_enabled name
        for row in "${protocols[@]}"; do
            IFS='|' read -r tag type port reality_enabled <<< "$row"
            name=$(get_protocol_display_name "$type" "$reality_enabled")
            echo "    ${i}) ${name}"
            i=$((i + 1))
        done

        echo
        echo "  0) 返回"
        echo "─────────────────────────────────────────────"
        read -p "  选择要卸载的协议 [0-$((i-1))]: " choice

        if [[ "$choice" == "0" ]]; then
            return
        fi

        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice < i )); then
            local selected_tag selected_name tmp_file remaining
            row=$(printf "%s\n" "${protocols[@]}" | sed -n "${choice}p")
            IFS='|' read -r selected_tag type port reality_enabled <<< "$row"
            selected_name=$(get_protocol_display_name "$type" "$reality_enabled")

            read -p "确认卸载 ${selected_name}? (y/n): " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                continue
            fi

            tmp_file=$(mktemp)
            jq --arg tag "$selected_tag" '.inbounds = [ .inbounds[]? | select(.tag != $tag) ]' "$CONFIG_FILE" > "$tmp_file"
            mv "$tmp_file" "$CONFIG_FILE"

            remaining=$(jq -r '.inbounds | length' "$CONFIG_FILE" 2>/dev/null || echo 0)
            if [[ "$remaining" -eq 0 ]]; then
                systemctl stop sing-box 2>/dev/null || true
                echo -e "${GREEN}已卸载 ${selected_name}，当前无协议，服务已停止${NC}"
            else
                apply_service_changes
                echo -e "${GREEN}已卸载 ${selected_name}${NC}"
            fi
            echo
            read -p "按回车键继续..." -r
        else
            echo -e "${RED}无效选择${NC}"
            sleep 1
        fi
    done
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

# 获取系统信息
get_system_info() {
    local os_name="unknown"
    local os_version="unknown"
    local kernel_version
    
    if [[ -f /etc/os-release ]]; then
        os_name=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
        os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    fi
    
    kernel_version=$(uname -r 2>/dev/null || echo "unknown")
    echo "${os_name} ${os_version} | ${kernel_version}"
}

# 获取核心版本
get_core_version() {
    if [[ ! -x "$BINARY_PATH" ]]; then
        echo "Sing-box 未安装"
        return
    fi
    
    local version
    version=$("$BINARY_PATH" version 2>/dev/null | head -1 | awk '{print $NF}')
    if [[ -n "$version" ]]; then
        echo "Sing-box ${version}"
    else
        echo "Sing-box 未知版本"
    fi
}

# 确保运行环境可用
ensure_sing_box_ready() {
    install_dependencies
    if [[ -x "$BINARY_PATH" ]]; then
        echo -e "${GREEN}检测到已安装sing-box，跳过重复安装${NC}"
    else
        install_sing_box
    fi
}

# 显示服务端管理信息
show_server_management() {
    local status status_text status_color protocol_count
    local system_info core_info
    
    system_info=$(get_system_info)
    core_info=$(get_core_version)
    status=$(get_service_status)
    
    case $status in
        "运行中")
            status_text="● 运行中"
            status_color="$GREEN"
            ;;
        "已停止")
            status_text="● 已停止"
            status_color="$YELLOW"
            ;;
        *)
            status_text="● 未安装"
            status_color="$RED"
            ;;
    esac
    
    echo -e "${CYAN}服务端管理${NC}"
    echo "  系统: ${system_info}"
    echo "  核心: ${core_info}"
    echo
    echo -e "  状态: ${status_color}${status_text}${NC}"
    
    protocol_count=0
    if [[ -f "$CONFIG_FILE" ]] && command -v jq &> /dev/null; then
        protocol_count=$(jq -r '.inbounds | length' "$CONFIG_FILE" 2>/dev/null || echo 0)
    fi
    
    if [[ "$protocol_count" =~ ^[0-9]+$ ]] && [[ "$protocol_count" -gt 0 ]]; then
        echo "  协议: 已安装 (${protocol_count}个)"
        while IFS='|' read -r type port reality_enabled; do
            local protocol_name
            case "$type" in
                "vless")
                    if [[ "$reality_enabled" == "true" ]]; then
                        protocol_name="VLESS+Reality"
                    else
                        protocol_name="VLESS"
                    fi
                    ;;
                "hysteria2")
                    protocol_name="Hysteria2"
                    ;;
                "shadowsocks")
                    protocol_name="Shadowsocks"
                    ;;
                "socks")
                    protocol_name="SOCKS5"
                    ;;
                "anytls")
                    protocol_name="AnyTLS"
                    ;;
                *)
                    protocol_name=$(echo "$type" | tr '[:lower:]' '[:upper:]')
                    ;;
            esac
            echo "    • ${protocol_name} (${port})"
        done < <(jq -r '.inbounds[]? | "\(.type)|\(.listen_port // "N/A")|\(.tls.reality.enabled // false)"' "$CONFIG_FILE" 2>/dev/null)
    else
        echo "  协议: 未安装"
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
    echo -e "${GREEN}3.${NC} 搭建 SOCKS5"
    echo -e "${GREEN}4.${NC} 搭建 Shadowsocks"
    echo -e "${GREEN}5.${NC} 搭建 AnyTLS"
    echo -e "${GREEN}6.${NC} 查看协议配置"
    echo -e "${GREEN}7.${NC} 卸载指定协议"
    echo -e "${BLUE}8.${NC} 启动后端"
    echo -e "${BLUE}9.${NC} 关闭后端"
    echo -e "${BLUE}10.${NC} 重启后端"
    echo -e "${BLUE}11.${NC} 查看后端状态"
    echo -e "${BLUE}12.${NC} 查看服务日志"
    echo -e "${YELLOW}13.${NC} 设置开机自启动"
    echo -e "${YELLOW}14.${NC} 关闭开机自启动"
    echo -e "${RED}15.${NC} 卸载"
    echo -e "${PURPLE}0.${NC} 退出"
    echo
    show_server_management
    echo
}

# 主函数
main() {
    check_root
    
    while true; do
        show_menu
        read -p "请选择操作 [0-15]: " choice
        
        case $choice in
            1)
                ensure_sing_box_ready
                install_vless_reality
                ;;
            2)
                ensure_sing_box_ready
                install_hysteria2
                ;;
            3)
                ensure_sing_box_ready
                install_socks5
                ;;
            4)
                ensure_sing_box_ready
                install_shadowsocks
                ;;
            5)
                ensure_sing_box_ready
                install_anytls
                ;;
            6)
                protocol_config_menu
                ;;
            7)
                uninstall_protocol_menu
                ;;
            8)
                start_service
                ;;
            9)
                stop_service
                ;;
            10)
                restart_service
                ;;
            11)
                show_status
                ;;
            12)
                show_logs
                ;;
            13)
                enable_auto_start
                ;;
            14)
                disable_auto_start
                ;;
            15)
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
