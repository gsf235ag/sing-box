# sing-box 多协议管理脚本

一个功能强大的 sing-box 服务器端管理脚本，支持 VLESS Reality 和 Hysteria2 协议，提供完整的服务管理功能。

## 🌟 功能特性

- **多协议支持**：VLESS Reality XTLS RPRX Vision、Hysteria2
- **自定义端口**：支持为每个协议自定义端口号
- **混合模式**：同时运行多个协议
- **自动安装**：一键安装 sing-box 最新版本
- **服务管理**：完整的 systemd 服务管理
- **配置查看**：实时查看节点配置信息
- **日志监控**：服务状态和日志查看
- **开机自启**：支持设置开机自动启动

## 📁 文件结构

```
项目根目录/
├── singbox_manager.sh          # 主脚本文件
├── README.md                   # 项目说明文档
└── 其他相关文件...
```

### 脚本安装后的系统文件结构

```
/etc/
├── sing-box/                   # sing-box 配置目录
│   ├── config.json            # 主配置文件
│   ├── acme/                  # ACME 证书存储目录 (Let's Encrypt模式)
│   │   └── [domain]/          # 域名证书目录
│   ├── cert.pem               # 自签名证书文件 (自签名模式)
│   └── key.pem                # 自签名私钥文件 (自签名模式)
├── systemd/system/
│   └── sing-box.service       # systemd 服务文件
└── local/bin/
    └── sing-box               # sing-box 二进制文件

/var/log/
└── sing-box.log              # 服务日志文件
```

## 🚀 快速开始

### 系统要求

- **操作系统**：CentOS 7+、Ubuntu 18+、Debian 9+
- **架构支持**：x86_64、ARM64、ARMv7
- **权限要求**：需要 root 权限运行
- **网络要求**：需要能访问外网（用于下载和证书申请）

### 安装步骤

1. **下载脚本**
```bash
wget -O singbox_manager.sh https://raw.githubusercontent.com/your-repo/singbox_manager.sh
```

2. **添加执行权限**
```bash
chmod +x singbox_manager.sh
```

3. **运行脚本**
```bash
sudo ./singbox_manager.sh
```

## 📋 使用说明

### 主菜单选项

| 选项 | 功能 | 说明 |
|------|------|------|
| 1 | 搭建 VLESS Reality | 安装 VLESS Reality XTLS RPRX Vision 协议 |
| 2 | 搭建 Hysteria2 | 安装 Hysteria2 协议 |
| 3 | 搭建混合协议 | 同时安装 VLESS Reality + Hysteria2 |
| 4 | 查看配置 | 显示已安装协议的客户端配置 |
| 5 | 启动后端 | 启动 sing-box 服务 |
| 6 | 关闭后端 | 停止 sing-box 服务 |
| 7 | 重启后端 | 重启 sing-box 服务 |
| 8 | 查看状态 | 查看服务运行状态 |
| 9 | 查看日志 | 查看服务日志 |
| 10 | 开机自启 | 启用开机自动启动 |
| 11 | 关闭自启 | 禁用开机自动启动 |
| 12 | 卸载 | 完全卸载 sing-box |
| 0 | 退出 | 退出脚本 |

### 协议配置

#### VLESS Reality
- **默认端口**：443
- **加密方式**：XTLS RPRX Vision
- **伪装域名**：itunes.apple.com
- **指纹**：Chrome

#### Hysteria2
- **默认端口**：8443
- **传输协议**：UDP
- **证书选项**：
  - Let's Encrypt 自动证书（推荐，需要域名）
  - 自签名证书（无需域名）
- **ALPN**：h3

## 🔧 配置示例

### VLESS Reality 客户端配置
```
vless://[UUID]@[SERVER_IP]:[PORT]?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=[PUBLIC_KEY]&sid=[SHORT_ID]&type=tcp&headerType=none#VLESS-Reality
```

### Hysteria2 客户端配置

**Let's Encrypt 证书模式：**
```
hy2://[PASSWORD]@[DOMAIN]:[PORT]#Hysteria2
```

**自签名证书模式：**
```
hy2://[PASSWORD]@[SERVER_IP]:[PORT]/?insecure=1#Hysteria2
```

## 📊 服务管理

### 查看服务状态
```bash
systemctl status sing-box
```

### 查看实时日志
```bash
journalctl -u sing-box -f
```

### 手动启动/停止
```bash
# 启动服务
systemctl start sing-box

# 停止服务
systemctl stop sing-box

# 重启服务
systemctl restart sing-box
```

## 🔍 故障排除

### 常见问题

1. **端口被占用**
   - 检查端口是否被其他服务占用
   - 使用 `netstat -tlnp | grep [PORT]` 查看端口占用情况

2. **服务启动失败**
   - 检查配置文件语法：`sing-box check -c /etc/sing-box/config.json`
   - 查看详细日志：`journalctl -u sing-box -n 50`

3. **连接失败**
   - 检查防火墙设置
   - 确认端口已开放
   - 验证客户端配置是否正确

### 日志位置
- **服务日志**：`/var/log/sing-box.log`
- **系统日志**：`journalctl -u sing-box`

## 🔒 安全建议

1. **防火墙配置**
   ```bash
   # 开放相应端口
   ufw allow 443/tcp
   ufw allow 8443/udp
   ```

2. **定期更新**
   - 定期检查 sing-box 新版本
   - 及时更新系统和依赖包

3. **监控服务**
   - 设置服务监控告警
   - 定期检查服务状态

## 📝 更新日志

### v2.1.1
- ✅ 改进域名解析验证功能
- ✅ 支持多种DNS查询方法（dig、nslookup、host、curl）
- ✅ 自动安装DNS工具包
- ✅ 更健壮的错误处理

### v2.1.0
- ✅ Hysteria2 支持证书类型选择
- ✅ 支持 Let's Encrypt 自动证书申请
- ✅ 保留自签名证书选项
- ✅ 添加域名解析验证功能

### v2.0.0
- ✅ 移除 AnyTLS 协议支持
- ✅ 添加自定义端口功能
- ✅ 优化混合协议模式
- ✅ 改进用户交互体验

### v1.0.0
- ✅ 初始版本发布
- ✅ 支持 VLESS Reality、Hysteria2、AnyTLS
- ✅ 基础服务管理功能

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 📄 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。

## ⚠️ 免责声明

本脚本仅供学习和研究使用，请遵守当地法律法规。使用者需自行承担使用风险。

---

**注意**：使用前请确保您了解相关协议的工作原理和安全风险。 