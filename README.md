# Coraza WAF Proxy

基于 Coraza WAF 的反向代理防火墙，支持攻击检测、地理IP封锁和实时攻击日志。

## 功能特性

- **Web应用防火墙**: 基于 Coraza WAF v3，提供完整的请求/响应过滤
- **攻击检测**: 支持SQL注入、XSS、RCE、LFI/RFI、SSRF等多种攻击检测
- **地理IP封锁**: 支持基于GeoIP的IP地理位置封锁
- **实时日志**: 记录并展示攻击事件，支持中文显示
- **管理后台**: Web界面配置和管理WAF规则
- **多规则集**: 集成 OWASP Core Rule Set (CRS)

## 系统要求

- Go 1.24+
- SQLite3

## 快速开始

### 构建

```bash
go build -o coraza-waf-proxy main.go
```

### 安装

```bash
./install.sh
```

服务启动后访问 `http://localhost:8080/`

### 配置文件

主要配置文件位于 `config/coraza.conf`，规则文件位于 `coreruleset/rules/`。

## 目录结构

```
.
├── config/              # WAF配置文件
├── coreruleset/         # OWASP CRS规则集
│   └── rules/           # 安全规则文件
├── static/              # 静态资源
│   ├── geoip/           # GeoIP数据库
│   ├── maps/            # 地理信息JSON
│   └── sounds/          # 告警声音
├── web/                 # Web界面
│   ├── html/            # HTML模板
│   └── js/              # JavaScript
├── main.go              # 主程序
└── go.mod               # Go模块
```

## 安全规则

本项目使用 OWASP Core Rule Set，包含以下防护类别：

- REQUEST-900: 初始化规则
- REQUEST-901: 协议强制
- REQUEST-920: 协议攻击防护
- REQUEST-921: 协议攻击
- REQUEST-922: 多部分攻击
- REQUEST-930: LFI/RFI攻击
- REQUEST-931: RFI攻击
- REQUEST-932: RCE攻击
- REQUEST-933: PHP注入
- REQUEST-941: XSS攻击
- REQUEST-942: SQL注入
- REQUEST-943: 会话固定
- REQUEST-944: Java攻击
- RESPONSE-950: 数据泄露
- RESPONSE-955: Webshell检测

## 许可证

本项目遵循相关开源许可证。
