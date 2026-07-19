# LabRemote

[![CI](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/ci.yml/badge.svg)](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/ci.yml)
[![Release](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/release.yml/badge.svg)](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/release.yml)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-38bdf8)](https://github.com/EricHongXDD/LabRemote-Go/releases)

LabRemote 是面向 Windows 10/11 amd64 的隔离隧道 + SSH + 网页访问 + MCP 桌面客户端。它直接使用 SoftEther 原生协议，在应用进程内运行 DHCP、ARP 和用户态 TCP/IP 栈，只把配置的 SSH 连接及用户明确打开的 HTTP/HTTPS 资源送入隧道。它不会连接、创建或修改 Windows VPN，也不会新增系统网卡或路由。

## 已实现能力

- 连接配置新增、编辑、删除与分组展示；
- 隧道密码和 SSH 密码均保存到 Windows Credential Manager；旧配置中的预共享密钥仅为兼容保留，不再参与连接；
- SoftEther 原生 TLS 会话、Virtual Hub 自动发现和 DHCP 地址获取；
- WireGuard netstack/gVisor 用户态 TCP/IP；SSH 拨号仅允许配置的主机与端口；
- SoftEther 服务器证书首次确认、SHA-256 固定和变化阻断；
- SSH 密码认证、首次主机指纹确认和指纹变化阻断；
- 通过同一隔离 SSH 连接上传与下载多个文件或递归传输文件夹，支持拖拽上传、活动终端目录默认值、空目录、覆盖保护、并行传输、断点续传、实时进度和取消；
- xterm-256color 多标签 PTY、中文、ANSI、搜索、复制、粘贴和窗口缩放；
- 左侧连接/断开快捷操作、双击连接和连接项右键菜单；
- 通过随机 `127.0.0.1` 临时代理和 SSH `direct-tcpip` 跳板完成网页访问，并在系统默认浏览器中打开；代理随 Profile 断开统一回收；
- 只监听 `127.0.0.1` 的 Streamable HTTP MCP 服务；
- 10 个 MCP 工具、Profile 最小权限、Bearer Token、Host/Origin 校验、速率与并发限制；
- MCP 开启后可导出包含当前客户端配置、授权连接、工具协议、安全规范和终端操作工作流的 AI Markdown 手册；
- JSONL 应用日志与只保存命令 SHA256 的 MCP 审计日志；
- Windows amd64 可执行文件与 NSIS 安装包构建。

## 构建环境

- Go 1.25.12
- Wails CLI 2.13.0
- Node.js 22.18.0
- npm 10.9.3
- NSIS 3.12
- MCP Go SDK 1.6.1

依赖版本固定在 `go.mod`、`go.sum`、`frontend/package.json` 和 `frontend/package-lock.json`。

## 开发与测试

```powershell
$env:GOCACHE = "$PWD\.tools\gocache"
go test ./...

Set-Location frontend
npm.cmd ci
npm.cmd test
npm.cmd run build
```

生产构建：

```powershell
.\scripts\build.ps1
```

输出位于 `build\bin`。详细使用步骤见 [用户使用手册](docs/用户使用手册.md)，MCP 客户端配置、工具参数与安全边界见 [MCP 使用、配置与安全手册](docs/MCP配置与安全.md)。

## 下载与发行

- 已发布版本：访问 [GitHub Releases](https://github.com/EricHongXDD/LabRemote-Go/releases)；
- `LabRemote.exe`：免安装主程序；
- `LabRemote-amd64-installer.exe`：Windows amd64 用户级 NSIS 安装包；
- `SHA256SUMS.txt`：发行文件的 SHA-256 校验值。

推送符合 `v*` 格式的标签会触发发行工作流。标签版本应与 `wails.json` 中的 `info.productVersion` 一致，例如 `v1.0.0`。也可以手动运行发行工作流，仅构建并上传供检查的 Actions Artifact，不创建 GitHub Release。

## 项目协作

提交修改前请阅读 [贡献指南](CONTRIBUTING.md) 和 [安全策略](SECURITY.md)。项目使用 GitHub Actions 持续验证 Go、TypeScript 和 React 代码，并通过 Dependabot 跟踪 Go、npm 与 Actions 依赖更新。

## 隔离边界

SoftEther Virtual Hub 必须提供 DHCP 地址。LabRemote 不会随机选择客户端地址。连接期间 Windows 的“VPN”仍显示未连接，系统默认路由和其他应用流量不受影响。

历史 Windows RAS 实现仅作为迁移参考保留，并由 `legacy_ras` 构建标签隔离；默认测试、构建和发布产物均不编译该实现。

仓库包含可选的实时隔离测试。设置 `LABREMOTE_LIVE_PROFILE_ID` 后，测试会完成 SoftEther、DHCP、用户态 TCP、SSH 密码认证，以及真实文件/文件夹上传、下载和大文件中断续传，并断言连接前、连接中、断开后的 Windows VPN、IPv4 路由与网卡快照完全一致。额外设置 `LABREMOTE_LIVE_WEB_URL` 可对指定 HTTP/HTTPS 资源执行隔离浏览器代理验收。

## 许可证

本仓库目前未附加开源许可证。代码公开可见不代表授予复制、修改或再分发许可；如需使用，请先联系仓库所有者取得授权。第三方组件许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
