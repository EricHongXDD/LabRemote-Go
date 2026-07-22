# LabRemote

[![CI](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/ci.yml/badge.svg)](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/ci.yml)
[![Release](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/release.yml/badge.svg)](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/release.yml)
[![Platforms: Windows, Linux, macOS](docs/assets/platforms.svg)](#支持平台与下载)

LabRemote 是面向 Windows、Linux 和 macOS 的 SSH + 可选隔离隧道 + 网页访问 + MCP 桌面客户端。连接可选择“隔离隧道 + SSH”或“仅 SSH”：前者使用 SoftEther 原生协议，在应用进程内运行 DHCP、ARP 和用户态 TCP/IP 栈；后者直接连接可公开到达的 SSH 服务器，不要求 VPN。两种方式的网页访问都通过已认证 SSH 的 `direct-tcpip` 转发，目标端口无需开放到公网。

## 已实现能力

- “隔离隧道 + SSH”和“仅 SSH”两种连接配置的新增、编辑、删除与分组展示；旧配置自动按隔离隧道模式读取；
- 隧道密码、SSH 密码、私钥文件路径和私钥口令保存到操作系统安全凭据库：Windows Credential Manager、macOS Keychain 或 Linux Secret Service；私钥文件仍保留在用户选择的原位置；旧配置中的预共享密钥仅为兼容保留，不再参与连接；
- SoftEther 原生 TLS 会话、Virtual Hub 自动发现和 DHCP 地址获取；
- WireGuard netstack/gVisor 用户态 TCP/IP；SSH 拨号仅允许配置的主机与端口；
- SoftEther 服务器证书首次确认、SHA-256 固定和变化阻断；
- SSH 密码或私钥认证、首次主机指纹确认和指纹变化阻断；
- 通过同一 SSH 连接上传与下载多个文件或递归传输文件夹；隔离模式继续经过用户态隧道，直接模式不建立 VPN；支持拖拽上传、活动终端目录默认值、空目录、覆盖保护、并行传输、断点续传、实时进度和取消；
- xterm-256color 多标签 PTY、中文、ANSI、搜索、复制、粘贴和窗口缩放；
- 左侧连接/断开快捷操作、双击连接和连接项右键菜单；
- 通过随机 `127.0.0.1` 临时代理和 SSH `direct-tcpip` 跳板完成网页访问，并在系统默认浏览器中打开；网络意外断开时自动恢复可选隧道和 SSH 后重试，代理随 Profile 主动断开统一回收；
- 只监听 `127.0.0.1` 的 Streamable HTTP MCP 服务；
- 13 个 MCP 工具，包括按已授权连接配置选择目标、非交互/交互 SSH 和异步文件上传；具备 Profile 独立最小权限、任务所有权隔离、Bearer Token、Host/Origin 校验、速率与并发限制；
- MCP 开启后可导出包含当前客户端配置、授权连接、工具协议、安全规范和终端操作工作流的 AI Markdown 手册；
- JSONL 应用日志与只保存命令 SHA256 的 MCP 审计日志；
- Windows amd64 可执行文件与 NSIS 安装包、Linux amd64 压缩包、macOS Universal 应用包构建。

## 构建环境

- Go 1.25.12
- Wails CLI 2.13.0
- Node.js 22.18.0
- npm 10.9.3
- NSIS 3.12
- MCP Go SDK 1.6.1

Linux 构建需要 GTK3 与 WebKitGTK 4.1；macOS 构建需要 Xcode Command Line Tools。发行工作流会在对应的原生 GitHub Runner 上安装并验证这些依赖。

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

该脚本生成 Windows 发行包，输出位于 `build\bin`。Linux 和 macOS 使用 `.github/workflows/release.yml` 中的原生 Runner 构建命令。详细使用步骤见 [用户使用手册](docs/用户使用手册.md)，MCP 客户端配置、工具参数与安全边界见 [MCP 使用、配置与安全手册](docs/MCP配置与安全.md)。

## 支持平台与下载

- 已发布版本：访问 [GitHub Releases](https://github.com/EricHongXDD/LabRemote-Go/releases)；
- `LabRemote-windows-amd64.exe`：Windows amd64 免安装主程序；
- `LabRemote-amd64-installer.exe`：Windows amd64 用户级 NSIS 安装包；
- `LabRemote-linux-amd64.tar.gz`：Linux amd64 可执行文件、README 与许可证；运行时需要 GTK3、WebKitGTK 4.1 和可用的 Secret Service；
- `LabRemote-macos-universal.zip`：同时支持 Apple Silicon 与 Intel 的 macOS `.app`；凭据保存到 Keychain；
- `SHA256SUMS.txt`：全部发行文件的 SHA-256 校验值。

推送符合 `v*` 格式的标签会自动构建三个平台并把产物上传到对应 GitHub Release。手动运行发行工作流时填写版本标签也会自动创建或更新 Release；只有显式关闭“发布到 Releases”时才仅保留 Actions Artifact。标签版本必须与 `wails.json` 中的 `info.productVersion` 一致，例如 `v1.1.0`。

当前 Windows 与 macOS 产物尚未配置代码签名或 Apple 公证；首次运行时操作系统可能显示未知开发者提示。请先用 `SHA256SUMS.txt` 核验下载文件。

## 项目协作

提交修改前请阅读 [贡献指南](CONTRIBUTING.md) 和 [安全策略](SECURITY.md)。项目使用 GitHub Actions 持续验证 Go、TypeScript 和 React 代码，并通过 Dependabot 跟踪 Go、npm 与 Actions 依赖更新。

## 隔离边界

隔离隧道模式要求 SoftEther Virtual Hub 提供 DHCP 地址。LabRemote 不会随机选择客户端地址；连接期间不会创建系统 VPN 或修改默认路由，其他应用流量不受影响。仅 SSH 模式使用操作系统普通 TCP 网络直接访问且只允许配置的 SSH 主机与端口，不建立 SoftEther 会话。

网页访问不会让浏览器直接访问目标。LabRemote 在本机创建带随机令牌的回环代理，再通过 SSH `direct-tcpip` 让远端 SSH 服务器访问目标。例如填写 `http://127.0.0.1:1294` 时，`127.0.0.1` 指 SSH 服务器自身，因此 1294 端口无需开放到公网。SSH 服务端必须允许 TCP 转发。

历史 Windows RAS 实现仅作为迁移参考保留，并由 `legacy_ras` 构建标签隔离；默认测试、构建和发布产物均不编译该实现。

仓库包含可选的实时隔离测试。设置 `LABREMOTE_LIVE_PROFILE_ID` 后，测试会完成 SoftEther、DHCP、用户态 TCP、SSH 身份认证，以及真实文件/文件夹上传、下载和大文件中断续传，并断言连接前、连接中、断开后的 Windows VPN、IPv4 路由与网卡快照完全一致。额外设置 `LABREMOTE_LIVE_WEB_URL` 可对指定 HTTP/HTTPS 资源执行隔离浏览器代理验收。

## 许可证

LabRemote 使用 [MIT License](LICENSE) 开源。第三方组件许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
