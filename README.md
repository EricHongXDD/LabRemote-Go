# LabRemote

[![CI](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/ci.yml/badge.svg)](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/ci.yml)
[![Release](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/release.yml/badge.svg)](https://github.com/EricHongXDD/LabRemote-Go/actions/workflows/release.yml)
[![Platforms: Windows, Linux, macOS](docs/assets/platforms.svg)](#支持平台与下载)

LabRemote 是面向 Windows、Linux 和 macOS 的 SSH + 可选 VPN + 网页访问 + MCP 桌面客户端。连接可选择“隔离隧道 + SSH”、“OpenVPN + SSH”、“aTrust + SSH”或“仅 SSH”。隔离隧道使用 SoftEther 原生协议，在应用进程内运行 DHCP、ARP 和用户态 TCP/IP 栈；OpenVPN 也在进程内完成协议认证与用户态 TCP/IP 传输；aTrust 通过独立网页登录建立进程内 TCP 通道；仅 SSH 直接连接服务器。所有方式的网页访问都通过已认证 SSH 的 `direct-tcpip` 转发，目标端口无需开放到公网。

## 已实现能力

- “隔离隧道 + SSH”、“OpenVPN + SSH”、“aTrust + SSH”和“仅 SSH”四种连接配置的新增、复制、编辑、删除与分组展示；复制会清空名称并安全复用其余配置和系统凭据，旧配置自动按隔离隧道模式读取；
- OpenVPN `.ovpn` / ZIP 配置导入、VPN 账号密码、静态挑战 OTP/TOTP 弹窗；支持标准账号密码配置，支持 Windows/Linux 进程内隔离传输，无需外部客户端；
- 选择一个或多个连接导出为密码保护的 `.lrcx` 连接包，并在其他电脑导入；连接配置、隧道/SSH 密码、兼容预共享密钥、SSH 私钥内容与口令、服务器证书和 SSH 主机信任记录使用 Argon2id 派生的 AES-256-GCM 密钥加密，全局 MCP Token 不会进入连接包；
- 隧道密码、SSH 密码、私钥文件路径和私钥口令保存到操作系统安全凭据库：Windows Credential Manager、macOS Keychain 或 Linux Secret Service；私钥文件仍保留在用户选择的原位置；旧配置中的预共享密钥仅为兼容保留，不再参与连接；
- SoftEther 原生 TLS 会话、Virtual Hub 自动发现和 DHCP 地址获取；
- WireGuard netstack/gVisor 用户态 TCP/IP；SSH 拨号仅允许配置的主机与端口；
- SoftEther 服务器证书首次确认、SHA-256 固定和变化阻断；
- SSH 密码或私钥认证、首次主机指纹确认和指纹变化阻断；
- “测试 SSH 服务器”同时验证认证、会话通道与 PTY，不启动 Shell 或执行用户命令；会话请求超时、服务器拒绝及资源上限分别返回明确错误。“本机隧道地址”是 DHCP 分配给客户端的地址，并非 SSH 服务器地址；
- 通过独立的 SSH 文件传输连接上传与下载多个文件或递归传输文件夹；取消或清理停滞传输不会关闭已有终端，传输连续 60 秒没有 SFTP 数据活动时退出并保留安全续传分片；隔离模式继续经过用户态隧道，直接模式不建立 VPN；支持拖拽上传、活动终端目录默认值、空目录、覆盖保护、并行传输、断点续传、实时进度、实时上传速度、后台最小化和取消；最小化后任务继续运行，并在右下角任务条持续显示状态；大文件上传会按剩余大小和并行文件数自适应使用 1-64 个标准 SFTP 请求，单任务总在途请求不超过 64 个；
- xterm-256color 多标签 PTY、中文、ANSI、搜索、复制、粘贴和窗口缩放；
- 左侧连接/断开快捷操作、双击连接和连接项右键菜单；
- 通过随机 `127.0.0.1` 临时代理和 SSH `direct-tcpip` 跳板完成网页访问，并在系统默认浏览器中打开；网络意外断开时自动恢复可选隧道和 SSH 后重试，代理随 Profile 主动断开统一回收；
- 只监听 `127.0.0.1` 的 Streamable HTTP MCP 服务；
- 16 个 MCP 工具，包括按已授权连接配置选择目标、非交互/交互 SSH 和异步文件上传、下载；具备 Profile 独立最小权限、任务所有权隔离、Bearer Token、Host/Origin 校验、速率与并发限制；
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

推送符合 `v*` 格式的标签会自动构建三个平台并把产物上传到对应 GitHub Release。手动运行发行工作流时填写版本标签也会自动创建或更新 Release；只有显式关闭“发布到 Releases”时才仅保留 Actions Artifact。标签版本必须与 `wails.json` 中的 `info.productVersion` 一致，例如 `v1.5.9`。

SSH 每 15 秒发送一次需要回复的心跳，10 秒无响应时淘汰失效连接，下一次操作重新建立连接。`ssh_exec` 的 30 秒默认超时（最多 300 秒）覆盖连接、创建会话、启动和等待退出全过程；连接和创建会话期间状态查询仍可返回。命令不会自动重放，避免重复执行实验。若传输失败，请保留原 `job_id` 和分片，先恢复连接，再用 `resume=true` 续传尚未完成的文件；已完成文件默认不会被覆盖。

当前 Windows 与 macOS 产物尚未配置代码签名或 Apple 公证；首次运行时操作系统可能显示未知开发者提示。请先用 `SHA256SUMS.txt` 核验下载文件。

## 项目协作

提交修改前请阅读 [贡献指南](CONTRIBUTING.md) 和 [安全策略](SECURITY.md)。项目使用 GitHub Actions 持续验证 Go、TypeScript 和 React 代码，并通过 Dependabot 跟踪 Go、npm 与 Actions 依赖更新。

## 隔离边界

隔离隧道模式要求 SoftEther Virtual Hub 提供 DHCP 地址。LabRemote 不会随机选择客户端地址；连接期间不会创建系统 VPN 或修改默认路由，其他应用流量不受影响。仅 SSH 模式使用操作系统普通 TCP 网络直接访问且只允许配置的 SSH 主机与端口，不建立 SoftEther 会话。

网页访问不会让浏览器直接访问目标。LabRemote 在本机创建带随机令牌的回环代理，再通过 SSH `direct-tcpip` 让远端 SSH 服务器访问目标。例如填写 `http://127.0.0.1:1294` 时，`127.0.0.1` 指 SSH 服务器自身，因此 1294 端口无需开放到公网。SSH 服务端必须允许 TCP 转发。

历史 Windows RAS 实现仅作为迁移参考保留，并由 `legacy_ras` 构建标签隔离；默认测试、构建和发布产物均不编译该实现。

仓库包含可选的实时隔离测试。设置 `LABREMOTE_LIVE_PROFILE_ID` 后，测试会完成 SoftEther、DHCP、用户态 TCP、SSH 身份认证，以及真实文件/文件夹上传、下载和大文件中断续传，并断言连接前、连接中、断开后的 Windows VPN、IPv4 路由与网卡快照完全一致。额外设置 `LABREMOTE_LIVE_WEB_URL` 可对指定 HTTP/HTTPS 资源执行隔离浏览器代理验收。

## OpenVPN 进程内隔离隧道

直接导入 VPN 服务提供方的配置并完成身份认证。无需安装或调用本机 OpenVPN 客户端，无需管理员/root 权限。协议认证、LZO 解码及 TCP/IP 均在应用进程内运行，不创建操作系统虚拟网卡，不修改系统路由、默认网关或 DNS。

1. 新建连接，选择 **OpenVPN 隔离隧道 + SSH（OTP）**。
2. 导入 `.ovpn` 配置文件或包含单个配置的 `.zip` 文件；配置包含备用服务器和 CA。压缩包有多个配置时，请解压后选择一个。
3. 输入 VPN **用户名**和**密码**。无需填写 OpenVPN 程序路径、预共享密钥或令牌种子。
4. 输入**SSH 服务器地址**、端口（通常为 22）、SSH 用户名，以及密码或私钥；VPN 与 SSH 凭据分别保存在系统安全凭据库。
5. 测试或连接时，配置要求 OTP/TOTP 则弹窗输入。从 VPN 服务提供方指定的验证器或令牌平台获取当前 **6 位数字**，确认令牌与 VPN 账号一致，并保留开头的 0。验证码不保存到配置、安全凭据库或应用日志。
6. 认证成功后建立用户态网络，再连接 SSH；取消验证码弹窗会停止本次连接，过期或认证失败时重新连接。整体连接最多等待 3 分钟。同一 VPN 账号不要同时在其他 VPN 客户端登录，以免互相抢占。

每个连接使用独立内存网络栈。只有配置的 SSH 主机与端口可进入该隧道；SSH 文件传输和网页代理沿用现有访问控制、主机指纹验证及转发机制。服务器推送的路由、默认网关和 DNS 只用于进程内网络，不会应用到系统。同一编辑窗口的 OpenVPN 与 SSH 测试会复用已认证的隧道，修改 SSH 参数或测试失败无需重复输入 OTP。更改 VPN 配置、关闭编辑窗口、空闲 15 分钟或退出应用时会回收测试会话与网络栈；重新认证需输入当时有效的验证码。正式连接在主动断开时回收。

支持 `dev tun`、TCP/UDP、内嵌 CA、账号密码与静态验证码挑战；支持 `cipher none`、LZO 和多备用服务器配置。拒绝配置脚本、插件、外部凭据/证书/私钥文件及系统路由指令。协议核心及本项目适配源码位于 `third_party/go-openvpn`，许可和修改说明与源码一并提供。

离线测试覆盖配置导入、TLS、OTP 认证、非对称 V1/V2 数据格式、认证与防重放、进程内双向 TCP/DNS，以及重复测试时的认证复用。SSH 目标超时时，客户端会通过 VPN 推送的 DNS 查询配置中的 VPN 主机名，区分数据通道故障和目标端口无响应；诊断仅保留协议参数与计数，不记录密码、验证码、密钥或数据载荷。实际 VPN 登录需使用有效账号和当前验证码验收。

## aTrust 进程内隔离接入

此功能为实验性适配，独立认证窗口当前支持 Windows/Linux 上安装的 Edge/Chrome；macOS 暂不支持这一认证入口。

选择 **aTrust 隔离隧道 + SSH（网页登录）** 并填写 HTTPS 服务器地址。点击认证或测试 SSH 后，按弹窗打开本次独立的 Edge/Chrome 认证窗口，在服务提供方页面手动完成统一认证和多因素认证。应用仅接收本次 OAuth 回调并在内存内保存会话，不调用已安装的 aTrust 客户端，不修改系统 VPN、网卡、路由、DNS 或代理。

数据面仅为配置的 SSH 主机与端口建立 aTrust TCP 流式通道，目标必须匹配服务端授权资源。网关证书使用系统 CA 验证；私有证书需要用户核对后明确接受指纹。服务端要求尚未支持的额外认证、终端准入或资源权限时，连接失败并提示，不伪造官方客户端或受信任进程身份，也不会回退到系统直连。

终端、SFTP 和网页代理均沿用这个 SSH 连接；网页访问由 SSH 服务器转发。测试窗口中的认证会话可复用，修改 SSH 参数无需重新认证；更改 aTrust 入口、关闭测试窗口、空闲 15 分钟或退出应用后回收会话。独立认证浏览器使用临时用户目录，完成或取消后关闭并清理。本实现的网关兼容性需以真实账号和授权资源实测为准。

## 许可证

LabRemote 使用 [MIT License](LICENSE) 开源。第三方组件许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
