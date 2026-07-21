# 更新日志

本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

- 增加“仅 SSH（直接连接）”模式，不要求 SoftEther/VPN 配置；旧连接默认保持隔离隧道模式；
- 仅 SSH 模式下的终端、SFTP 和 MCP 直接使用 SSH，网页访问仍通过 SSH `direct-tcpip` 转发，可访问远端 `127.0.0.1` 或内网端口而无需公网开放；
- 网页访问会在 SSH 或可选隔离隧道意外断开后自动恢复连接并重试一次，现有浏览器代理地址无需重新创建；
- SSH 增加密码和私钥文件两种认证方式；私钥文件路径与可选口令保存在系统安全凭据库，Profile JSON 不记录本地路径；
- 删除、强制断开、指纹确认、凭据清理和传输取消等确认操作改用 LabRemote 应用内弹窗，不再显示 WebView 的 `localhost` 原生提示；
- 使用 MIT License 开源；
- 增加 Linux amd64 与 macOS Universal 发行包；
- macOS 使用 Keychain、Linux 使用 Secret Service 保存凭据；
- 手动或标签触发的多平台构建会自动汇总到 GitHub Release。

## [1.0.0] - 2026-07-19

- 首次公开发布；
- 提供进程内 SoftEther 隔离隧道、SSH 多标签终端和网页访问；
- 提供支持拖拽、并发与断点续传的上传/下载；
- 提供带最小权限、Bearer Token、审计和导出说明手册的本地 MCP 服务；
- 提供 Windows amd64 可执行文件与 NSIS 用户级安装包构建。
