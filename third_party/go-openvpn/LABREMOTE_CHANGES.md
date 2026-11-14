# LabRemote 内嵌适配

来源：`github.com/buengese/go-openvpn`，v1.0.0，提交 `dbe4687d19d1671ac969728a82c5cd26f02d45ba`。

保留上游协议层源码、测试、原有版权与 LGPL-2.1-or-later 许可及使用例外。此目录的许可证独立于宿主 MIT 代码。修改日期：2026-11-14。

- 删除命令行、移动端封装、内核网卡后端及操作系统路由/DNS集成；`Client.Device` 必须由宿主显式提供，缺省返回错误。
- 宿主通过现有 WireGuard netstack/gVisor 创建纯内存网络设备，不使用该库自带的网络栈依赖。
- `internal/crypto`、`internal/datachannel/params.go` 添加 `cipher none` 的 HMAC 认证数据通道，保留现有序列号和重放检查；用于无数据加密配置的兼容。新代码注释给出协议布局出处。
- `internal/datachannel` 按每个接收包的 opcode 独立解析 V1/V2 头部与 AEAD 附加认证数据，兼容服务端发送 V1、客户端发送 V2 的非对称格式。密钥、认证和重放窗口保持不变；增加篡改、跨格式重放及进程内双向 TCP 回归测试。协议依据为 OpenVPN 2.5 `ssl.c` 的 `handle_data_channel_packet`，未复制其实现。
- 数据包丢弃事件仅记录错误类别，用于宿主提供协商参数与包计数诊断，不记录载荷、认证内容或密钥。
- 依赖清单只保留协议层使用的 Go LZO 解码器。上游系统集成测试未纳入本适配目录；保留的协议测试可在本模块中单独运行。
- 禁用 `SSLKEYLOGFILE` 环境变量触发的 TLS 密钥落盘；握手派生材料仅在内存内捕获。
- `profile/fileref.go` 将 Windows 上以斜杠或反斜杠起始的根路径视为越界；宿主同时在导入层拒绝所有外部文件引用。
- 从上游本机模拟服务器派生 `testserver` 测试夹具，关闭日志、删除命令行入口，增加内存设备、认证断言与 none/LZO 场景；该包仅被测试引用，不进入应用二进制。

本目录随宿主源码一起分发，可修改后重新构建和链接，不依赖预编译协议二进制。
