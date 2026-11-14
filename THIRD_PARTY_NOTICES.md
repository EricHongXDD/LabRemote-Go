# Third-party notices

LabRemote 的进程内隔离传输包含或依赖以下开源项目：

- SoftEther VPN：协议兼容逻辑和握手水印依据官方源代码独立实现。版权归 SoftEther VPN Project 及其贡献者所有，使用 Apache License 2.0。<https://github.com/SoftEtherVPN/SoftEtherVPN>
- WireGuard userspace netstack adapter：使用 MIT License。<https://git.zx2c4.com/wireguard-go/>
- gVisor TCP/IP stack：使用 Apache License 2.0。<https://gvisor.dev/>
- pkg/sftp：用于在已认证 SSH 连接中创建 SFTP 客户端子通道，使用 BSD 2-Clause License。<https://github.com/pkg/sftp>
- go-keyring：用于访问 macOS Keychain 与 Linux Secret Service，使用 MIT License。<https://github.com/zalando/go-keyring>
- go-openvpn v1.0.0：用于进程内 OpenVPN 控制通道、TLS 认证、密钥派生、数据通道和 LZO 帧解码。来源为 <https://github.com/buengese/go-openvpn>，提交 `dbe4687d19d1671ac969728a82c5cd26f02d45ba`；原始代码与本地适配位于 `third_party/go-openvpn`，使用 LGPL-2.1-or-later 及上游使用例外。许可、完整适配源码和修改说明随项目提供，可替换修改后重新构建和链接。此组件的许可证独立于宿主 MIT 代码。
- go-lzo v0.2.0：纯 Go LZO 解码器，来源为 <https://github.com/buengese/go-lzo>，使用 MIT License。
- v5vpn-rea-client aTrust 协议包：来源为 <https://github.com/hygkui/v5vpn-rea-client>，提交 `c9e7afb07a2745655ae8fec4be8027c9a383814f`，Copyright 2026 hygkui and contributors，Apache-2.0。经适配的源码、许可、NOTICE 和修改说明位于 `internal/atrust/protocol`；只使用 aTrust 协议代码，不包含其界面、系统代理或凭据提取功能。

LabRemote 不包含研究阶段使用的 `go-softether` AGPL 原型；`.tools/research` 不参与应用或安装包构建。
