# Third-party notices

LabRemote 的进程内隔离传输包含或依赖以下开源项目：

- SoftEther VPN：协议兼容逻辑和握手水印依据官方源代码独立实现。版权归 SoftEther VPN Project 及其贡献者所有，使用 Apache License 2.0。<https://github.com/SoftEtherVPN/SoftEtherVPN>
- WireGuard userspace netstack adapter：使用 MIT License。<https://git.zx2c4.com/wireguard-go/>
- gVisor TCP/IP stack：使用 Apache License 2.0。<https://gvisor.dev/>
- pkg/sftp：用于在已认证 SSH 连接中创建 SFTP 客户端子通道，使用 BSD 2-Clause License。<https://github.com/pkg/sftp>
- go-keyring：用于访问 macOS Keychain 与 Linux Secret Service，使用 MIT License。<https://github.com/zalando/go-keyring>

LabRemote 不包含研究阶段使用的 `go-softether` AGPL 原型；`.tools/research` 不参与应用或安装包构建。
