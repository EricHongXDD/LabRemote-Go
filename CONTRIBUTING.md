# 贡献指南

感谢参与 LabRemote。提交修改前，请先确认改动不会削弱隔离隧道、凭据存储、主机指纹固定和 MCP 最小权限边界。

## 开发环境

- Windows 10/11 amd64；
- Go 1.25.1；
- Node.js 22.18.0 与 npm 10.9.3；
- Wails CLI 2.13.0；
- 仅在生成 NSIS 安装包时需要 NSIS 3.12。

## 本地验证

```powershell
$env:GOCACHE = "$PWD\.tools\gocache"
go mod verify
go test ./...
go vet ./...

Set-Location frontend
npm.cmd ci
npm.cmd test
npm.cmd run build
```

生产构建使用：

```powershell
.\scripts\build.ps1
```

## 提交要求

1. 一个提交只解决一个清晰问题，提交信息使用简短动词短语；
2. 新增或修改行为必须补充相应测试和用户文档；
3. 不得提交真实服务器地址、用户名、密码、Token、私钥、用户配置、日志或诊断备份；
4. 不得绕过证书/主机指纹确认、MCP 权限校验或隔离路由限制；
5. `frontend/wailsjs` 是 Wails 生成绑定，后端公开方法或模型变化后应同步更新并验证前端构建。

Pull Request 应说明变更原因、用户影响、验证方式，以及涉及安全边界时的风险分析。
