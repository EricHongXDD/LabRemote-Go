# LabRemote MCP 使用、配置与安全手册

## 1. 功能与边界

LabRemote 在桌面程序内提供一个本机 Streamable HTTP MCP 服务，让支持 MCP 的客户端通过已保存的连接配置建立“隔离隧道 + SSH”或“仅 SSH”连接、查询状态、执行 SSH 命令或操作 MCP 专属交互终端。

MCP 服务具有以下边界：

- 只有 LabRemote 正在运行且界面中 MCP 已开启时可用；
- 只监听本机 IPv4 回环地址 `127.0.0.1`，不会监听局域网地址；
- 所有请求必须携带界面生成的 Bearer Token；
- 只显示明确授权给 MCP 的连接配置；
- 隧道密码、SSH 密码、私钥文件路径、私钥口令和服务器密钥不会作为 MCP 参数或返回值出现；
- 当前 MCP 提供连接、命令和交互终端工具，不提供文件上传或下载工具；文件传输请使用 LabRemote 图形界面的“传输”窗口；
- 工具名中的 `vpn_connect`、`vpn_disconnect` 是兼容名称：`isolated_tunnel` 配置操作进程内 SoftEther 隔离隧道和 SSH，`direct_ssh` 配置只操作直接 SSH 连接；都不会连接或修改系统 VPN。

## 2. 首次启用

### 2.1 先完成图形界面首次连接

首次连接某台服务器时，LabRemote 会要求确认 SSH 主机密钥指纹；隔离模式还会要求确认 SoftEther 服务器证书。MCP 没有接受指纹的工具，因此应先在图形界面连接一次，并与管理员核对指纹后确认。

如果服务器证书或 SSH 主机密钥以后发生变化，LabRemote 会继续阻断 MCP 连接，必须先查明变化原因；不要为了恢复 MCP 而绕过指纹校验。

### 2.2 为连接配置授予 MCP 权限

编辑目标连接，在 MCP 权限区域按需启用：

| 界面权限 | 作用 | 对应工具 |
|---|---|---|
| 允许 MCP 看到此配置 | MCP 可以列出、查询并连接此配置 | `profiles_list`、`connection_status`、`vpn_connect` |
| 允许执行非交互命令 | 允许执行非交互 SSH 命令 | `ssh_exec` |
| 允许创建交互会话 | 允许创建和操作 MCP 专属 PTY | `ssh_session_open/write/read/resize/close` |
| 允许断开连接 | 允许请求断开 SSH 与可选隔离隧道 | `vpn_disconnect` |

建议只勾选实际需要的最小权限。仅打开全局 MCP 开关不会自动授权任何连接。

### 2.3 启动服务

1. 在主窗口左下角输入端口，允许范围为 `1024-65535`，默认 `38765`；
2. 开启 MCP 开关；
3. 确认状态显示为“已开启”，地址类似 `http://127.0.0.1:38765/mcp`；
4. 点击“复制 MCP 配置”。

如果希望让 AI 直接理解全部工具和终端操作流程，可以在 MCP 开启后点击“导出 AI 终端操作手册”，选择本地位置保存 `.md` 文件。导出的文档会根据当前状态动态包含：

- 当前 Streamable HTTP 地址和带 Bearer Token 的客户端配置；
- 当前明确授权给 MCP 的连接 ID、SSH 目标和能力；
- 10 个 MCP 工具的用途、关键参数与限制；
- 非交互命令和交互 PTY 的推荐调用流程；
- Base64 编码、增量读取 cursor、退出码和截断处理规则；
- 高风险终端操作的确认要求、错误处理和会话清理规范。

文档不会包含隧道密码、SSH 密码、私钥路径、私钥口令或系统凭据引用，但会包含当前 MCP Token。它等同于本机访问凭据，只能提供给同一台电脑上的受信任 AI 客户端。

开启状态和端口会保存到当前操作系统用户配置中。下次启动 LabRemote 时，如果上次保持开启，程序会尝试恢复 MCP 服务。端口已被其他程序占用时，恢复或手动开启会失败。

## 3. MCP 客户端配置

“复制 MCP 配置”会生成包含当前地址和令牌的 JSON：

```json
{
  "mcpServers": {
    "labremote": {
      "url": "http://127.0.0.1:38765/mcp",
      "headers": {
        "Authorization": "Bearer <界面生成的令牌>"
      }
    }
  }
}
```

将 `labremote` 节点合并到 MCP 客户端的配置中，并按客户端要求重新加载配置或重启客户端。客户端必须同时支持：

- Streamable HTTP MCP；
- 为 MCP 请求添加自定义 `Authorization` 请求头。

如果客户端只支持 `stdio`，或者不允许设置请求头，则不能直接连接此服务。不要通过删除鉴权、改为公网监听或把 Token 写入 URL 来规避限制。

Token 等同于本机 MCP 访问凭据：

- 不要把复制出的完整 JSON 提交到 Git、工单或聊天记录；
- 不要在多台电脑之间复用；
- 怀疑泄露时点击“重新生成令牌”；
- 重新生成后旧令牌立即失效，当前 MCP 交互会话会关闭，客户端需要更新配置。

导出的 AI Markdown 同样包含 Token。任务完成后应妥善保管或删除；如果文件曾进入不受信任的位置，应立即重新生成令牌并重新导出。

## 4. 推荐的连通性检查

客户端加载配置后，按以下顺序检查：

1. 调用 `profiles_list`；
2. 从返回结果复制目标 `id`，不要猜测 `profile_id`；
3. 调用 `connection_status`；
4. 如尚未连接，调用 `vpn_connect`；
5. 再次调用 `connection_status`：隔离模式确认 `vpn_status=connected`，仅 SSH 模式确认 `vpn_status=not_required`；两者都应为 `route_ready=true`、`ssh_connected=true`；
6. 根据已授予权限调用 `ssh_exec` 或打开交互会话。

示例工具输入：

```json
{
  "profile_id": "从 profiles_list 返回的 id"
}
```

`vpn_status` 中的“VPN”只是兼容命名。`connection_mode=direct_ssh` 时固定返回 `not_required`，表示没有 VPN 阶段；`connection_mode=isolated_tunnel` 时返回进程内隔离隧道状态。系统 VPN、路由和网卡不会因此改变。

## 5. 工具参考

### 5.1 `profiles_list`

列出所有启用了“允许 MCP 看到此配置”的连接。

输入：无。

返回字段：

```json
{
  "profiles": [
    {
      "id": "profile-id",
      "name": "显示名称",
      "connection_mode": "direct_ssh",
      "vpn_status": "not_required",
      "ssh_status": "connected"
    }
  ]
}
```

状态查询失败时，单个配置的状态可能返回 `unknown`，但不会因此隐藏其他已授权配置。

### 5.2 `connection_status`

查询指定配置的连接方式、可选隔离隧道、SSH、会话和文件传输状态。

输入：

```json
{"profile_id":"profile-id"}
```

主要返回字段：

| 字段 | 含义 |
|---|---|
| `connection_mode` | `isolated_tunnel`（隔离隧道 + SSH）或 `direct_ssh`（仅 SSH） |
| `vpn_status` | 仅 SSH 为 `not_required`；隔离模式为 `disconnected`、`preparing`、`dialing`、`connected`、`reconnecting`、`disconnecting` 或 `failed` |
| `route_ready` | 进程内用户态网络是否已可访问目标 SSH |
| `ssh_connected` | SSH 客户端连接是否已建立 |
| `ui_sessions` | 图形界面终端数量 |
| `mcp_sessions` | MCP 交互终端数量 |
| `active_commands` | 正在运行的非交互命令数量 |
| `active_transfers` | 正在运行的图形界面上传/下载任务数量 |

### 5.3 `vpn_connect`

使用系统安全凭据库中已保存的凭据，按 Profile 建立进程内隔离隧道和 SSH，或只建立直接 SSH 连接。

输入：

```json
{"profile_id":"profile-id"}
```

成功返回：

```json
{"ok":true}
```

重复调用是安全的：连接已经存在时会复用现有连接。该工具只要求配置对 MCP 可见，不要求命令或交互权限。

### 5.4 `vpn_disconnect`

断开指定配置的 SSH 与可选进程内隔离隧道。必须启用“允许断开连接”。

输入：

```json
{
  "profile_id": "profile-id",
  "force": false
}
```

- `force=false`：存在活动 MCP 会话、命令或文件传输时拒绝断开；
- `force=true`：可取消 MCP 侧活动资源并断开；
- 只要存在图形界面终端，无论 `force` 是否为 `true`，MCP 都不能断开该连接；请由用户在图形界面处理。

### 5.5 `ssh_exec`

执行一条非交互远端命令。必须启用“允许执行非交互命令”。调用时会自动按 Profile 建立直接 SSH，或先建立隔离隧道再连接 SSH。

输入：

```json
{
  "profile_id": "profile-id",
  "command": "uname -a",
  "timeout_seconds": 30,
  "max_output_bytes": 1048576
}
```

参数限制：

- `command`：不能为空；由远端 Shell 解释；
- `timeout_seconds`：默认 30 秒，最大 300 秒；
- `max_output_bytes`：stdout 和 stderr 各自的限制，默认 1 MiB，最大 4 MiB；
- 全局最多同时运行 4 个 MCP SSH 命令。

返回示例：

```json
{
  "ok": true,
  "exit_code": 0,
  "stdout": "Linux ...\n",
  "stderr": "",
  "duration_ms": 125,
  "truncated": false
}
```

`ok=true` 表示工具调用和 SSH 会话成功完成，不代表远端命令退出码一定为 0；判断命令结果应读取 `exit_code`。`truncated=true` 表示至少一个输出流超过限制，返回内容已截断。

### 5.6 `ssh_session_open`

打开 MCP 专属的交互式 SSH PTY。必须启用“允许创建交互会话”。最多同时存在 8 个 MCP 会话。

输入：

```json
{
  "profile_id": "profile-id",
  "cols": 120,
  "rows": 30
}
```

`cols` 默认 120，允许 `20-1000`；`rows` 默认 30，允许 `5-500`。成功返回后保存 `session_id`，后续工具必须使用该值。

### 5.7 `ssh_session_write`

向 MCP 交互会话写入数据。数据必须先进行标准 Base64 编码，单次解码后最多 65536 字节。

例如发送 `ls -la` 并回车：

```json
{
  "session_id": "mcp-session-...",
  "data_base64": "bHMgLWxhCg=="
}
```

不要把明文命令直接放入 `data_base64`。方向键、控制字符和 UTF-8 文本也都应先编码为字节，再做 Base64 编码。

### 5.8 `ssh_session_read`

按游标增量读取 MCP 交互会话输出。

输入：

```json
{
  "session_id": "mcp-session-...",
  "cursor": 0,
  "max_bytes": 65536,
  "wait_ms": 1000
}
```

参数与返回规则：

- 首次读取使用 `cursor=0`；
- 后续读取必须使用上次返回的 `cursor`；
- `max_bytes` 默认 65536，单次最大 1 MiB；
- `wait_ms` 为没有新输出时的最长等待时间，范围 `0-30000` 毫秒；
- `data_base64` 是输出字节的 Base64，需要由客户端解码；
- `open=true` 表示会话仍在运行；
- `truncated=true` 表示调用方游标过旧，部分早期输出已被 2 MiB 环形缓冲区覆盖；应从本次返回的游标继续读取；
- `error` 包含会话关闭原因或读取错误。

典型循环：读取 → 解码 `data_base64` → 保存返回的 `cursor` → 在 `open=true` 时继续读取。

### 5.9 `ssh_session_resize`

调整 MCP 交互会话的 PTY 尺寸：

```json
{
  "session_id": "mcp-session-...",
  "cols": 160,
  "rows": 40
}
```

调整时要求 `cols >= 20`、`rows >= 5`；建议继续使用 `ssh_session_open` 的范围（列数不超过 1000、行数不超过 500）。

### 5.10 `ssh_session_close`

关闭 MCP 自己创建的交互会话：

```json
{"session_id":"mcp-session-..."}
```

MCP 工具不能读取、写入、缩放或关闭图形界面创建的终端。关闭全局 MCP 服务时，所有 MCP 专属会话会关闭，但图形界面终端保持运行。

## 6. 常用工作流

### 6.1 执行一次命令

1. `profiles_list` 获取 `profile_id`；
2. `connection_status` 检查状态；
3. `vpn_connect` 建立连接；
4. `ssh_exec` 执行命令；
5. 检查 `exit_code`、`stderr` 和 `truncated`；
6. 不再使用且权限允许时调用 `vpn_disconnect`。

### 6.2 运行交互程序

1. `ssh_session_open` 获取 `session_id`；
2. `ssh_session_read` 读取初始提示符并保存 `cursor`；
3. 将输入编码为 Base64 后调用 `ssh_session_write`；
4. 使用最新 `cursor` 循环调用 `ssh_session_read`；
5. 窗口尺寸变化时调用 `ssh_session_resize`；
6. 完成后调用 `ssh_session_close`。

客户端应始终在 `finally`、任务清理或等价流程中关闭已打开的交互会话，避免占满 8 个会话配额。

## 7. 安全设计

- 服务固定监听 `127.0.0.1`，并验证请求来源地址必须为回环地址；
- `Host` 只接受当前端口的 `127.0.0.1` 或 `localhost`；
- 请求带有 `Origin` 时，仅接受 `127.0.0.1` 或 `localhost`；
- 使用随机 256 位 Bearer Token，并采用常量时间比较；
- Token 保存在操作系统安全凭据库（Windows Credential Manager、macOS Keychain 或 Linux Secret Service），不写入普通 JSON 配置；
- 每分钟最多接受 120 个已鉴权请求，超限返回 HTTP 429；
- HTTP 请求头最大 16 KiB，读写和空闲超时均受限；
- 最多 4 个并发命令、8 个 MCP 交互会话；
- 每个交互会话使用 2 MiB 有界环形缓冲区；
- 审计日志只保存工具名、`profile_id`、结果、退出码、耗时和命令 SHA-256，不保存命令正文、stdout 或 stderr；
- MCP 不能操作图形界面终端，也不能在图形终端存在时断开对应隔离隧道。

本机其他进程如果获得 Token，仍可能调用 MCP。回环监听不能替代 Token 保密和 Profile 最小授权。

## 8. 运维与撤销

需要立即停止访问时，可按影响范围选择：

1. 关闭全局 MCP 开关：停止服务并关闭全部 MCP 交互会话；
2. 重新生成令牌：使所有使用旧 Token 的客户端立即失效；
3. 编辑连接并关闭“允许 MCP 看到此配置”：仅撤销该 Profile；
4. 单独关闭命令、交互或断开权限：保留只读状态查询和连接能力；
5. 退出 LabRemote：MCP 服务随桌面进程停止。

相关文件位置：

```text
%APPDATA%\LabRemote\settings.json
%LOCALAPPDATA%\LabRemote\logs\app-YYYY-MM-DD.jsonl
%LOCALAPPDATA%\LabRemote\logs\mcp-audit-YYYY-MM-DD.jsonl
```

访问令牌、SSH/隧道密码、私钥文件路径与私钥口令位于操作系统安全凭据库，不在上述文件中。

## 9. 故障排查

| 错误或现象 | 原因 | 处理方式 |
|---|---|---|
| `MCP_DISABLED` | MCP 服务未开启 | 在 LabRemote 左下角开启 MCP 后重新复制配置 |
| `MCP_BUSY` / 端口无法监听 | 端口被占用，或命令/会话达到并发上限 | 更换端口；关闭不用的会话；等待命令结束 |
| HTTP 401 / `MCP_UNAUTHORIZED` | Token 缺失、错误或已重新生成 | 从界面重新复制完整配置并重载客户端 |
| HTTP 403 | 请求不是来自回环地址，或 Host/Origin 不符合限制 | 使用复制出的 `127.0.0.1` 地址，不要通过代理或端口转发 |
| HTTP 429 | 一分钟内超过 120 个请求 | 等待 `Retry-After` 指示的时间，降低轮询频率 |
| `MCP_PROFILE_FORBIDDEN` | Profile 未授权给 MCP，或 `profile_id` 不正确 | 编辑连接开启 MCP 可见权限，再通过 `profiles_list` 获取 ID |
| `MCP_TOOL_FORBIDDEN` | 未授予命令、交互或断开权限；或存在图形终端时请求断开 | 调整最小必要权限，或由用户在图形界面处理活动终端 |
| `TUNNEL_CERT_UNKNOWN` / `SSH_HOST_KEY_UNKNOWN` | 尚未在图形界面确认服务器指纹 | 先在图形界面连接并核对、确认指纹 |
| `TUNNEL_CERT_CHANGED` / `SSH_HOST_KEY_CHANGED` | 已固定指纹发生变化 | 停止连接并联系管理员核实，不要绕过 |
| `SSH_AUTH_FAILED` | 用户名、密码或服务器公钥授权不匹配 | 在连接编辑页核对认证方式并更新 SSH 凭据 |
| `SSH_PRIVATE_KEY_NOT_FOUND` | 私钥文件路径失效或文件不可读 | 在连接编辑页重新选择私钥文件 |
| `SSH_KEY_PASSPHRASE_REQUIRED` / `SSH_KEY_PASSPHRASE_INVALID` | 私钥口令缺失或错误 | 在连接编辑页更新私钥口令 |
| `SSH_COMMAND_TIMEOUT` | 命令超过超时，或请求被取消 | 调高 `timeout_seconds`，最大 300；或拆分任务 |
| `MCP_SESSION_NOT_FOUND` | 会话已关闭、ID 错误，或试图操作图形界面会话 | 重新调用 `ssh_session_open`，只使用其返回的 ID |
| `truncated=true` | 命令输出超限，或交互输出已覆盖旧游标 | 提高允许范围内的输出限制、及时增量读取，或把输出写入远端文件后分段查看 |

## 10. 部署建议

`ssh_exec` 和交互终端本质上允许在远端服务器运行 Shell 命令。客户端字符串黑名单不能提供可靠隔离。生产环境建议：

- 使用专门的低权限 SSH 账号；
- 通过服务器端 sudoers、容器、作业系统或受限 Shell 控制权限；
- 每个连接只授予需要的 MCP 能力；
- 不需要交互时只启用 `ssh_exec`，不需要执行命令时仅授权 Profile 可见；
- 定期检查 MCP 审计日志，并在客户端迁移、人员变化或疑似泄露后重新生成 Token；
- 不要把 MCP 服务改为 `0.0.0.0`，不要通过反向代理、端口转发或公网隧道暴露。
