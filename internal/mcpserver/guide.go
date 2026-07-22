package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

// AIGuideMarkdown 生成一份可以直接交给 AI 客户端的 MCP 终端操作手册。
func (c *Controller) AIGuideMarkdown(ctx context.Context) (string, error) {
	configuration, err := c.ClientConfig(ctx)
	if err != nil {
		return "", err
	}
	profiles, err := c.core.MCPProfiles(ctx)
	if err != nil {
		return "", err
	}
	return buildAIGuideMarkdown(c.Status(), configuration, profiles, time.Now()), nil
}

func buildAIGuideMarkdown(status Status, configuration string, profiles []model.ConnectionProfile, generatedAt time.Time) string {
	var guide strings.Builder
	guide.WriteString("# LabRemote AI 终端操作手册\n\n")
	guide.WriteString("> 本文档由 LabRemote 自动生成，用于让支持 MCP 的 AI 客户端安全操作已授权的远程终端。\n")
	guide.WriteString("> 文档内含当前 MCP Bearer Token，等同于本机访问凭据。请勿提交到 Git、工单、公开聊天或发送给无关人员。\n\n")
	fmt.Fprintf(&guide, "- 生成时间：`%s`\n", generatedAt.Local().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&guide, "- MCP 服务：`%s`\n", markdownInline(status.Address))
	guide.WriteString("- 服务范围：仅监听当前电脑的 `127.0.0.1`，AI 客户端必须运行在同一台电脑上。\n\n")

	guide.WriteString("## 1. 给 AI 的强制操作指令\n\n")
	guide.WriteString("你正在通过名为 `labremote` 的 MCP 服务操作远程终端。必须遵守以下规则：\n\n")
	guide.WriteString("1. 开始任务时先调用 `profiles_list`，从返回值取得真实 `profile_id`，不得猜测或复用其他环境的 ID。\n")
	guide.WriteString("2. 调用 `connection_status` 检查状态；需要时再调用 `vpn_connect`。工具名中的 VPN 是兼容名称：`isolated_tunnel` 配置会建立进程内 SoftEther 隧道和 SSH，`direct_ssh` 配置只建立 SSH。\n")
	guide.WriteString("3. 一次性命令优先使用 `ssh_exec`；只有 `vim`、`top`、`tmux`、REPL 等交互程序才使用 `ssh_session_*`。\n")
	guide.WriteString("4. 判断命令是否成功必须同时检查 `exit_code`、`stderr` 和 `truncated`，不能只看 `ok`。\n")
	guide.WriteString("5. 删除/覆盖数据、安装软件、重启服务或主机、修改账号权限、网络、防火墙和安全配置前，必须向用户说明具体影响并取得明确确认。\n")
	guide.WriteString("6. 不得输出、转述或记录本文档中的 Bearer Token；不得尝试把 MCP 暴露到公网、局域网或其他代理。\n")
	guide.WriteString("7. 交互会话完成后必须调用 `ssh_session_close`；不要遗留后台 PTY 占用会话配额。\n")
	guide.WriteString("8. 除非用户明确要求，不调用 `vpn_disconnect`；存在图形终端时 MCP 无权断开连接。\n")
	guide.WriteString("9. 用户明确要求上传时，先确认本机绝对路径、目标 Profile 和远端目录，再使用 `file_upload_*`；`overwrite` 默认保持 `false`，只有用户明确同意覆盖时才设为 `true`。MCP 暂不提供下载工具。\n")
	guide.WriteString("10. 如果当前 AI 环境不能注册 Streamable HTTP MCP 或不能添加自定义 Authorization 请求头，应明确告知用户完成客户端配置，不得假装已经连接。\n\n")

	guide.WriteString("## 2. MCP 客户端配置（含敏感令牌）\n\n")
	guide.WriteString("将以下 `labremote` 节点合并到 AI 客户端的 MCP 配置，然后重新加载客户端：\n\n")
	guide.WriteString("```json\n")
	guide.WriteString(configuration)
	guide.WriteString("\n```\n\n")
	guide.WriteString("客户端必须支持 Streamable HTTP，并允许为请求添加 `Authorization` 请求头。不要把 Token 改放到 URL 中。\n\n")

	guide.WriteString("## 3. 当前已授权连接\n\n")
	if len(profiles) == 0 {
		guide.WriteString("**当前没有连接配置授权给 MCP。** 请在 LabRemote 中编辑连接，至少开启“允许 MCP 看到此配置”，然后重新导出本文档。\n\n")
	} else {
		guide.WriteString("| profile_id | 名称 | 连接方式 | SSH 目标 | 已授权能力 |\n")
		guide.WriteString("|---|---|---|---|---|\n")
		for _, value := range profiles {
			fmt.Fprintf(&guide, "| `%s` | %s | %s | `%s:%d` | %s |\n",
				markdownInline(value.ID), markdownTable(value.DisplayName), connectionModeLabel(value), markdownInline(value.SSH.ServerAddress), value.SSH.Port, markdownTable(profileCapabilities(value)))
		}
		guide.WriteString("\n权限以 MCP 服务实时检查结果为准。用户在 LabRemote 中撤销权限后，本文档中的旧表格不会继续授权。\n\n")
	}

	guide.WriteString("## 4. 工具速查\n\n")
	guide.WriteString("| 工具 | 用途 | 关键输入 |\n")
	guide.WriteString("|---|---|---|\n")
	guide.WriteString("| `profiles_list` | 列出 MCP 可见连接及状态 | 无输入 |\n")
	guide.WriteString("| `connection_status` | 查询连接方式、隧道、SSH、会话和传输状态 | `profile_id` |\n")
	guide.WriteString("| `vpn_connect` | 按配置建立隔离隧道 + SSH 或仅 SSH | `profile_id` |\n")
	guide.WriteString("| `vpn_disconnect` | 断开 SSH 与可选隔离隧道 | `profile_id`, `force` |\n")
	guide.WriteString("| `ssh_exec` | 执行非交互 Shell 命令 | `profile_id`, `command`, `timeout_seconds`, `max_output_bytes` |\n")
	guide.WriteString("| `ssh_session_open` | 打开 MCP 专属 PTY | `profile_id`, `cols`, `rows` |\n")
	guide.WriteString("| `ssh_session_write` | 向 PTY 写入 Base64 字节 | `session_id`, `data_base64` |\n")
	guide.WriteString("| `ssh_session_read` | 按 cursor 增量读取 Base64 输出 | `session_id`, `cursor`, `max_bytes`, `wait_ms` |\n")
	guide.WriteString("| `ssh_session_resize` | 调整 PTY 尺寸 | `session_id`, `cols`, `rows` |\n")
	guide.WriteString("| `ssh_session_close` | 关闭 MCP 专属 PTY | `session_id` |\n")
	guide.WriteString("| `file_upload_start` | 异步上传本机文件或目录 | `profile_id`, `local_paths`, `remote_directory`, `overwrite`, `resume` |\n")
	guide.WriteString("| `file_upload_status` | 查询 MCP 自有上传任务 | `job_id` |\n")
	guide.WriteString("| `file_upload_cancel` | 取消 MCP 自有上传任务 | `job_id` |\n\n")

	guide.WriteString("## 5. 推荐工作流：执行一次命令\n\n")
	guide.WriteString("1. 调用 `profiles_list`。\n")
	guide.WriteString("2. 对选定 ID 调用 `connection_status`。\n")
	guide.WriteString("3. 未连接时调用 `vpn_connect`，随后再次查询状态。隔离隧道配置应为 `vpn_status=connected`；仅 SSH 配置应为 `vpn_status=not_required`；两者都必须确认 `route_ready=true`、`ssh_connected=true`。\n")
	guide.WriteString("4. 调用 `ssh_exec`：\n\n")
	guide.WriteString("```json\n")
	fmt.Fprintf(&guide, "{\n  \"profile_id\": %q,\n  \"command\": \"pwd && uname -a\",\n  \"timeout_seconds\": 30,\n  \"max_output_bytes\": 1048576\n}\n", exampleProfileID(profiles))
	guide.WriteString("```\n\n")
	guide.WriteString("5. `ok=true` 只表示工具调用完成；仍要检查 `exit_code`。`truncated=true` 时应缩小输出范围或把输出写到远端文件后分段读取。\n\n")

	guide.WriteString("## 6. 推荐工作流：操作交互终端\n\n")
	guide.WriteString("1. 使用 `ssh_session_open` 打开 PTY，保存返回的 `session_id`。默认建议 `cols=120`、`rows=30`。\n")
	guide.WriteString("2. 首次调用 `ssh_session_read` 时使用 `cursor=0`；解码返回的 `data_base64`，并保存新 `cursor`。\n")
	guide.WriteString("3. 输入必须先按 UTF-8 转成字节，再做标准 Base64 编码。例如 `pwd\\n` 对应 `cHdkCg==`：\n\n")
	guide.WriteString("```json\n")
	guide.WriteString("{\n  \"session_id\": \"ssh_session_open 返回的 ID\",\n  \"data_base64\": \"cHdkCg==\"\n}\n")
	guide.WriteString("```\n\n")
	guide.WriteString("4. 循环调用 `ssh_session_read`，每次传入上一次返回的 `cursor`。建议 `max_bytes=65536`、`wait_ms=1000`。\n")
	guide.WriteString("5. `open=false` 表示会话已经结束；`truncated=true` 表示旧输出被 2 MiB 环形缓冲区覆盖，应从本次返回的 cursor 继续。\n")
	guide.WriteString("6. 完成后调用 `ssh_session_close`。异常、取消和任务清理路径也必须关闭会话。\n\n")

	guide.WriteString("## 7. 推荐工作流：上传文件或目录\n\n")
	guide.WriteString("1. 确认用户要上传的内容、目标连接和远端目录；`local_paths` 指 LabRemote 所在电脑上的路径，不是 AI 沙箱或远端服务器路径。\n")
	guide.WriteString("2. 从 `profiles_list` 选择 `file_upload_allowed=true` 的 Profile；需要时先调用 `vpn_connect`。\n")
	guide.WriteString("3. 调用 `file_upload_start`。本地路径必须是绝对路径，目标目录必填；默认 `overwrite=false`，中断后希望复用安全分片时设置 `resume=true`：\n\n")
	guide.WriteString("```json\n")
	fmt.Fprintf(&guide, "{\n  \"profile_id\": %q,\n  \"local_paths\": [\"C:\\\\Users\\\\example\\\\payload.bin\"],\n  \"remote_directory\": \"/srv/uploads\",\n  \"overwrite\": false,\n  \"resume\": true\n}\n", exampleProfileID(profiles))
	guide.WriteString("```\n\n")
	guide.WriteString("4. 保存返回的 `job_id`，使用 `file_upload_status` 低频轮询，直到 `state` 为 `completed`、`failed` 或 `cancelled`。关注 `bytes_transferred`、`bytes_resumed`、文件/目录完成数和错误字段。\n")
	guide.WriteString("5. 用户取消任务时调用 `file_upload_cancel`。MCP 只能查询或取消当前服务实例自己创建的上传任务，不能操作图形界面任务。\n\n")

	guide.WriteString("## 8. 参数限制与状态解释\n\n")
	guide.WriteString("- `ssh_exec.timeout_seconds`：默认 30，最大 300 秒。\n")
	guide.WriteString("- `ssh_exec.max_output_bytes`：stdout/stderr 各默认 1 MiB，最大 4 MiB。\n")
	guide.WriteString("- 非交互命令最多并发 4 个；MCP 交互会话最多 8 个。\n")
	guide.WriteString("- `ssh_session_write` 单次解码后最多 65536 字节。\n")
	guide.WriteString("- `ssh_session_read.max_bytes` 单次最大 1 MiB；`wait_ms` 范围为 0-30000。\n")
	guide.WriteString("- `file_upload_start.local_paths`：1-32 个本机绝对路径，单个最多 4096 字节、总计最多 32768 字节；文件夹会递归上传但不跟随符号链接。\n")
	guide.WriteString("- 每个 Profile 同时最多一个上传任务；任务内部最多并行处理 3 个文件，单个大文件使用并发 SFTP 请求。\n")
	guide.WriteString("- 上传状态依次可能为 `queued`、`scanning`、`uploading`，终态为 `completed`、`failed` 或 `cancelled`。\n")
	guide.WriteString("- `connection_mode` 为 `isolated_tunnel` 或 `direct_ssh`。`vpn_status=not_required` 表示该配置直接连接 SSH；其他状态包括 `disconnected`、`preparing`、`dialing`、`connected`、`reconnecting`、`disconnecting`、`failed`。\n")
	guide.WriteString("- `vpn_disconnect(force=true)` 仍不能关闭图形界面创建的终端。\n\n")

	guide.WriteString("## 9. 常见错误处理\n\n")
	guide.WriteString("| 错误 | AI 应采取的动作 |\n")
	guide.WriteString("|---|---|\n")
	guide.WriteString("| `MCP_UNAUTHORIZED` / HTTP 401 | 停止重试，请用户重新导出配置或更新 Token |\n")
	guide.WriteString("| `MCP_PROFILE_FORBIDDEN` | 重新调用 `profiles_list`；请用户检查连接的 MCP 可见权限 |\n")
	guide.WriteString("| `MCP_TOOL_FORBIDDEN` | 不绕过权限；请用户按最小权限原则授权所需能力 |\n")
	guide.WriteString("| `TUNNEL_CERT_UNKNOWN` / `SSH_HOST_KEY_UNKNOWN` | 请用户先在 LabRemote 图形界面核对并确认指纹 |\n")
	guide.WriteString("| `TUNNEL_CERT_CHANGED` / `SSH_HOST_KEY_CHANGED` | 立即停止，提示用户联系管理员核实，绝不绕过 |\n")
	guide.WriteString("| `SSH_AUTH_FAILED` | 请用户在 LabRemote 编辑连接并更新凭据 |\n")
	guide.WriteString("| `SSH_COMMAND_TIMEOUT` | 拆分任务或在理由充分时提高超时，上限 300 秒 |\n")
	guide.WriteString("| `MCP_BUSY` | 降低并发、关闭不用的会话，稍后重试 |\n")
	guide.WriteString("| `MCP_SESSION_NOT_FOUND` | 丢弃旧 ID，重新打开会话 |\n")
	guide.WriteString("| `MCP_UPLOAD_INVALID` | 修正本机绝对路径、目标目录或路径数量后重试 |\n")
	guide.WriteString("| `MCP_UPLOAD_NOT_FOUND` | 丢弃旧任务 ID；只能使用当前 MCP 返回的 `job_id` |\n")
	guide.WriteString("| `UPLOAD_BUSY` | 等待该 Profile 的当前上传结束，或取消自有上传任务 |\n")
	guide.WriteString("| `UPLOAD_TARGET_EXISTS` | 不自动覆盖；请用户确认后再设置 `overwrite=true` |\n\n")

	guide.WriteString("## 10. 安全与撤销\n\n")
	guide.WriteString("本文档本身包含访问令牌。任务完成后应妥善保管或删除文件；怀疑泄露时，在 LabRemote 中点击“重新生成令牌”，旧令牌会立即失效。关闭 MCP 开关会停止服务、取消 MCP 自有上传并关闭 MCP 专属会话，但不会关闭图形界面的 SSH 标签或传输任务。\n")
	return guide.String()
}

func profileCapabilities(value model.ConnectionProfile) string {
	capabilities := []string{"查看/连接"}
	if value.MCPPolicy.AllowExec {
		capabilities = append(capabilities, "非交互命令")
	}
	if value.MCPPolicy.AllowInteractive {
		capabilities = append(capabilities, "交互终端")
	}
	if value.MCPPolicy.AllowFileUpload {
		capabilities = append(capabilities, "文件上传")
	}
	if value.MCPPolicy.AllowDisconnect {
		capabilities = append(capabilities, "断开连接")
	}
	return strings.Join(capabilities, "、")
}

func connectionModeLabel(value model.ConnectionProfile) string {
	if value.UsesIsolatedTunnel() {
		return "隔离隧道 + SSH"
	}
	return "仅 SSH"
}

func exampleProfileID(profiles []model.ConnectionProfile) string {
	if len(profiles) == 0 {
		return "profiles_list 返回的 profile_id"
	}
	return profiles[0].ID
}

func markdownInline(value string) string {
	value = strings.ReplaceAll(value, "`", "ˋ")
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

func markdownTable(value string) string {
	value = markdownInline(value)
	return strings.ReplaceAll(value, "|", "\\|")
}
