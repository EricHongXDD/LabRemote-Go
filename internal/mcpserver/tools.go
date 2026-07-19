package mcpserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CoreService interface {
	MCPProfiles(ctx context.Context) ([]model.ConnectionProfile, error)
	ConnectionStatus(ctx context.Context, profileID string) (model.ConnectionStatus, error)
	MCPConnect(ctx context.Context, profileID string) error
	MCPDisconnect(ctx context.Context, profileID string, force bool) error
	MCPExec(ctx context.Context, request model.ExecRequest) (model.ExecResult, error)
	MCPOpenSession(ctx context.Context, profileID string, cols, rows int) (string, error)
	MCPWriteSession(ctx context.Context, sessionID string, data []byte) error
	MCPReadSession(ctx context.Context, sessionID string, cursor uint64, maxBytes int, wait time.Duration) (model.SessionReadResult, error)
	MCPResizeSession(ctx context.Context, sessionID string, cols, rows int) error
	MCPCloseSession(ctx context.Context, sessionID string) error
	CloseMCPSessions(ctx context.Context)
}

type emptyInput struct{}

type profileInput struct {
	ProfileID string `json:"profile_id" jsonschema:"要操作的连接配置 ID"`
}

type profileSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	VPNStatus string `json:"vpn_status"`
	SSHStatus string `json:"ssh_status"`
}

type profilesOutput struct {
	Profiles []profileSummary `json:"profiles"`
}

type statusOutput struct {
	ProfileID       string `json:"profile_id"`
	VPNStatus       string `json:"vpn_status"`
	RouteReady      bool   `json:"route_ready"`
	SSHConnected    bool   `json:"ssh_connected"`
	UISessions      int    `json:"ui_sessions"`
	MCPSessions     int    `json:"mcp_sessions"`
	ActiveCommands  int    `json:"active_commands"`
	ActiveTransfers int    `json:"active_transfers"`
}

type okOutput struct {
	OK bool `json:"ok"`
}

type disconnectInput struct {
	ProfileID string `json:"profile_id" jsonschema:"要断开的连接配置 ID"`
	Force     bool   `json:"force,omitempty" jsonschema:"是否强制关闭 MCP 会话；不会关闭图形会话"`
}

type execInput struct {
	ProfileID      string `json:"profile_id" jsonschema:"已授权的连接配置 ID"`
	Command        string `json:"command" jsonschema:"要在远程服务器执行的命令"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"超时秒数，默认 30，最大 300"`
	MaxOutputBytes int    `json:"max_output_bytes,omitempty" jsonschema:"每个输出流的最大字节数，默认 1048576"`
}

type execOutput struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
	Truncated  bool   `json:"truncated"`
}

type sessionOpenInput struct {
	ProfileID string `json:"profile_id"`
	Cols      int    `json:"cols,omitempty"`
	Rows      int    `json:"rows,omitempty"`
}

type sessionOpenOutput struct {
	SessionID string `json:"session_id"`
}

type sessionWriteInput struct {
	SessionID  string `json:"session_id"`
	DataBase64 string `json:"data_base64"`
}

type sessionReadInput struct {
	SessionID string `json:"session_id"`
	Cursor    uint64 `json:"cursor,omitempty"`
	MaxBytes  int    `json:"max_bytes,omitempty"`
	WaitMS    int    `json:"wait_ms,omitempty"`
}

type sessionResizeInput struct {
	SessionID string `json:"session_id"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

type sessionCloseInput struct {
	SessionID string `json:"session_id"`
}

func addTools(server *mcp.Server, controller *Controller) {
	mcp.AddTool(server, &mcp.Tool{Name: "profiles_list", Description: "列出明确授权给 MCP 使用的 LabRemote 连接配置"}, controller.profilesList)
	mcp.AddTool(server, &mcp.Tool{Name: "connection_status", Description: "查询一个已授权配置的进程内隔离隧道、SSH 和活动会话状态"}, controller.connectionStatus)
	mcp.AddTool(server, &mcp.Tool{Name: "vpn_connect", Description: "兼容名称：使用 Windows 凭据库中的秘密建立进程内 SoftEther 隧道和 SSH 连接"}, controller.vpnConnect)
	mcp.AddTool(server, &mcp.Tool{Name: "vpn_disconnect", Description: "兼容名称：断开进程内隔离隧道；图形终端存在时始终拒绝"}, controller.vpnDisconnect)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_exec", Description: "在已授权的 SSH 服务器执行一条非交互命令"}, controller.sshExec)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_open", Description: "打开 MCP 专属的交互式 SSH PTY 会话"}, controller.sessionOpen)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_write", Description: "向 MCP 交互会话写入 Base64 数据"}, controller.sessionWrite)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_read", Description: "按 cursor 读取 MCP 交互会话的有界输出缓冲区"}, controller.sessionRead)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_resize", Description: "调整 MCP 交互会话的 PTY 行列"}, controller.sessionResize)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_close", Description: "关闭 MCP 自己创建的交互会话"}, controller.sessionClose)
}

func result[Output any](output Output) (*mcp.CallToolResult, Output, error) {
	return &mcp.CallToolResult{}, output, nil
}

func toolError[Output any](err error) (*mcp.CallToolResult, Output, error) {
	var zero Output
	return nil, zero, err
}

func (c *Controller) profilesList(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, profilesOutput, error) {
	values, err := c.core.MCPProfiles(ctx)
	if err != nil {
		return toolError[profilesOutput](err)
	}
	output := profilesOutput{Profiles: make([]profileSummary, 0, len(values))}
	for _, value := range values {
		status, statusErr := c.core.ConnectionStatus(ctx, value.ID)
		if statusErr != nil {
			output.Profiles = append(output.Profiles, profileSummary{ID: value.ID, Name: value.DisplayName, VPNStatus: "unknown", SSHStatus: "unknown"})
			continue
		}
		sshStatus := "disconnected"
		if status.SSHConnected {
			sshStatus = "connected"
		}
		output.Profiles = append(output.Profiles, profileSummary{ID: value.ID, Name: value.DisplayName, VPNStatus: string(status.VPN.State), SSHStatus: sshStatus})
	}
	return result(output)
}

func (c *Controller) connectionStatus(ctx context.Context, _ *mcp.CallToolRequest, input profileInput) (*mcp.CallToolResult, statusOutput, error) {
	if err := c.requireAuthorizedProfile(ctx, input.ProfileID); err != nil {
		return toolError[statusOutput](err)
	}
	status, err := c.core.ConnectionStatus(ctx, input.ProfileID)
	if err != nil {
		return toolError[statusOutput](err)
	}
	return result(statusOutput{
		ProfileID: status.ProfileID, VPNStatus: string(status.VPN.State), RouteReady: status.VPN.RouteReady,
		SSHConnected: status.SSHConnected, UISessions: status.UISessions, MCPSessions: status.MCPSessions,
		ActiveCommands: status.ActiveCommands, ActiveTransfers: status.ActiveTransfers,
	})
}

func (c *Controller) vpnConnect(ctx context.Context, _ *mcp.CallToolRequest, input profileInput) (*mcp.CallToolResult, okOutput, error) {
	start := time.Now()
	err := c.core.MCPConnect(ctx, input.ProfileID)
	c.audit.Tool("vpn_connect", input.ProfileID, "", outcome(err), 0, time.Since(start))
	if err != nil {
		return toolError[okOutput](err)
	}
	return result(okOutput{OK: true})
}

func (c *Controller) vpnDisconnect(ctx context.Context, _ *mcp.CallToolRequest, input disconnectInput) (*mcp.CallToolResult, okOutput, error) {
	start := time.Now()
	err := c.core.MCPDisconnect(ctx, input.ProfileID, input.Force)
	c.audit.Tool("vpn_disconnect", input.ProfileID, "", outcome(err), 0, time.Since(start))
	if err != nil {
		return toolError[okOutput](err)
	}
	return result(okOutput{OK: true})
}

func (c *Controller) sshExec(ctx context.Context, _ *mcp.CallToolRequest, input execInput) (*mcp.CallToolResult, execOutput, error) {
	select {
	case c.execSlots <- struct{}{}:
		defer func() { <-c.execSlots }()
	default:
		return toolError[execOutput](model.NewAppError("MCP_BUSY", "并发 SSH 命令已达到上限", "mcp_exec", true))
	}
	timeout := input.TimeoutSeconds
	if timeout <= 0 {
		timeout = 30
	}
	start := time.Now()
	value, err := c.core.MCPExec(ctx, model.ExecRequest{
		ProfileID: input.ProfileID, Command: input.Command, Timeout: time.Duration(timeout) * time.Second, MaxOutputBytes: input.MaxOutputBytes,
	})
	c.audit.Tool("ssh_exec", input.ProfileID, input.Command, outcome(err), value.ExitCode, time.Since(start))
	if err != nil {
		return toolError[execOutput](err)
	}
	return result(execOutput{OK: true, ExitCode: value.ExitCode, Stdout: value.Stdout, Stderr: value.Stderr, DurationMS: value.DurationMS, Truncated: value.Truncated})
}

func (c *Controller) sessionOpen(ctx context.Context, _ *mcp.CallToolRequest, input sessionOpenInput) (*mcp.CallToolResult, sessionOpenOutput, error) {
	cols, rows := input.Cols, input.Rows
	if cols == 0 {
		cols = 120
	}
	if rows == 0 {
		rows = 30
	}
	c.sessionMu.Lock()
	if len(c.sessions) >= 8 {
		c.sessionMu.Unlock()
		return toolError[sessionOpenOutput](model.NewAppError("MCP_BUSY", "MCP 交互会话已达到上限", "mcp_session", true))
	}
	c.sessionMu.Unlock()
	sessionID, err := c.core.MCPOpenSession(ctx, input.ProfileID, cols, rows)
	if err != nil {
		return toolError[sessionOpenOutput](err)
	}
	c.sessionMu.Lock()
	c.sessions[sessionID] = struct{}{}
	c.sessionMu.Unlock()
	c.audit.Tool("ssh_session_open", input.ProfileID, "", "success", 0, 0)
	return result(sessionOpenOutput{SessionID: sessionID})
}

func (c *Controller) sessionWrite(ctx context.Context, _ *mcp.CallToolRequest, input sessionWriteInput) (*mcp.CallToolResult, okOutput, error) {
	data, err := base64.StdEncoding.DecodeString(input.DataBase64)
	if err != nil {
		return toolError[okOutput](fmt.Errorf("data_base64 无效: %w", err))
	}
	if len(data) > 65536 {
		return toolError[okOutput](model.NewAppError("MCP_BUSY", "单次写入不能超过 65536 字节", "mcp_session", false))
	}
	if err := c.core.MCPWriteSession(ctx, input.SessionID, data); err != nil {
		return toolError[okOutput](err)
	}
	return result(okOutput{OK: true})
}

func (c *Controller) sessionRead(ctx context.Context, _ *mcp.CallToolRequest, input sessionReadInput) (*mcp.CallToolResult, model.SessionReadResult, error) {
	wait := input.WaitMS
	if wait < 0 {
		wait = 0
	}
	if wait > 30000 {
		wait = 30000
	}
	value, err := c.core.MCPReadSession(ctx, input.SessionID, input.Cursor, input.MaxBytes, time.Duration(wait)*time.Millisecond)
	if err != nil {
		return toolError[model.SessionReadResult](err)
	}
	return result(value)
}

func (c *Controller) sessionResize(ctx context.Context, _ *mcp.CallToolRequest, input sessionResizeInput) (*mcp.CallToolResult, okOutput, error) {
	if err := c.core.MCPResizeSession(ctx, input.SessionID, input.Cols, input.Rows); err != nil {
		return toolError[okOutput](err)
	}
	return result(okOutput{OK: true})
}

func (c *Controller) sessionClose(ctx context.Context, _ *mcp.CallToolRequest, input sessionCloseInput) (*mcp.CallToolResult, okOutput, error) {
	if err := c.core.MCPCloseSession(ctx, input.SessionID); err != nil {
		return toolError[okOutput](err)
	}
	c.sessionMu.Lock()
	delete(c.sessions, input.SessionID)
	c.sessionMu.Unlock()
	return result(okOutput{OK: true})
}

func (c *Controller) requireAuthorizedProfile(ctx context.Context, profileID string) error {
	values, err := c.core.MCPProfiles(ctx)
	if err != nil {
		return err
	}
	for _, value := range values {
		if value.ID == profileID {
			return nil
		}
	}
	return model.NewAppError("MCP_PROFILE_FORBIDDEN", "此连接配置未授权给 MCP", "mcp_policy", false)
}

func outcome(err error) string {
	if err != nil {
		return "failed"
	}
	return "success"
}
