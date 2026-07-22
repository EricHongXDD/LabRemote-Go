package mcpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
	MCPStartUpload(ctx context.Context, request model.UploadRequest) (model.UploadProgress, error)
	MCPUploadStatus(ctx context.Context, jobID string) (model.UploadProgress, error)
	MCPCancelUpload(ctx context.Context, jobID string) error
	CloseMCPUploads(ctx context.Context, jobIDs []string)
	CloseMCPSessions(ctx context.Context)
}

type emptyInput struct{}

type profileInput struct {
	ProfileID string `json:"profile_id" jsonschema:"要操作的连接配置 ID"`
}

type profileSummary struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	ConnectionMode    string `json:"connection_mode"`
	VPNStatus         string `json:"vpn_status"`
	SSHStatus         string `json:"ssh_status"`
	FileUploadAllowed bool   `json:"file_upload_allowed"`
}

type profilesOutput struct {
	Profiles []profileSummary `json:"profiles"`
}

type statusOutput struct {
	ProfileID       string `json:"profile_id"`
	ConnectionMode  string `json:"connection_mode"`
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

type fileUploadStartInput struct {
	ProfileID       string   `json:"profile_id" jsonschema:"已授权文件上传的连接配置 ID"`
	LocalPaths      []string `json:"local_paths" jsonschema:"LabRemote 所在电脑上的绝对文件或目录路径，最多 32 个"`
	RemoteDirectory string   `json:"remote_directory" jsonschema:"SSH 服务器上的目标目录；不存在时自动创建"`
	Overwrite       bool     `json:"overwrite,omitempty" jsonschema:"是否允许覆盖已存在的同名目标，默认 false"`
	Resume          bool     `json:"resume,omitempty" jsonschema:"是否续传匹配的安全分片文件，默认 false"`
}

type uploadJobInput struct {
	JobID string `json:"job_id" jsonschema:"file_upload_start 返回的上传任务 ID"`
}

func addTools(server *mcp.Server, controller *Controller) {
	mcp.AddTool(server, &mcp.Tool{Name: "profiles_list", Description: "列出明确授权给 MCP 使用的 LabRemote 连接配置"}, controller.profilesList)
	mcp.AddTool(server, &mcp.Tool{Name: "connection_status", Description: "查询一个已授权配置的连接方式、隔离隧道、SSH 和活动会话状态"}, controller.connectionStatus)
	mcp.AddTool(server, &mcp.Tool{Name: "vpn_connect", Description: "兼容名称：按配置建立隔离隧道加 SSH，或仅建立直接 SSH 连接"}, controller.vpnConnect)
	mcp.AddTool(server, &mcp.Tool{Name: "vpn_disconnect", Description: "兼容名称：断开 SSH 与可选隔离隧道；图形终端存在时始终拒绝"}, controller.vpnDisconnect)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_exec", Description: "在已授权的 SSH 服务器执行一条非交互命令"}, controller.sshExec)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_open", Description: "打开 MCP 专属的交互式 SSH PTY 会话"}, controller.sessionOpen)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_write", Description: "向 MCP 交互会话写入 Base64 数据"}, controller.sessionWrite)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_read", Description: "按 cursor 读取 MCP 交互会话的有界输出缓冲区"}, controller.sessionRead)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_resize", Description: "调整 MCP 交互会话的 PTY 行列"}, controller.sessionResize)
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_session_close", Description: "关闭 MCP 自己创建的交互会话"}, controller.sessionClose)
	mcp.AddTool(server, &mcp.Tool{Name: "file_upload_start", Description: "异步上传 LabRemote 所在电脑上的文件或目录到指定 SSH 服务器目录；支持并发、断点续传与默认拒绝覆盖"}, controller.fileUploadStart)
	mcp.AddTool(server, &mcp.Tool{Name: "file_upload_status", Description: "查询当前 MCP 服务自己创建的文件上传任务进度"}, controller.fileUploadStatus)
	mcp.AddTool(server, &mcp.Tool{Name: "file_upload_cancel", Description: "取消当前 MCP 服务自己创建的文件上传任务"}, controller.fileUploadCancel)
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
			output.Profiles = append(output.Profiles, profileSummary{ID: value.ID, Name: value.DisplayName, ConnectionMode: string(value.EffectiveConnectionMode()), VPNStatus: "unknown", SSHStatus: "unknown", FileUploadAllowed: value.MCPPolicy.AllowFileUpload})
			continue
		}
		sshStatus := "disconnected"
		if status.SSHConnected {
			sshStatus = "connected"
		}
		output.Profiles = append(output.Profiles, profileSummary{ID: value.ID, Name: value.DisplayName, ConnectionMode: string(value.EffectiveConnectionMode()), VPNStatus: string(status.VPN.State), SSHStatus: sshStatus, FileUploadAllowed: value.MCPPolicy.AllowFileUpload})
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
		ProfileID: status.ProfileID, ConnectionMode: string(status.ConnectionMode), VPNStatus: string(status.VPN.State), RouteReady: status.VPN.RouteReady,
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

func (c *Controller) fileUploadStart(ctx context.Context, _ *mcp.CallToolRequest, input fileUploadStartInput) (*mcp.CallToolResult, model.UploadProgress, error) {
	request, err := normalizeFileUploadInput(input)
	if err != nil {
		return toolError[model.UploadProgress](err)
	}
	start := time.Now()
	progress, err := c.core.MCPStartUpload(ctx, request)
	if c.audit != nil {
		// 审计日志只记录 Profile 和任务结果，不记录本地文件路径。
		c.audit.Tool("file_upload_start", request.ProfileID, "", outcome(err), 0, time.Since(start))
	}
	if err != nil {
		return toolError[model.UploadProgress](err)
	}
	jobID := strings.TrimSpace(progress.JobID)
	if jobID == "" {
		return toolError[model.UploadProgress](model.NewAppError("MCP_UPLOAD_INVALID", "上传引擎未返回任务 ID", "mcp_upload", true))
	}
	progress.JobID = jobID
	c.uploadMu.Lock()
	c.uploadJobs[jobID] = request.ProfileID
	c.uploadMu.Unlock()
	return result(progress)
}

func (c *Controller) fileUploadStatus(ctx context.Context, _ *mcp.CallToolRequest, input uploadJobInput) (*mcp.CallToolResult, model.UploadProgress, error) {
	profileID, err := c.ownedUpload(input.JobID)
	if err != nil {
		return toolError[model.UploadProgress](err)
	}
	progress, err := c.core.MCPUploadStatus(ctx, strings.TrimSpace(input.JobID))
	if c.audit != nil {
		c.audit.Tool("file_upload_status", profileID, "", outcome(err), 0, 0)
	}
	if err != nil {
		return toolError[model.UploadProgress](c.normalizeOwnedUploadError(strings.TrimSpace(input.JobID), err))
	}
	return result(progress)
}

func (c *Controller) fileUploadCancel(ctx context.Context, _ *mcp.CallToolRequest, input uploadJobInput) (*mcp.CallToolResult, okOutput, error) {
	jobID := strings.TrimSpace(input.JobID)
	profileID, err := c.ownedUpload(jobID)
	if err != nil {
		return toolError[okOutput](err)
	}
	err = c.core.MCPCancelUpload(ctx, jobID)
	if c.audit != nil {
		c.audit.Tool("file_upload_cancel", profileID, "", outcome(err), 0, 0)
	}
	if err != nil {
		return toolError[okOutput](c.normalizeOwnedUploadError(jobID, err))
	}
	return result(okOutput{OK: true})
}

func normalizeFileUploadInput(input fileUploadStartInput) (model.UploadRequest, error) {
	profileID := strings.TrimSpace(input.ProfileID)
	remoteDirectory := strings.TrimSpace(input.RemoteDirectory)
	if profileID == "" || len(profileID) > 256 {
		return model.UploadRequest{}, model.NewAppError("MCP_UPLOAD_INVALID", "profile_id 不能为空且不能超过 256 字节", "mcp_upload", false)
	}
	if remoteDirectory == "" || len(remoteDirectory) > 4096 || strings.ContainsRune(remoteDirectory, '\x00') {
		return model.UploadRequest{}, model.NewAppError("MCP_UPLOAD_INVALID", "remote_directory 必须是 1-4096 字节的有效目录", "mcp_upload", false)
	}
	if len(input.LocalPaths) == 0 || len(input.LocalPaths) > 32 {
		return model.UploadRequest{}, model.NewAppError("MCP_UPLOAD_INVALID", "local_paths 必须包含 1-32 个本地绝对路径", "mcp_upload", false)
	}
	localPaths := make([]string, 0, len(input.LocalPaths))
	totalPathBytes := 0
	for _, rawPath := range input.LocalPaths {
		path := strings.TrimSpace(rawPath)
		if path == "" || len(path) > 4096 || strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) {
			return model.UploadRequest{}, model.NewAppError("MCP_UPLOAD_INVALID", "local_paths 只能包含不超过 4096 字节的本地绝对路径", "mcp_upload", false)
		}
		totalPathBytes += len(path)
		if totalPathBytes > 32768 {
			return model.UploadRequest{}, model.NewAppError("MCP_UPLOAD_INVALID", "local_paths 总长度不能超过 32768 字节", "mcp_upload", false)
		}
		localPaths = append(localPaths, filepath.Clean(path))
	}
	return model.UploadRequest{
		ProfileID: profileID, LocalPaths: localPaths, RemoteDirectory: remoteDirectory,
		Overwrite: input.Overwrite, Resume: input.Resume,
	}, nil
}

func (c *Controller) ownedUpload(jobID string) (string, error) {
	jobID = strings.TrimSpace(jobID)
	if jobID == "" || len(jobID) > 256 {
		return "", model.NewAppError("MCP_UPLOAD_NOT_FOUND", "上传任务不存在或不属于当前 MCP 服务", "mcp_upload", false)
	}
	c.uploadMu.Lock()
	profileID, ok := c.uploadJobs[jobID]
	c.uploadMu.Unlock()
	if !ok {
		return "", model.NewAppError("MCP_UPLOAD_NOT_FOUND", "上传任务不存在或不属于当前 MCP 服务", "mcp_upload", false)
	}
	return profileID, nil
}

func (c *Controller) normalizeOwnedUploadError(jobID string, err error) error {
	var appErr *model.AppError
	if !errors.As(err, &appErr) || appErr.Code != "UPLOAD_NOT_FOUND" {
		return err
	}
	c.uploadMu.Lock()
	delete(c.uploadJobs, jobID)
	c.uploadMu.Unlock()
	return model.NewAppError("MCP_UPLOAD_NOT_FOUND", "上传任务不存在或不属于当前 MCP 服务", "mcp_upload", false)
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
