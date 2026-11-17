package mcpserver

import (
	"context"
	"strings"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/browserproxy"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type browserOpenInput struct {
	ProfileID string `json:"profile_id" jsonschema:"已授权网页访问的连接配置 ID"`
	TargetURL string `json:"target_url" jsonschema:"SSH 服务器可访问的 HTTP/HTTPS 地址，如 http://127.0.0.1:8080；127.0.0.1 指远端服务器"`
}

type browserListOutput struct {
	Accesses []model.BrowserAccess `json:"accesses"`
}

type browserCloseInput struct {
	ProfileID string `json:"profile_id"`
	AccessID  string `json:"access_id" jsonschema:"browser_open 或 browser_list 返回的网页访问 ID"`
}

type directoryInput struct {
	ProfileID string `json:"profile_id"`
	Directory string `json:"directory,omitempty" jsonschema:"远端目录，默认 SSH 主目录；支持绝对路径、相对路径和 ~/"`
}

type sessionDirectoryOutput struct {
	Directory string `json:"directory"`
}

func validateProfileID(value string) error {
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
		return model.NewAppError("MCP_INPUT_INVALID", "profile_id 不能为空且不能超过 256 字节", "mcp_input", false)
	}
	return nil
}

func (c *Controller) browserOpen(ctx context.Context, _ *mcp.CallToolRequest, input browserOpenInput) (*mcp.CallToolResult, model.BrowserAccess, error) {
	input.ProfileID = strings.TrimSpace(input.ProfileID)
	input.TargetURL = strings.TrimSpace(input.TargetURL)
	if err := validateProfileID(input.ProfileID); err != nil {
		return toolError[model.BrowserAccess](err)
	}
	if len(input.TargetURL) > 8192 {
		return toolError[model.BrowserAccess](model.NewAppError("BROWSER_URL_INVALID", "网页地址不能超过 8192 字节", "browser_proxy", false))
	}
	if err := browserproxy.ValidateTargetURL(input.TargetURL); err != nil {
		return toolError[model.BrowserAccess](err)
	}
	start := time.Now()
	access, err := c.core.MCPOpenBrowser(ctx, input.ProfileID, input.TargetURL)
	// 地址可能包含访问令牌，审计仅保存配置和结果。
	if c.audit != nil {
		c.audit.Tool("browser_open", input.ProfileID, "", outcome(err), 0, time.Since(start))
	}
	if err != nil {
		return toolError[model.BrowserAccess](err)
	}
	return result(access)
}

func (c *Controller) browserList(ctx context.Context, _ *mcp.CallToolRequest, input profileInput) (*mcp.CallToolResult, browserListOutput, error) {
	profileID := strings.TrimSpace(input.ProfileID)
	if err := validateProfileID(profileID); err != nil {
		return toolError[browserListOutput](err)
	}
	accesses, err := c.core.MCPListBrowser(ctx, profileID)
	if err != nil {
		return toolError[browserListOutput](err)
	}
	if accesses == nil {
		accesses = make([]model.BrowserAccess, 0)
	}
	return result(browserListOutput{Accesses: accesses})
}

func (c *Controller) browserClose(ctx context.Context, _ *mcp.CallToolRequest, input browserCloseInput) (*mcp.CallToolResult, okOutput, error) {
	input.ProfileID = strings.TrimSpace(input.ProfileID)
	input.AccessID = strings.TrimSpace(input.AccessID)
	if err := validateProfileID(input.ProfileID); err != nil {
		return toolError[okOutput](err)
	}
	if input.AccessID == "" || len(input.AccessID) > 256 || strings.ContainsAny(input.AccessID, "\x00\r\n") {
		return toolError[okOutput](model.NewAppError("MCP_INPUT_INVALID", "access_id 无效", "mcp_input", false))
	}
	err := c.core.MCPCloseBrowser(ctx, input.ProfileID, input.AccessID)
	if c.audit != nil {
		c.audit.Tool("browser_close", input.ProfileID, "", outcome(err), 0, 0)
	}
	if err != nil {
		return toolError[okOutput](err)
	}
	return result(okOutput{OK: true})
}

func (c *Controller) fileListDirectory(ctx context.Context, _ *mcp.CallToolRequest, input directoryInput) (*mcp.CallToolResult, model.RemoteDirectory, error) {
	input.ProfileID = strings.TrimSpace(input.ProfileID)
	input.Directory = strings.TrimSpace(input.Directory)
	if err := validateProfileID(input.ProfileID); err != nil {
		return toolError[model.RemoteDirectory](err)
	}
	if len(input.Directory) > 4096 || strings.ContainsRune(input.Directory, '\x00') {
		return toolError[model.RemoteDirectory](model.NewAppError("MCP_INPUT_INVALID", "directory 不能包含空字符或超过 4096 字节", "mcp_input", false))
	}
	value, err := c.core.MCPListRemoteDirectory(ctx, input.ProfileID, input.Directory)
	if err != nil {
		return toolError[model.RemoteDirectory](err)
	}
	return result(value)
}

func (c *Controller) sessionDirectory(ctx context.Context, _ *mcp.CallToolRequest, input sessionCloseInput) (*mcp.CallToolResult, sessionDirectoryOutput, error) {
	value, err := c.core.MCPSessionWorkingDirectory(ctx, input.SessionID)
	if err != nil {
		return toolError[sessionDirectoryOutput](err)
	}
	return result(sessionDirectoryOutput{Directory: value})
}
