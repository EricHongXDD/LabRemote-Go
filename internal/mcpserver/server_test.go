package mcpserver

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

type lifecycleCore struct {
	uiSessions        int
	mcpClosed         int
	profiles          []model.ConnectionProfile
	uploadRequest     model.UploadRequest
	uploadProgress    model.UploadProgress
	uploadCancelled   string
	closedUploads     []string
	uploadStatusErr   error
	downloadRequest   model.DownloadRequest
	downloadProgress  model.DownloadProgress
	downloadCancelled string
	closedDownloads   []string
	downloadStatusErr error
}

func (c *lifecycleCore) MCPProfiles(context.Context) ([]model.ConnectionProfile, error) {
	return c.profiles, nil
}
func (c *lifecycleCore) ConnectionStatus(context.Context, string) (model.ConnectionStatus, error) {
	return model.ConnectionStatus{}, nil
}
func (c *lifecycleCore) MCPConnect(context.Context, string) error          { return nil }
func (c *lifecycleCore) MCPDisconnect(context.Context, string, bool) error { return nil }
func (c *lifecycleCore) MCPExec(context.Context, model.ExecRequest) (model.ExecResult, error) {
	return model.ExecResult{}, nil
}
func (c *lifecycleCore) MCPOpenSession(context.Context, string, int, int) (string, error) {
	return "mcp-session-test", nil
}
func (c *lifecycleCore) MCPWriteSession(context.Context, string, []byte) error { return nil }
func (c *lifecycleCore) MCPReadSession(context.Context, string, uint64, int, time.Duration) (model.SessionReadResult, error) {
	return model.SessionReadResult{}, nil
}
func (c *lifecycleCore) MCPResizeSession(context.Context, string, int, int) error { return nil }
func (c *lifecycleCore) MCPCloseSession(context.Context, string) error            { return nil }
func (c *lifecycleCore) MCPStartUpload(_ context.Context, request model.UploadRequest) (model.UploadProgress, error) {
	c.uploadRequest = request
	if c.uploadProgress.JobID == "" {
		c.uploadProgress = model.UploadProgress{JobID: "upload-mcp-test", ProfileID: request.ProfileID, State: model.UploadQueued}
	}
	return c.uploadProgress, nil
}
func (c *lifecycleCore) MCPUploadStatus(context.Context, string) (model.UploadProgress, error) {
	return c.uploadProgress, c.uploadStatusErr
}
func (c *lifecycleCore) MCPCancelUpload(_ context.Context, jobID string) error {
	c.uploadCancelled = jobID
	return nil
}
func (c *lifecycleCore) CloseMCPUploads(_ context.Context, jobIDs []string) {
	c.closedUploads = append(c.closedUploads, jobIDs...)
}
func (c *lifecycleCore) MCPStartDownload(_ context.Context, request model.DownloadRequest) (model.DownloadProgress, error) {
	c.downloadRequest = request
	if c.downloadProgress.JobID == "" {
		c.downloadProgress = model.DownloadProgress{JobID: "download-mcp-test", ProfileID: request.ProfileID, State: model.DownloadQueued}
	}
	return c.downloadProgress, nil
}
func (c *lifecycleCore) MCPDownloadStatus(context.Context, string) (model.DownloadProgress, error) {
	return c.downloadProgress, c.downloadStatusErr
}
func (c *lifecycleCore) MCPCancelDownload(_ context.Context, jobID string) error {
	c.downloadCancelled = jobID
	return nil
}
func (c *lifecycleCore) CloseMCPDownloads(_ context.Context, jobIDs []string) {
	c.closedDownloads = append(c.closedDownloads, jobIDs...)
}
func (c *lifecycleCore) CloseMCPSessions(context.Context) { c.mcpClosed++ }

func freeLocalPort(t *testing.T) int {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func TestStopMCPDoesNotTouchUISessions(t *testing.T) {
	core := &lifecycleCore{uiSessions: 2}
	controller := NewController(core, secrets.NewMemoryStore(), nil)
	ctx := context.Background()
	status, err := controller.Start(ctx, freeLocalPort(t))
	if err != nil || !status.Enabled || status.Address == "" {
		t.Fatalf("MCP 启动失败: %#v, %v", status, err)
	}
	if err := controller.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if core.mcpClosed != 1 || core.uiSessions != 2 {
		t.Fatalf("关闭边界异常: mcpClosed=%d uiSessions=%d", core.mcpClosed, core.uiSessions)
	}
	if controller.Status().Enabled {
		t.Fatal("停止后 MCP 状态仍为开启")
	}
}

func TestMCPOwnerRecordIsRemovedAfterStop(t *testing.T) {
	ownerFile := filepath.Join(t.TempDir(), "mcp-owner.json")
	controller := NewControllerWithOwnerFile(&lifecycleCore{}, secrets.NewMemoryStore(), nil, ownerFile)
	ctx := context.Background()
	if _, err := controller.Start(ctx, freeLocalPort(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ownerFile); err != nil {
		t.Fatalf("MCP 启动后未写入所有权记录: %v", err)
	}
	if err := controller.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ownerFile); !os.IsNotExist(err) {
		t.Fatalf("MCP 停止后所有权记录仍存在: %v", err)
	}
}

func TestStartReturnsBusyForUnrecognizedPortOwner(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	controller := NewController(&lifecycleCore{}, secrets.NewMemoryStore(), nil)
	_, err = controller.Start(context.Background(), port)
	if appErrorCode(err) != "MCP_BUSY" {
		t.Fatalf("未识别的端口占用应返回 MCP_BUSY，实际为 %v", err)
	}
}

func TestAIGuideMarkdownRequiresRunningMCP(t *testing.T) {
	controller := NewController(&lifecycleCore{}, secrets.NewMemoryStore(), nil)
	if _, err := controller.AIGuideMarkdown(context.Background()); err == nil {
		t.Fatal("MCP 未开启时不应生成包含令牌的 AI 操作手册")
	}
}

func TestAIGuideMarkdownContainsConfigurationToolsAndAuthorizedProfiles(t *testing.T) {
	profile := model.ConnectionProfile{
		ID:          "profile-guide-test",
		DisplayName: "实验室 | 服务器",
		VPN:         model.VPNConfig{CredentialRef: "SECRET-VPN-CREDENTIAL-REF"},
		SSH: model.SSHConfig{
			ServerAddress: "192.0.2.20", Port: 22,
			CredentialRef: "SECRET-SSH-CREDENTIAL-REF",
		},
		MCPPolicy: model.MCPPolicy{
			EnabledForProfile: true,
			AllowExec:         true,
			AllowInteractive:  true,
			AllowFileUpload:   true,
			AllowFileDownload: true,
			AllowDisconnect:   false,
		},
	}
	controller := NewController(&lifecycleCore{profiles: []model.ConnectionProfile{profile}}, secrets.NewMemoryStore(), nil)
	ctx := context.Background()
	if _, err := controller.Start(ctx, freeLocalPort(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Stop(ctx) })

	guide, err := controller.AIGuideMarkdown(ctx)
	if err != nil {
		t.Fatal(err)
	}
	config, err := controller.ClientConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(guide, config) {
		t.Fatal("AI 操作手册未包含当前 MCP 客户端配置")
	}
	for _, expected := range []string{
		"profile-guide-test", "实验室 \\| 服务器", "192.0.2.20:22", "非交互命令", "交互终端",
		"profiles_list", "connection_status", "vpn_connect", "vpn_disconnect", "ssh_exec",
		"ssh_session_open", "ssh_session_write", "ssh_session_read", "ssh_session_resize", "ssh_session_close",
		"file_upload_start", "file_upload_status", "file_upload_cancel", "文件上传",
		"file_download_start", "file_download_status", "file_download_cancel", "文件下载",
		"data_base64", "cursor", "exit_code", "truncated", "Bearer Token",
	} {
		if !strings.Contains(guide, expected) {
			t.Fatalf("AI 操作手册缺少关键内容 %q", expected)
		}
	}
	for _, forbidden := range []string{"SECRET-VPN-CREDENTIAL-REF", "SECRET-SSH-CREDENTIAL-REF"} {
		if strings.Contains(guide, forbidden) {
			t.Fatalf("AI 操作手册泄露凭据引用 %q", forbidden)
		}
	}
}
