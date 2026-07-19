package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	appcore "github.com/EricHongXDD/LabRemote-Go/internal/app"
	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/logging"
	"github.com/EricHongXDD/LabRemote-Go/internal/mcpserver"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type wailsEventSink struct {
	mu      sync.RWMutex
	context context.Context
	logger  *slog.Logger
}

func (s *wailsEventSink) SetContext(ctx context.Context) {
	s.mu.Lock()
	s.context = ctx
	s.mu.Unlock()
}

func (s *wailsEventSink) Emit(name string, payload any) {
	s.mu.RLock()
	ctx := s.context
	s.mu.RUnlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, name, payload)
	}
	if s.logger != nil && name != "terminal:data" && name != "upload:progress" && name != "download:progress" {
		s.logger.Info("application_event", "event", name, "payload", fmt.Sprint(payload))
	}
}

type DesktopApp struct {
	ctx          context.Context
	service      *appcore.Service
	mcp          *mcpserver.Controller
	settings     *appcore.SettingsStore
	events       *wailsEventSink
	logger       *slog.Logger
	logClosers   []io.Closer
	shutdownOnce sync.Once
}

func NewDesktopApp() (*DesktopApp, error) {
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("定位用户配置目录失败: %w", err)
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("定位用户缓存目录失败: %w", err)
	}
	configDirectory := filepath.Join(configRoot, "LabRemote")
	logDirectory := filepath.Join(cacheRoot, "LabRemote", "logs")
	appLogger, appCloser, err := logging.NewJSONLogger(logging.DailyPath(logDirectory, "app"))
	if err != nil {
		return nil, err
	}
	auditLogger, auditCloser, err := logging.NewJSONLogger(logging.DailyPath(logDirectory, "mcp-audit"))
	if err != nil {
		appCloser.Close()
		return nil, err
	}
	eventSink := &wailsEventSink{logger: appLogger}
	var sink events.Sink = eventSink
	repository := profile.NewJSONRepository(filepath.Join(configDirectory, "profiles.json"))
	secretStore := secrets.NewPlatformStore()
	knownHosts := sshclient.NewKnownHosts(filepath.Join(configDirectory, "known_hosts"))
	vpnManager := vpn.NewIsolatedManager(repository, secretStore, sink)
	sshManager := sshclient.NewManager(repository, secretStore, knownHosts, sink, vpnManager)
	service := appcore.NewService(repository, secretStore, vpnManager, sshManager, knownHosts)
	mcpController := mcpserver.NewController(service, secretStore, mcpserver.NewAuditor(auditLogger))
	return &DesktopApp{
		service:    service,
		mcp:        mcpController,
		settings:   appcore.NewSettingsStore(filepath.Join(configDirectory, "settings.json")),
		events:     eventSink,
		logger:     appLogger,
		logClosers: []io.Closer{appCloser, auditCloser},
	}, nil
}

func (a *DesktopApp) startup(ctx context.Context) {
	a.ctx = ctx
	a.events.SetContext(ctx)
	settings, err := a.settings.Load()
	if err != nil {
		a.logger.Error("读取设置失败", "error", err.Error())
		return
	}
	if settings.MCPEnabled {
		if _, err := a.mcp.Start(ctx, settings.MCPPort); err != nil {
			a.logger.Error("恢复 MCP 服务失败", "error", err.Error())
		}
	}
}

func (a *DesktopApp) shutdown(ctx context.Context) {
	a.shutdownOnce.Do(func() {
		shutdownContext, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		_ = a.mcp.Stop(shutdownContext)
		a.service.Shutdown(shutdownContext)
		for _, closer := range a.logClosers {
			_ = closer.Close()
		}
	})
}

func (a *DesktopApp) ListProfiles() ([]model.ConnectionProfile, error) {
	return a.service.ListProfiles(a.ctx)
}

func (a *DesktopApp) SaveProfile(request appcore.SaveProfileRequest) (model.ConnectionProfile, error) {
	return a.service.SaveProfile(a.ctx, request)
}

func (a *DesktopApp) DeleteProfile(profileID string, deleteSecrets bool) error {
	return a.service.DeleteProfile(a.ctx, profileID, deleteSecrets)
}

func (a *DesktopApp) ClearSavedCredential(profileID, kind string) error {
	return a.service.ClearCredential(a.ctx, profileID, kind)
}

func (a *DesktopApp) TestTunnelConnection(request appcore.TestConnectionRequest) (appcore.ConnectionTestResult, error) {
	return a.service.TestTunnelConnection(a.ctx, request)
}

func (a *DesktopApp) TestSSHConnection(request appcore.TestConnectionRequest) (appcore.ConnectionTestResult, error) {
	return a.service.TestSSHConnection(a.ctx, request)
}

func (a *DesktopApp) ConnectAndOpenTerminal(profileID string, cols, rows int) (string, error) {
	return a.service.ConnectAndOpenTerminal(a.ctx, profileID, cols, rows)
}

func (a *DesktopApp) OpenBrowserResource(profileID, targetURL string) (string, error) {
	localURL, err := a.service.OpenBrowserResource(a.ctx, profileID, targetURL)
	if err != nil {
		return "", err
	}
	runtime.BrowserOpenURL(a.ctx, localURL)
	return localURL, nil
}

func (a *DesktopApp) CloseBrowserAccess(profileID string) {
	a.service.CloseBrowserAccess(a.ctx, profileID)
}

func (a *DesktopApp) AcceptHostKey(profileID, fingerprint string) error {
	return a.service.AcceptHostKey(profileID, fingerprint)
}

func (a *DesktopApp) AcceptTunnelCertificate(profileID, fingerprint string) error {
	return a.service.AcceptTunnelCertificate(a.ctx, profileID, fingerprint)
}

func (a *DesktopApp) WriteTerminal(sessionID, data string) error {
	return a.service.WriteTerminal(a.ctx, sessionID, []byte(data))
}

func (a *DesktopApp) ResizeTerminal(sessionID string, cols, rows int) error {
	return a.service.ResizeTerminal(a.ctx, sessionID, cols, rows)
}

func (a *DesktopApp) CloseTerminal(sessionID string) error {
	return a.service.CloseSession(a.ctx, sessionID)
}

func (a *DesktopApp) TerminalWorkingDirectory(sessionID string) (string, error) {
	return a.service.TerminalWorkingDirectory(a.ctx, sessionID)
}

func (a *DesktopApp) SelectUploadFiles() ([]model.UploadSelection, error) {
	paths, err := runtime.OpenMultipleFilesDialog(a.ctx, runtime.OpenDialogOptions{
		Title:           "选择要上传的文件",
		ShowHiddenFiles: true,
	})
	if err != nil {
		return nil, err
	}
	selections := make([]model.UploadSelection, 0, len(paths))
	for _, value := range paths {
		selection, selectionErr := describeUploadSelection(value)
		if selectionErr != nil {
			return nil, selectionErr
		}
		selections = append(selections, selection)
	}
	return selections, nil
}

func (a *DesktopApp) SelectUploadDirectory() (model.UploadSelection, error) {
	value, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title:                      "选择要上传的文件夹",
		ShowHiddenFiles:            true,
		CanCreateDirectories:       false,
		TreatPackagesAsDirectories: true,
	})
	if err != nil || value == "" {
		return model.UploadSelection{}, err
	}
	return describeUploadSelection(value)
}

func (a *DesktopApp) DescribeUploadSelections(paths []string) ([]model.UploadSelection, error) {
	selections := make([]model.UploadSelection, 0, len(paths))
	for _, value := range paths {
		selection, err := describeUploadSelection(value)
		if err != nil {
			return nil, err
		}
		selections = append(selections, selection)
	}
	return selections, nil
}

func describeUploadSelection(value string) (model.UploadSelection, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return model.UploadSelection{}, model.NewAppError("UPLOAD_LOCAL_READ_FAILED", "无法解析所选本地路径", "file_upload", false)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return model.UploadSelection{}, model.NewAppError("UPLOAD_LOCAL_READ_FAILED", "无法读取所选本地项目", "file_upload", false)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return model.UploadSelection{}, model.NewAppError("UPLOAD_SYMLINK_UNSUPPORTED", "不支持上传符号链接，请选择其实际文件或文件夹", "file_upload", false)
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return model.UploadSelection{}, model.NewAppError("UPLOAD_LOCAL_TYPE_UNSUPPORTED", "只能上传普通文件或文件夹", "file_upload", false)
	}
	return model.UploadSelection{
		Path: absolute, Name: filepath.Base(absolute), IsDirectory: info.IsDir(), Size: info.Size(),
	}, nil
}

func (a *DesktopApp) StartUpload(request model.UploadRequest) (model.UploadProgress, error) {
	return a.service.StartUpload(a.ctx, request)
}

func (a *DesktopApp) UploadStatus(jobID string) (model.UploadProgress, error) {
	return a.service.UploadStatus(jobID)
}

func (a *DesktopApp) CancelUpload(jobID string) error {
	return a.service.CancelUpload(jobID)
}

func (a *DesktopApp) SelectDownloadDirectory() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title:                      "选择下载保存目录",
		ShowHiddenFiles:            true,
		CanCreateDirectories:       true,
		TreatPackagesAsDirectories: true,
	})
}

func (a *DesktopApp) ListRemoteDirectory(profileID string, directory string) (model.RemoteDirectory, error) {
	return a.service.ListRemoteDirectory(a.ctx, profileID, directory)
}

func (a *DesktopApp) StartDownload(request model.DownloadRequest) (model.DownloadProgress, error) {
	return a.service.StartDownload(a.ctx, request)
}

func (a *DesktopApp) DownloadStatus(jobID string) (model.DownloadProgress, error) {
	return a.service.DownloadStatus(jobID)
}

func (a *DesktopApp) CancelDownload(jobID string) error {
	return a.service.CancelDownload(jobID)
}

func (a *DesktopApp) DisconnectProfile(profileID string, force bool) error {
	return a.service.Disconnect(a.ctx, profileID, force)
}

func (a *DesktopApp) ConnectionStatus(profileID string) (model.ConnectionStatus, error) {
	return a.service.ConnectionStatus(a.ctx, profileID)
}

func (a *DesktopApp) StartMCP(port int) (mcpserver.Status, error) {
	status, err := a.mcp.Start(a.ctx, port)
	if err != nil {
		return status, err
	}
	settings, _ := a.settings.Load()
	settings.MCPPort = port
	settings.MCPEnabled = true
	if err := a.settings.Save(settings); err != nil {
		return status, err
	}
	runtime.EventsEmit(a.ctx, "mcp:status", status)
	return status, nil
}

func (a *DesktopApp) StopMCP() error {
	if err := a.mcp.Stop(a.ctx); err != nil {
		return err
	}
	settings, _ := a.settings.Load()
	settings.MCPEnabled = false
	if err := a.settings.Save(settings); err != nil {
		return err
	}
	runtime.EventsEmit(a.ctx, "mcp:status", a.mcp.Status())
	return nil
}

func (a *DesktopApp) MCPStatus() mcpserver.Status { return a.mcp.Status() }

func (a *DesktopApp) MCPAccessToken() (string, error) { return a.mcp.AccessToken(a.ctx) }

func (a *DesktopApp) MCPClientConfig() (string, error) { return a.mcp.ClientConfig(a.ctx) }

func (a *DesktopApp) ExportMCPAIGuide() (string, error) {
	content, err := a.mcp.AIGuideMarkdown(a.ctx)
	if err != nil {
		return "", err
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "导出 AI 终端操作手册",
		DefaultFilename: "LabRemote-AI-终端操作手册.md",
		Filters: []runtime.FileFilter{
			{DisplayName: "Markdown 文档 (*.md)", Pattern: "*.md"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
		CanCreateDirectories: true,
	})
	if err != nil || path == "" {
		return "", err
	}
	if filepath.Ext(path) == "" {
		path += ".md"
	}
	if err := writeMCPAIGuide(path, content); err != nil {
		return "", model.NewAppError("MCP_GUIDE_EXPORT_FAILED", "无法写入 AI 终端操作手册", "mcp_export", true).WithDetails(map[string]any{"reason": err.Error()})
	}
	return path, nil
}

func writeMCPAIGuide(path, content string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(file, content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (a *DesktopApp) RegenerateMCPToken() (string, error) {
	return a.mcp.RegenerateToken(a.ctx)
}

func (a *DesktopApp) CopyText(value string) error {
	return runtime.ClipboardSetText(a.ctx, value)
}
