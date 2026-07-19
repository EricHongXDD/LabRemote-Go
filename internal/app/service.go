package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/browserproxy"
	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/policy"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
	"github.com/google/uuid"
)

type SaveProfileRequest struct {
	Profile         model.ConnectionProfile `json:"profile"`
	VPNPreSharedKey string                  `json:"vpn_pre_shared_key"`
	VPNPassword     string                  `json:"vpn_password"`
	SSHPassword     string                  `json:"ssh_password"`
}

type TestConnectionRequest struct {
	Profile     model.ConnectionProfile `json:"profile"`
	VPNPassword string                  `json:"vpn_password"`
	SSHPassword string                  `json:"ssh_password"`
}

type ConnectionTestResult struct {
	Success               bool   `json:"success"`
	Kind                  string `json:"kind"`
	Message               string `json:"message"`
	IPAddress             string `json:"ip_address,omitempty"`
	TunnelFingerprint     string `json:"tunnel_fingerprint,omitempty"`
	SSHHostKeyFingerprint string `json:"ssh_host_key_fingerprint,omitempty"`
	DurationMS            int64  `json:"duration_ms"`
}

type Service struct {
	profiles   profile.Repository
	secrets    secrets.Store
	vpn        vpn.Transport
	ssh        *sshclient.Manager
	knownHosts *sshclient.KnownHosts
	browser    *browserproxy.Manager
}

func NewService(profiles profile.Repository, secretStore secrets.Store, vpnManager vpn.Transport, sshManager *sshclient.Manager, knownHosts *sshclient.KnownHosts) *Service {
	return &Service{profiles: profiles, secrets: secretStore, vpn: vpnManager, ssh: sshManager, knownHosts: knownHosts, browser: browserproxy.NewManager(sshManager)}
}

func (s *Service) ListProfiles(ctx context.Context) ([]model.ConnectionProfile, error) {
	return s.profiles.List(ctx)
}

func (s *Service) GetProfile(ctx context.Context, profileID string) (model.ConnectionProfile, error) {
	return s.profiles.Get(ctx, profileID)
}

func (s *Service) SaveProfile(ctx context.Context, request SaveProfileRequest) (model.ConnectionProfile, error) {
	value := request.Profile
	now := time.Now()
	isNew := strings.TrimSpace(value.ID) == ""
	var previous model.ConnectionProfile
	if isNew {
		value.ID = uuid.NewString()
		value.CreatedAt = now
	} else {
		existing, err := s.profiles.Get(ctx, value.ID)
		if err != nil {
			return model.ConnectionProfile{}, err
		}
		value.CreatedAt = existing.CreatedAt
		previous = existing
	}
	value.UpdatedAt = now
	value.VPN.Type = model.VPNTypeSoftEther
	value.VPN.SplitTunnel = true
	if value.VPN.ServerPort == 0 {
		value.VPN.ServerPort = 992
	}
	if !isNew {
		previousPort := previous.VPN.ServerPort
		if previousPort == 0 {
			previousPort = 992
		}
		if !strings.EqualFold(strings.TrimSpace(previous.VPN.ServerAddress), strings.TrimSpace(value.VPN.ServerAddress)) || previousPort != value.VPN.ServerPort {
			value.VPN.ServerCertificate = ""
		}
	}
	value.VPN.CredentialRef = model.VPNPasswordKey(value.ID)
	value.SSH.CredentialRef = model.SSHPasswordKey(value.ID)
	if err := value.Validate(); err != nil {
		return model.ConnectionProfile{}, err
	}
	values, err := s.profiles.List(ctx)
	if err != nil {
		return model.ConnectionProfile{}, err
	}
	for _, existing := range values {
		if existing.ID != value.ID && existing.VPN.ConnectionName == value.VPN.ConnectionName {
			return model.ConnectionProfile{}, model.NewAppError("PROFILE_INVALID", "VPN 连接名称已存在", "profile", false)
		}
	}
	if isNew && (request.VPNPassword == "" || request.SSHPassword == "") {
		return model.ConnectionProfile{}, model.NewAppError("PROFILE_INVALID", "新建连接时隧道密码和 SSH 密码均为必填", "profile", false)
	}
	secretValues := []struct {
		key   string
		value string
	}{
		{model.VPNPSKKey(value.ID), request.VPNPreSharedKey},
		{model.VPNPasswordKey(value.ID), request.VPNPassword},
		{model.SSHPasswordKey(value.ID), request.SSHPassword},
	}
	for _, item := range secretValues {
		if item.value == "" {
			continue
		}
		secret := []byte(item.value)
		if err := s.secrets.Put(ctx, item.key, secret); err != nil {
			secrets.Zero(secret)
			return model.ConnectionProfile{}, model.NewAppError("SECRET_STORE_FAILED", "保存 Windows 凭据失败", "profile", true)
		}
		secrets.Zero(secret)
	}
	if err := s.profiles.Upsert(ctx, value); err != nil {
		return model.ConnectionProfile{}, err
	}
	return value, nil
}

func (s *Service) DeleteProfile(ctx context.Context, profileID string, deleteSecrets bool) error {
	s.browser.CloseProfile(ctx, profileID)
	s.ssh.CloseProfile(ctx, profileID)
	_ = s.vpn.Disconnect(ctx, profileID, true)
	if err := s.profiles.Delete(ctx, profileID); err != nil {
		return err
	}
	if err := s.knownHosts.Remove(profileID); err != nil {
		return err
	}
	if deleteSecrets {
		for _, key := range []string{model.VPNPSKKey(profileID), model.VPNPasswordKey(profileID), model.SSHPasswordKey(profileID)} {
			if err := s.secrets.Delete(ctx, key); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) ClearCredential(ctx context.Context, profileID, kind string) error {
	if _, err := s.profiles.Get(ctx, profileID); err != nil {
		return err
	}
	var key string
	switch kind {
	case "vpn_psk":
		key = model.VPNPSKKey(profileID)
	case "vpn_password":
		key = model.VPNPasswordKey(profileID)
	case "ssh_password":
		key = model.SSHPasswordKey(profileID)
	default:
		return model.NewAppError("PROFILE_INVALID", "未知的凭据类型", "profile", false)
	}
	return s.secrets.Delete(ctx, key)
}

func (s *Service) TestTunnelConnection(ctx context.Context, request TestConnectionRequest) (ConnectionTestResult, error) {
	return s.runConnectionTest(ctx, request, false)
}

func (s *Service) TestSSHConnection(ctx context.Context, request TestConnectionRequest) (ConnectionTestResult, error) {
	return s.runConnectionTest(ctx, request, true)
}

func (s *Service) runConnectionTest(ctx context.Context, request TestConnectionRequest, includeSSH bool) (ConnectionTestResult, error) {
	startedAt := time.Now()
	probeContext, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()

	value := request.Profile
	originalProfileID := strings.TrimSpace(value.ID)
	var savedProfile model.ConnectionProfile
	hasSavedProfile := false
	if originalProfileID != "" {
		stored, err := s.profiles.Get(probeContext, originalProfileID)
		if err != nil {
			return ConnectionTestResult{}, err
		}
		savedProfile = stored
		hasSavedProfile = true
	}

	value.ID = "connection-test-" + uuid.NewString()
	value.DisplayName = strings.TrimSpace(value.VPN.ConnectionName)
	value.VPN.Type = model.VPNTypeSoftEther
	value.VPN.SplitTunnel = true
	if value.VPN.ServerPort == 0 {
		value.VPN.ServerPort = 992
	}
	if hasSavedProfile && sameTunnelEndpoint(value, savedProfile) {
		value.VPN.ServerCertificate = savedProfile.VPN.ServerCertificate
	} else {
		value.VPN.ServerCertificate = ""
	}
	value.VPN.CredentialRef = model.VPNPasswordKey(value.ID)
	value.SSH.CredentialRef = model.SSHPasswordKey(value.ID)
	value.CreatedAt = time.Now()
	value.UpdatedAt = value.CreatedAt
	if !includeSSH {
		// 隧道测试不依赖 SSH 表单，使用只存在于临时配置中的占位字段完成结构校验。
		value.SSH.ServerAddress = "127.0.0.1"
		value.SSH.Port = 22
		value.SSH.Username = "connection-test"
	}
	if err := value.Validate(); err != nil {
		return ConnectionTestResult{}, err
	}

	temporaryRoot, err := os.MkdirTemp("", "labremote-connection-test-")
	if err != nil {
		return ConnectionTestResult{}, model.NewAppError("CONNECTION_TEST_FAILED", "无法创建连接测试环境", "connection_test", true)
	}
	defer os.RemoveAll(temporaryRoot)
	temporaryRepository := profile.NewJSONRepository(filepath.Join(temporaryRoot, "profiles.json"))
	if err := temporaryRepository.Upsert(probeContext, value); err != nil {
		return ConnectionTestResult{}, err
	}

	temporarySecrets := secrets.NewMemoryStore()
	vpnPassword, err := s.connectionTestSecret(probeContext, originalProfileID, request.VPNPassword, model.VPNPasswordKey, "隔离隧道密码")
	if err != nil {
		return ConnectionTestResult{}, err
	}
	if err := temporarySecrets.Put(probeContext, model.VPNPasswordKey(value.ID), vpnPassword); err != nil {
		secrets.Zero(vpnPassword)
		return ConnectionTestResult{}, err
	}
	secrets.Zero(vpnPassword)

	transport := vpn.NewIsolatedManager(temporaryRepository, temporarySecrets, events.Nop{})
	defer transport.Shutdown(context.Background())
	status, tunnelFingerprint, err := connectProbeTunnel(probeContext, transport, value.ID)
	if err != nil {
		return ConnectionTestResult{}, err
	}
	if !includeSSH {
		return ConnectionTestResult{
			Success: true, Kind: "tunnel",
			Message:   "隔离隧道认证及用户态网络初始化成功",
			IPAddress: status.IPAddress, TunnelFingerprint: tunnelFingerprint,
			DurationMS: time.Since(startedAt).Milliseconds(),
		}, nil
	}

	sshPassword, err := s.connectionTestSecret(probeContext, originalProfileID, request.SSHPassword, model.SSHPasswordKey, "SSH 密码")
	if err != nil {
		return ConnectionTestResult{}, err
	}
	if err := temporarySecrets.Put(probeContext, model.SSHPasswordKey(value.ID), sshPassword); err != nil {
		secrets.Zero(sshPassword)
		return ConnectionTestResult{}, err
	}
	secrets.Zero(sshPassword)

	temporaryKnownHosts := sshclient.NewKnownHosts(filepath.Join(temporaryRoot, "known_hosts"))
	sshFingerprint := ""
	if hasSavedProfile && sameSSHEndpoint(value, savedProfile) {
		record, ok, lookupErr := s.knownHosts.Lookup(originalProfileID)
		if lookupErr != nil {
			return ConnectionTestResult{}, lookupErr
		}
		if ok {
			sshFingerprint = record.Fingerprint
			record.ProfileID = value.ID
			if err := temporaryKnownHosts.Store(record); err != nil {
				return ConnectionTestResult{}, err
			}
		}
	}
	sshManager := sshclient.NewManager(temporaryRepository, temporarySecrets, temporaryKnownHosts, events.Nop{}, transport)
	defer sshManager.CloseAll(context.Background())
	err = sshManager.Connect(probeContext, value.ID)
	if err != nil {
		var appError *model.AppError
		if errors.As(err, &appError) && appError.Code == "SSH_HOST_KEY_UNKNOWN" {
			sshFingerprint, _ = appError.Details["fingerprint"].(string)
			if sshFingerprint == "" {
				return ConnectionTestResult{}, err
			}
			if acceptErr := sshManager.AcceptHostKey(value.ID, sshFingerprint); acceptErr != nil {
				return ConnectionTestResult{}, acceptErr
			}
			err = sshManager.Connect(probeContext, value.ID)
		}
	}
	if err != nil {
		return ConnectionTestResult{}, err
	}
	return ConnectionTestResult{
		Success: true, Kind: "ssh",
		Message:   "SSH 服务器端口、主机指纹和密码认证均测试成功",
		IPAddress: status.IPAddress, TunnelFingerprint: tunnelFingerprint,
		SSHHostKeyFingerprint: sshFingerprint,
		DurationMS:            time.Since(startedAt).Milliseconds(),
	}, nil
}

func (s *Service) connectionTestSecret(ctx context.Context, originalProfileID, provided string, key func(string) string, label string) ([]byte, error) {
	if provided != "" {
		return []byte(provided), nil
	}
	if originalProfileID == "" {
		return nil, model.NewAppError("PROFILE_INVALID", label+"不能为空", "connection_test", false)
	}
	value, err := s.secrets.Get(ctx, key(originalProfileID))
	if err != nil {
		return nil, model.NewAppError("SECRET_NOT_FOUND", "未找到已保存的"+label+"，请重新输入", "connection_test", false)
	}
	return value, nil
}

func connectProbeTunnel(ctx context.Context, transport *vpn.IsolatedManager, profileID string) (model.VPNStatus, string, error) {
	status, err := transport.Connect(ctx, profileID)
	fingerprint := ""
	if err != nil {
		var appError *model.AppError
		if errors.As(err, &appError) && appError.Code == "TUNNEL_CERT_UNKNOWN" {
			fingerprint, _ = appError.Details["fingerprint"].(string)
			if fingerprint == "" {
				return model.VPNStatus{}, "", err
			}
			if acceptErr := transport.AcceptCertificate(ctx, profileID, fingerprint); acceptErr != nil {
				return model.VPNStatus{}, "", acceptErr
			}
			status, err = transport.Connect(ctx, profileID)
		}
	}
	return status, fingerprint, err
}

func sameTunnelEndpoint(left, right model.ConnectionProfile) bool {
	leftPort := left.VPN.ServerPort
	if leftPort == 0 {
		leftPort = 992
	}
	rightPort := right.VPN.ServerPort
	if rightPort == 0 {
		rightPort = 992
	}
	return strings.EqualFold(strings.TrimSpace(left.VPN.ServerAddress), strings.TrimSpace(right.VPN.ServerAddress)) && leftPort == rightPort
}

func sameSSHEndpoint(left, right model.ConnectionProfile) bool {
	return strings.EqualFold(strings.TrimSpace(left.SSH.ServerAddress), strings.TrimSpace(right.SSH.ServerAddress)) && left.SSH.Port == right.SSH.Port
}

func (s *Service) EnsureConnected(ctx context.Context, profileID string) error {
	if _, err := s.vpn.Connect(ctx, profileID); err != nil {
		return err
	}
	return s.ssh.Connect(ctx, profileID)
}

func (s *Service) ConnectAndOpenTerminal(ctx context.Context, profileID string, cols, rows int) (string, error) {
	if err := s.EnsureConnected(ctx, profileID); err != nil {
		return "", err
	}
	return s.ssh.OpenTerminal(ctx, profileID, cols, rows, "ui")
}

func (s *Service) OpenBrowserResource(ctx context.Context, profileID, targetURL string) (string, error) {
	if _, err := s.profiles.Get(ctx, profileID); err != nil {
		return "", err
	}
	if err := browserproxy.ValidateTargetURL(targetURL); err != nil {
		return "", err
	}
	if err := s.EnsureConnected(ctx, profileID); err != nil {
		return "", err
	}
	return s.browser.Open(ctx, profileID, targetURL)
}

func (s *Service) CloseBrowserAccess(ctx context.Context, profileID string) {
	s.browser.CloseProfile(ctx, profileID)
}

func (s *Service) AcceptHostKey(profileID, fingerprint string) error {
	return s.ssh.AcceptHostKey(profileID, fingerprint)
}

func (s *Service) AcceptTunnelCertificate(ctx context.Context, profileID, fingerprint string) error {
	return s.vpn.AcceptCertificate(ctx, profileID, fingerprint)
}

func (s *Service) WriteTerminal(ctx context.Context, sessionID string, data []byte) error {
	return s.ssh.WriteTerminal(ctx, sessionID, data)
}

func (s *Service) ResizeTerminal(ctx context.Context, sessionID string, cols, rows int) error {
	return s.ssh.ResizeTerminal(ctx, sessionID, cols, rows)
}

func (s *Service) CloseSession(ctx context.Context, sessionID string) error {
	return s.ssh.CloseSession(ctx, sessionID)
}

func (s *Service) TerminalWorkingDirectory(ctx context.Context, sessionID string) (string, error) {
	return s.ssh.TerminalWorkingDirectory(ctx, sessionID)
}

func (s *Service) StartUpload(ctx context.Context, request model.UploadRequest) (model.UploadProgress, error) {
	if err := s.EnsureConnected(ctx, request.ProfileID); err != nil {
		return model.UploadProgress{}, err
	}
	return s.ssh.StartUpload(ctx, request)
}

func (s *Service) UploadStatus(jobID string) (model.UploadProgress, error) {
	return s.ssh.UploadStatus(jobID)
}

func (s *Service) CancelUpload(jobID string) error {
	return s.ssh.CancelUpload(jobID)
}

func (s *Service) ListRemoteDirectory(ctx context.Context, profileID string, directory string) (model.RemoteDirectory, error) {
	if err := s.EnsureConnected(ctx, profileID); err != nil {
		return model.RemoteDirectory{}, err
	}
	return s.ssh.ListRemoteDirectory(ctx, profileID, directory)
}

func (s *Service) StartDownload(ctx context.Context, request model.DownloadRequest) (model.DownloadProgress, error) {
	if err := s.EnsureConnected(ctx, request.ProfileID); err != nil {
		return model.DownloadProgress{}, err
	}
	return s.ssh.StartDownload(ctx, request)
}

func (s *Service) DownloadStatus(jobID string) (model.DownloadProgress, error) {
	return s.ssh.DownloadStatus(jobID)
}

func (s *Service) CancelDownload(jobID string) error {
	return s.ssh.CancelDownload(jobID)
}

func (s *Service) Disconnect(ctx context.Context, profileID string, force bool) error {
	ui, mcp, commands := s.ssh.Counts(profileID)
	transfers := s.ssh.ActiveUploadCount(profileID) + s.ssh.ActiveDownloadCount(profileID)
	browserSessions := s.browser.Count(profileID)
	if (ui+mcp+commands+transfers+browserSessions) > 0 && !force {
		return model.NewAppError("VPN_BUSY", "隔离隧道正被活动会话、文件传输或浏览器代理使用；请关闭相关任务或选择强制断开", "tunnel_disconnect", false).WithDetails(map[string]any{
			"ui_sessions": ui, "mcp_sessions": mcp, "active_commands": commands, "active_transfers": transfers, "browser_sessions": browserSessions,
		})
	}
	s.browser.CloseProfile(ctx, profileID)
	s.ssh.CloseProfile(ctx, profileID)
	return s.vpn.Disconnect(ctx, profileID, force)
}

func (s *Service) ConnectionStatus(ctx context.Context, profileID string) (model.ConnectionStatus, error) {
	vpnStatus, err := s.vpn.Status(ctx, profileID)
	if err != nil {
		return model.ConnectionStatus{}, err
	}
	ui, mcp, commands := s.ssh.Counts(profileID)
	transfers := s.ssh.ActiveUploadCount(profileID) + s.ssh.ActiveDownloadCount(profileID)
	browserSessions := s.browser.Count(profileID)
	vpnStatus.ReferenceNum = ui + mcp + commands + transfers + browserSessions
	return model.ConnectionStatus{
		ProfileID:       profileID,
		VPN:             vpnStatus,
		SSHConnected:    s.ssh.IsConnected(profileID),
		UISessions:      ui,
		MCPSessions:     mcp,
		ActiveCommands:  commands,
		ActiveTransfers: transfers,
		BrowserSessions: browserSessions,
	}, nil
}

func (s *Service) MCPProfiles(ctx context.Context) ([]model.ConnectionProfile, error) {
	values, err := s.profiles.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]model.ConnectionProfile, 0, len(values))
	for _, value := range values {
		if value.MCPPolicy.EnabledForProfile {
			result = append(result, value)
		}
	}
	return result, nil
}

func (s *Service) MCPConnect(ctx context.Context, profileID string) error {
	value, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return err
	}
	if err := policy.RequireProfile(value); err != nil {
		return err
	}
	return s.EnsureConnected(ctx, profileID)
}

func (s *Service) MCPDisconnect(ctx context.Context, profileID string, force bool) error {
	value, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return err
	}
	if err := policy.RequireDisconnect(value); err != nil {
		return err
	}
	ui, _, _ := s.ssh.Counts(profileID)
	if ui > 0 {
		return model.NewAppError("MCP_TOOL_FORBIDDEN", "MCP 不得断开图形界面正在使用的隔离隧道", "mcp_policy", false)
	}
	return s.Disconnect(ctx, profileID, force)
}

func (s *Service) MCPExec(ctx context.Context, request model.ExecRequest) (model.ExecResult, error) {
	value, err := s.profiles.Get(ctx, request.ProfileID)
	if err != nil {
		return model.ExecResult{}, err
	}
	if err := policy.RequireExec(value); err != nil {
		return model.ExecResult{}, err
	}
	if err := s.EnsureConnected(ctx, request.ProfileID); err != nil {
		return model.ExecResult{}, err
	}
	return s.ssh.Exec(ctx, request)
}

func (s *Service) MCPOpenSession(ctx context.Context, profileID string, cols, rows int) (string, error) {
	value, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return "", err
	}
	if err := policy.RequireInteractive(value); err != nil {
		return "", err
	}
	if err := s.EnsureConnected(ctx, profileID); err != nil {
		return "", err
	}
	return s.ssh.OpenTerminal(ctx, profileID, cols, rows, "mcp")
}

func (s *Service) MCPWriteSession(ctx context.Context, sessionID string, data []byte) error {
	if !strings.HasPrefix(sessionID, "mcp-session-") {
		return model.NewAppError("MCP_SESSION_NOT_FOUND", "MCP 只能访问自己创建的会话", "mcp_session", false)
	}
	return s.ssh.WriteTerminal(ctx, sessionID, data)
}

func (s *Service) MCPReadSession(ctx context.Context, sessionID string, cursor uint64, maxBytes int, wait time.Duration) (model.SessionReadResult, error) {
	if !strings.HasPrefix(sessionID, "mcp-session-") {
		return model.SessionReadResult{}, model.NewAppError("MCP_SESSION_NOT_FOUND", "MCP 只能访问自己创建的会话", "mcp_session", false)
	}
	return s.ssh.ReadTerminal(ctx, sessionID, cursor, maxBytes, wait)
}

func (s *Service) MCPResizeSession(ctx context.Context, sessionID string, cols, rows int) error {
	if !strings.HasPrefix(sessionID, "mcp-session-") {
		return model.NewAppError("MCP_SESSION_NOT_FOUND", "MCP 只能访问自己创建的会话", "mcp_session", false)
	}
	return s.ssh.ResizeTerminal(ctx, sessionID, cols, rows)
}

func (s *Service) MCPCloseSession(ctx context.Context, sessionID string) error {
	if !strings.HasPrefix(sessionID, "mcp-session-") {
		return model.NewAppError("MCP_SESSION_NOT_FOUND", "MCP 只能访问自己创建的会话", "mcp_session", false)
	}
	return s.ssh.CloseSession(ctx, sessionID)
}

func (s *Service) CloseMCPSessions(ctx context.Context) {
	s.ssh.CloseOwnerSessions(ctx, "mcp")
}

func (s *Service) Shutdown(ctx context.Context) {
	s.browser.CloseAll(ctx)
	s.ssh.CloseAll(ctx)
	s.vpn.Shutdown(ctx)
}

func IsAppError(err error, code string) bool {
	var appError *model.AppError
	return errors.As(err, &appError) && appError.Code == code
}
