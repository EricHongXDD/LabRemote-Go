package vpn

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/softether"
)

type isolatedRuntime struct {
	mu   sync.Mutex
	link *softether.Link
}

type IsolatedManager struct {
	repository profile.Repository
	secrets    secrets.Store
	states     *StateMachine
	mu         sync.Mutex
	runtimes   map[string]*isolatedRuntime
	pending    map[string]string
}

func NewIsolatedManager(repository profile.Repository, secretStore secrets.Store, sink events.Sink) *IsolatedManager {
	return &IsolatedManager{
		repository: repository, secrets: secretStore, states: NewStateMachine(sink),
		runtimes: make(map[string]*isolatedRuntime), pending: make(map[string]string),
	}
}

func (m *IsolatedManager) runtime(profileID string) *isolatedRuntime {
	m.mu.Lock()
	defer m.mu.Unlock()
	runtime := m.runtimes[profileID]
	if runtime == nil {
		runtime = &isolatedRuntime{}
		m.runtimes[profileID] = runtime
	}
	return runtime
}

func (m *IsolatedManager) EnsureProfile(_ context.Context, value model.ConnectionProfile) error {
	return value.Validate()
}

func (m *IsolatedManager) Connect(ctx context.Context, profileID string) (model.VPNStatus, error) {
	value, err := m.repository.Get(ctx, profileID)
	if err != nil {
		m.states.Set(profileID, model.VPNFailed, "PROFILE_NOT_FOUND")
		return model.VPNStatus{}, err
	}
	if err := value.Validate(); err != nil {
		m.states.Set(profileID, model.VPNFailed, "PROFILE_INVALID")
		return model.VPNStatus{}, err
	}
	runtime := m.runtime(profileID)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !value.UsesIsolatedTunnel() {
		if runtime.link != nil {
			_ = runtime.link.Close()
			runtime.link = nil
		}
		return m.states.Update(profileID, func(status *model.VPNStatus) {
			status.State = model.VPNNotRequired
			status.ErrorCode = ""
			status.IPAddress = ""
			status.Interface = "直接 SSH 网络"
			status.RouteReady = true
		}), nil
	}
	if runtime.link != nil {
		select {
		case <-runtime.link.Done():
			runtime.link = nil
		default:
			return m.states.Get(profileID), nil
		}
	}
	m.states.Set(profileID, model.VPNPreparing, "")
	password, err := m.secrets.Get(ctx, model.VPNPasswordKey(profileID))
	if err != nil {
		m.states.Set(profileID, model.VPNFailed, "SECRET_NOT_FOUND")
		return model.VPNStatus{}, model.NewAppError("SECRET_NOT_FOUND", "未找到隔离隧道密码", "tunnel_auth", false)
	}
	defer secrets.Zero(password)
	port := value.VPN.ServerPort
	if port == 0 {
		port = 992
	}
	m.states.Set(profileID, model.VPNDialing, "")
	session, err := softether.Open(ctx, softether.Config{
		Server: value.VPN.ServerAddress, Port: port, Hub: value.VPN.HubName,
		Username: value.VPN.Username, Password: password, CertificatePin: value.VPN.ServerCertificate,
	})
	if err != nil {
		return model.VPNStatus{}, m.connectionError(profileID, err)
	}
	link, err := softether.NewLink(ctx, session)
	if err != nil {
		_ = session.Close()
		m.states.Set(profileID, model.VPNFailed, "TUNNEL_NETWORK_FAILED")
		return model.VPNStatus{}, model.NewAppError("TUNNEL_NETWORK_FAILED", "隔离隧道已认证，但用户态网络初始化失败", "tunnel_network", true).WithDetails(map[string]any{"reason": err.Error()})
	}
	runtime.link = link
	lease := link.Lease()
	status := m.states.Update(profileID, func(status *model.VPNStatus) {
		status.State = model.VPNConnected
		status.ErrorCode = ""
		status.IPAddress = lease.Address.String()
		status.Interface = "LabRemote 用户态网络栈"
		status.RouteReady = true
	})
	go m.watch(profileID, runtime, link)
	return status, nil
}

func (m *IsolatedManager) Status(ctx context.Context, profileID string) (model.VPNStatus, error) {
	value, err := m.repository.Get(ctx, profileID)
	if err != nil {
		return model.VPNStatus{}, err
	}
	if err := value.Validate(); err != nil {
		return model.VPNStatus{}, err
	}
	status := m.states.Get(profileID)
	if !value.UsesIsolatedTunnel() {
		status.State = model.VPNNotRequired
		status.ErrorCode = ""
		status.IPAddress = ""
		status.Interface = "直接 SSH 网络"
		status.RouteReady = true
	}
	return status, nil
}

func (m *IsolatedManager) DialContext(ctx context.Context, profileID, network, address string) (net.Conn, error) {
	value, err := m.repository.Get(ctx, profileID)
	if err != nil {
		return nil, err
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	expected := net.JoinHostPort(strings.Trim(value.SSH.ServerAddress, "[]"), strconv.Itoa(int(value.SSH.Port)))
	if address != expected || (network != "tcp" && network != "tcp4") {
		return nil, model.NewAppError("TUNNEL_TARGET_DENIED", "连接传输仅允许访问配置的 SSH 目标", "connection_policy", false)
	}
	if !value.UsesIsolatedTunnel() {
		connection, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, address)
		if err != nil {
			return nil, model.NewAppError("SSH_PORT_UNREACHABLE", "无法直接访问 SSH 服务器端口", "ssh_probe", true).WithDetails(map[string]any{"address": address, "reason": err.Error()})
		}
		return connection, nil
	}
	runtime := m.runtime(profileID)
	runtime.mu.Lock()
	link := runtime.link
	runtime.mu.Unlock()
	if link == nil {
		return nil, model.NewAppError("TUNNEL_NOT_CONNECTED", "隔离隧道尚未连接", "tunnel_dial", true)
	}
	connection, err := link.DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, model.NewAppError("SSH_PORT_UNREACHABLE", "隔离隧道已建立，但 SSH 服务器端口不可达", "ssh_probe", true).WithDetails(map[string]any{"address": address, "reason": err.Error()})
	}
	return connection, nil
}

func (m *IsolatedManager) Disconnect(ctx context.Context, profileID string, _ bool) error {
	value, err := m.repository.Get(ctx, profileID)
	if err != nil {
		return err
	}
	runtime := m.runtime(profileID)
	runtime.mu.Lock()
	link := runtime.link
	runtime.link = nil
	runtime.mu.Unlock()
	if !value.UsesIsolatedTunnel() {
		if link != nil {
			_ = link.Close()
		}
		m.states.Update(profileID, func(status *model.VPNStatus) {
			status.State = model.VPNNotRequired
			status.ErrorCode = ""
			status.IPAddress = ""
			status.Interface = "直接 SSH 网络"
			status.RouteReady = true
		})
		return nil
	}
	if link == nil {
		m.states.Set(profileID, model.VPNDisconnected, "")
		return nil
	}
	m.states.Set(profileID, model.VPNDisconnecting, "")
	_ = link.Close()
	m.states.Update(profileID, func(status *model.VPNStatus) {
		status.State = model.VPNDisconnected
		status.ErrorCode = ""
		status.IPAddress = ""
		status.Interface = ""
		status.RouteReady = false
	})
	return nil
}

func (m *IsolatedManager) AcceptCertificate(ctx context.Context, profileID, fingerprint string) error {
	value, err := m.repository.Get(ctx, profileID)
	if err != nil {
		return err
	}
	if !value.UsesIsolatedTunnel() {
		return model.NewAppError("TUNNEL_NOT_REQUIRED", "仅 SSH 连接不使用隔离隧道证书", "tunnel_certificate", false)
	}
	m.mu.Lock()
	pending := m.pending[profileID]
	m.mu.Unlock()
	if pending == "" || pending != fingerprint {
		return model.NewAppError("TUNNEL_CERT_UNKNOWN", "没有可确认的隧道证书，或指纹已变化", "tunnel_certificate", false)
	}
	value.VPN.ServerCertificate = fingerprint
	value.UpdatedAt = time.Now()
	if err := m.repository.Upsert(ctx, value); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.pending, profileID)
	m.mu.Unlock()
	return nil
}

func (m *IsolatedManager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	profileIDs := make([]string, 0, len(m.runtimes))
	for profileID := range m.runtimes {
		profileIDs = append(profileIDs, profileID)
	}
	m.mu.Unlock()
	for _, profileID := range profileIDs {
		_ = m.Disconnect(ctx, profileID, true)
	}
}

func (m *IsolatedManager) watch(profileID string, runtime *isolatedRuntime, link *softether.Link) {
	<-link.Done()
	runtime.mu.Lock()
	if runtime.link != link {
		runtime.mu.Unlock()
		return
	}
	runtime.link = nil
	runtime.mu.Unlock()
	if errors.Is(link.Err(), net.ErrClosed) {
		return
	}
	m.states.Update(profileID, func(status *model.VPNStatus) {
		status.State = model.VPNFailed
		status.ErrorCode = "TUNNEL_DISCONNECTED"
		status.RouteReady = false
	})
}

func (m *IsolatedManager) connectionError(profileID string, err error) error {
	var certificateError *softether.CertificateError
	if errors.As(err, &certificateError) {
		if certificateError.Kind == "unknown" {
			m.mu.Lock()
			m.pending[profileID] = certificateError.Fingerprint
			m.mu.Unlock()
			m.states.Set(profileID, model.VPNFailed, "TUNNEL_CERT_UNKNOWN")
			return model.NewAppError("TUNNEL_CERT_UNKNOWN", "首次连接需要确认 SoftEther 服务器证书指纹", "tunnel_certificate", false).WithDetails(map[string]any{
				"address": certificateError.Address, "fingerprint": certificateError.Fingerprint,
			})
		}
		m.states.Set(profileID, model.VPNFailed, "TUNNEL_CERT_CHANGED")
		return model.NewAppError("TUNNEL_CERT_CHANGED", "SoftEther 服务器证书指纹已变化，连接已阻断", "tunnel_certificate", false).WithDetails(map[string]any{
			"address": certificateError.Address, "expected": certificateError.Expected, "actual": certificateError.Fingerprint,
		})
	}
	var protocolError *softether.ProtocolError
	if errors.As(err, &protocolError) && protocolError.Code == 9 {
		m.states.Set(profileID, model.VPNFailed, "TUNNEL_AUTH_FAILED")
		return model.NewAppError("TUNNEL_AUTH_FAILED", "SoftEther 用户名或密码错误", "tunnel_auth", false)
	}
	m.states.Set(profileID, model.VPNFailed, "TUNNEL_CONNECT_FAILED")
	return model.NewAppError("TUNNEL_CONNECT_FAILED", "建立 SoftEther 隔离隧道失败", "tunnel_connect", true).WithDetails(map[string]any{"reason": err.Error()})
}

var _ Transport = (*IsolatedManager)(nil)
