package atrust

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	protocol "github.com/EricHongXDD/LabRemote-Go/internal/atrust/protocol"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/softether"
	"github.com/google/uuid"
)

type Config struct {
	Server, ProfileID, ProfileName, CertificatePin string
	Auth                                           *AuthBroker
	Credentials                                    secrets.Store
	CredentialScope                                string
}
type Session struct {
	client                  *protocol.Client
	done                    chan struct{}
	once                    sync.Once
	mu                      sync.Mutex
	connections             map[net.Conn]struct{}
	certificatePin          string
	refreshMu               sync.Mutex
	verifiedAt              time.Time
	credentials             secrets.Store
	credentialScope, server string
}

func Open(ctx context.Context, config Config) (*Session, error) {
	return openSession(ctx, config, protocol.NewClient)
}

func openSession(ctx context.Context, config Config, newClient func(string, protocol.Options) (*protocol.Client, error)) (*Session, error) {
	server, err := model.NormalizeATrustAddress(config.Server)
	if err != nil {
		return nil, err
	}
	if config.CredentialScope == "" {
		config.CredentialScope = config.ProfileID
	}
	if config.Credentials != nil && config.CredentialScope != "" {
		unlock, err := lockCredential(ctx, CredentialKey(config.CredentialScope, server))
		if err != nil {
			return nil, err
		}
		defer unlock()
	}
	session := &Session{done: make(chan struct{}), connections: make(map[net.Conn]struct{}), certificatePin: config.CertificatePin, credentials: config.Credentials, credentialScope: config.CredentialScope, server: server, verifiedAt: time.Now()}
	options := protocol.Options{GatewayTLS: func(address string) *tls.Config {
		session.mu.Lock()
		pin := session.certificatePin
		session.mu.Unlock()
		return gatewayTLS(address, pin)
	}}
	client, err := newClient(server, options)
	if err != nil {
		return nil, fmt.Errorf("aTrust 入口初始化失败")
	}
	success := false
	defer func() {
		if !success && client != nil {
			client.Close()
		}
	}()
	saved, err := loadRemembered(ctx, config.Credentials, config.CredentialScope, server)
	if err != nil {
		return nil, err
	}
	if saved == nil {
		saved = &rememberedSession{Version: 1, Server: server, Device: strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", ""))}
	}
	client.SetDeviceID(saved.Device)
	if saved.State != nil {
		if err := client.ResumeSession(ctx, *saved.State); err == nil {
			state := client.SessionState()
			saved.State = &state
			if err := saveRemembered(ctx, config.Credentials, config.CredentialScope, saved); err != nil {
				return nil, err
			}
			success, session.client = true, client
			return session, nil
		} else if !errors.Is(err, protocol.ErrNoSession) {
			// 网络故障不等于登录失效；保留票据，让下次连接继续尝试恢复。
			return nil, SessionCheckError(err)
		}
		client.Close()
		client, err = newClient(server, options)
		if err != nil {
			return nil, fmt.Errorf("aTrust 入口初始化失败")
		}
		client.SetDeviceID(saved.Device)
		saved.State = nil
	}
	if err := saveRemembered(ctx, config.Credentials, config.CredentialScope, saved); err != nil {
		return nil, err
	}
	if config.Auth == nil {
		return nil, fmt.Errorf("当前环境无法打开 aTrust 网页认证")
	}
	loginURL, callbackURL, err := client.SSOEntrance(ctx)
	if err != nil {
		return nil, fmt.Errorf("aTrust 认证入口查询失败，或该认证方式尚未支持")
	}
	// OAuth state 绑定本次独立窗口；网关原有 state 在交付回调时恢复。
	login, err := url.Parse(loginURL)
	if err != nil {
		return nil, fmt.Errorf("aTrust 认证入口格式无效")
	}
	originalState := login.Query().Get("state")
	nonce := uuid.NewString()
	query := login.Query()
	query.Set("state", nonce)
	login.RawQuery = query.Encode()
	loginURL = login.String()
	callback, err := config.Auth.Request(ctx, LoginChallenge{ProfileID: config.ProfileID, ProfileName: config.ProfileName, Server: server}, loginURL, callbackURL)
	if err != nil {
		return nil, loginFailure(err)
	}
	callback, err = restoreCallbackState(callback, callbackURL, nonce, originalState)
	if err != nil {
		return nil, err
	}
	if err = client.CompleteSSO(ctx, callback, callbackURL); err != nil {
		return nil, err
	}
	state := client.SessionState()
	saved.State = &state
	if err := saveRemembered(ctx, config.Credentials, config.CredentialScope, saved); err != nil {
		return nil, err
	}
	success = true
	session.client = client
	return session, nil
}

// SessionCheckError 区分网关拒绝与传输故障，只展示安全的状态码，不泄露原始响应或票据。
func SessionCheckError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("aTrust 会话复核已取消或超时，已保留登录票据：%w", err)
	}
	var status *protocol.HTTPStatusError
	var api *protocol.APIError
	hasStatus, hasAPI := errors.As(err, &status), errors.As(err, &api)
	if hasStatus {
		codes := fmt.Sprintf("HTTP %d", status.StatusCode)
		if hasAPI {
			codes += fmt.Sprintf("，业务码 %d", api.Code)
		}
		if status.StatusCode == 403 {
			return fmt.Errorf("aTrust 授权资源访问被拒绝（%s），已保留登录票据，请核对账号资源权限", codes)
		}
		return fmt.Errorf("aTrust 网关会话查询失败（%s），已保留登录票据，请稍后重试", codes)
	}
	if hasAPI {
		return fmt.Errorf("aTrust 网关会话查询被拒绝（业务码 %d），已保留登录票据", api.Code)
	}
	return fmt.Errorf("aTrust 会话复核暂时失败，已保留登录票据，请检查网络后重试")
}

func loginFailure(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("aTrust 网页认证已取消：%w", err)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("aTrust 网页认证等待超时，请重新连接并完成浏览器登录：%w", err)
	default:
		return fmt.Errorf("aTrust 认证窗口失败：%w", err)
	}
}

func restoreCallbackState(raw, expected, nonce, original string) (string, error) {
	if !validCallback(raw, expected) {
		return "", fmt.Errorf("aTrust 认证回调与当前请求不匹配")
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if nonce == "" || q.Get("state") != nonce {
		return "", fmt.Errorf("aTrust 认证回调状态校验失败，已停止连接")
	}
	if original == "" {
		q.Del("state")
	} else {
		q.Set("state", original)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// gatewayTLS 先验证系统 CA 与名称；私有证书必须由用户核对指纹后明确接受。
func gatewayTLS(address, pin string) *tls.Config {
	host, _, _ := net.SplitHostPort(address)
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("aTrust 网关未提供证书")
		}
		leaf := state.PeerCertificates[0]
		digest := sha256.Sum256(leaf.Raw)
		fingerprint := "SHA256:" + base64.StdEncoding.EncodeToString(digest[:])
		if pin != "" {
			if pin == fingerprint {
				return nil
			}
			return &softether.CertificateError{Kind: "changed", Address: address, Fingerprint: fingerprint, Expected: pin}
		}
		pool := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			pool.AddCert(certificate)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: pool}); err == nil {
			return nil
		}
		return &softether.CertificateError{Kind: "unknown", Address: address, Fingerprint: fingerprint}
	}}
}

func (s *Session) Done() <-chan struct{} { return s.done }

// Refresh 在没有活动数据通道时定期复核票据，活动通道的授权仍由数据网关执行。
func (s *Session) Refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	if time.Since(s.verifiedAt) < 30*time.Second {
		return nil
	}
	// 网页在线状态与已认证的数据通道生命周期不同；不能为新建 SFTP 通道拆掉活动 SSH。
	// 新数据连接仍须经过数据网关认证和目标资源检查，不会绕过服务端授权。
	s.mu.Lock()
	active := len(s.connections) > 0
	s.mu.Unlock()
	if active {
		return nil
	}
	if err := s.client.CheckSession(ctx, s.client.Username()); err != nil {
		return err
	}
	state := s.client.SessionState()
	if err := saveRemembered(ctx, s.credentials, s.credentialScope, &rememberedSession{Version: 1, Server: s.server, Device: s.client.DeviceID(), State: &state}); err != nil {
		return err
	}
	s.verifiedAt = time.Now()
	return nil
}
func (s *Session) TargetDiagnostics(address string) map[string]any {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return map[string]any{}
	}
	number, _ := net.LookupPort("tcp", port)
	return s.client.TargetDiagnostics(host, number)
}
func (s *Session) SetCertificatePin(pin string) { s.mu.Lock(); s.certificatePin = pin; s.mu.Unlock() }
func (s *Session) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("aTrust 当前只支持目标 TCP 通道")
	}
	select {
	case <-s.done:
		return nil, net.ErrClosed
	default:
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portNumber, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, err
	}
	connection, err := s.client.DialTCP(ctx, host, portNumber)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		_ = connection.Close()
		return nil, net.ErrClosed
	default:
	}
	tracked := &trackedConnection{Conn: connection, session: s}
	s.connections[tracked] = struct{}{}
	return tracked, nil
}

type trackedConnection struct {
	net.Conn
	session *Session
	once    sync.Once
}

func (c *trackedConnection) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.session.mu.Lock()
		delete(c.session.connections, c)
		c.session.mu.Unlock()
	})
	return err
}
func (s *Session) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.refreshMu.Lock()
		defer s.refreshMu.Unlock()
		s.mu.Lock()
		connections := make([]net.Conn, 0, len(s.connections))
		for connection := range s.connections {
			connections = append(connections, connection)
		}
		s.connections = nil
		s.mu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
		s.client.SetSession("")
		s.client.Close()
	})
	return nil
}
