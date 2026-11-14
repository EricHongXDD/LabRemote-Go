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

	protocol "github.com/EricHongXDD/LabRemote-Go/internal/atrust/protocol"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/softether"
	"github.com/google/uuid"
)

type Config struct {
	Server, ProfileID, ProfileName, CertificatePin string
	Auth                                           *AuthBroker
}
type Session struct {
	client         *protocol.Client
	done           chan struct{}
	once           sync.Once
	mu             sync.Mutex
	connections    map[net.Conn]struct{}
	certificatePin string
}

func Open(ctx context.Context, config Config) (*Session, error) {
	server, err := model.NormalizeATrustAddress(config.Server)
	if err != nil {
		return nil, err
	}
	if config.Auth == nil {
		return nil, fmt.Errorf("当前环境无法打开 aTrust 网页认证")
	}
	session := &Session{done: make(chan struct{}), connections: make(map[net.Conn]struct{}), certificatePin: config.CertificatePin}
	client, err := protocol.NewClient(server, protocol.Options{GatewayTLS: func(address string) *tls.Config {
		session.mu.Lock()
		pin := session.certificatePin
		session.mu.Unlock()
		return gatewayTLS(address, pin)
	}})
	if err != nil {
		return nil, fmt.Errorf("aTrust 入口初始化失败")
	}
	success := false
	defer func() {
		if !success {
			client.Close()
		}
	}()
	client.SetDeviceID(strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", "")))
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
		return nil, fmt.Errorf("aTrust 网页认证已取消或超时")
	}
	callback, err = restoreCallbackState(callback, callbackURL, nonce, originalState)
	if err != nil {
		return nil, err
	}
	if err = client.CompleteSSO(ctx, callback, callbackURL); err != nil {
		return nil, err
	}
	success = true
	session.client = client
	return session, nil
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
