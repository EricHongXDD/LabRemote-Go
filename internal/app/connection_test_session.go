package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/atrust"
	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/openvpn"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
	"github.com/google/uuid"
)

const connectionTestIdleTimeout = 15 * time.Minute

type connectionTestSession struct {
	ctx            context.Context
	cancel         context.CancelFunc
	gate           chan struct{}
	root           string
	id             string
	repository     *profile.JSONRepository
	secrets        *secrets.MemoryStore
	transport      *vpn.IsolatedManager
	signature      [32]byte
	certificatePin string
	timer          *time.Timer
	expiration     uint64
	closeOnce      sync.Once
	done           chan struct{}
}

func (s *Service) newConnectionTestSession() (*connectionTestSession, error) {
	root, err := os.MkdirTemp("", "labremote-connection-test-")
	if err != nil {
		return nil, model.NewAppError("CONNECTION_TEST_FAILED", "无法创建连接测试环境", "connection_test", true)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entry := &connectionTestSession{ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1), root: root, id: "connection-test-" + uuid.NewString(), repository: profile.NewJSONRepository(filepath.Join(root, "profiles.json")), secrets: secrets.NewMemoryStore(), done: make(chan struct{})}
	entry.transport = s.newTestTransport(entry)
	return entry, nil
}

func (s *Service) newTestTransport(entry *connectionTestSession) *vpn.IsolatedManager {
	var sink events.Sink = events.Nop{}
	if provider, ok := s.vpn.(interface{ EventSink() events.Sink }); ok {
		sink = provider.EventSink()
	}
	transport := vpn.NewIsolatedManager(entry.repository, entry.secrets, sink)
	if provider, ok := s.vpn.(interface{ OTPBroker() *openvpn.OTPBroker }); ok {
		transport.SetOTPBroker(provider.OTPBroker())
	}
	if provider, ok := s.vpn.(interface{ ATrustAuthBroker() *atrust.AuthBroker }); ok {
		transport.SetATrustAuthBroker(provider.ATrustAuthBroker())
	}
	return transport
}

// acquireConnectionTestSession 复用同一表单的 OpenVPN/aTrust 认证，SSH 客户端仍逐次创建。
func (s *Service) acquireConnectionTestSession(ctx context.Context, request TestConnectionRequest) (*connectionTestSession, func(), error) {
	key := strings.TrimSpace(request.TestSessionID)
	if len(key) > 128 {
		return nil, nil, model.NewAppError("PROFILE_INVALID", "测试会话标识无效", "connection_test", false)
	}
	cache := key != "" && (request.Profile.EffectiveConnectionMode() == model.ConnectionModeOpenVPNSSH || request.Profile.EffectiveConnectionMode() == model.ConnectionModeATrustSSH)
	s.testMu.Lock()
	if s.testsClosed {
		s.testMu.Unlock()
		return nil, nil, fmt.Errorf("连接测试已停止")
	}
	if s.testSessions == nil {
		s.testSessions = make(map[string]*connectionTestSession)
	}
	var entry *connectionTestSession
	if cache {
		entry = s.testSessions[key]
	}
	if entry == nil {
		if cache && len(s.testSessions) >= 16 {
			s.testMu.Unlock()
			return nil, nil, model.NewAppError("CONNECTION_TEST_BUSY", "测试会话过多，请关闭其他配置窗口后重试", "connection_test", true)
		}
		var err error
		entry, err = s.newConnectionTestSession()
		if err != nil {
			s.testMu.Unlock()
			return nil, nil, err
		}
		if cache {
			s.testSessions[key] = entry
		}
	}
	if entry.timer != nil {
		entry.timer.Stop()
	}
	entry.expiration++
	s.testMu.Unlock()
	select {
	case entry.gate <- struct{}{}:
	case <-ctx.Done():
		if !cache {
			entry.close()
		}
		return nil, nil, ctx.Err()
	case <-entry.ctx.Done():
		return nil, nil, entry.ctx.Err()
	}
	if err := entry.ctx.Err(); err != nil {
		<-entry.gate
		return nil, nil, err
	}
	release := func() {
		<-entry.gate
		if !cache {
			entry.close()
			return
		}
		s.testMu.Lock()
		if s.testSessions[key] == entry && entry.ctx.Err() == nil {
			entry.expiration++
			expiration := entry.expiration
			entry.timer = time.AfterFunc(connectionTestIdleTimeout, func() { s.expireConnectionTestSession(key, entry, expiration) })
		}
		s.testMu.Unlock()
	}
	return entry, release, nil
}

func (s *Service) expireConnectionTestSession(key string, entry *connectionTestSession, expiration uint64) {
	s.testMu.Lock()
	if s.testSessions[key] != entry || entry.expiration != expiration {
		s.testMu.Unlock()
		return
	}
	delete(s.testSessions, key)
	s.testMu.Unlock()
	entry.close()
}

// tunnelTestSignature 不包含 SSH 地址、用户名或密码，调整 SSH 参数不会触发 VPN 再认证。
func tunnelTestSignature(value model.ConnectionProfile, password []byte) [32]byte {
	hash := sha256.New()
	endpoint := value.VPN.OpenVPNConfig
	if value.EffectiveConnectionMode() == model.ConnectionModeATrustSSH {
		endpoint = value.VPN.ServerAddress
	}
	_, _ = hash.Write([]byte(endpoint))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(value.VPN.Username))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(password)
	var signature [32]byte
	copy(signature[:], hash.Sum(nil))
	return signature
}

func (s *Service) CloseConnectionTestSession(sessionID string) {
	s.closeConnectionTestSession(strings.TrimSpace(sessionID), nil)
}

func (s *Service) closeConnectionTestSession(key string, expected *connectionTestSession) {
	s.testMu.Lock()
	entry := s.testSessions[key]
	if entry != nil && (expected == nil || expected == entry) {
		delete(s.testSessions, key)
		if entry.timer != nil {
			entry.timer.Stop()
		}
	} else {
		entry = nil
	}
	s.testMu.Unlock()
	if entry != nil {
		entry.close()
	}
}

func (entry *connectionTestSession) close() {
	entry.closeOnce.Do(func() {
		entry.cancel()
		go func() {
			entry.gate <- struct{}{}
			defer func() { <-entry.gate; close(entry.done) }()
			entry.transport.Shutdown(context.Background())
			entry.clearSSHSecrets()
			_ = entry.secrets.Delete(context.Background(), model.VPNPasswordKey(entry.id))
			_ = os.RemoveAll(entry.root)
		}()
	})
}

func (entry *connectionTestSession) clearSSHSecrets() {
	for _, key := range []string{model.SSHPasswordKey(entry.id), model.SSHPrivateKeyPathKey(entry.id), model.SSHPrivateKeyPassphraseKey(entry.id)} {
		_ = entry.secrets.Delete(context.Background(), key)
	}
}

func (s *Service) closeAllConnectionTests(ctx context.Context) {
	s.testMu.Lock()
	s.testsClosed = true
	entries := s.testSessions
	s.testSessions = nil
	for _, entry := range entries {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		entry.close()
	}
	s.testMu.Unlock()
	for _, entry := range entries {
		select {
		case <-entry.done:
		case <-ctx.Done():
			return
		}
	}
}
