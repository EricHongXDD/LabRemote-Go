package vpn

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/atrust"
	protocol "github.com/EricHongXDD/LabRemote-Go/internal/atrust/protocol"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/softether"
)

func (m *IsolatedManager) ATrustAuthBroker() *atrust.AuthBroker     { return m.aTrustAuth }
func (m *IsolatedManager) SetATrustAuthBroker(b *atrust.AuthBroker) { m.aTrustAuth = b }

func (m *IsolatedManager) connectATrust(ctx context.Context, value model.ConnectionProfile) (model.VPNStatus, error) {
	if err := value.Validate(); err != nil {
		return model.VPNStatus{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	r := m.runtime(value.ID)
	select {
	case r.connectGate <- struct{}{}:
		defer func() { <-r.connectGate }()
	case <-ctx.Done():
		return model.VPNStatus{}, ctx.Err()
	}
	r.mu.Lock()
	if r.aTrust != nil {
		select {
		case <-r.aTrust.Done():
			r.aTrust = nil
		default:
			r.aTrust.SetCertificatePin(value.VPN.ServerCertificate)
			r.mu.Unlock()
			return m.states.Get(value.ID), nil
		}
	}
	generation := r.generation
	connectCtx, stop := context.WithCancel(ctx)
	r.aTrustCancel = stop
	r.mu.Unlock()
	defer stop()
	m.states.Set(value.ID, model.VPNDialing, "")
	session, err := atrust.Open(connectCtx, atrust.Config{Server: value.VPN.ServerAddress, ProfileID: value.ID, ProfileName: value.DisplayName, CertificatePin: value.VPN.ServerCertificate, Auth: m.aTrustAuth})
	if err != nil {
		m.states.Set(value.ID, model.VPNFailed, "ATRUST_AUTH_FAILED")
		return m.states.Get(value.ID), model.NewAppError("ATRUST_AUTH_FAILED", err.Error(), "atrust_auth", true)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation != r.generation || connectCtx.Err() != nil {
		_ = session.Close()
		return model.VPNStatus{}, context.Canceled
	}
	r.aTrust = session
	r.aTrustCancel = nil
	return m.states.Update(value.ID, func(s *model.VPNStatus) {
		s.State = model.VPNConnected
		s.ErrorCode = ""
		s.RouteReady = true
		s.IPAddress = ""
		s.Interface = "LabRemote aTrust 进程内目标 TCP 通道"
	}), nil
}

func (m *IsolatedManager) dialATrust(ctx context.Context, value model.ConnectionProfile, network, address string) (net.Conn, error) {
	r := m.runtime(value.ID)
	r.mu.Lock()
	session := r.aTrust
	r.mu.Unlock()
	if session == nil {
		return nil, model.NewAppError("ATRUST_NOT_CONNECTED", "aTrust 隔离通道尚未认证", "atrust_dial", true)
	}
	connection, err := session.DialContext(ctx, network, address)
	if err == nil {
		return connection, nil
	}
	diagnostic := session.TargetDiagnostics(address)
	diagnostic["reason"] = err.Error()
	m.states.events.Emit("atrust:diagnostic", diagnostic)
	if errors.Is(err, protocol.ErrNotManaged) {
		return nil, model.NewAppError("ATRUST_TARGET_NOT_AUTHORIZED", "当前 aTrust 授权资源未匹配此 SSH 地址和端口，请核对目标地址及账号资源权限", "atrust_dial", false)
	}
	var certificate *softether.CertificateError
	if errors.As(err, &certificate) {
		if certificate.Kind == "unknown" {
			m.mu.Lock()
			m.pending[value.ID] = certificate.Fingerprint
			m.mu.Unlock()
			return nil, model.NewAppError("TUNNEL_CERT_UNKNOWN", "需要确认 aTrust 数据网关证书指纹", "tunnel_certificate", false).WithDetails(map[string]any{"address": certificate.Address, "fingerprint": certificate.Fingerprint})
		}
		return nil, model.NewAppError("TUNNEL_CERT_CHANGED", "aTrust 数据网关证书指纹已变化，连接已阻断", "tunnel_certificate", false)
	}
	return nil, model.NewAppError("ATRUST_TARGET_UNREACHABLE", "aTrust 目标 TCP 通道建立失败："+err.Error(), "atrust_dial", true)
}
