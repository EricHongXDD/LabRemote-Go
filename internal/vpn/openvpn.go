package vpn

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/openvpn"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

func (m *IsolatedManager) OTPBroker() *openvpn.OTPBroker          { return m.otp }
func (m *IsolatedManager) SetOTPBroker(broker *openvpn.OTPBroker) { m.otp = broker }

func (m *IsolatedManager) connectOpenVPN(ctx context.Context, value model.ConnectionProfile) (model.VPNStatus, error) {
	if err := value.Validate(); err != nil {
		return model.VPNStatus{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	r := m.runtime(value.ID)
	select {
	case r.connectGate <- struct{}{}:
		defer func() { <-r.connectGate }()
	case <-ctx.Done():
		return model.VPNStatus{}, ctx.Err()
	}
	r.mu.Lock()
	if r.openVPN != nil {
		select {
		case <-r.openVPN.Done():
			r.openVPN = nil
		default:
			r.mu.Unlock()
			status := m.states.Get(value.ID)
			if !status.RouteReady {
				return status, model.NewAppError("OPENVPN_RECONNECTING", "OpenVPN 正在重连，请稍后重试", "openvpn", true)
			}
			return status, nil
		}
	}
	generation := r.generation
	connectContext, cancelConnect := context.WithCancel(ctx)
	r.openVPNCancel = cancelConnect
	r.mu.Unlock()
	defer cancelConnect()
	m.states.Set(value.ID, model.VPNDialing, "")
	fail := func(message string) (model.VPNStatus, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.generation != generation {
			return m.states.Get(value.ID), model.NewAppError("OPENVPN_CONNECT_CANCELLED", "OpenVPN 连接已取消", "openvpn", true)
		}
		m.states.Update(value.ID, func(status *model.VPNStatus) {
			status.State = model.VPNFailed
			status.RouteReady = false
			status.ErrorCode = "OPENVPN_CONNECT_FAILED"
		})
		return m.states.Get(value.ID), model.NewAppError("OPENVPN_CONNECT_FAILED", message, "openvpn", true)
	}
	password, err := m.secrets.Get(connectContext, model.VPNPasswordKey(value.ID))
	if err != nil {
		return fail("未找到 OpenVPN 密码，请编辑连接并重新填写")
	}
	defer secrets.Zero(password)
	session, err := openvpn.Open(connectContext, openvpn.Config{
		Text:      value.VPN.OpenVPNConfig,
		ProfileID: value.ID, ProfileName: value.DisplayName, Username: value.VPN.Username,
		Password: password, OTP: m.otp,
	})
	if err != nil {
		return fail(err.Error())
	}
	r.mu.Lock()
	if r.generation != generation || connectContext.Err() != nil {
		r.mu.Unlock()
		_ = session.Close()
		return fail("OpenVPN 连接已取消")
	}
	r.openVPN = session
	r.openVPNCancel = nil
	m.states.Update(value.ID, func(status *model.VPNStatus) {
		status.State = model.VPNConnected
		status.ErrorCode = ""
		status.RouteReady = true
		status.IPAddress = session.IPAddress()
		status.Interface = "LabRemote OpenVPN 进程内隔离网络栈"
	})
	r.mu.Unlock()
	go func() {
		<-session.Done()
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.openVPN != session {
			return
		}
		r.openVPN = nil
		m.states.Update(value.ID, func(status *model.VPNStatus) {
			status.State = model.VPNFailed
			status.RouteReady = false
			status.ErrorCode = "OPENVPN_DISCONNECTED"
		})
	}()
	return m.states.Get(value.ID), nil
}

func (m *IsolatedManager) dialOpenVPN(ctx context.Context, value model.ConnectionProfile, network, address string) (net.Conn, error) {
	r := m.runtime(value.ID)
	r.mu.Lock()
	session := r.openVPN
	r.mu.Unlock()
	if session == nil || !m.states.Get(value.ID).RouteReady {
		return nil, model.NewAppError("OPENVPN_NOT_CONNECTED", "OpenVPN 尚未连接", "openvpn", true)
	}
	select {
	case <-session.Done():
		return nil, model.NewAppError("OPENVPN_NOT_CONNECTED", "OpenVPN 已断开", "openvpn", true)
	default:
	}
	probeContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	connection, err := session.DialContext(probeContext, network, address)
	if err != nil {
		dnsProbe := session.ProbeDNS(ctx)
		diagnostic := session.Diagnostics()
		diagnostic["dns_probe"] = dnsProbe
		diagnostic["profile_id"] = value.ID
		diagnostic["address"] = address
		m.states.events.Emit("vpn:diagnostic", diagnostic)
		message := "OpenVPN 已认证，但 SSH 目标未响应"
		if dnsProbe == "reply_received" {
			message = "OpenVPN 双向网络已验证，但 SSH 目标端口未响应，请检查目标地址、访问权限或服务器防火墙"
		}
		if diagnostic["decrypt_failures"].(uint64) > 0 {
			message = "OpenVPN 数据包认证或解码失败，SSH 连接未建立"
		}
		message += fmt.Sprintf("（发送 %d / 接收 %d / 校验失败 %d）", diagnostic["packets_sent"], diagnostic["packets_received"], diagnostic["decrypt_failures"])
		return nil, model.NewAppError("SSH_PORT_UNREACHABLE", message, "ssh_probe", true).WithDetails(diagnostic)
	}
	return connection, nil
}
