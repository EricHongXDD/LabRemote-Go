package app

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/openvpn"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
	"github.com/buengese/go-openvpn/testserver"
)

func TestConnectionTestsReuseOpenVPNAfterSSHFailure(t *testing.T) {
	var authCount, otpCount atomic.Int32
	server, err := testserver.Start(testserver.Config{Auth: func(_, _ string) bool { authCount.Add(1); return true }})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	service, _ := newProfileTestService(t)
	var broker *openvpn.OTPBroker
	broker = openvpn.NewOTPBroker(events.Func(func(name string, payload any) {
		if name == "openvpn:otp" {
			otpCount.Add(1)
			if err := broker.Submit(payload.(openvpn.Challenge).ID, "012345"); err != nil {
				t.Error(err)
			}
		}
	}))
	service.vpn.(*vpn.IsolatedManager).SetOTPBroker(broker)
	value := openVPNProfile(t)
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	value.VPN.OpenVPNConfig = fmt.Sprintf("client\ndev tun\nproto tcp\nremote %s %s\nauth-user-pass\nremote-cert-tls server\nstatic-challenge \"Enter OTP Code:\" 1\n<ca>\n%s</ca>\n", host, port, server.CA)
	request := TestConnectionRequest{TestSessionID: "draft-test", Profile: value, VPNPassword: "vpn-test", SSHPassword: "ssh-test"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := service.TestTunnelConnection(ctx, request); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"192.0.2.7", "192.0.2.8"} {
		request.Profile.SSH.ServerAddress = target
		request.Profile.SSH.Username = "ubuntu"
		probeContext, stop := context.WithTimeout(ctx, 80*time.Millisecond)
		_, err := service.TestSSHConnection(probeContext, request)
		stop()
		if err == nil {
			t.Fatal("模拟服务器未提供 SSH，不应测试成功")
		}
	}
	if _, err := service.TestTunnelConnection(ctx, request); err != nil {
		t.Fatal(err)
	}
	if otpCount.Load() != 1 || authCount.Load() != 1 {
		t.Fatalf("重复 SSH 测试触发了 VPN 重认证: OTP=%d auth=%d", otpCount.Load(), authCount.Load())
	}
	// VPN 凭据和配置改变时，必须重新认证，不能复用旧会话。
	request.VPNPassword = "changed-vpn-test"
	if _, err := service.TestTunnelConnection(ctx, request); err != nil {
		t.Fatal(err)
	}
	if otpCount.Load() != 2 {
		t.Fatal("修改 VPN 密码后仍复用旧认证")
	}
	request.Profile.VPN.OpenVPNConfig += "verb 4\n"
	if _, err := service.TestTunnelConnection(ctx, request); err != nil {
		t.Fatal(err)
	}
	if otpCount.Load() != 3 {
		t.Fatal("修改 VPN 配置后仍复用旧认证")
	}
	entry := service.testSessions[request.TestSessionID]
	service.CloseConnectionTestSession(request.TestSessionID)
	select {
	case <-entry.done:
	case <-time.After(time.Second):
		t.Fatal("关闭窗口后测试会话没有回收")
	}
	if _, err := entry.secrets.Get(ctx, "LabRemote/"+entry.id+"/vpn-password"); err == nil {
		t.Fatal("关闭会话未清理测试凭据")
	}
	if _, err := service.TestTunnelConnection(ctx, request); err != nil {
		t.Fatal(err)
	}
	if otpCount.Load() != 4 {
		t.Fatal("关闭测试会话后未重新认证")
	}
}

func TestCloseConnectionTestCancelsPendingOTP(t *testing.T) {
	server, err := testserver.Start(testserver.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	service, _ := newProfileTestService(t)
	requested := make(chan struct{}, 1)
	broker := openvpn.NewOTPBroker(events.Func(func(name string, _ any) {
		if name == "openvpn:otp" {
			requested <- struct{}{}
		}
	}))
	service.vpn.(*vpn.IsolatedManager).SetOTPBroker(broker)
	value := openVPNProfile(t)
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	value.VPN.OpenVPNConfig = strings.Replace(value.VPN.OpenVPNConfig, "remote openvpn1.shu.edu.cn 443", fmt.Sprintf("proto tcp\nremote %s %s", host, port), 1)
	a := strings.Index(value.VPN.OpenVPNConfig, "<ca>\n")
	value.VPN.OpenVPNConfig = value.VPN.OpenVPNConfig[:a] + "<ca>\n" + string(server.CA) + "</ca>\n"
	finished := make(chan error, 1)
	go func() {
		_, err := service.TestTunnelConnection(context.Background(), TestConnectionRequest{TestSessionID: "pending", Profile: value, VPNPassword: "test"})
		finished <- err
	}()
	select {
	case <-requested:
	case <-time.After(3 * time.Second):
		t.Fatal("未收到 OTP 请求")
	}
	service.CloseConnectionTestSession("pending")
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("取消后仍测试成功")
		}
	case <-time.After(time.Second):
		t.Fatal("关闭窗口没有取消正在等待的 OTP")
	}
}
