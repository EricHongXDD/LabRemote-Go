package openvpn

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/routing"
	"github.com/buengese/go-openvpn/testserver"
	"golang.org/x/net/dns/dnsmessage"
)

func TestInProcessOpenVPNOTPAndTCP(t *testing.T) {
	for _, scenario := range []string{"connect", "directional_lzo", "none_lzo", "reject", "cancel", "untrusted_ca"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			peer, err := (&memoryBackend{}).Open(ctx, device.Params{MTU: 1500, Push: &routing.PushOptions{Ifconfig: &routing.Ifconfig{Local: net.ParseIP("10.8.0.5")}}})
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			remote := peer.(*memoryDevice)
			listener, err := remote.network.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.8.0.5"), Port: 22})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if scenario == "directional_lzo" {
				dnsListener, err := remote.network.ListenUDP(&net.UDPAddr{IP: net.ParseIP("10.8.0.5"), Port: 53})
				if err != nil {
					t.Fatal(err)
				}
				defer dnsListener.Close()
				go func() {
					buffer := make([]byte, 512)
					for {
						n, address, err := dnsListener.ReadFrom(buffer)
						if err != nil {
							return
						}
						var query dnsmessage.Message
						if query.Unpack(buffer[:n]) != nil {
							continue
						}
						query.Header.Response = true
						query.Header.RecursionAvailable = true
						query.Header.RCode = dnsmessage.RCodeNameError
						response, err := query.Pack()
						if err == nil {
							_, _ = dnsListener.WriteTo(response, address)
						}
					}
				}()
			}
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				buffer := make([]byte, 4)
				if _, err := io.ReadFull(conn, buffer); err == nil && string(buffer) == "ping" {
					_, _ = conn.Write([]byte("pong"))
				}
			}()
			authenticated := make(chan bool, 1)
			cipher := "AES-256-GCM"
			compression := scenario == "none_lzo" || scenario == "directional_lzo"
			if scenario == "none_lzo" {
				cipher = "none"
			}
			server, err := testserver.Start(testserver.Config{Device: peer, DNSAddress: "10.8.0.5", Cipher: cipher, Compression: compression, PushPeerID: scenario == "directional_lzo", Auth: func(user, password string) bool {
				valid := user == "student" && password == "SCRV1:c2VjcmV0:MDEyMzQ1"
				authenticated <- valid
				return valid && scenario != "reject"
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			prompted := make(chan bool, 1)
			var broker *OTPBroker
			broker = NewOTPBroker(events.Func(func(name string, payload any) {
				if name != "openvpn:otp" {
					return
				}
				challenge := payload.(Challenge)
				prompted <- true
				code := "012345"
				if scenario == "cancel" {
					code = ""
				}
				if err := broker.Submit(challenge.ID, code); err != nil {
					t.Error(err)
				}
			}))
			ca := string(server.CA)
			if scenario == "untrusted_ca" {
				text := testConfig(t)
				ca = strings.Split(strings.Split(text, "<ca>\n")[1], "</ca>")[0]
			}
			host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
			config := fmt.Sprintf("client\ndev tun\nproto tcp\nremote %s %s\nauth-user-pass\nremote-cert-tls server\ncipher none\nstatic-challenge \"Enter OTP Code:\" 1\n<ca>\n%s</ca>\n", host, port, ca)
			if compression {
				config += "comp-lzo\n"
			}
			session, err := Open(ctx, Config{Text: config, ProfileID: "test", Username: "student", Password: []byte("secret"), OTP: broker})
			if scenario != "connect" && scenario != "none_lzo" && scenario != "directional_lzo" {
				if err == nil {
					_ = session.Close()
					t.Fatal("认证失败、取消或证书不受信任时不应连接成功")
				}
				if scenario == "untrusted_ca" {
					select {
					case <-prompted:
						t.Fatal("证书验证之前不应索取验证码")
					default:
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if scenario == "directional_lzo" {
				session.probeHost = "vpn.test"
				if result := session.ProbeDNS(ctx); result != "reply_received" {
					t.Fatalf("DNS 回包未被识别: %s", result)
				}
			}
			if !<-authenticated {
				t.Fatal("静态挑战凭据编码不正确")
			}
			connection, err := session.DialContext(ctx, "tcp4", "10.8.0.5:22")
			if err != nil {
				t.Fatalf("用户态 TCP 拨号失败: %v", err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
			_, _ = connection.Write([]byte("ping"))
			response := make([]byte, 4)
			if _, err := io.ReadFull(connection, response); err != nil || string(response) != "pong" {
				t.Fatalf("进程内 OpenVPN 未完成双向 TCP 传输: %v", err)
			}
			_ = session.Close()
			select {
			case <-session.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("断开未回收协议会话")
			}
		})
	}
}

func TestOTPValidationExpiry(t *testing.T) {
	requests := make(chan Challenge, 1)
	broker := NewOTPBroker(events.Func(func(name string, payload any) {
		if name == "openvpn:otp" {
			requests <- payload.(Challenge)
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := broker.Request(ctx, Challenge{}); done <- err }()
	request := <-requests
	for _, invalid := range []string{"12345", "12345x"} {
		if err := broker.Submit(request.ID, invalid); err == nil {
			t.Fatal("错误验证码必须拒绝")
		}
	}
	cancel()
	<-done
	if err := broker.Submit(request.ID, "123456"); err == nil {
		t.Fatal("过期请求必须拒绝")
	}
}
