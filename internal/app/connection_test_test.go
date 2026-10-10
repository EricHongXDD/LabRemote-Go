package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"golang.org/x/crypto/ssh"
)

func TestSSHConnectionTestVerifiesTerminalAfterAuthentication(t *testing.T) {
	for _, denyChannel := range []bool{false, true} {
		name := "通道允许"
		if denyChannel {
			name = "认证成功但通道拒绝"
		}
		t.Run(name, func(t *testing.T) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(key)
			if err != nil {
				t.Fatal(err)
			}
			config := &ssh.ServerConfig{NoClientAuth: true}
			config.AddHostKey(signer)
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					raw, err := listener.Accept()
					if err != nil {
						return
					}
					go func() {
						defer raw.Close()
						conn, channels, requests, err := ssh.NewServerConn(raw, config)
						if err != nil {
							return
						}
						defer conn.Close()
						go ssh.DiscardRequests(requests)
						for incoming := range channels {
							if denyChannel {
								_ = incoming.Reject(ssh.ResourceShortage, "测试服务器会话上限")
								continue
							}
							channel, requests, err := incoming.Accept()
							if err != nil {
								continue
							}
							go func() {
								defer channel.Close()
								for request := range requests {
									// 测试只允许验证 PTY，任何启动 Shell 或执行命令的请求均拒绝。
									_ = request.Reply(request.Type == "pty-req", nil)
								}
							}()
						}
					}()
				}
			}()
			service, _ := newProfileTestService(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := service.TestSSHConnection(ctx, TestConnectionRequest{Profile: model.ConnectionProfile{
				DisplayName: "终端测试", ConnectionMode: model.ConnectionModeDirectSSH,
				SSH: model.SSHConfig{ServerAddress: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Username: "test"},
			}, SSHPassword: "test"})
			if denyChannel {
				var appError *model.AppError
				if result.Success || !errors.As(err, &appError) || appError.Code != "SSH_SESSION_LIMIT" {
					t.Fatalf("认证后通道拒绝不应报测试成功: %+v %v", result, err)
				}
			} else if err != nil || !result.Success || !strings.Contains(result.Message, "会话通道和 PTY") {
				t.Fatalf("完整测试未通过: %+v %v", result, err)
			}
		})
	}
}
