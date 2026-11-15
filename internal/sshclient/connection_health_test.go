package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// healthTestManager 可分别模拟握手、通道创建、命令启动及执行期间的远端无响应。
func healthTestManager(t *testing.T, mode string) (*Manager, string, <-chan struct{}) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	if mode == "auth-rejected" {
		config.NoClientAuth = false
		config.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, errors.New("测试认证拒绝") }
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	var mu sync.Mutex
	connections := make([]net.Conn, 0)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, raw)
			mu.Unlock()
			go func() {
				defer raw.Close()
				if mode == "handshake-close" || mode == "handshake-banner-close" {
					if mode == "handshake-banner-close" {
						_, _ = io.WriteString(raw, "SSH-2.0-TestPeer\r\n")
					}
					// 保留读方向以稳定模拟对端 EOF，而非因未读数据随机触发 RST。
					_ = raw.(*net.TCPConn).CloseWrite()
					_, _ = io.Copy(io.Discard, raw)
					return
				}
				if mode == "handshake" {
					select {
					case entered <- struct{}{}:
					default:
					}
					_, _ = io.Copy(io.Discard, raw)
					return
				}
				conn, channels, requests, err := ssh.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if mode == "channel" {
						select {
						case entered <- struct{}{}:
						default:
						}
						continue
					}
					if mode == "reject" {
						_ = incoming.Reject(ssh.ResourceShortage, "会话已满")
						continue
					}
					channel, channelRequests, err := incoming.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer channel.Close()
						for request := range channelRequests {
							select {
							case entered <- struct{}{}:
							default:
							}
							if mode == "start" || mode == "sftp" {
								continue
							}
							if mode == "pty-denied" && request.Type == "pty-req" {
								_ = request.Reply(false, nil)
								continue
							}
							_ = request.Reply(true, nil)
							if (mode == "terminal-missing-exit" || mode == "terminal-normal-exit") && request.Type == "exec" {
								_, _ = io.WriteString(channel, "\x1eLABREMOTE_PID=123\x1f测试终端输出")
								if mode == "terminal-normal-exit" {
									_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								}
								return
							}
							if mode == "sftp-healthy" && request.Type == "subsystem" {
								go func() {
									// 大量错误输出不能堵住 SFTP 的正常响应。
									_, _ = channel.Stderr().Write(make([]byte, 3*1024*1024))
								}()
								server, err := sftp.NewServer(channel)
								if err == nil {
									go func() { _ = server.Serve(); _ = server.Close() }()
								}
							}
						}
					}()
				}
			}()
		}
	}()
	root := t.TempDir()
	repository := profile.NewJSONRepository(filepath.Join(root, "profiles.json"))
	address := listener.Addr().(*net.TCPAddr)
	id := "health-test"
	value := model.ConnectionProfile{ID: id, DisplayName: "连接健康测试", ConnectionMode: model.ConnectionModeDirectSSH,
		SSH: model.SSHConfig{ServerAddress: "127.0.0.1", Port: uint16(address.Port), Username: "test"}}
	if err := repository.Upsert(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	store := secrets.NewMemoryStore()
	_ = store.Put(context.Background(), model.SSHPasswordKey(id), []byte("test"))
	known := NewKnownHosts(filepath.Join(root, "known_hosts"))
	if err := known.Store(HostKeyRecord{ProfileID: id, Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(address.Port)),
		KeyType: signer.PublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(signer.PublicKey())}); err != nil {
		t.Fatal(err)
	}
	transport := vpn.NewIsolatedManager(repository, store, events.Nop{})
	manager := NewManager(repository, store, known, events.Nop{}, transport)
	t.Cleanup(func() {
		_ = listener.Close()
		manager.CloseAll(context.Background())
		transport.Shutdown(context.Background())
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range connections {
			_ = conn.Close()
		}
	})
	return manager, id, entered
}

func TestExecTimeoutCoversHandshakeChannelAndStart(t *testing.T) {
	for _, mode := range []string{"handshake", "channel", "start", "wait"} {
		t.Run(mode, func(t *testing.T) {
			manager, id, entered := healthTestManager(t, mode)
			if mode != "handshake" {
				if err := manager.Connect(context.Background(), id); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				_, err := manager.Exec(context.Background(), model.ExecRequest{ProfileID: id, Command: "test", Timeout: 250 * time.Millisecond})
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("未进入模拟阻塞点")
			}
			status := make(chan bool, 1)
			go func() { status <- manager.IsConnected(id) }()
			select {
			case <-status:
			case <-time.After(100 * time.Millisecond):
				t.Fatal("网络等待阻塞状态查询")
			}
			select {
			case err := <-done:
				var appError *model.AppError
				if !errors.As(err, &appError) || appError.Code != "SSH_COMMAND_TIMEOUT" {
					t.Fatalf("超时返回不正确: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("SSH 操作没有按时退出")
			}
			_, _, commands := manager.Counts(id)
			if commands != 0 {
				t.Fatalf("超时后仍占用命令计数: %d", commands)
			}
			if mode == "wait" && !manager.IsConnected(id) {
				t.Fatal("命令执行超时不应关闭其他终端使用的健康连接")
			}
		})
	}
}

func TestConnectWaitCanCancelWithoutBlockingStatus(t *testing.T) {
	manager, id, entered := healthTestManager(t, "handshake")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- manager.Connect(ctx, id) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("握手未开始")
	}
	waitContext, cancelWait := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelWait()
	if err := manager.Connect(waitContext, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("等待连接未遵守取消: %v", err)
	}
	manager.invalidateClient(id)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("取消未释放握手")
	}
	if manager.IsConnected(id) {
		t.Fatal("取消后不应重新登记连接")
	}
}

func TestRejectedChannelDoesNotInvalidateHealthyClient(t *testing.T) {
	manager, id, _ := healthTestManager(t, "reject")
	_, err := manager.Exec(context.Background(), model.ExecRequest{ProfileID: id, Command: "test", Timeout: time.Second})
	if err == nil {
		t.Fatal("应报告通道拒绝")
	}
	if !manager.IsConnected(id) {
		t.Fatal("通道数量限制不应关闭健康连接和其他终端")
	}
}

func TestSFTPSetupCancellationPreservesPrimarySSH(t *testing.T) {
	for _, mode := range []string{"sftp", "sftp-version"} {
		t.Run(mode, func(t *testing.T) {
			manager, id, _ := healthTestManager(t, mode)
			if err := manager.Connect(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, _, err := manager.newSFTPClient(ctx, id); done <- err }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("无响应的 SFTP 不应初始化成功")
				}
			case <-time.After(time.Second):
				t.Fatal("取消未释放 SFTP 初始化")
			}
			if !manager.IsConnected(id) {
				t.Fatal("取消传输关闭了主 SSH 连接")
			}
		})
	}
}

func TestDedicatedSFTPDownloadCompletesAndPreservesPrimarySSH(t *testing.T) {
	manager, id, _ := healthTestManager(t, "sftp-healthy")
	if err := manager.Connect(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(source, []byte("独立连接文件下载"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	remoteSource := filepath.ToSlash(source)
	if filepath.VolumeName(source) != "" {
		remoteSource = "/" + remoteSource
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	initial, err := manager.StartDownload(ctx, model.DownloadRequest{ProfileID: id, RemotePaths: []string{remoteSource}, LocalDirectory: destination, Resume: true})
	if err != nil {
		t.Fatal(err)
	}
	for {
		progress, err := manager.DownloadStatus(initial.JobID)
		if err != nil {
			t.Fatal(err)
		}
		if progress.State == model.DownloadCompleted {
			break
		}
		if !downloadStateActive(progress.State) {
			t.Fatalf("下载失败: %+v", progress)
		}
		select {
		case <-ctx.Done():
			t.Fatal("下载没有完成")
		case <-time.After(10 * time.Millisecond):
		}
	}
	data, err := os.ReadFile(filepath.Join(destination, "payload.txt"))
	if err != nil || string(data) != "独立连接文件下载" {
		t.Fatalf("下载结果错误: %q %v", data, err)
	}
	if !manager.IsConnected(id) {
		t.Fatal("下载清理关闭了主 SSH 连接")
	}
	if err := manager.probeClient(ctx, id, manager.runtime(id).client); err != nil {
		t.Fatalf("下载后主连接不可用: %v", err)
	}
}

func TestTransferWatchdogCancellationAndIdle(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		activity := &transferActivity{}
		activity.last.Store(time.Now().UnixNano())
		closed := make(chan struct{})
		go watchTransfer(ctx, activity, 80*time.Millisecond, func() { close(closed) })
		if cancelled {
			cancel()
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("停滞或取消未关闭传输")
		}
		cancel()
	}
}

func TestStaleClientCleanupPreservesReplacement(t *testing.T) {
	manager, id, _ := healthTestManager(t, "wait")
	replacementManager, replacementID, _ := healthTestManager(t, "wait")
	if err := manager.Connect(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := replacementManager.Connect(context.Background(), replacementID); err != nil {
		t.Fatal(err)
	}
	runtime := manager.runtime(id)
	replacementRuntime := replacementManager.runtime(replacementID)
	replacementRuntime.mu.Lock()
	replacement := replacementRuntime.client
	replacementRuntime.mu.Unlock()
	runtime.mu.Lock()
	old := runtime.client
	runtime.client = replacement
	runtime.mu.Unlock()
	manager.invalidateClientIf(id, old)
	if !manager.IsConnected(id) {
		t.Fatal("旧请求清理关闭了新连接")
	}
	if err := manager.probeClient(context.Background(), id, replacement); err != nil {
		t.Fatalf("新连接不可用: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = old.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("旧连接没有释放")
	}
}

func TestTerminalProbeRequiresSessionAndPTY(t *testing.T) {
	for _, test := range []struct{ mode, expected string }{
		{"wait", ""}, {"reject", "SSH_SESSION_LIMIT"}, {"pty-denied", "SSH_SESSION_FAILED"}, {"channel", "SSH_SESSION_TIMEOUT"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			manager, id, _ := healthTestManager(t, test.mode)
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := manager.ProbeTerminal(ctx, id)
			if test.expected == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var appError *model.AppError
				if !errors.As(err, &appError) || appError.Code != test.expected || appError.Details["reason"] == "" {
					t.Fatalf("未保留失败阶段与原因: %v", err)
				}
			}
			ui, mcp, commands := manager.Counts(id)
			if ui+mcp+commands != 0 {
				t.Fatal("连接测试不应保留终端或命令")
			}
		})
	}
}

func TestHandshakeTimeoutDoesNotReportCredentialFailure(t *testing.T) {
	manager, id, _ := healthTestManager(t, "handshake")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := manager.Connect(ctx, id)
	var appError *model.AppError
	if !errors.As(err, &appError) || appError.Code != "SSH_HANDSHAKE_TIMEOUT" || !appError.Retryable || appError.Details["reason"] == "" {
		t.Fatalf("无响应的握手不应归因于密码错误: %v", err)
	}
}

func TestHandshakeCloseDoesNotReportCredentialFailure(t *testing.T) {
	for _, mode := range []string{"handshake-close", "handshake-banner-close"} {
		t.Run(mode, func(t *testing.T) {
			manager, id, _ := healthTestManager(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := manager.Connect(ctx, id)
			var appError *model.AppError
			if !errors.As(err, &appError) || appError.Code != "SSH_PEER_CLOSED" || !appError.Retryable || appError.Details["reason"] == "" {
				t.Fatalf("对端关闭连接不应误报为身份认证失败: %v", err)
			}
		})
	}
}

func TestRejectedPasswordStillReportsAuthenticationFailure(t *testing.T) {
	manager, id, _ := healthTestManager(t, "auth-rejected")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := manager.Connect(ctx, id)
	var appError *model.AppError
	if !errors.As(err, &appError) || appError.Code != "SSH_AUTH_FAILED" {
		t.Fatalf("真正的口令认证失败不能误报为网络断开: %v", err)
	}
}

// failedProbeConn 模拟客户端尚未收到关闭通知，但保活已经失败的缓存连接。
type failedProbeConn struct {
	ssh.Conn
	probes atomic.Int32
}

// delayedProbeConn 模拟网络短暂延迟，保活最终仍能获得正常回复。
type delayedProbeConn struct {
	ssh.Conn
	allow   chan struct{}
	entered chan struct{}
	probes  atomic.Int32
}

func (c *delayedProbeConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	if c.probes.Add(1) == 1 {
		close(c.entered)
	}
	<-c.allow
	return c.Conn.SendRequest(name, wantReply, payload)
}

func TestCancelledMCPProbePreservesSharedSSHAndCoalescesWaiters(t *testing.T) {
	manager, id, _ := healthTestManager(t, "wait")
	if err := manager.Connect(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	runtime := manager.runtime(id)
	runtime.mu.Lock()
	delayed := &delayedProbeConn{Conn: runtime.client.Conn, allow: make(chan struct{}), entered: make(chan struct{})}
	shared := &ssh.Client{Conn: delayed}
	runtime.client = shared
	runtime.mu.Unlock()
	defer func() {
		select {
		case <-delayed.allow:
		default:
			close(delayed.allow)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := manager.Connect(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("短请求取消结果错误: %v", err)
	}
	if !manager.IsConnected(id) {
		t.Fatal("取消单个 MCP 请求关闭了共享 SSH")
	}
	resumed := make(chan error, 1)
	go func() { resumed <- manager.Connect(context.Background(), id) }()
	close(delayed.allow)
	select {
	case err := <-resumed:
		if err != nil {
			t.Fatalf("后续请求未复用健康连接: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("保活恢复后仍无法连接")
	}
	runtime.mu.Lock()
	current := runtime.client
	runtime.mu.Unlock()
	if current != shared || delayed.probes.Load() > 2 {
		t.Fatal("取消等待导致重复连接或重复保活")
	}
}

func (c *failedProbeConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	c.probes.Add(1)
	return false, nil, io.EOF
}

func TestConnectReplacesUnresponsiveCachedClient(t *testing.T) {
	manager, id, _ := healthTestManager(t, "wait")
	if err := manager.Connect(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	runtime := manager.runtime(id)
	runtime.mu.Lock()
	old := runtime.client
	failed := &failedProbeConn{Conn: old.Conn}
	stale := &ssh.Client{Conn: failed}
	runtime.client = stale
	runtime.mu.Unlock()
	if err := manager.Connect(context.Background(), id); err != nil {
		t.Fatalf("重连未恢复失效缓存: %v", err)
	}
	runtime.mu.Lock()
	replacement := runtime.client
	runtime.mu.Unlock()
	if failed.probes.Load() != 1 || replacement == stale || replacement == nil {
		t.Fatal("重连没有探测并替换旧连接")
	}
	if err := manager.ProbeTerminal(context.Background(), id); err != nil {
		t.Fatalf("新连接无法创建真实终端通道: %v", err)
	}
	// 旧会话延迟返回失败时不得关闭刚建立的新连接。
	manager.checkClientAfterSessionFailure(id, stale)
	if err := manager.probeClient(context.Background(), id, replacement); err != nil || !manager.IsConnected(id) {
		t.Fatalf("旧会话清理破坏了新连接: %v", err)
	}
}

func TestTerminalMissingExitStatusPreservesHealthyTransport(t *testing.T) {
	for _, mode := range []string{"terminal-missing-exit", "terminal-normal-exit"} {
		t.Run(mode, func(t *testing.T) {
			manager, id, _ := healthTestManager(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for attempt := 0; attempt < 2; attempt++ {
				sessionID, err := manager.OpenTerminal(ctx, id, 80, 24, "ui")
				if err != nil {
					t.Fatalf("第 %d 次打开终端失败: %v", attempt+1, err)
				}
				session, err := manager.getSession(sessionID)
				if err != nil {
					t.Fatal(err)
				}
				for {
					_, _, open, _, reason := session.buffer.Read(ctx, 0, 4096, 10*time.Millisecond)
					if !open {
						if mode == "terminal-missing-exit" && (!strings.Contains(reason, "服务器未返回退出状态") || strings.Contains(reason, "wait:")) {
							t.Fatalf("缺少退出状态的提示不正确: %s", reason)
						}
						if mode == "terminal-normal-exit" && reason != "" {
							t.Fatalf("正常退出不应报告网络故障: %s", reason)
						}
						break
					}
					select {
					case <-ctx.Done():
						t.Fatal("终端关闭未被检测")
					case <-time.After(time.Millisecond):
					}
				}
				manager.checkClientAfterSessionFailure(id, session.client)
				runtime := manager.runtime(id)
				runtime.mu.Lock()
				current := runtime.client
				runtime.mu.Unlock()
				if current != session.client {
					t.Fatal("终端退出不应清理仍可响应的共享连接")
				}
			}
		})
	}
}
