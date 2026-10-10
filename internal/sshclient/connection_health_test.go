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
	"sync"
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
							_ = request.Reply(true, nil)
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
