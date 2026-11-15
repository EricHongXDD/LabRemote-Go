//go:build windows

package app

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
)

// 显式启用后，只用指定配置的应用票据执行无副作用命令和下载指定诊断文件。
// 不启动本地 MCP 端口，不打开认证窗口，不关闭正在运行的桌面应用连接。
func TestLiveATrustMCPCommandsAndDownloadsPreserveSSH(t *testing.T) {
	if os.Getenv("LABREMOTE_ATRUST_MCP_INTEGRATION") != "1" {
		t.Skip("需要显式启用 aTrust MCP 集成测试")
	}
	profileID, remotePath := os.Getenv("LABREMOTE_ATRUST_PROFILE_ID"), os.Getenv("LABREMOTE_ATRUST_TEST_DOWNLOAD")
	if profileID == "" || remotePath == "" {
		t.Fatal("需要指定已授权配置及只读诊断文件")
	}
	root, err := os.UserConfigDir()
	if err != nil {
		t.Fatal("无法定位用户配置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	value, err := profile.NewJSONRepository(filepath.Join(root, "LabRemote", "profiles.json")).Get(ctx, profileID)
	if err != nil || value.EffectiveConnectionMode() != model.ConnectionModeATrustSSH {
		t.Fatal("配置不存在或未使用 aTrust")
	}
	repository := profile.NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	if err := repository.Upsert(ctx, value); err != nil {
		t.Fatal("无法创建隔离的测试配置")
	}
	var disconnected atomic.Int32
	sink := events.Func(func(name string, payload any) {
		if name == "ssh:status" {
			if status, ok := payload.(map[string]any); ok && status["connected"] == false {
				disconnected.Add(1)
			}
		}
	})
	store := secrets.NewPlatformStore()
	transport := vpn.NewIsolatedManager(repository, store, sink)
	transport.SetATrustAuthBroker(nil)
	known := sshclient.NewKnownHosts(filepath.Join(root, "LabRemote", "known_hosts"))
	ssh := sshclient.NewManager(repository, store, known, sink, transport)
	service := NewService(repository, store, transport, ssh, known)
	defer service.Shutdown(context.Background())
	command := func() {
		result, err := service.MCPExec(ctx, model.ExecRequest{ProfileID: profileID, Command: "printf 'labremote-mcp-stability\\n'", Timeout: 10 * time.Second, MaxOutputBytes: 128})
		if err != nil || result.ExitCode != 0 || result.Stdout != "labremote-mcp-stability\n" {
			t.Fatalf("MCP 诊断命令失败：%v", err)
		}
	}
	for round := 0; round < 3; round++ {
		if round > 0 {
			timer := time.NewTimer(16 * time.Second)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				t.Fatal("稳定性测试超时")
			}
		}
		command()
		job, err := service.MCPStartDownload(ctx, model.DownloadRequest{ProfileID: profileID, RemotePaths: []string{remotePath}, LocalDirectory: t.TempDir()})
		if err != nil {
			t.Fatalf("MCP 下载创建失败：%v", err)
		}
		command()
		ticker := time.NewTicker(50 * time.Millisecond)
		for {
			progress, err := service.MCPDownloadStatus(ctx, job.JobID)
			if err != nil || progress.State == model.DownloadFailed || progress.State == model.DownloadCancelled {
				ticker.Stop()
				t.Fatalf("MCP 下载失败：%v", err)
			}
			if progress.State == model.DownloadCompleted {
				ticker.Stop()
				break
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				ticker.Stop()
				t.Fatal("MCP 下载等待超时")
			}
		}
		if !ssh.IsConnected(profileID) || disconnected.Load() != 0 {
			t.Fatal("新建下载通道关闭了共享 SSH")
		}
	}
	t.Log("跨越 30 秒复核周期的三轮 MCP 命令与下载通过，零重新认证、零共享 SSH 断开")
}
