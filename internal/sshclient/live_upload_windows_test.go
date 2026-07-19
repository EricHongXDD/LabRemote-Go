//go:build windows

package sshclient_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/softether"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
	"github.com/google/uuid"
)

func TestLiveIsolatedFileAndDirectoryUpload(t *testing.T) {
	profileID := os.Getenv("LABREMOTE_LIVE_PROFILE_ID")
	if profileID == "" {
		t.Skip("未设置 LABREMOTE_LIVE_PROFILE_ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	configRoot, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	realRepository := profile.NewJSONRepository(filepath.Join(configRoot, "LabRemote", "profiles.json"))
	value, err := realRepository.Get(ctx, profileID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := snapshotWindowsNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secretStore := secrets.NewWindowsStore()
	password, err := secretStore.Get(ctx, model.VPNPasswordKey(profileID))
	if err != nil {
		t.Fatal(err)
	}
	port := value.VPN.ServerPort
	if port == 0 {
		port = 992
	}
	probeContext, probeCancel := context.WithTimeout(ctx, 15*time.Second)
	_, err = softether.Open(probeContext, softether.Config{
		Server: value.VPN.ServerAddress, Port: port, Hub: value.VPN.HubName,
		Username: value.VPN.Username, Password: password,
	})
	probeCancel()
	secrets.Zero(password)
	var certificateError *softether.CertificateError
	if !errors.As(err, &certificateError) || certificateError.Kind != "unknown" {
		t.Fatalf("无法取得服务器证书指纹: %v", err)
	}
	value.VPN.ServerCertificate = certificateError.Fingerprint
	value.VPN.ServerPort = port
	value.VPN.Type = model.VPNTypeSoftEther
	value.VPN.SplitTunnel = true
	temporaryRepository := profile.NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	if err := temporaryRepository.Upsert(ctx, value); err != nil {
		t.Fatal(err)
	}
	knownHosts := sshclient.NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
	transport := vpn.NewIsolatedManager(temporaryRepository, secretStore, events.Nop{})
	manager := sshclient.NewManager(temporaryRepository, secretStore, knownHosts, events.Nop{}, transport)
	defer transport.Shutdown(context.Background())
	defer manager.CloseAll(context.Background())
	if _, err := transport.Connect(ctx, profileID); err != nil {
		t.Fatal(err)
	}
	err = manager.Connect(ctx, profileID)
	var appError *model.AppError
	if !errors.As(err, &appError) || appError.Code != "SSH_HOST_KEY_UNKNOWN" {
		t.Fatalf("首次 SSH 连接应要求确认主机指纹: %v", err)
	}
	fingerprint, _ := appError.Details["fingerprint"].(string)
	if fingerprint == "" {
		t.Fatal("SSH 主机指纹为空")
	}
	if err := manager.AcceptHostKey(profileID, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := manager.Connect(ctx, profileID); err != nil {
		t.Fatal(err)
	}
	terminalID, err := manager.OpenTerminal(ctx, profileID, 100, 30, "ui")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.WriteTerminal(ctx, terminalID, []byte("cd /tmp\n")); err != nil {
		t.Fatal(err)
	}
	terminalDirectory := ""
	for attempt := 0; attempt < 30; attempt++ {
		terminalDirectory, err = manager.TerminalWorkingDirectory(ctx, terminalID)
		if err == nil && terminalDirectory == "/tmp" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if terminalDirectory != "/tmp" {
		t.Fatalf("当前终端目录 = %q，期望 /tmp，错误: %v", terminalDirectory, err)
	}
	if err := manager.CloseSession(ctx, terminalID); err != nil {
		t.Fatal(err)
	}

	localRoot := t.TempDir()
	standalone := filepath.Join(localRoot, "standalone.txt")
	if err := os.WriteFile(standalone, []byte("standalone-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataset := filepath.Join(localRoot, "dataset")
	if err := os.MkdirAll(filepath.Join(dataset, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataset, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataset, "nested", "value.txt"), []byte("folder-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	largeValue := bytes.Repeat([]byte("labremote-resume-block-"), 256*1024)
	largePath := filepath.Join(localRoot, "large-resume.bin")
	if err := os.WriteFile(largePath, largeValue, 0o600); err != nil {
		t.Fatal(err)
	}
	remoteName := ".labremote-upload-test-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	remoteDirectory := "~/" + remoteName
	cleanupDone := false
	defer func() {
		if cleanupDone {
			return
		}
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_, _ = manager.Exec(cleanupContext, model.ExecRequest{
			ProfileID: profileID, Command: fmt.Sprintf("rm -rf -- \"$HOME/%s\"", remoteName),
			Timeout: 15 * time.Second, MaxOutputBytes: 4096,
		})
	}()
	progress, err := manager.StartUpload(ctx, model.UploadRequest{
		ProfileID: profileID, LocalPaths: []string{standalone, dataset}, RemoteDirectory: remoteDirectory,
		Resume: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	progress = waitUpload(t, ctx, manager, progress.JobID)
	if progress.State != model.UploadCompleted {
		t.Fatalf("上传未完成: state=%s code=%s message=%s", progress.State, progress.ErrorCode, progress.ErrorMessage)
	}
	if progress.FilesCompleted != 2 || progress.DirectoriesCompleted != 3 {
		t.Fatalf("上传计数异常: files=%d directories=%d", progress.FilesCompleted, progress.DirectoriesCompleted)
	}
	verifyCommand := fmt.Sprintf(
		"set -eu; test -d \"$HOME/%[1]s/dataset/empty\"; test \"$(cat \"$HOME/%[1]s/standalone.txt\")\" = standalone-value; test \"$(cat \"$HOME/%[1]s/dataset/nested/value.txt\")\" = folder-value; printf labremote-upload-ok",
		remoteName,
	)
	result, err := manager.Exec(ctx, model.ExecRequest{ProfileID: profileID, Command: verifyCommand, Timeout: 20 * time.Second, MaxOutputBytes: 4096})
	if err != nil || result.ExitCode != 0 || result.Stdout != "labremote-upload-ok" {
		t.Fatalf("远端上传内容验证失败: exit=%d stdout=%q stderr=%q err=%v", result.ExitCode, result.Stdout, result.Stderr, err)
	}

	interruptedUpload, err := manager.StartUpload(ctx, model.UploadRequest{
		ProfileID: profileID, LocalPaths: []string{largePath}, RemoteDirectory: remoteDirectory, Resume: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	interruptedUpload = cancelUploadAfterProgress(t, ctx, manager, interruptedUpload.JobID, 256*1024)
	if interruptedUpload.State != model.UploadCancelled {
		t.Fatalf("大文件上传未按预期取消: state=%s code=%s", interruptedUpload.State, interruptedUpload.ErrorCode)
	}
	resumedUpload, err := manager.StartUpload(ctx, model.UploadRequest{
		ProfileID: profileID, LocalPaths: []string{largePath}, RemoteDirectory: remoteDirectory, Resume: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resumedUpload = waitUpload(t, ctx, manager, resumedUpload.JobID)
	if resumedUpload.State != model.UploadCompleted || resumedUpload.BytesResumed <= 0 {
		t.Fatalf("大文件上传未成功续传: state=%s resumed=%d code=%s message=%s", resumedUpload.State, resumedUpload.BytesResumed, resumedUpload.ErrorCode, resumedUpload.ErrorMessage)
	}

	remoteListing, err := manager.ListRemoteDirectory(ctx, profileID, remoteDirectory)
	if err != nil {
		t.Fatal(err)
	}
	remotePaths := make(map[string]string)
	for _, entry := range remoteListing.Entries {
		remotePaths[entry.Name] = entry.Path
	}
	for _, name := range []string{"standalone.txt", "dataset", "large-resume.bin"} {
		if remotePaths[name] == "" {
			t.Fatalf("远端目录浏览缺少 %s", name)
		}
	}

	downloadRoot := t.TempDir()
	downloadProgress, err := manager.StartDownload(ctx, model.DownloadRequest{
		ProfileID: profileID, RemotePaths: []string{remotePaths["standalone.txt"], remotePaths["dataset"]},
		LocalDirectory: downloadRoot, Resume: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	downloadProgress = waitDownload(t, ctx, manager, downloadProgress.JobID)
	if downloadProgress.State != model.DownloadCompleted || downloadProgress.FilesCompleted != 2 || downloadProgress.DirectoriesCompleted != 3 {
		t.Fatalf("递归下载异常: state=%s files=%d dirs=%d code=%s message=%s", downloadProgress.State, downloadProgress.FilesCompleted, downloadProgress.DirectoriesCompleted, downloadProgress.ErrorCode, downloadProgress.ErrorMessage)
	}
	downloadedStandalone, err := os.ReadFile(filepath.Join(downloadRoot, "standalone.txt"))
	if err != nil || string(downloadedStandalone) != "standalone-value" {
		t.Fatalf("下载的独立文件内容异常: value=%q err=%v", downloadedStandalone, err)
	}
	downloadedNested, err := os.ReadFile(filepath.Join(downloadRoot, "dataset", "nested", "value.txt"))
	if err != nil || string(downloadedNested) != "folder-value" {
		t.Fatalf("下载的嵌套文件内容异常: value=%q err=%v", downloadedNested, err)
	}
	if info, err := os.Stat(filepath.Join(downloadRoot, "dataset", "empty")); err != nil || !info.IsDir() {
		t.Fatalf("下载未保留空目录: info=%v err=%v", info, err)
	}

	largeDownloadRoot := t.TempDir()
	interruptedDownload, err := manager.StartDownload(ctx, model.DownloadRequest{
		ProfileID: profileID, RemotePaths: []string{remotePaths["large-resume.bin"]},
		LocalDirectory: largeDownloadRoot, Resume: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	interruptedDownload = cancelDownloadAfterProgress(t, ctx, manager, interruptedDownload.JobID, 256*1024)
	if interruptedDownload.State != model.DownloadCancelled {
		t.Fatalf("大文件下载未按预期取消: state=%s code=%s", interruptedDownload.State, interruptedDownload.ErrorCode)
	}
	resumedDownload, err := manager.StartDownload(ctx, model.DownloadRequest{
		ProfileID: profileID, RemotePaths: []string{remotePaths["large-resume.bin"]},
		LocalDirectory: largeDownloadRoot, Resume: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	resumedDownload = waitDownload(t, ctx, manager, resumedDownload.JobID)
	if resumedDownload.State != model.DownloadCompleted || resumedDownload.BytesResumed <= 0 {
		t.Fatalf("大文件下载未成功续传: state=%s resumed=%d code=%s message=%s", resumedDownload.State, resumedDownload.BytesResumed, resumedDownload.ErrorCode, resumedDownload.ErrorMessage)
	}
	downloadedLarge, err := os.ReadFile(filepath.Join(largeDownloadRoot, "large-resume.bin"))
	if err != nil || !bytes.Equal(downloadedLarge, largeValue) {
		t.Fatalf("大文件下载内容不一致: bytes=%d err=%v", len(downloadedLarge), err)
	}
	cleanupResult, err := manager.Exec(ctx, model.ExecRequest{
		ProfileID: profileID, Command: fmt.Sprintf("rm -rf -- \"$HOME/%s\"", remoteName),
		Timeout: 15 * time.Second, MaxOutputBytes: 4096,
	})
	if err != nil || cleanupResult.ExitCode != 0 {
		t.Fatalf("清理远端测试目录失败: exit=%d stderr=%q err=%v", cleanupResult.ExitCode, cleanupResult.Stderr, err)
	}
	cleanupDone = true
	middle, err := snapshotWindowsNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manager.CloseAll(context.Background())
	transport.Shutdown(context.Background())
	after, err := snapshotWindowsNetwork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, middle) || !bytes.Equal(before, after) {
		t.Fatal("上传前、上传后或断开后的 Windows VPN、路由与网卡状态不一致")
	}
}

func cancelUploadAfterProgress(t *testing.T, ctx context.Context, manager *sshclient.Manager, jobID string, threshold int64) model.UploadProgress {
	t.Helper()
	for {
		progress, err := manager.UploadStatus(jobID)
		if err != nil {
			t.Fatal(err)
		}
		if progress.BytesTransferred >= threshold && progress.State == model.UploadUploading {
			if err := manager.CancelUpload(jobID); err != nil {
				t.Fatal(err)
			}
			return waitUpload(t, ctx, manager, jobID)
		}
		if progress.State == model.UploadCompleted || progress.State == model.UploadFailed || progress.State == model.UploadCancelled {
			t.Fatalf("上传在达到取消阈值前结束: state=%s transferred=%d", progress.State, progress.BytesTransferred)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitUpload(t *testing.T, ctx context.Context, manager *sshclient.Manager, jobID string) model.UploadProgress {
	t.Helper()
	for {
		progress, err := manager.UploadStatus(jobID)
		if err != nil {
			t.Fatal(err)
		}
		switch progress.State {
		case model.UploadCompleted, model.UploadFailed, model.UploadCancelled:
			return progress
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func cancelDownloadAfterProgress(t *testing.T, ctx context.Context, manager *sshclient.Manager, jobID string, threshold int64) model.DownloadProgress {
	t.Helper()
	for {
		progress, err := manager.DownloadStatus(jobID)
		if err != nil {
			t.Fatal(err)
		}
		if progress.BytesTransferred >= threshold && progress.State == model.DownloadDownloading {
			if err := manager.CancelDownload(jobID); err != nil {
				t.Fatal(err)
			}
			return waitDownload(t, ctx, manager, jobID)
		}
		if progress.State == model.DownloadCompleted || progress.State == model.DownloadFailed || progress.State == model.DownloadCancelled {
			t.Fatalf("下载在达到取消阈值前结束: state=%s transferred=%d", progress.State, progress.BytesTransferred)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitDownload(t *testing.T, ctx context.Context, manager *sshclient.Manager, jobID string) model.DownloadProgress {
	t.Helper()
	for {
		progress, err := manager.DownloadStatus(jobID)
		if err != nil {
			t.Fatal(err)
		}
		switch progress.State {
		case model.DownloadCompleted, model.DownloadFailed, model.DownloadCancelled:
			return progress
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func snapshotWindowsNetwork(ctx context.Context) ([]byte, error) {
	script := `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$vpn = @(Get-VpnConnection -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object Name,ConnectionStatus,ServerAddress,TunnelType,SplitTunneling)
$routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore)
$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Sort-Object InterfaceIndex,Name | Select-Object InterfaceIndex,Name,Status,MacAddress,InterfaceDescription)
@{vpn=$vpn;routes=$routes;adapters=$adapters} | ConvertTo-Json -Compress -Depth 5`
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	return command.Output()
}
