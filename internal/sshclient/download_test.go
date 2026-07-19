package sshclient

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/pkg/sftp"
)

func TestBuildDownloadPlanPreservesFoldersAndEmptyDirectories(t *testing.T) {
	remoteRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(remoteRoot, "source", "dataset", "nested", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remoteRoot, "source", "dataset", "nested", "value.bin"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	withDownloadSFTPClient(t, remoteRoot, func(client *sftp.Client) {
		workingDirectory, err := client.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		selected := path.Join(workingDirectory, "source", "dataset")
		plan, err := buildDownloadPlan(context.Background(), client, []string{selected}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.files) != 1 || len(plan.directories) != 3 || plan.totalBytes != 5 {
			t.Fatalf("下载计划异常: files=%d dirs=%d bytes=%d", len(plan.files), len(plan.directories), plan.totalBytes)
		}
		foundEmpty := false
		for _, entry := range plan.directories {
			if entry.relativePath == path.Join("dataset", "nested", "empty") {
				foundEmpty = true
			}
		}
		if !foundEmpty {
			t.Fatal("下载计划未保留空目录")
		}
	})
}

func TestDownloadFileViaSFTPConflictCancellationAndResume(t *testing.T) {
	remoteRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(remoteRoot, "source"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remoteRoot, "source", "payload.txt"), []byte("remote-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	largeValue := bytes.Repeat([]byte("resume-data-"), 128*1024)
	if err := os.WriteFile(filepath.Join(remoteRoot, "source", "large.bin"), largeValue, 0o600); err != nil {
		t.Fatal(err)
	}
	withDownloadSFTPClient(t, remoteRoot, func(client *sftp.Client) {
		workingDirectory, err := client.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		remoteDirectory := path.Join(workingDirectory, "source")
		plan, err := buildDownloadPlan(context.Background(), client, []string{remoteDirectory}, nil)
		if err != nil {
			t.Fatal(err)
		}
		localRoot := t.TempDir()
		for _, directory := range plan.directories {
			destination, destinationErr := safeLocalDestination(localRoot, directory.relativePath)
			if destinationErr != nil {
				t.Fatal(destinationErr)
			}
			if err := os.MkdirAll(destination, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		var payload downloadEntry
		var large downloadEntry
		for _, entry := range plan.files {
			switch path.Base(entry.remotePath) {
			case "payload.txt":
				payload = entry
			case "large.bin":
				large = entry
			}
		}
		payloadDestination, _ := safeLocalDestination(localRoot, payload.relativePath)
		if _, err := downloadFile(context.Background(), client, payload, payloadDestination, false, true, nil, nil); err != nil {
			t.Fatal(err)
		}
		value, err := os.ReadFile(payloadDestination)
		if err != nil || string(value) != "remote-value" {
			t.Fatalf("下载内容异常: value=%q err=%v", value, err)
		}
		conflictPlan := downloadPlan{files: []downloadEntry{payload}, totalBytes: payload.size}
		err = preflightDownload(context.Background(), localRoot, conflictPlan, false)
		var appError *model.AppError
		if !errors.As(err, &appError) || appError.Code != "DOWNLOAD_CONFLICT" {
			t.Fatalf("期望 DOWNLOAD_CONFLICT，实际为 %v", err)
		}

		largeDestination, _ := safeLocalDestination(localRoot, large.relativePath)
		cancelContext, cancel := context.WithCancel(context.Background())
		_, err = downloadFile(cancelContext, client, large, largeDestination, false, true, func(int64) { cancel() }, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("期望取消错误，实际为 %v", err)
		}
		if _, err := os.Lstat(largeDestination); !os.IsNotExist(err) {
			t.Fatalf("取消后不应提交目标文件: %v", err)
		}
		localEntries, err := os.ReadDir(filepath.Dir(largeDestination))
		if err != nil {
			t.Fatal(err)
		}
		partialName := ""
		for _, entry := range localEntries {
			if strings.HasPrefix(entry.Name(), ".labremote-") && strings.HasSuffix(entry.Name(), ".part") {
				info, infoErr := entry.Info()
				if infoErr != nil {
					t.Fatal(infoErr)
				}
				if info.Size() <= 0 || info.Size() >= large.size {
					t.Fatalf("取消后的续传文件大小异常: %d", info.Size())
				}
				partialName = entry.Name()
			}
		}
		if partialName == "" {
			t.Fatal("取消后应保留下载续传文件")
		}
		var resumed int64
		if _, err := downloadFile(context.Background(), client, large, largeDestination, false, true, nil, func(value int64) {
			resumed = value
		}); err != nil {
			t.Fatal(err)
		}
		if resumed <= 0 {
			t.Fatalf("续传字节数 = %d，期望大于 0", resumed)
		}
		downloaded, err := os.ReadFile(largeDestination)
		if err != nil || !bytes.Equal(downloaded, largeValue) {
			t.Fatalf("续传后的内容不一致: bytes=%d err=%v", len(downloaded), err)
		}
		if _, err := os.Lstat(filepath.Join(filepath.Dir(largeDestination), partialName)); !os.IsNotExist(err) {
			t.Fatalf("续传完成后不应保留临时文件: %v", err)
		}
	})
}

func TestValidLocalComponentRejectsWindowsUnsafeNames(t *testing.T) {
	for _, name := range []string{"..", "CON", "aux.txt", "bad:name", "trailing.", "folder\\child"} {
		if validLocalComponent(name) {
			t.Fatalf("应拒绝 Windows 不安全名称 %q", name)
		}
	}
	for _, name := range []string{"report.txt", "数据集", ".config"} {
		if !validLocalComponent(name) {
			t.Fatalf("应接受安全名称 %q", name)
		}
	}
}

func withDownloadSFTPClient(t *testing.T, remoteRoot string, run func(*sftp.Client)) {
	t.Helper()
	clientConnection, serverConnection := net.Pipe()
	server, err := sftp.NewServer(serverConnection, sftp.WithServerWorkingDirectory(remoteRoot))
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve() }()
	client, err := sftp.NewClientPipe(clientConnection, clientConnection)
	if err != nil {
		t.Fatal(err)
	}
	run(client)
	_ = client.Close()
	_ = server.Close()
	<-serverDone
}
