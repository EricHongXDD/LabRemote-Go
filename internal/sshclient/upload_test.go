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

func TestBuildUploadPlanIncludesFilesFoldersAndEmptyDirectories(t *testing.T) {
	root := t.TempDir()
	standalone := filepath.Join(root, "standalone.txt")
	if err := os.WriteFile(standalone, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, "dataset")
	if err := os.MkdirAll(filepath.Join(folder, "nested", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "nested", "value.bin"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := buildUploadPlan(context.Background(), []string{standalone, folder}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.files) != 2 {
		t.Fatalf("文件数 = %d，期望 2", len(plan.files))
	}
	if len(plan.directories) != 3 {
		t.Fatalf("目录数 = %d，期望 3", len(plan.directories))
	}
	if plan.totalBytes != 8 {
		t.Fatalf("总字节数 = %d，期望 8", plan.totalBytes)
	}
	want := path.Join("dataset", "nested", "value.bin")
	found := false
	for _, entry := range plan.files {
		if entry.relativePath == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("计划中缺少 %s", want)
	}
}

func TestBuildUploadPlanRejectsDuplicateRemoteDestination(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first", "same.txt")
	second := filepath.Join(root, "second", "same.txt")
	if err := os.MkdirAll(filepath.Dir(first), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(second), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildUploadPlan(context.Background(), []string{first, second}, nil)
	var appError *model.AppError
	if !errors.As(err, &appError) || appError.Code != "UPLOAD_DESTINATION_CONFLICT" {
		t.Fatalf("期望 UPLOAD_DESTINATION_CONFLICT，实际为 %v", err)
	}
}

func TestCopyUploadHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var destination bytes.Buffer
	written, err := copyUpload(ctx, &destination, bytes.NewReader([]byte("data")), nil)
	if !errors.Is(err, context.Canceled) || written != 0 || destination.Len() != 0 {
		t.Fatalf("取消结果不符合预期：written=%d len=%d err=%v", written, destination.Len(), err)
	}
}

func TestUploadFileViaSFTPAndConflictProtection(t *testing.T) {
	remoteRoot := t.TempDir()
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
	defer func() {
		_ = client.Close()
		_ = server.Close()
		<-serverDone
	}()

	localRoot := t.TempDir()
	localPath := filepath.Join(localRoot, "payload.txt")
	if err := os.WriteFile(localPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(localPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := prepareRemoteRoot(context.Background(), client, "uploads")
	if err != nil {
		t.Fatal(err)
	}
	entry := uploadEntry{
		localPath: localPath, relativePath: "payload.txt", displayName: "payload.txt",
		size: info.Size(), modTime: info.ModTime(),
	}
	destination := path.Join(root, entry.relativePath)
	if _, err := uploadFile(context.Background(), client, entry, destination, false, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	plan := uploadPlan{files: []uploadEntry{entry}, totalBytes: entry.size}
	err = preflightUpload(context.Background(), client, root, plan, false)
	var appError *model.AppError
	if !errors.As(err, &appError) || appError.Code != "UPLOAD_CONFLICT" {
		t.Fatalf("期望覆盖保护冲突，实际为 %v", err)
	}

	if err := os.WriteFile(localPath, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(localPath)
	if err != nil {
		t.Fatal(err)
	}
	entry.size = info.Size()
	entry.modTime = info.ModTime()
	if _, err := uploadFile(context.Background(), client, entry, destination, true, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(filepath.Join(remoteRoot, "uploads", "payload.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "second" {
		t.Fatalf("远端内容 = %q，期望 second", value)
	}

	cancelPath := filepath.Join(localRoot, "cancel.bin")
	if err := os.WriteFile(cancelPath, bytes.Repeat([]byte("x"), 1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	cancelInfo, err := os.Stat(cancelPath)
	if err != nil {
		t.Fatal(err)
	}
	cancelEntry := uploadEntry{
		localPath: cancelPath, relativePath: "cancel.bin", displayName: "cancel.bin",
		size: cancelInfo.Size(), modTime: cancelInfo.ModTime(),
	}
	cancelContext, cancel := context.WithCancel(context.Background())
	_, err = uploadFile(cancelContext, client, cancelEntry, path.Join(root, cancelEntry.relativePath), false, true, func(int64) { cancel() }, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("期望取消错误，实际为 %v", err)
	}
	if _, err := client.Lstat(path.Join(root, cancelEntry.relativePath)); !os.IsNotExist(err) {
		t.Fatalf("取消后不应留下目标文件: %v", err)
	}
	entries, err := client.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	partialName := ""
	for _, remoteEntry := range entries {
		if strings.HasPrefix(remoteEntry.Name(), ".labremote-") && strings.HasSuffix(remoteEntry.Name(), ".part") {
			partialName = remoteEntry.Name()
			if remoteEntry.Size() <= 0 || remoteEntry.Size() >= cancelEntry.size {
				t.Fatalf("取消后的续传文件大小异常: %d", remoteEntry.Size())
			}
		}
	}
	if partialName == "" {
		t.Fatal("取消后应保留可安全续传的临时文件")
	}
	var resumed int64
	if _, err := uploadFile(context.Background(), client, cancelEntry, path.Join(root, cancelEntry.relativePath), false, true, nil, func(value int64) {
		resumed = value
	}); err != nil {
		t.Fatal(err)
	}
	if resumed <= 0 {
		t.Fatalf("续传字节数 = %d，期望大于 0", resumed)
	}
	if info, err := client.Stat(path.Join(root, cancelEntry.relativePath)); err != nil || info.Size() != cancelEntry.size {
		t.Fatalf("续传完成后的目标文件异常: info=%v err=%v", info, err)
	}
	if _, err := client.Lstat(path.Join(root, partialName)); !os.IsNotExist(err) {
		t.Fatalf("续传完成后不应保留临时文件: %v", err)
	}
}
