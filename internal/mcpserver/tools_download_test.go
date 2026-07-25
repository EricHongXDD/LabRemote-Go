package mcpserver

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

func TestMCPFileDownloadLifecycleAndOwnership(t *testing.T) {
	core := &lifecycleCore{}
	controller := NewController(core, nil, nil)
	localDirectory := t.TempDir()

	_, started, err := controller.fileDownloadStart(context.Background(), nil, fileDownloadStartInput{
		ProfileID: " profile-1 ", RemotePaths: []string{" /srv/results ", "~/report.csv"}, LocalDirectory: localDirectory, Resume: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if started.JobID != "download-mcp-test" || core.downloadRequest.ProfileID != "profile-1" || core.downloadRequest.LocalDirectory != filepath.Clean(localDirectory) || !core.downloadRequest.Resume {
		t.Fatalf("下载请求映射异常: progress=%#v request=%#v", started, core.downloadRequest)
	}
	if len(core.downloadRequest.RemotePaths) != 2 || core.downloadRequest.RemotePaths[0] != "/srv/results" || core.downloadRequest.RemotePaths[1] != "~/report.csv" {
		t.Fatalf("远端路径未正确规范化: %#v", core.downloadRequest.RemotePaths)
	}

	_, status, err := controller.fileDownloadStatus(context.Background(), nil, downloadJobInput{JobID: started.JobID})
	if err != nil || status.JobID != started.JobID {
		t.Fatalf("查询 MCP 下载任务失败: %#v %v", status, err)
	}
	_, cancelled, err := controller.fileDownloadCancel(context.Background(), nil, downloadJobInput{JobID: started.JobID})
	if err != nil || !cancelled.OK || core.downloadCancelled != started.JobID {
		t.Fatalf("取消 MCP 下载任务失败: %#v %v", cancelled, err)
	}

	if _, _, err := controller.fileDownloadStatus(context.Background(), nil, downloadJobInput{JobID: "download-from-gui"}); appErrorCode(err) != "MCP_DOWNLOAD_NOT_FOUND" {
		t.Fatalf("MCP 不应访问非本控制器创建的任务: %v", err)
	}
}

func TestMCPFileDownloadInputValidation(t *testing.T) {
	controller := NewController(&lifecycleCore{}, nil, nil)
	tests := []struct {
		name  string
		input fileDownloadStartInput
	}{
		{name: "相对本地目录", input: fileDownloadStartInput{ProfileID: "p", RemotePaths: []string{"/tmp/a"}, LocalDirectory: "downloads"}},
		{name: "缺少远端路径", input: fileDownloadStartInput{ProfileID: "p", LocalDirectory: t.TempDir()}},
		{name: "缺少本地目录", input: fileDownloadStartInput{ProfileID: "p", RemotePaths: []string{"/tmp/a"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := controller.fileDownloadStart(context.Background(), nil, test.input); appErrorCode(err) != "MCP_DOWNLOAD_INVALID" {
				t.Fatalf("应拒绝无效下载参数: %v", err)
			}
		})
	}
}

func TestMCPFileDownloadAuditDoesNotRecordPaths(t *testing.T) {
	var log bytes.Buffer
	controller := NewController(&lifecycleCore{}, nil, NewAuditor(slog.New(slog.NewJSONHandler(&log, nil))))
	localDirectory := t.TempDir()
	remotePath := "/srv/private/secret-report.csv"
	if _, _, err := controller.fileDownloadStart(context.Background(), nil, fileDownloadStartInput{
		ProfileID: "profile-1", RemotePaths: []string{remotePath}, LocalDirectory: localDirectory,
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), localDirectory) || strings.Contains(log.String(), remotePath) || !strings.Contains(log.String(), "file_download_start") {
		t.Fatalf("下载审计日志内容异常: %s", log.String())
	}
}

func TestProfilesListReportsIndependentDownloadPermission(t *testing.T) {
	core := &lifecycleCore{profiles: []model.ConnectionProfile{{
		ID: "profile-1", DisplayName: "测试服务器",
		MCPPolicy: model.MCPPolicy{EnabledForProfile: true, AllowFileDownload: true},
	}}}
	controller := NewController(core, nil, nil)
	_, output, err := controller.profilesList(context.Background(), nil, emptyInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Profiles) != 1 || !output.Profiles[0].FileDownloadAllowed || output.Profiles[0].FileUploadAllowed {
		t.Fatalf("profiles_list 未返回独立下载权限: %#v", output)
	}
}

func TestExpiredOwnedDownloadReturnsMCPNotFoundAndDropsOwnership(t *testing.T) {
	core := &lifecycleCore{downloadStatusErr: model.NewAppError("DOWNLOAD_NOT_FOUND", "下载任务不存在", "file_download", false)}
	controller := NewController(core, nil, nil)
	controller.downloadJobs["download-expired"] = "profile-1"
	if _, _, err := controller.fileDownloadStatus(context.Background(), nil, downloadJobInput{JobID: "download-expired"}); appErrorCode(err) != "MCP_DOWNLOAD_NOT_FOUND" {
		t.Fatalf("过期下载任务错误未规范化: %v", err)
	}
	if _, err := controller.ownedDownload("download-expired"); appErrorCode(err) != "MCP_DOWNLOAD_NOT_FOUND" {
		t.Fatalf("过期任务所有权未清理: %v", err)
	}
}

func TestStoppingMCPClosesOwnedDownloads(t *testing.T) {
	core := &lifecycleCore{}
	controller := NewController(core, secrets.NewMemoryStore(), nil)
	ctx := context.Background()
	if _, err := controller.Start(ctx, freeLocalPort(t)); err != nil {
		t.Fatal(err)
	}
	controller.downloadMu.Lock()
	controller.downloadJobs["download-mcp-test"] = "profile-1"
	controller.downloadMu.Unlock()
	if err := controller.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if len(core.closedDownloads) != 1 || core.closedDownloads[0] != "download-mcp-test" {
		t.Fatalf("停止 MCP 未清理自有下载任务: %#v", core.closedDownloads)
	}
}
