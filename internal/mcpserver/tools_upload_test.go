package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

func TestMCPFileUploadLifecycleAndOwnership(t *testing.T) {
	core := &lifecycleCore{}
	controller := NewController(core, nil, nil)
	localPath := filepath.Join(t.TempDir(), "payload.bin")

	_, started, err := controller.fileUploadStart(context.Background(), nil, fileUploadStartInput{
		ProfileID: " profile-1 ", LocalPaths: []string{localPath}, RemoteDirectory: " /srv/uploads ", Resume: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if started.JobID != "upload-mcp-test" || core.uploadRequest.ProfileID != "profile-1" || core.uploadRequest.RemoteDirectory != "/srv/uploads" || !core.uploadRequest.Resume {
		t.Fatalf("上传请求映射异常: progress=%#v request=%#v", started, core.uploadRequest)
	}
	if len(core.uploadRequest.LocalPaths) != 1 || core.uploadRequest.LocalPaths[0] != filepath.Clean(localPath) {
		t.Fatalf("本地路径未正确规范化: %#v", core.uploadRequest.LocalPaths)
	}

	_, status, err := controller.fileUploadStatus(context.Background(), nil, uploadJobInput{JobID: started.JobID})
	if err != nil || status.JobID != started.JobID {
		t.Fatalf("查询 MCP 上传任务失败: %#v %v", status, err)
	}
	_, cancelled, err := controller.fileUploadCancel(context.Background(), nil, uploadJobInput{JobID: started.JobID})
	if err != nil || !cancelled.OK || core.uploadCancelled != started.JobID {
		t.Fatalf("取消 MCP 上传任务失败: %#v %v", cancelled, err)
	}

	if _, _, err := controller.fileUploadStatus(context.Background(), nil, uploadJobInput{JobID: "upload-from-gui"}); appErrorCode(err) != "MCP_UPLOAD_NOT_FOUND" {
		t.Fatalf("MCP 不应访问非本控制器创建的任务: %v", err)
	}
}

func TestMCPFileUploadInputValidation(t *testing.T) {
	controller := NewController(&lifecycleCore{}, nil, nil)
	absPath := filepath.Join(t.TempDir(), "payload.bin")
	tests := []struct {
		name  string
		input fileUploadStartInput
	}{
		{name: "相对本地路径", input: fileUploadStartInput{ProfileID: "p", LocalPaths: []string{"relative.txt"}, RemoteDirectory: "/tmp"}},
		{name: "缺少远端目录", input: fileUploadStartInput{ProfileID: "p", LocalPaths: []string{absPath}}},
		{name: "缺少本地路径", input: fileUploadStartInput{ProfileID: "p", RemoteDirectory: "/tmp"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := controller.fileUploadStart(context.Background(), nil, test.input); appErrorCode(err) != "MCP_UPLOAD_INVALID" {
				t.Fatalf("应拒绝无效上传参数: %v", err)
			}
		})
	}
}

func TestMCPFileUploadAuditDoesNotRecordLocalPath(t *testing.T) {
	var log bytes.Buffer
	controller := NewController(&lifecycleCore{}, nil, NewAuditor(slog.New(slog.NewJSONHandler(&log, nil))))
	localPath := filepath.Join(t.TempDir(), "sensitive-name.txt")
	if _, _, err := controller.fileUploadStart(context.Background(), nil, fileUploadStartInput{
		ProfileID: "profile-1", LocalPaths: []string{localPath}, RemoteDirectory: "/tmp",
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), localPath) || !strings.Contains(log.String(), "file_upload_start") {
		t.Fatalf("上传审计日志内容异常: %s", log.String())
	}
}

func TestProfilesListReportsIndependentUploadPermission(t *testing.T) {
	core := &lifecycleCore{profiles: []model.ConnectionProfile{{
		ID: "profile-1", DisplayName: "测试服务器",
		MCPPolicy: model.MCPPolicy{EnabledForProfile: true, AllowFileUpload: true},
	}}}
	controller := NewController(core, nil, nil)
	_, output, err := controller.profilesList(context.Background(), nil, emptyInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Profiles) != 1 || !output.Profiles[0].FileUploadAllowed {
		t.Fatalf("profiles_list 未返回独立上传权限: %#v", output)
	}
}

func TestExpiredOwnedUploadReturnsMCPNotFoundAndDropsOwnership(t *testing.T) {
	core := &lifecycleCore{uploadStatusErr: model.NewAppError("UPLOAD_NOT_FOUND", "上传任务不存在", "file_upload", false)}
	controller := NewController(core, nil, nil)
	controller.uploadJobs["upload-expired"] = "profile-1"
	if _, _, err := controller.fileUploadStatus(context.Background(), nil, uploadJobInput{JobID: "upload-expired"}); appErrorCode(err) != "MCP_UPLOAD_NOT_FOUND" {
		t.Fatalf("过期上传任务错误未规范化: %v", err)
	}
	if _, err := controller.ownedUpload("upload-expired"); appErrorCode(err) != "MCP_UPLOAD_NOT_FOUND" {
		t.Fatalf("过期任务所有权未清理: %v", err)
	}
}

func TestStoppingMCPClosesOwnedUploads(t *testing.T) {
	core := &lifecycleCore{}
	controller := NewController(core, secrets.NewMemoryStore(), nil)
	ctx := context.Background()
	if _, err := controller.Start(ctx, freeLocalPort(t)); err != nil {
		t.Fatal(err)
	}
	controller.uploadMu.Lock()
	controller.uploadJobs["upload-mcp-test"] = "profile-1"
	controller.uploadMu.Unlock()
	if err := controller.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if len(core.closedUploads) != 1 || core.closedUploads[0] != "upload-mcp-test" {
		t.Fatalf("停止 MCP 未清理自有上传任务: %#v", core.closedUploads)
	}
}

func appErrorCode(err error) string {
	var appErr *model.AppError
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return ""
}
