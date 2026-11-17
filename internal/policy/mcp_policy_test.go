package policy

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

func TestBrowserAndDirectoryLeastPrivilege(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   model.MCPPolicy
		browser bool
		browse  bool
	}{
		{"未开放配置", model.MCPPolicy{AllowBrowser: true, AllowFileUpload: true}, false, false},
		{"仅查看", model.MCPPolicy{EnabledForProfile: true}, false, false},
		{"命令不开放网页", model.MCPPolicy{EnabledForProfile: true, AllowExec: true}, false, false},
		{"独立网页权限", model.MCPPolicy{EnabledForProfile: true, AllowBrowser: true}, true, false},
		{"上传允许浏览", model.MCPPolicy{EnabledForProfile: true, AllowFileUpload: true}, false, true},
		{"下载允许浏览", model.MCPPolicy{EnabledForProfile: true, AllowFileDownload: true}, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := model.ConnectionProfile{MCPPolicy: test.value}
			if (RequireBrowser(profile) == nil) != test.browser || (RequireFileBrowse(profile) == nil) != test.browse {
				t.Fatal("网页或目录权限未按最小授权检查")
			}
		})
	}
	var legacy model.ConnectionProfile
	if err := json.Unmarshal([]byte(`{"mcp_policy":{"enabled_for_profile":true,"allow_exec":true}}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.MCPPolicy.AllowBrowser || RequireBrowser(legacy) == nil {
		t.Fatal("旧配置不得自动授权网页访问")
	}
}

func TestRequireFileUploadUsesIndependentLeastPrivilege(t *testing.T) {
	tests := []struct {
		name    string
		policy  model.MCPPolicy
		wantErr string
	}{
		{name: "配置不可见", policy: model.MCPPolicy{AllowFileUpload: true}, wantErr: "MCP_PROFILE_FORBIDDEN"},
		{name: "未授权上传", policy: model.MCPPolicy{EnabledForProfile: true}, wantErr: "MCP_TOOL_FORBIDDEN"},
		{name: "已授权上传", policy: model.MCPPolicy{EnabledForProfile: true, AllowFileUpload: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := RequireFileUpload(model.ConnectionProfile{MCPPolicy: test.policy})
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("授权上传不应失败: %v", err)
				}
				return
			}
			var appErr *model.AppError
			if !errors.As(err, &appErr) || appErr.Code != test.wantErr {
				t.Fatalf("错误代码不符: got=%v want=%s", err, test.wantErr)
			}
		})
	}
}

func TestRequireFileDownloadUsesIndependentLeastPrivilege(t *testing.T) {
	tests := []struct {
		name    string
		policy  model.MCPPolicy
		wantErr string
	}{
		{name: "配置不可见", policy: model.MCPPolicy{AllowFileDownload: true}, wantErr: "MCP_PROFILE_FORBIDDEN"},
		{name: "未授权下载", policy: model.MCPPolicy{EnabledForProfile: true}, wantErr: "MCP_TOOL_FORBIDDEN"},
		{name: "上传权限不能代替下载权限", policy: model.MCPPolicy{EnabledForProfile: true, AllowFileUpload: true}, wantErr: "MCP_TOOL_FORBIDDEN"},
		{name: "已授权下载", policy: model.MCPPolicy{EnabledForProfile: true, AllowFileDownload: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := RequireFileDownload(model.ConnectionProfile{MCPPolicy: test.policy})
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("授权下载不应失败: %v", err)
				}
				return
			}
			var appErr *model.AppError
			if !errors.As(err, &appErr) || appErr.Code != test.wantErr {
				t.Fatalf("错误代码不符: got=%v want=%s", err, test.wantErr)
			}
		})
	}
}
