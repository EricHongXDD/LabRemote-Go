package policy

import (
	"errors"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

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
