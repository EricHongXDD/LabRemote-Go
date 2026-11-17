package app

import (
	"context"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

func TestMCPBrowserPolicyRevocationAndUIIsolation(t *testing.T) {
	ctx := context.Background()
	service, _ := newProfileTestService(t)
	value, err := service.SaveProfile(ctx, SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "MCP 网页测试", ConnectionMode: model.ConnectionModeDirectSSH,
			SSH:       model.SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "test"},
			MCPPolicy: model.MCPPolicy{EnabledForProfile: true, AllowBrowser: true, AllowDisconnect: true},
		}, SSHPassword: "test-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	uiURL, err := service.browser.Open(ctx, value.ID, "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	access, err := service.browser.OpenOwned(ctx, value.ID, "http://127.0.0.1:8080", "mcp")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := service.MCPListBrowser(ctx, value.ID)
	if err != nil || len(listed) != 1 || listed[0] != access {
		t.Fatalf("查询 MCP 自有链接失败: %#v %v", listed, err)
	}
	uiID := service.browser.ListOwned(value.ID, "ui")[0].AccessID
	if err := service.MCPCloseBrowser(ctx, value.ID, uiID); !IsAppError(err, "MCP_BROWSER_NOT_FOUND") {
		t.Fatalf("MCP 不应关闭桌面链接: %v", err)
	}
	if err := service.MCPDisconnect(ctx, value.ID, true); !IsAppError(err, "MCP_TOOL_FORBIDDEN") {
		t.Fatalf("存在桌面网页代理时不得强制断开: %v", err)
	}
	value.MCPPolicy.AllowBrowser = false
	if _, err := service.SaveProfile(ctx, SaveProfileRequest{Profile: value}); err != nil {
		t.Fatal(err)
	}
	if len(service.browser.ListOwned(value.ID, "mcp")) != 0 || service.browser.ListOwned(value.ID, "ui")[0].AccessURL != uiURL {
		t.Fatal("撤销权限应清理 MCP 链接并保留桌面代理")
	}
	if _, err := service.MCPOpenBrowser(ctx, value.ID, "http://127.0.0.1:8080"); !IsAppError(err, "MCP_TOOL_FORBIDDEN") {
		t.Fatalf("未授权时不得连接或创建代理: %v", err)
	}
	if _, err := service.MCPListBrowser(ctx, value.ID); !IsAppError(err, "MCP_TOOL_FORBIDDEN") {
		t.Fatalf("未授权时不得查询链接: %v", err)
	}
	if err := service.MCPCloseBrowser(ctx, value.ID, access.AccessID); !IsAppError(err, "MCP_TOOL_FORBIDDEN") {
		t.Fatalf("关闭操作也应复查权限: %v", err)
	}
	if _, err := service.MCPListRemoteDirectory(ctx, value.ID, "/"); !IsAppError(err, "MCP_TOOL_FORBIDDEN") {
		t.Fatalf("未授权目录浏览应在连接前拒绝: %v", err)
	}
	if _, err := service.MCPSessionWorkingDirectory(ctx, "ui-session-test"); !IsAppError(err, "MCP_SESSION_NOT_FOUND") {
		t.Fatalf("不得读取桌面终端目录: %v", err)
	}
}
