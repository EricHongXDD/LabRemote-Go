package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNewToolsThroughMCPProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var audit bytes.Buffer
	core := &lifecycleCore{profiles: []model.ConnectionProfile{{ID: "p", MCPPolicy: model.MCPPolicy{EnabledForProfile: true, AllowBrowser: true}}}}
	controller := NewController(core, nil, NewAuditor(slog.New(slog.NewJSONHandler(&audit, nil))))
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	addTools(server, controller)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 21 {
		t.Fatalf("工具注册异常: %#v %v", listed, err)
	}
	guide := buildAIGuideMarkdown(Status{}, "{}", core.profiles, time.Now())
	for _, tool := range listed.Tools {
		if !strings.Contains(guide, "`"+tool.Name+"`") {
			t.Fatalf("自动导出的手册缺少工具 %s", tool.Name)
		}
	}
	for _, call := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"browser_open", map[string]any{"profile_id": " p ", "target_url": "http://127.0.0.1:8080/path?token=private"}, "http://127.0.0.1:12345/__labremote_browser__/secret"},
		{"browser_list", map[string]any{"profile_id": "p"}, `"accesses":[]`},
		{"browser_close", map[string]any{"profile_id": "p", "access_id": "test-access"}, `"ok":true`},
		{"file_list_directory", map[string]any{"profile_id": "p", "directory": "/srv/中文"}, "/srv/中文"},
		{"ssh_session_directory", map[string]any{"session_id": "mcp-session-test"}, "/home/test"},
		{"profiles_list", map[string]any{}, `"browser_allowed":true`},
	} {
		response, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: call.name, Arguments: call.args})
		if err != nil || response.IsError {
			t.Fatalf("%s 调用失败: %#v %v", call.name, response, err)
		}
		encoded, err := json.Marshal(response.StructuredContent)
		if err != nil || !strings.Contains(string(encoded), call.want) {
			t.Fatalf("%s 结构化返回错误: %s %v", call.name, encoded, err)
		}
	}
	if strings.Contains(audit.String(), "private") || strings.Contains(audit.String(), "secret") || !strings.Contains(audit.String(), "browser_open") {
		t.Fatalf("审计日志泄露链接或未记录调用: %s", audit.String())
	}
}

func TestBrowserInputValidation(t *testing.T) {
	c := NewController(&lifecycleCore{}, nil, nil)
	for _, target := range []string{"", "file:///etc/passwd", "http://user:password@example.com", "http://a/" + strings.Repeat("x", 8192)} {
		if _, _, err := c.browserOpen(context.Background(), nil, browserOpenInput{ProfileID: "p", TargetURL: target}); err == nil {
			t.Fatalf("应拒绝无效网页地址: %q", target)
		}
	}
	if _, _, err := c.fileListDirectory(context.Background(), nil, directoryInput{ProfileID: "p", Directory: "a\x00b"}); err == nil {
		t.Fatal("应拒绝包含空字符的目录")
	}
	if _, _, err := c.browserClose(context.Background(), nil, browserCloseInput{ProfileID: "p"}); err == nil {
		t.Fatal("应拒绝空访问 ID")
	}
}
