package mcpserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

func TestMCPHTTPCallsWithOldSessionAfterRestart(t *testing.T) {
	ctx := context.Background()
	core := &lifecycleCore{profiles: []model.ConnectionProfile{{ID: "restart-test", MCPPolicy: model.MCPPolicy{EnabledForProfile: true}}}}
	controller := NewController(core, secrets.NewMemoryStore(), nil)
	port := freeLocalPort(t)
	status, err := controller.Start(ctx, port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Stop(ctx) })
	token, err := controller.AccessToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	post := func(sessionID, auth, body string) (int, string, string) {
		t.Helper()
		request := newMCPTestRequest(t, ctx, status.Address, auth, body)
		if sessionID != "" {
			request.Header.Set("Mcp-Session-Id", sessionID)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, response.Header.Get("Mcp-Session-Id"), string(payload)
	}
	code, sessionID, body := post("", token, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if code != http.StatusOK || sessionID != "" || !strings.Contains(body, `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("无状态初始化失败: HTTP %d, session=%q, %s", code, sessionID, body)
	}
	code, _, body = post("", token, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if code != http.StatusAccepted {
		t.Fatalf("就绪通知失败: HTTP %d, %s", code, body)
	}
	const listProfiles = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"profiles_list","arguments":{}}}`
	code, _, body = post("", token, listProfiles)
	if code != http.StatusOK || !strings.Contains(body, `"id":"restart-test"`) {
		t.Fatalf("无会话工具调用失败: HTTP %d, %s", code, body)
	}
	if err := controller.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Start(ctx, port); err != nil {
		t.Fatal(err)
	}
	code, _, body = post("old-client-session", token, listProfiles)
	if code != http.StatusOK || !strings.Contains(body, `"id":"restart-test"`) {
		t.Fatalf("重启后携带旧会话 ID 的工具调用失败: HTTP %d, %s", code, body)
	}
	code, _, _ = post("old-client-session", "wrong-token", listProfiles)
	if code != http.StatusUnauthorized {
		t.Fatalf("错误令牌返回 HTTP %d，预期 401", code)
	}
}

type cancelHTTPCore struct {
	lifecycleCore
	started chan struct{}
	ended   chan error
}

func (c *cancelHTTPCore) MCPExec(ctx context.Context, _ model.ExecRequest) (model.ExecResult, error) {
	close(c.started)
	<-ctx.Done()
	c.ended <- ctx.Err()
	return model.ExecResult{}, ctx.Err()
}

func TestMCPHTTPCancellationReachesTool(t *testing.T) {
	core := &cancelHTTPCore{started: make(chan struct{}), ended: make(chan error, 1)}
	controller := NewController(core, secrets.NewMemoryStore(), nil)
	status, err := controller.Start(context.Background(), freeLocalPort(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.Stop(context.Background()) })
	token, err := controller.AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := newMCPTestRequest(t, ctx, status.Address, token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ssh_exec","arguments":{"profile_id":"test","command":"test","timeout_seconds":6}}}`)
	go func() {
		if response, err := http.DefaultClient.Do(request); err == nil {
			response.Body.Close()
		}
	}()
	select {
	case <-core.started:
		cancel()
	case <-ctx.Done():
		t.Fatal("工具未收到 HTTP 请求")
	}
	select {
	case err := <-core.ended:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("工具未收到取消信号: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP 请求取消后工具仍在运行")
	}
}

func newMCPTestRequest(t *testing.T, ctx context.Context, address, token, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("MCP-Protocol-Version", "2025-11-25")
	return request
}
