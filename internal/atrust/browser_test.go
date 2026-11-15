package atrust

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
)

func TestIndependentBrowserCallback(t *testing.T) {
	if os.Getenv("LABREMOTE_TEST_ATRUST_BROWSER") != "1" {
		t.Skip("未启用独立浏览器窗口测试")
	}
	callback := "https://gateway.example/passport/v1/auth/httpsOauth2?code=local-test"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, callback, http.StatusFound) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	// 不注册任何前端监听器，仍应自动打开真实浏览器并收到本次回调。
	broker := NewAuthBroker(events.Nop{})
	got, err := broker.Request(ctx, LoginChallenge{Server: "https://gateway.example", ProfileName: "本机回调测试"}, server.URL, "https://gateway.example/passport/v1/auth/httpsOauth2")
	if err != nil || got != callback {
		t.Fatalf("独立认证窗口回调失败: %s %v", got, err)
	}
}

func TestBrowserLauncherExitCanHandOffToWindow(t *testing.T) {
	directory := t.TempDir()
	processDone := make(chan error, 1)
	processDone <- nil
	close(processDone)
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(directory, "DevToolsActivePort"), []byte("34567\n/devtools/browser/test-only\n"), 0600)
	}()
	endpoint, err := waitBrowserEndpoint(context.Background(), directory, processDone, time.Second)
	if err != nil || endpoint != "ws://127.0.0.1:34567/devtools/browser/test-only" {
		t.Fatalf("启动器交接被误判为窗口关闭：%s %v", endpoint, err)
	}
}

func TestBrowserStartupReportsFailureAndCancellation(t *testing.T) {
	processDone := make(chan error, 1)
	processDone <- errors.New("test-startup-failure")
	if _, err := waitBrowserEndpoint(context.Background(), t.TempDir(), processDone, time.Second); err == nil || !strings.Contains(err.Error(), "test-startup-failure") {
		t.Fatal("启动失败原因被隐藏")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waitBrowserEndpoint(ctx, t.TempDir(), nil, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("窗口启动未响应取消")
	}
}
