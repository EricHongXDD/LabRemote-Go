package atrust

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
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
	got, err := browserCallback(ctx, server.URL, "https://gateway.example/passport/v1/auth/httpsOauth2")
	if err != nil || got != callback {
		t.Fatalf("独立认证窗口回调失败: %s %v", got, err)
	}
}
