package browserproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

type mappingDialer struct {
	address string
	mu      sync.Mutex
	profile string
	target  string
}

type failingDialer struct{}

func TestMCPBrowserLimitAndConcurrentReuse(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(failingDialer{})
	defer manager.CloseAll(ctx)
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := manager.OpenOwned(ctx, "p", "http://127.0.0.1:8080", "mcp"); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if manager.Count("p") != 1 {
		t.Fatal("并发请求同一目标应仅创建一个代理")
	}
	for i := 1; i < 16; i++ {
		if _, err := manager.OpenOwned(ctx, "p", fmt.Sprintf("http://127.0.0.1:8080/%d", i), "mcp"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := manager.OpenOwned(ctx, "p", "http://127.0.0.1:8080/overflow", "mcp"); err == nil {
		t.Fatal("超过代理上限应拒绝")
	}
	if _, err := manager.OpenOwned(ctx, "p", "http://127.0.0.1:8080", "mcp"); err != nil {
		t.Fatalf("达到上限后仍应复用已有链接: %v", err)
	}
	if _, err := manager.Open(ctx, "p", "http://127.0.0.1:8080/ui"); err != nil {
		t.Fatalf("MCP 上限不应阻止桌面使用: %v", err)
	}
}

func TestBrowserOwnershipLifecycle(t *testing.T) {
	ctx := context.Background()
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.RequestURI()))
	}))
	defer remote.Close()
	remoteURL, _ := url.Parse(remote.URL)
	manager := NewManager(&mappingDialer{address: remoteURL.Host})
	defer manager.CloseAll(ctx)
	uiURL, err := manager.Open(ctx, "p", "http://127.0.0.1:8080/path?x=1")
	if err != nil {
		t.Fatal(err)
	}
	access, err := manager.OpenOwned(ctx, "p", "http://127.0.0.1:8080/path?x=1", "mcp")
	if err != nil {
		t.Fatal(err)
	}
	if access.AccessURL == uiURL || access.AccessID == "" || manager.Count("p") != 2 {
		t.Fatal("MCP 和桌面代理应独立创建")
	}
	duplicate, err := manager.OpenOwned(ctx, "p", access.TargetURL, "mcp")
	if err != nil || duplicate != access || manager.Count("p") != 2 {
		t.Fatal("同一调用方重复打开应复用完整链接")
	}
	if values := manager.ListOwned("p", "mcp"); len(values) != 1 || values[0] != access {
		t.Fatalf("查询应仅返回 MCP 自有链接: %#v", values)
	}
	uiID := manager.ListOwned("p", "ui")[0].AccessID
	if err := manager.CloseOwned(ctx, "p", uiID, "mcp"); err == nil {
		t.Fatal("MCP 不得关闭桌面代理")
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 3 * time.Second}
	response, err := client.Get(access.AccessURL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "/path?x=1" {
		t.Fatalf("完整访问链接不可用: %d %s", response.StatusCode, body)
	}
	if err := manager.CloseOwned(ctx, "other-profile", access.AccessID, "mcp"); err == nil {
		t.Fatal("不得跨配置关闭代理")
	}
	if err := manager.CloseOwned(ctx, "p", access.AccessID, "mcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(access.AccessURL); err == nil {
		t.Fatal("关闭后链接仍可访问")
	}
	_, err = manager.OpenOwned(ctx, "p", access.TargetURL, "mcp")
	if err != nil {
		t.Fatal(err)
	}
	manager.CloseOwner(ctx, "mcp")
	if manager.Count("p") != 1 || len(manager.ListOwned("p", "mcp")) != 0 {
		t.Fatal("停止 MCP 应仅清理 MCP 代理")
	}
	response, err = client.Get(uiURL)
	if err != nil {
		t.Fatalf("清理 MCP 后桌面链接不可用: %v", err)
	}
	_ = response.Body.Close()
}

func (failingDialer) DialWebContext(context.Context, string, string, string) (net.Conn, error) {
	return nil, model.NewAppError("BROWSER_RECONNECT_FAILED", "网页访问连接自动恢复失败", "browser_proxy", true).WithDetails(map[string]any{"reason": "sensitive transport detail"})
}

func (d *mappingDialer) DialWebContext(ctx context.Context, profileID, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.profile = profileID
	d.target = address
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, "tcp4", d.address)
}

func TestBrowserProxyUsesSSHDialerAndRewritesSessionState(t *testing.T) {
	var expectedHost string
	remote := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/start":
			if request.Host != expectedHost {
				http.Error(response, "host mismatch", http.StatusBadRequest)
				return
			}
			for _, cookie := range request.Cookies() {
				if strings.HasPrefix(cookie.Name, "labremote_browser_") {
					http.Error(response, "proxy cookie leaked", http.StatusBadRequest)
					return
				}
			}
			response.Header().Add("Set-Cookie", "remote=ok; Domain=192.0.2.20; Path=/; Secure; SameSite=None")
			response.Header().Set("Location", "http://"+expectedHost+"/next")
			response.WriteHeader(http.StatusFound)
		case "/next":
			cookie, err := request.Cookie("remote")
			if err != nil || cookie.Value != "ok" {
				http.Error(response, "cookie missing", http.StatusUnauthorized)
				return
			}
			_, _ = response.Write([]byte("isolated browser ok"))
		default:
			http.NotFound(response, request)
		}
	}))
	defer remote.Close()
	remoteURL, err := url.Parse(remote.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := remoteURL.Port()
	expectedHost = net.JoinHostPort("192.0.2.20", port)
	dialer := &mappingDialer{address: remoteURL.Host}
	manager := NewManager(dialer)

	bootstrapURL, err := manager.Open(context.Background(), "profile-1", "192.0.2.20:"+port+"/start?source=labremote")
	if err != nil {
		t.Fatal(err)
	}
	if manager.Count("profile-1") != 1 {
		t.Fatalf("unexpected session count: %d", manager.Count("profile-1"))
	}
	parsedBootstrap, err := url.Parse(bootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized, err := http.Get("http://" + parsedBootstrap.Host + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d", unauthorized.StatusCode)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	response, err := client.Get(bootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "isolated browser ok" {
		t.Fatalf("unexpected response: status=%d body=%q", response.StatusCode, string(body))
	}
	dialer.mu.Lock()
	profile, target := dialer.profile, dialer.target
	dialer.mu.Unlock()
	if profile != "profile-1" || target != expectedHost {
		t.Fatalf("unexpected isolated dial: profile=%q target=%q", profile, target)
	}

	closeContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	manager.CloseProfile(closeContext, "profile-1")
	if manager.Count("profile-1") != 0 {
		t.Fatal("browser session was not removed")
	}
}

func TestNormalizeTargetURL(t *testing.T) {
	target, err := normalizeTargetURL("192.168.1.2:2512/app?q=1#ignored")
	if err != nil {
		t.Fatal(err)
	}
	if target.String() != "http://192.168.1.2:2512/app?q=1" {
		t.Fatalf("normalized URL = %q", target.String())
	}

	for _, value := range []string{"", "ftp://192.168.1.2/file", "http://0.0.0.0", "http://[::1]", "http://192.168.1.2:70000"} {
		if _, err := normalizeTargetURL(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
	for _, value := range []string{"http://localhost:8080", "http://127.0.0.1:2512"} {
		if _, err := normalizeTargetURL(value); err != nil {
			t.Fatalf("远端 SSH 主机本地资源 %q 应被允许: %v", value, err)
		}
	}
}

func TestBrowserAccessLinkWorksAcrossIndependentBrowsers(t *testing.T) {
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/app?source=link" {
			t.Errorf("目标路径丢失: %s", r.URL.RequestURI())
		}
		for _, cookie := range r.Cookies() {
			if strings.HasPrefix(cookie.Name, "labremote_browser_") {
				t.Error("认证凭据不应转发到远端")
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer remote.Close()
	remoteURL, _ := url.Parse(remote.URL)
	manager := NewManager(&mappingDialer{address: remoteURL.Host})
	defer manager.CloseAll(context.Background())
	link, err := manager.Open(context.Background(), "profile", "http://192.0.2.20/app?source=link")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(link)
	plainURL := "http://" + parsed.Host + "/app?source=link"
	// 两套 Cookie 存储模拟独立浏览器和无痕窗口，不共享第一套会话。
	for index := 0; index < 2; index++ {
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
		for _, check := range []struct {
			address string
			status  int
		}{
			{plainURL, http.StatusForbidden},
			{link + "invalid", http.StatusForbidden},
			{link, http.StatusOK},
			{plainURL, http.StatusOK},
			{link, http.StatusOK},
		} {
			response, err := client.Get(check.address)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != check.status {
				t.Fatalf("浏览器 %d: status=%d, want=%d", index, response.StatusCode, check.status)
			}
		}
	}
	reused, err := manager.Open(context.Background(), "profile", "http://192.0.2.20/app?source=link")
	if err != nil || reused != link || manager.Count("profile") != 1 {
		t.Fatal("复制链接应复用同一代理")
	}
	manager.CloseProfile(context.Background(), "profile")
	client := &http.Client{Timeout: time.Second}
	if response, err := client.Get(link); err == nil {
		_ = response.Body.Close()
		t.Fatal("关闭访问后旧链接仍然有效")
	}
}

func TestBrowserProxyErrorPageDoesNotExposeStructuredInternalError(t *testing.T) {
	manager := NewManager(failingDialer{})
	defer manager.CloseAll(context.Background())
	bootstrapURL, err := manager.Open(context.Background(), "profile-error", "http://127.0.0.1:1294")
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	response, err := client.Get(bootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(text, "自动恢复失败") {
		t.Fatalf("错误页内容异常: status=%d body=%q", response.StatusCode, text)
	}
	if strings.Contains(text, "APPERROR") || strings.Contains(text, "sensitive transport detail") {
		t.Fatalf("错误页不应暴露结构化内部错误: %q", text)
	}
}
