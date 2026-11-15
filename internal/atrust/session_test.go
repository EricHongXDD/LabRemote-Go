package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	protocol "github.com/EricHongXDD/LabRemote-Go/internal/atrust/protocol"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

func TestRememberedSessionIsValidatedAndReusedAcrossNewClients(t *testing.T) {
	for _, scenario := range []struct {
		name, mode string
		launches   int32
		wantError  bool
	}{
		{"重启后恢复", "online", 1, false},
		{"网页会话过期但数据授权有效", "web-expired", 1, false},
		{"网页会话无效业务码不撤销数据票据", "passport-session-invalid", 1, false},
		{"网页在线接口故障但数据授权有效", "passport-business-only", 1, false},
		{"票据过期重新登录", "expired", 2, false},
		{"服务端要求多因素认证", "mfa", 2, false},
		{"登录身份变化重新认证", "changed-user", 2, false},
		{"网络故障保留票据", "unavailable", 1, true},
		{"HTTP拒绝后重新认证", "unauthorized", 2, false},
		{"资源权限拒绝保留票据", "forbidden", 1, true},
		{"网关业务故障保留票据", "business-failure", 1, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var mode atomic.Value
			mode.Store("online")
			var launches, resources, configurations, loginChecks atomic.Int32
			var serverURL string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if mode.Load() == "unavailable" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				data := map[string]any{}
				switch r.URL.Path {
				case "/passport/v1/public/authConfig":
					configurations.Add(1)
					data = map[string]any{"security": map[string]any{"csrfToken": "csrf-test"}, "authServerInfoList": []any{map[string]any{"authType": "auth/httpsOauth2", "loginUrl": "https://identity.example/login?state=original"}}}
				case "/passport/v1/auth/httpsOauth2":
					http.SetCookie(w, &http.Cookie{Name: "sid", Value: "session-test", Path: "/", Secure: true})
				case "/passport/v1/auth/authCheck":
					loginChecks.Add(1)
					if cookie, err := r.Cookie("sid"); err != nil || cookie.Value != "session-test" {
						t.Error("恢复后未携带本客户端的会话 Cookie")
					}
				case "/passport/v1/user/onlineInfo":
					if cookie, err := r.Cookie("sid"); err != nil || cookie.Value != "session-test" {
						t.Error("在线查询未恢复本客户端的 Cookie")
					}
					if mode.Load() == "unauthorized" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if mode.Load() == "passport-session-invalid" {
						_ = json.NewEncoder(w).Encode(map[string]any{"code": 75500002, "message": "session invalid"})
						return
					}
					name := "test-user"
					if mode.Load() == "changed-user" {
						name = "other-user"
					}
					if mode.Load() == "business-failure" || mode.Load() == "passport-business-only" {
						_ = json.NewEncoder(w).Encode(map[string]any{"code": 75599999, "message": "temporary failure"})
						return
					}
					data = map[string]any{"isOnline": mode.Load() != "expired" && mode.Load() != "mfa" && mode.Load() != "web-expired", "username": name}
				case "/controller/v1/user/clientResource":
					if mode.Load() == "expired" || mode.Load() == "mfa" || mode.Load() == "unauthorized" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if mode.Load() == "business-failure" {
						_ = json.NewEncoder(w).Encode(map[string]any{"code": 75599999, "message": "temporary failure"})
						return
					}
					if mode.Load() == "forbidden" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					resources.Add(1)
				default:
					t.Errorf("未预期的请求路径 %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": data})
			}))
			defer server.Close()
			serverURL = server.URL
			broker := NewAuthBroker(nil)
			broker.open = func(_ context.Context, loginURL, callback string) (string, error) {
				launches.Add(1)
				mode.Store("online")
				login, _ := url.Parse(loginURL)
				return callback + "?code=test-code&state=" + url.QueryEscape(login.Query().Get("state")), nil
			}
			factory := func(server string, options protocol.Options) (*protocol.Client, error) {
				// 只在本地模拟 HTTPS 网关中信任测试证书，生产入口仍使用系统 CA。
				options.InsecureSkipVerify = true
				return protocol.NewClient(server, options)
			}
			store := secrets.NewMemoryStore()
			config := Config{Server: serverURL, ProfileID: "persistent-profile", Credentials: store, Auth: broker}
			first, err := openSession(context.Background(), config, factory)
			if err != nil {
				t.Fatal(err)
			}
			device := first.client.DeviceID()
			_ = first.Close()
			before, _ := store.Get(context.Background(), CredentialKey(config.ProfileID, serverURL))
			defer secrets.Zero(before)
			mode.Store(scenario.mode)
			// 第二次创建全新的 HTTP 客户端，不依赖原有连接或内存会话。
			second, err := openSession(context.Background(), config, factory)
			if (err != nil) != scenario.wantError {
				t.Fatalf("恢复结果不正确: %v", err)
			}
			if second != nil {
				defer second.Close()
				if second.client.DeviceID() != device {
					t.Error("恢复或重新认证时设备标识发生变化")
				}
			}
			if launches.Load() != scenario.launches {
				t.Fatalf("浏览器启动次数不正确: %d", launches.Load())
			}
			if configurations.Load() != launches.Load() || loginChecks.Load() != launches.Load() {
				t.Error("复用或恢复会话不应重新进入 authConfig/authCheck 登录流程")
			}
			if scenario.wantError {
				after, _ := store.Get(context.Background(), CredentialKey(config.ProfileID, serverURL))
				defer secrets.Zero(after)
				if string(before) != string(after) || resources.Load() != 1 {
					t.Error("网络故障时修改票据或错误使用了授权资源")
				}
			} else if resources.Load() != 2 {
				t.Error("恢复后未重新获取服务器授权资源")
			}
			if scenario.mode == "online" {
				mode.Store("expired")
				second.verifiedAt = time.Time{}
				active, peer := net.Pipe()
				second.connections[active] = struct{}{}
				if err := second.Refresh(context.Background()); err != nil {
					t.Errorf("网页票据过期不应破坏已认证的活动通道: %v", err)
				}
				if resources.Load() != 2 {
					t.Error("活动通道不应因创建新 SSH/SFTP 连接而重入网页认证检查")
				}
				delete(second.connections, active)
				_ = active.Close()
				_ = peer.Close()
				if err := second.Refresh(context.Background()); !errors.Is(err, protocol.ErrNoSession) {
					t.Error("应用持续运行时未识别服务端会话过期")
				}
			}
		})
	}
}

func TestCredentialScopeAndGatewayIsolation(t *testing.T) {
	ctx := context.Background()
	store := secrets.NewMemoryStore()
	saved := &rememberedSession{Version: 1, Server: "https://vpn.example", Device: strings.Repeat("A", 32), State: &protocol.SessionState{SID: "test-ticket", Username: "test-user"}}
	if err := saveRemembered(ctx, store, "profile-a", saved); err != nil {
		t.Fatal(err)
	}
	if value, err := loadRemembered(ctx, store, "profile-a", "https://VPN.EXAMPLE"); err != nil || value == nil {
		t.Fatal("服务器主机名大小写不应导致重复认证")
	}
	for _, pair := range [][2]string{{"profile-b", saved.Server}, {"profile-a", "https://other.example"}} {
		value, err := loadRemembered(ctx, store, pair[0], pair[1])
		if err != nil || value != nil {
			t.Fatal("不同配置或网关不应共享票据")
		}
	}
	if err := ForgetCredential(ctx, store, "profile-a", saved.Server); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, CredentialKey("profile-a", saved.Server)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatal("清除后票据仍然存在")
	}
}
