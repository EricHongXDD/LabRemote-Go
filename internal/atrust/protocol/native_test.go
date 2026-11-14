package atrust

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAuthResponseMustBeAnUnambiguousJSONStatus(t *testing.T) {
	for _, response := range []string{`{"code":1,"message":"OK"}`, `{"code":01}`, `{"message":"not OK","data":{"code":0}}`, `{"code":0} garbage`, `{"message":"Failed"}`} {
		if checkAuthPayload([]byte(response)) == nil {
			t.Fatalf("错误认证状态被接受: %s", response)
		}
	}
	for _, response := range []string{`{"code":0}`, `{"message":"OK"}`} {
		if err := checkAuthPayload([]byte(response)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSSOAndTargetTCPStayInsideSession(t *testing.T) {
	// 模拟网关只返回测试票据，未使用实际账号或外部网络。
	dataServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dataTLS := dataServer.TLS.Clone()
	dataServer.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", dataTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 7)
		if _, err = io.ReadFull(connection, header); err != nil {
			return
		}
		if string(header[:5]) != string([]byte{5, 1, 0x81, 0x53, 3}) {
			return
		}
		payload := make([]byte, int(binary.BigEndian.Uint16(header[5:])))
		if _, err = io.ReadFull(connection, payload); err != nil {
			return
		}
		accepted <- string(payload)
		target := make([]byte, 10)
		if _, err = io.ReadFull(connection, target); err != nil {
			return
		}
		status := []byte(`{"code":0}`)
		wire := append([]byte{5, 0x81, 0x53, 0, 0, byte(len(status))}, status...)
		wire = append(wire, 5, 0, 0xa5, 1, 127, 0, 0, 1, 0, 22)
		if _, err = connection.Write(wire); err != nil {
			return
		}
		for {
			h := make([]byte, 4)
			if _, err = io.ReadFull(connection, h); err != nil {
				return
			}
			size := int(binary.BigEndian.Uint16(h[2:]))
			if size == 0 && h[1] == 0 {
				t.Error("连接建立前不得发送空 TCP 数据帧")
				return
			}
			payload := make([]byte, size)
			if _, err = io.ReadFull(connection, payload); err != nil {
				return
			}
			if h[1] == 1 {
				return
			}
			if size > 0 {
				_, _ = connection.Write(append(h, payload...))
			}
		}
	}()
	var serverURL string
	refreshed := false
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data := map[string]any{}
		switch r.URL.Path {
		case pathAuthConfig:
			if r.URL.Query().Get("mod") == "1" {
				refreshed = true
			}
			data = map[string]any{"security": map[string]any{"csrfToken": "refreshed-csrf"}, "firstAuth": []string{}, "authServerInfoList": []map[string]any{{"authType": "auth/httpsOauth2", "loginUrl": "https://identity.example/login"}}}
		case "/passport/v1/auth/httpsOauth2":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "test-session", Path: "/", Secure: true})
			w.Header().Set("Location", "atrust://callback?ticket=test-ticket")
			w.WriteHeader(http.StatusFound)
			return
		case "/controller/v1/public/reportEnv":
			if !refreshed || r.Header.Get("X-Csrf-Token") != "refreshed-csrf" {
				t.Error("网页回调后未刷新认证上下文")
			}
		case pathAuthCheck:
			if r.Header.Get("Sid-Ticket") != "" {
				t.Error("认证复核前不得将临时 sid 冒充 sidTicket")
			}
		case pathOnlineInfo:
			data = map[string]any{"isOnline": true, "username": "test-user"}
		case pathClientResource:
			data = map[string]any{"appList": map[string]any{"data": map[string]any{
				"config":  map[string]any{"nodeGroupConf": map[string]any{"nodeGroupList": []any{map[string]any{"id": "node", "addressInfo": []any{map[string]any{"type": "wan", "address": listener.Addr().String()}}}}}},
				"appInfo": []any{map[string]any{"apps": []any{map[string]any{"id": "ssh-app", "nodeGroupId": "node", "addressList": []any{map[string]any{"host": "192.0.2.10", "port": "22", "protocol": "tcp"}}}}}},
			}}}
		default:
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": data})
	}))
	defer control.Close()
	serverURL = control.URL
	client, err := NewClient(serverURL, Options{GatewayTLS: func(string) *tls.Config { return dataTLS.Clone() }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// 只对本机测试 CA 建立信任，生产默认仍使用系统 CA。
	client.http.Transport = control.Client().Transport
	client.gatewayTLS = func(string) *tls.Config {
		cfg := control.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		return cfg
	}
	client.SetDeviceID("TEST-DEVICE")
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, callback, err := client.SSOEntrance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.CompleteSSO(ctx, callback+"?code=test-code", callback); err != nil {
		t.Fatal(err)
	}
	connection, err := client.DialTCP(ctx, "192.0.2.10", 22)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err = connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err = io.ReadFull(connection, got); err != nil || string(got) != "ping" {
		t.Fatalf("隔离 TCP 未完成双向传输: %v", err)
	}
	select {
	case auth := <-accepted:
		if !json.Valid([]byte(auth)) {
			t.Fatal("认证帧必须是有效 JSON，包含 Windows 路径时也应正确转义")
		}
		if strings.Contains(auth, "aTrustXtunnel") || strings.Contains(auth, `"process_trusted":"TRUSTED"`) {
			t.Fatal("不得声明官方客户端或已授信进程身份")
		}
	default:
		t.Fatal("网关未收到认证帧")
	}
	if _, err = client.DialTCP(ctx, "192.0.2.11", 22); err == nil {
		t.Fatal("没有授权资源匹配时不得回退默认线路")
	}
}

func TestLiveSSOEntrance(t *testing.T) {
	server := os.Getenv("LABREMOTE_TEST_ATRUST_SERVER")
	if server == "" {
		t.Skip("未启用实际认证入口只读检查")
	}
	client, err := NewClient(server, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	login, callback, err := client.SSOEntrance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(login, "https://") || !strings.HasPrefix(callback, server+"/passport/v1/auth/") {
		t.Fatal("认证入口格式无效")
	}
}

func TestSSOChecksHonorNextStepsAndHideServerDetails(t *testing.T) {
	for _, scenario := range []struct{ name, response, want string }{
		{"允许", `{"code":0,"data":{}}`, ""},
		{"额外短信", `{"code":0,"data":{"nextService":"auth/sms"}}`, "额外认证（auth/sms）"},
		{"认证列表", `{"code":0,"data":{"nextServiceList":[{"authType":"auth/totp"}]}}`, "额外认证（auth/totp）"},
		{"网关拒绝", `{"code":75599999,"message":"secret-ticket-must-not-appear"}`, "业务码 75599999"},
		{"终端准入", `{"code":0,"data":{"nextService":"unknown/policy"}}`, "终端准入"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != pathAuthCheck || r.Header.Get("X-Csrf-Token") != "test-csrf" {
					t.Error("会话复核请求不完整")
				}
				_, _ = io.WriteString(w, scenario.response)
			}))
			defer server.Close()
			client, err := NewClient(server.URL, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.csrfToken = "test-csrf"
			err = client.completeSSOChecks(context.Background())
			if scenario.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), scenario.want) || strings.Contains(err.Error(), "secret-ticket") {
				t.Fatalf("复核结果不正确或泄露响应内容: %v", err)
			}
		})
	}
}

var _ net.Conn = (*TCPConn)(nil)

func TestTCPResourceDoesNotExpandInvalidPortsOrUDP(t *testing.T) {
	for _, scenario := range []struct {
		protocol, ports string
		port            int
		want            bool
	}{
		{"udp", "22", 22, false}, {"tcp", "80,443", 22, false}, {"tcp", "80,443", 443, true},
		{"tcp", "20-25", 22, true}, {"tcp", "20-25", 26, false}, {"tcp", "bad", 22, false},
		{"all", "0", 22, true}, {"tcp", "22", 22, true},
	} {
		entry := routeEntry{Protocol: scenario.protocol, Ports: scenario.ports}
		if got := entry.matchesTCPPort(scenario.port); got != scenario.want {
			t.Errorf("资源协议或端口匹配错误: %#v", scenario)
		}
	}
}
