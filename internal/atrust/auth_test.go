package atrust

import (
	"context"
	"encoding/json"
	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"strings"
	"testing"
	"time"
)

func TestAuthBrokerOnlyExportsNonSecretChallenge(t *testing.T) {
	challenge := make(chan LoginChallenge, 1)
	broker := NewAuthBroker(events.Func(func(name string, payload any) {
		if name == "atrust:login" {
			encoded, _ := json.Marshal(payload)
			if strings.Contains(string(encoded), "secret") {
				t.Error("事件不应包含认证 URL 或票据")
			}
			challenge <- payload.(LoginChallenge)
		}
	}))
	broker.open = func(context.Context, string, string) (string, error) {
		return "https://vpn.example/passport/v1/auth/httpsOauth2?code=secret", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan string, 1)
	go func() {
		callback, _ := broker.Request(ctx, LoginChallenge{Server: "https://vpn.example"}, "https://identity.example/login?state=secret", "https://vpn.example/passport/v1/auth/httpsOauth2")
		done <- callback
	}()
	request := <-challenge
	if err := broker.Open(request.ID); err != nil {
		t.Fatal(err)
	}
	if callback := <-done; !validCallback(callback, "https://vpn.example/passport/v1/auth/httpsOauth2") {
		t.Fatal("合法回调丢失")
	}
	if validCallback("https://evil.example/passport/v1/auth/httpsOauth2?code=secret", "https://vpn.example/passport/v1/auth/httpsOauth2") {
		t.Fatal("跨入口回调不得接受")
	}
}

func TestCallbackStateBindsIndependentLogin(t *testing.T) {
	expected := "https://vpn.example/passport/v1/auth/httpsOauth2"
	if _, err := restoreCallbackState(expected+"?code=code&state=wrong", expected, "nonce", ""); err == nil {
		t.Fatal("不能接受其他认证请求的回调")
	}
	callback, err := restoreCallbackState(expected+"?code=code&state=nonce", expected, "nonce", "gateway-state")
	if err != nil || !strings.Contains(callback, "state=gateway-state") {
		t.Fatalf("未恢复网关原有认证状态: %v", err)
	}
}
