package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
)

func TestAuthBrokerOnlyExportsNonSecretChallenge(t *testing.T) {
	challenge := make(chan LoginChallenge, 1)
	opening, proceed := make(chan struct{}), make(chan struct{})
	var launches atomic.Int32
	broker := NewAuthBroker(events.Func(func(name string, payload any) {
		if name == "atrust:login" {
			encoded, _ := json.Marshal(payload)
			if strings.Contains(string(encoded), "secret") {
				t.Error("事件不应包含认证 URL 或票据")
			}
			challenge <- payload.(LoginChallenge)
		}
	}))
	broker.open = func(ctx context.Context, _, _ string) (string, error) {
		launches.Add(1)
		close(opening)
		select {
		case <-proceed:
		case <-ctx.Done():
			return "", ctx.Err()
		}
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
	<-opening
	if err := broker.Open(request.ID); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if callback := <-done; !validCallback(callback, "https://vpn.example/passport/v1/auth/httpsOauth2") {
		t.Fatal("合法回调丢失")
	}
	if validCallback("https://evil.example/passport/v1/auth/httpsOauth2?code=secret", "https://vpn.example/passport/v1/auth/httpsOauth2") {
		t.Fatal("跨入口回调不得接受")
	}
	if launches.Load() != 1 {
		t.Fatal("重复点击不应启动多个认证窗口")
	}
}

func TestAuthRequestOpensBrowserWithoutFrontendEvent(t *testing.T) {
	broker := NewAuthBroker(events.Nop{})
	broker.open = func(context.Context, string, string) (string, error) {
		return "https://vpn.example/callback?code=test", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := broker.Request(ctx, LoginChallenge{Server: "https://vpn.example"}, "https://identity.example/login", "https://vpn.example/callback")
	if err != nil || got != "https://vpn.example/callback?code=test" {
		t.Fatalf("前端事件丢失时也应直接打开认证窗口: %v", err)
	}
}

func TestAuthBrowserFailureIsNotReportedAsTimeout(t *testing.T) {
	broker := NewAuthBroker(events.Nop{})
	expected := errors.New("未找到测试浏览器")
	broker.open = func(context.Context, string, string) (string, error) { return "", expected }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := broker.Request(ctx, LoginChallenge{Server: "https://vpn.example"}, "https://identity.example/login", "https://vpn.example/callback")
	err = loginFailure(err)
	if !errors.Is(err, expected) || !strings.Contains(err.Error(), expected.Error()) || strings.Contains(err.Error(), "超时") {
		t.Fatalf("启动失败应保留真实原因: %v", err)
	}
}

func TestAuthCancelClosesActiveBrowserAndExpiresRequest(t *testing.T) {
	challenges := make(chan LoginChallenge, 1)
	broker := NewAuthBroker(events.Func(func(name string, payload any) {
		if name == "atrust:login" {
			challenges <- payload.(LoginChallenge)
		}
	}))
	started, closed := make(chan struct{}), make(chan struct{})
	broker.open = func(ctx context.Context, _, _ string) (string, error) {
		close(started)
		<-ctx.Done()
		close(closed)
		return "", ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := broker.Request(ctx, LoginChallenge{Server: "https://vpn.example"}, "https://identity.example/login", "https://vpn.example/callback")
		done <- err
	}()
	challenge := <-challenges
	<-started
	broker.Cancel(challenge.ID)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("取消未立即结束认证: %v", err)
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("取消未关闭本次浏览器")
	}
	if err := broker.Open(challenge.ID); err == nil {
		t.Fatal("已取消请求不能重新打开")
	}
}

func TestAuthCancellationAndDeadlineRemainDistinct(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		err := loginFailure(cause)
		if !errors.Is(err, cause) {
			t.Fatalf("认证错误丢失原因: %v", err)
		}
		if strings.Contains(err.Error(), "已取消") != errors.Is(cause, context.Canceled) {
			t.Fatalf("取消与超时未区分: %v", err)
		}
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
