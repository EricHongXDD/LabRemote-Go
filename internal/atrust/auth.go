package atrust

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/google/uuid"
)

type LoginChallenge struct {
	ID          string `json:"id"`
	ProfileID   string `json:"profile_id"`
	ProfileName string `json:"profile_name"`
	Server      string `json:"server"`
	AuthHost    string `json:"auth_host"`
}
type loginResult struct {
	callback string
	err      error
}
type pendingLogin struct {
	ctx                   context.Context
	loginURL, callbackURL string
	result                chan loginResult
	started               bool
	cancel                context.CancelFunc
}
type AuthBroker struct {
	mu      sync.Mutex
	pending map[string]*pendingLogin
	events  events.Sink
	open    func(context.Context, string, string) (string, error)
}

func NewAuthBroker(sink events.Sink) *AuthBroker {
	if sink == nil {
		sink = events.Nop{}
	}
	return &AuthBroker{pending: make(map[string]*pendingLogin), events: sink, open: browserCallback}
}

func validCallback(value, expected string) bool {
	u, err := url.Parse(value)
	e, eErr := url.Parse(expected)
	return err == nil && eErr == nil && len(value) <= 16384 && u.User == nil && u.Scheme == "https" && strings.EqualFold(u.Host, e.Host) && u.Path == e.Path && (u.Query().Get("code") != "" || u.Query().Get("ticket") != "")
}

// Request 只向界面发送入口名称；认证 URL、回调票据和会话不进入事件日志。
func (b *AuthBroker) Request(ctx context.Context, challenge LoginChallenge, loginURL, callbackURL string) (string, error) {
	challenge.ID = uuid.NewString()
	auth, _ := url.Parse(loginURL)
	challenge.AuthHost = auth.Hostname()
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	entry := &pendingLogin{ctx: requestCtx, loginURL: loginURL, callbackURL: callbackURL, result: make(chan loginResult, 1), cancel: cancel}
	b.mu.Lock()
	b.pending[challenge.ID] = entry
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, challenge.ID)
		b.mu.Unlock()
		b.events.Emit("atrust:login-closed", map[string]string{"id": challenge.ID})
	}()
	b.events.Emit("atrust:login", challenge)
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case answer := <-entry.result:
		return answer.callback, answer.err
	}
}

// Open 由用户点击后打开独立认证浏览器；只监听本次网关回调。
func (b *AuthBroker) Open(id string) error {
	b.mu.Lock()
	entry := b.pending[id]
	if entry == nil || entry.started {
		b.mu.Unlock()
		return fmt.Errorf("认证请求已结束或认证窗口已打开")
	}
	entry.started = true
	b.mu.Unlock()
	callback, err := b.open(entry.ctx, entry.loginURL, entry.callbackURL)
	select {
	case entry.result <- loginResult{callback: callback, err: err}:
	default:
	}
	return err
}
func (b *AuthBroker) Cancel(id string) {
	b.mu.Lock()
	entry := b.pending[id]
	b.mu.Unlock()
	if entry == nil {
		return
	}
	entry.cancel()
	select {
	case entry.result <- loginResult{err: context.Canceled}:
	default:
	}
}
