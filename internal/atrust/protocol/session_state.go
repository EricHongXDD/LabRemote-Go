package atrust

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// SessionState 只包含本客户端已取得的网关会话，不包含密码、验证码或浏览器登录资料。
// 调用方必须将其放入系统安全凭据库，不得输出到日志或配置导出。
type SessionState struct {
	SID      string `json:"sid"`
	Cookie   string `json:"cookie,omitempty"`
	CSRF     string `json:"csrf,omitempty"`
	Username string `json:"username"`
	SignKey  string `json:"sign_key,omitempty"`
}

func (c *Client) SessionState() SessionState {
	c.mu.RLock()
	state := SessionState{SID: c.sidTicket, CSRF: c.csrfToken, Username: c.username, SignKey: c.signKey}
	c.mu.RUnlock()
	base, _ := url.Parse(c.baseURL)
	for _, cookie := range c.http.Jar.Cookies(base) {
		if cookie.Name == "sid" {
			state.Cookie = cookie.Value
		}
	}
	return state
}

// ResumeSession 始终向服务器复核会话和当前资源权限，恢复票据本身不代表认证成功。
func (c *Client) ResumeSession(ctx context.Context, state SessionState) error {
	if state.SID == "" || state.Username == "" {
		return ErrNoSession
	}
	c.SetSession(state.SID)
	c.SetUsername(state.Username)
	c.mu.Lock()
	c.csrfToken, c.signKey = state.CSRF, state.SignKey
	c.mu.Unlock()
	base, _ := url.Parse(c.baseURL)
	if state.Cookie != "" {
		c.http.Jar.SetCookies(base, []*http.Cookie{{Name: "sid", Value: state.Cookie, Path: "/", Secure: true, HttpOnly: true}})
	}
	return c.CheckSession(ctx, state.Username)
}

// CheckSession 以 SDP 授权资源为准；Passport 网页在线状态可能已失效，而数据票据仍有效。
// 目标连接仍须通过数据网关的认证和资源匹配，不能用网页状态提前撤销有效数据票据。
func (c *Client) CheckSession(ctx context.Context, username string) error {
	if username == "" {
		return ErrNoSession
	}
	info, err := c.OnlineInfo(ctx)
	if err == nil && info.IsOnline && info.Username != username {
		return ErrNoSession
	}
	if _, err := c.ClientResource(ctx); err != nil {
		return sessionCheckFailure("授权资源查询", err)
	}
	return nil
}

func sessionCheckFailure(stage string, err error) error {
	var api *APIError
	var status *HTTPStatusError
	// 只把明确的未认证响应视为登录失效；权限不足、限流或网关业务故障保留原票据。
	if errors.Is(err, ErrNoSession) || errors.As(err, &status) && status.StatusCode == http.StatusUnauthorized || errors.As(err, &api) && (api.Code == 10000004 || api.Code == 75500002) {
		return fmt.Errorf("aTrust %s确认会话失效：%w", stage, ErrNoSession)
	}
	return fmt.Errorf("aTrust %s暂时失败：%w", stage, err)
}
