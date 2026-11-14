package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// SSOEntrance 只返回网关指定的 HTTPS 认证入口，认证内容由用户在独立窗口输入。
func (c *Client) SSOEntrance(ctx context.Context) (string, string, error) {
	cfg, err := c.FetchAuthConfig(ctx)
	if err != nil {
		return "", "", err
	}
	for _, method := range cfg.AuthServerList {
		if method.AuthType != "auth/httpsOauth2" && method.AuthType != "auth/oauth2" {
			continue
		}
		if method.LoginURL == "" {
			continue
		}
		login, err := url.Parse(method.LoginURL)
		if err != nil || login.Scheme != "https" || login.Hostname() == "" || login.User != nil {
			continue
		}
		callback := c.baseURL + "/passport/v1/" + method.AuthType
		return login.String(), callback, nil
	}
	return "", "", fmt.Errorf("此 aTrust 入口尚未提供受支持的 HTTPS 网页认证方式")
}

// CompleteSSO 仅接受当前网关的认证回调；不读取其他浏览器或官方客户端的会话。
func (c *Client) CompleteSSO(ctx context.Context, rawCallback, expectedCallback string) error {
	callback, err := url.Parse(rawCallback)
	expected, expectedErr := url.Parse(expectedCallback)
	if err != nil || expectedErr != nil || callback.Scheme != "https" || !strings.EqualFold(callback.Host, expected.Host) || callback.Path != expected.Path || callback.User != nil || len(rawCallback) > 16384 {
		return fmt.Errorf("aTrust 认证回调与当前请求不匹配")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, callback.String(), nil)
	if err != nil {
		return fmt.Errorf("aTrust 认证回调格式无效")
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Csrf-Token", c.csrf())
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("aTrust 认证票据交换失败")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("aTrust 认证票据交换被拒绝（HTTP %d）", response.StatusCode)
	}
	// 网关以重定向查询参数交付一次性票据，先消费票据再查询认证状态。
	ticket := ""
	if location := response.Header.Get("Location"); location != "" {
		u, parseErr := url.Parse(location)
		if parseErr == nil {
			ticket = u.Query().Get("ticket")
			if ticket == "" {
				var payload struct {
					Ticket string `json:"ticket"`
				}
				if json.Unmarshal([]byte(u.Query().Get("data")), &payload) == nil {
					ticket = payload.Ticket
				}
			}
		}
	}
	if ticket == "" {
		ticket = callback.Query().Get("ticket")
	}
	if ticket != "" {
		// 网页回调后刷新当前认证上下文，不能重新申请另一张登录票据。
		query := clientQuery()
		query.Set("mod", "1")
		config, configErr := doJSON[AuthConfig](ctx, c, requestSpec{method: http.MethodGet, path: pathAuthConfig, query: query, withCSRF: true})
		if configErr != nil {
			return gatewayStageError("网页回调后的认证上下文刷新", configErr)
		}
		c.setAuthConfig(config)
		_, err = doJSON[map[string]any](ctx, c, requestSpec{method: "POST", path: "/controller/v1/public/reportEnv", query: clientQuery(), withCSRF: true, jsonBody: map[string]any{
			"ticket": ticket, "deviceId": c.deviceID, "env": map[string]any{"endpoint": map[string]any{"device_id": c.deviceID, "device": map[string]any{"type": "browser"}}},
		}})
		if err != nil {
			return gatewayStageError("会话确认", err)
		}
	}
	base, _ := url.Parse(c.baseURL)
	// 复核前仅使用网关下发的 Cookie，不把临时 sid 伪装为 sidTicket。
	if err := c.completeSSOChecks(ctx); err != nil {
		return err
	}
	sid := ""
	for _, cookie := range c.http.Jar.Cookies(base) {
		if cookie.Name == "sid" {
			sid = cookie.Value
			break
		}
		if cookie.Name == "sidTicket" {
			sid = cookie.Value
		}
	}
	if sid == "" {
		return fmt.Errorf("aTrust 尚未签发已认证会话，已停止连接")
	}
	c.SetSession(sid)
	info, err := c.OnlineInfo(ctx)
	if err != nil {
		return gatewayStageError("在线状态查询", err)
	}
	if !info.IsOnline || info.Username == "" {
		return fmt.Errorf("aTrust 尚未确认登录用户，已停止连接")
	}
	// 认证复核可能更新会话 Cookie，数据通道必须使用完成认证后的会话。
	for _, cookie := range c.http.Jar.Cookies(base) {
		if cookie.Name == "sid" && cookie.Value != "" {
			c.SetSession(cookie.Value)
			break
		}
	}
	c.SetUsername(info.Username)
	if _, err := c.ClientResource(ctx); err != nil {
		return gatewayStageError("授权资源获取", err)
	}
	return nil
}

// completeSSOChecks 执行网关指定的复核步骤，不能把额外认证误判为已登录。
func (c *Client) completeSSOChecks(ctx context.Context) error {
	service := "auth/authCheck"
	for step := 0; step < 8; step++ {
		method := http.MethodGet
		var body any
		if service == "auth/accessCheck" {
			method = http.MethodPost
			body = map[string]any{}
		}
		check, err := doJSON[struct {
			NextService     string `json:"nextService"`
			NextServiceList []struct {
				AuthType string `json:"authType"`
			} `json:"nextServiceList"`
		}](ctx, c, requestSpec{method: method, path: "/passport/v1/" + service, query: clientQuery(), jsonBody: body, withCSRF: true, withSession: true})
		if err != nil {
			var api *APIError
			if errors.As(err, &api) {
				return fmt.Errorf("aTrust 会话复核被拒绝（%s，业务码 %d）：%s", service, api.Code, safeGatewayMessage(api.Message))
			}
			return fmt.Errorf("aTrust 会话复核接口失败（%s），未建立目标通道", service)
		}
		service = check.NextService
		if service == "" && len(check.NextServiceList) > 0 {
			service = check.NextServiceList[0].AuthType
		}
		switch service {
		case "":
			return nil
		case "auth/authCheck", "auth/accessCheck":
			continue
		case "auth/sms", "auth/customSms", "auth/otp", "auth/totp":
			return fmt.Errorf("aTrust 网关要求额外认证（%s），当前版本尚未完成该步骤", service)
		default:
			return fmt.Errorf("aTrust 网关要求尚未支持的额外认证或终端准入，未建立目标通道")
		}
	}
	return fmt.Errorf("aTrust 会话复核步骤过多，已停止连接")
}

var gatewayOpaqueValue = regexp.MustCompile(`[A-Za-z0-9_./:=+%\-]{12,}`)

// safeGatewayMessage 仅保留简短错误说明，隐藏 URL、票据等不透明长串。
func safeGatewayMessage(value string) string {
	if len(value) > 400 {
		return "网关返回的详细说明已隐藏"
	}
	return gatewayOpaqueValue.ReplaceAllString(strings.Join(strings.Fields(value), " "), "[已隐藏]")
}

func gatewayStageError(stage string, err error) error {
	var api *APIError
	if errors.As(err, &api) {
		return fmt.Errorf("aTrust %s失败（业务码 %d）：%s", stage, api.Code, safeGatewayMessage(api.Message))
	}
	return fmt.Errorf("aTrust %s接口失败，未建立目标通道", stage)
}
