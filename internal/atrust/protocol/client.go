// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// client.go — aTrust 控制面的 HTTP 客户端。
//
// 这个包只负责"把请求发出去、把 JSON 收回来、把会话维持住"。
// 登录流程的分支判断在 login.go，由调用方决定下一步。
//
// ⚠ 会话机制是这两个问题的来源，改动前请先读 §24.10 与 §24.14：
//
//  1. 渲染层的请求体里 token 恒为空串，会话**完全靠 cookie**。
//     因此 cookie jar 不是可选项，是必需品。
//  2. sessionIdExchange 之后，原生 agent 的后续请求（onlineInfo /
//     passportTokenExchange）既不带头也不带显式凭据，只靠同一条
//     keep-alive 连接上积累的 cookie。

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// apiTimeout 限制单个控制面请求。authConfig 在冷启动的网关上可能较慢。
	apiTimeout = 30 * time.Second

	// userAgent 与官方 aTrustTray 一致。部分网关按 UA 分流行为，
	// 换成别的值可能走到非预期分支。
	userAgent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) aTrustTray/2.5.16.31 Chrome/87.0.4280.141 " +
		"Electron/11.5.0 Safari/537.36 aTrustTray-Windows-Plat SPCClientType"

	// cookieSidTicket 是会话 cookie 名。与请求头 Sid-Ticket 是同一份凭据
	// 的两个通道：浏览器侧用 cookie，原生 agent 用头。
	cookieSidTicket = "sidTicket"
)

// APIError 表示网关返回了非 0 的业务码。
//
// 与传输错误分开是有意义的：传输错误值得重试，业务码不重试。
type APIError struct {
	Code    int
	Message string
	Path    string
}

// HTTPStatusError 只保留状态码和固定接口路径，响应正文不进入错误日志。
type HTTPStatusError struct {
	StatusCode int
	Path       string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("aTrust: %s 返回 HTTP %d，响应正文已隐藏", e.Path, e.StatusCode)
}

func (e *APIError) Error() string {
	return fmt.Sprintf("aTrust %s 返回 %d: %s", e.Path, e.Code, e.Message)
}

// IsAPIError 报告 err 是否是网关业务错误，并取回其码值。
func IsAPIError(err error) (code int, ok bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code, true
	}
	return 0, false
}

// Client 是 aTrust 控制面客户端。
//
// 一个 Client 绑定一个网关地址与一份会话。并发安全（内部有锁），
// 但同一时刻只应有一个登录流程在跑。
type Client struct {
	gatewayTLS func(string) *tls.Config

	baseURL string // 形如 https://host:port，不含尾部斜杠
	http    *http.Client

	mu         sync.RWMutex
	sidTicket  string
	csrfToken  string
	authConfig *AuthConfig

	// ---------- 数据面所需的会话材料（tunnel.go） ----------
	//
	// 这些字段都由控制面流程填充：username 来自登录参数，deviceID 由
	// EnsureDeviceID 生成并持久化，signKey 从 antiMITMAttackData 派生，
	// nodeAddr / currentAppID 在资源树解析后确定。
	username     string
	deviceID     string
	signKey      string
	nodeAddr     string
	currentAppID string
	// resources 保存最近一次资源树解析结果，供 DialTCP 选路。
	resources     *resourceIndex
	resourceShape []string

	// InsecureSkipVerify 由构造时决定。生产环境应当校验证书；
	// 留出这个开关是因为不少内网网关用自签证书——官方客户端自己也
	// 有一条 sslVerify skipped 分支（§25.6.6）。
	logf func(format string, args ...any)
}

// Options 是 NewClient 的可选参数。
type Options struct {
	// GatewayTLS 为数据面提供独立的服务器证书验证策略。
	GatewayTLS func(string) *tls.Config

	// InsecureSkipVerify 跳过 TLS 证书校验。默认 false。
	InsecureSkipVerify bool
	// Timeout 覆盖默认的单请求超时。
	Timeout time.Duration
	// Logf 用于记录协议层事件；nil 表示不记录。
	Logf func(format string, args ...any)
}

// NewClient 创建绑定到 rawURL 的客户端。rawURL 可带或不带 scheme，
// 不带时按 https 处理（aTrust 控制面只有 HTTPS）。
func NewClient(rawURL string, opt Options) (*Client, error) {
	base, err := normalizeBaseURL(rawURL)
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("aTrust: 创建 cookie jar 失败: %w", err)
	}

	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = apiTimeout
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opt.InsecureSkipVerify},
		MaxIdleConnsPerHost: 4,
		// 保持连接复用：会话的 cookie 是在同一条连接上积累的，
		// 频繁重建连接虽然仍有 jar 兜底，但会丢掉服务端的连接级状态。
		ForceAttemptHTTP2: false,
	}

	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	return &Client{
		baseURL:    base,
		gatewayTLS: opt.GatewayTLS,
		http: &http.Client{
			Timeout:   timeout,
			Jar:       jar,
			Transport: transport,
			// 不自动跟随重定向：aTrust 的 30x 往往意味着地址被改写或
			// 网关不可达，静默跟随会把错误伪装成成功。
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logf: logf,
	}, nil
}

// BaseURL 返回规范化后的网关地址（无尾斜杠）。
func (c *Client) BaseURL() string { return c.baseURL }

// SidTicket 返回当前会话票据（未登录时为空）。
func (c *Client) SidTicket() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sidTicket
}

// AuthConfig 返回最近一次取得的配置（未取到时为 nil）。
// 返回的是内部指针，调用方**不得修改**。
func (c *Client) AuthConfig() *AuthConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authConfig
}

// SetSession 手动注入会话票据。
//
// 主要用于两个场景：从持久化状态恢复会话，以及在测试里预置状态。
// 正常登录流程由 psw 的响应自动设置。
func (c *Client) SetSession(sidTicket string) {
	c.mu.Lock()
	c.sidTicket = sidTicket
	c.mu.Unlock()
	c.installCookie(sidTicket)
}

// installCookie 把票据写入 jar。
//
// 这一步不能省：网关侧的后续请求校验的是 Cookie 头，而 jar 只会在
// 收到 Set-Cookie 时自动填充。我们自己构造的票据必须手动放进去。
func (c *Client) installCookie(sid string) {
	u, err := url.Parse(c.baseURL)
	if err != nil || sid == "" {
		return
	}
	c.http.Jar.SetCookies(u, []*http.Cookie{{
		Name:     cookieSidTicket,
		Value:    sid,
		Path:     "/",
		HttpOnly: false, // 渲染层需要读它
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}})
}

// Close 释放空闲连接。
func (c *Client) Close() {
	if t, ok := c.http.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

// ---------- 请求原语 ----------

// requestSpec 描述一次调用。get 与 postJSON 共用同一套头处理。
type requestSpec struct {
	method      string
	path        string // 以 / 开头，可含 query
	query       url.Values
	jsonBody    any
	formBody    url.Values
	withCSRF    bool
	withSession bool
	// rawBody 用于接收原始响应体（manifest.js 之类的非 JSON 响应）。
	rawBody bool
}

// do 执行请求并把响应体读全。非 2xx 一律视为传输层错误。
func (c *Client) do(ctx context.Context, spec requestSpec) ([]byte, error) {
	u := c.baseURL + spec.path
	if len(spec.query) > 0 {
		sep := "?"
		if strings.Contains(spec.path, "?") {
			sep = "&"
		}
		u += sep + spec.query.Encode()
	}

	var body io.Reader
	contentType := ""

	switch {
	case spec.formBody != nil:
		body = strings.NewReader(spec.formBody.Encode())
		contentType = "application/x-www-form-urlencoded"
	case spec.jsonBody != nil:
		buf, err := json.Marshal(spec.jsonBody)
		if err != nil {
			return nil, fmt.Errorf("aTrust: 编码请求体失败: %w", err)
		}
		body = bytes.NewReader(buf)
		contentType = "application/json;charset=utf-8"
	}

	req, err := http.NewRequestWithContext(ctx, spec.method, u, body)
	if err != nil {
		return nil, fmt.Errorf("aTrust: 构造请求失败: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-Sdp-Traceid", newTraceID())

	if spec.withCSRF {
		if tok := c.csrf(); tok != "" {
			req.Header.Set("X-Csrf-Token", tok)
		}
	}
	if spec.withSession {
		// 显式带上头，与 cookie 双保险。官方客户端在不同路径上分别用
		// 这两种通道，两个都提供最稳妥。
		if sid := c.SidTicket(); sid != "" {
			req.Header.Set("Sid-Ticket", sid)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aTrust: 请求 %s 失败: %w", spec.path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("aTrust: 读取 %s 响应失败: %w", spec.path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPStatusError{StatusCode: resp.StatusCode, Path: spec.path}
	}
	return raw, nil
}

// doJSON 执行请求并解出 Envelope[T]。
//
// 这个泛型辅助让每个接口都能拿到强类型，同时统一处理 code != 0。
func doJSON[T any](ctx context.Context, c *Client, spec requestSpec) (*T, error) {
	raw, err := c.do(ctx, spec)
	if err != nil {
		return nil, err
	}

	var env Envelope[T]
	dec := json.NewDecoder(bytes.NewReader(raw))
	// 网关有时会在响应里塞多余字段或把数字写成字符串；不强求严格匹配。
	dec.UseNumber()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("aTrust: %s 响应不是合法 JSON: %w（原文: %s）",
			spec.path, err, "响应正文已隐藏")
	}

	if env.Code != 0 {
		return nil, &APIError{Code: env.Code, Message: env.Message, Path: spec.path}
	}
	return &env.Data, nil
}

func (c *Client) csrf() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.csrfToken
}

// setAuthConfig 记录配置并顺带更新 csrf 令牌。
func (c *Client) setAuthConfig(cfg *AuthConfig) {
	c.mu.Lock()
	c.authConfig = cfg
	if cfg != nil {
		c.csrfToken = cfg.Security.CSRFToken
	}
	c.mu.Unlock()
}

// ---------- 小工具 ----------

func normalizeBaseURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("aTrust: 网关地址为空")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("aTrust: 网关地址无效: %w", err)
	}
	if u.Host == "" {
		return "", errors.New("aTrust: 网关地址缺少主机部分")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("aTrust: 不支持的协议 %q", u.Scheme)
	}
	// 去掉路径与查询：aTrust 的所有端点都是绝对路径。
	return u.Scheme + "://" + u.Host, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
