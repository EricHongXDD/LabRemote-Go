package browserproxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

const bootstrapPrefix = "/__labremote_browser__/"

type Dialer interface {
	DialWebContext(ctx context.Context, profileID, network, address string) (net.Conn, error)
}

type session struct {
	id           string
	profileID    string
	targetKey    string
	token        string
	cookieName   string
	bootstrapURL string
	server       *http.Server
	transport    *http.Transport
	listener     net.Listener
	closeOnce    sync.Once
}

type Manager struct {
	dialer   Dialer
	mu       sync.Mutex
	sessions map[string]map[string]*session
}

func NewManager(dialer Dialer) *Manager {
	return &Manager{dialer: dialer, sessions: make(map[string]map[string]*session)}
}

func ValidateTargetURL(rawURL string) error {
	_, err := normalizeTargetURL(rawURL)
	return err
}

func (m *Manager) Open(ctx context.Context, profileID, rawURL string) (string, error) {
	target, err := normalizeTargetURL(rawURL)
	if err != nil {
		return "", err
	}
	targetKey := target.String()

	m.mu.Lock()
	for _, current := range m.sessions[profileID] {
		if current.targetKey == targetKey {
			value := current.bootstrapURL
			m.mu.Unlock()
			return value, nil
		}
	}
	m.mu.Unlock()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", model.NewAppError("BROWSER_PROXY_START_FAILED", "无法启动本机网页访问代理", "browser_proxy", true).WithDetails(map[string]any{"reason": err.Error()})
	}
	token, err := randomToken(32)
	if err != nil {
		_ = listener.Close()
		return "", model.NewAppError("BROWSER_PROXY_START_FAILED", "无法创建网页访问会话", "browser_proxy", true)
	}
	id, err := randomToken(12)
	if err != nil {
		_ = listener.Close()
		return "", model.NewAppError("BROWSER_PROXY_START_FAILED", "无法创建网页访问会话", "browser_proxy", true)
	}
	localOrigin := "http://" + listener.Addr().String()
	current := &session{
		id: id, profileID: profileID, targetKey: targetKey, token: token,
		cookieName:   "labremote_browser_" + id,
		bootstrapURL: localOrigin + bootstrapPrefix + token,
		listener:     listener,
	}
	current.transport = &http.Transport{
		Proxy: nil,
		DialContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			return m.dialer.DialWebContext(dialContext, profileID, network, address)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	proxy := reverseProxy(target, localOrigin, current.cookieName, current.transport)
	current.server = &http.Server{
		Handler:           current.authorize(target, proxy),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	m.mu.Lock()
	if m.sessions[profileID] == nil {
		m.sessions[profileID] = make(map[string]*session)
	}
	// 并发打开同一目标时复用先创建的代理，避免多余监听端口。
	for _, existing := range m.sessions[profileID] {
		if existing.targetKey == targetKey {
			value := existing.bootstrapURL
			m.mu.Unlock()
			_ = listener.Close()
			current.transport.CloseIdleConnections()
			return value, nil
		}
	}
	m.sessions[profileID][id] = current
	m.mu.Unlock()

	go func() {
		err := current.server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			_ = current.close(context.Background())
		}
		m.remove(current)
	}()
	return current.bootstrapURL, nil
}

func (m *Manager) Count(profileID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions[profileID])
}

func (m *Manager) CloseProfile(ctx context.Context, profileID string) {
	m.mu.Lock()
	values := make([]*session, 0, len(m.sessions[profileID]))
	for _, current := range m.sessions[profileID] {
		values = append(values, current)
	}
	delete(m.sessions, profileID)
	m.mu.Unlock()
	for _, current := range values {
		_ = current.close(ctx)
	}
}

func (m *Manager) CloseAll(ctx context.Context) {
	m.mu.Lock()
	values := make([]*session, 0)
	for _, profileSessions := range m.sessions {
		for _, current := range profileSessions {
			values = append(values, current)
		}
	}
	m.sessions = make(map[string]map[string]*session)
	m.mu.Unlock()
	for _, current := range values {
		_ = current.close(ctx)
	}
}

func (m *Manager) remove(value *session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions[value.profileID][value.id] == value {
		delete(m.sessions[value.profileID], value.id)
		if len(m.sessions[value.profileID]) == 0 {
			delete(m.sessions, value.profileID)
		}
	}
}

func (s *session) close(ctx context.Context) error {
	var result error
	s.closeOnce.Do(func() {
		result = s.server.Shutdown(ctx)
		if result != nil {
			_ = s.server.Close()
		}
		s.transport.CloseIdleConnections()
		_ = s.listener.Close()
	})
	return result
}

func (s *session) authorize(target *url.URL, next http.Handler) http.Handler {
	initialLocation := target.EscapedPath()
	if initialLocation == "" {
		initialLocation = "/"
	}
	if target.RawQuery != "" {
		initialLocation += "?" + target.RawQuery
	}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == bootstrapPrefix+s.token {
			http.SetCookie(response, &http.Cookie{
				Name: s.cookieName, Value: s.token, Path: "/", HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			response.Header().Set("Cache-Control", "no-store")
			http.Redirect(response, request, initialLocation, http.StatusSeeOther)
			return
		}
		cookie, err := request.Cookie(s.cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.token)) != 1 {
			response.Header().Set("Cache-Control", "no-store")
			http.Error(response, "LabRemote 网页访问会话无效，请从客户端重新打开。", http.StatusForbidden)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func reverseProxy(target *url.URL, localOrigin, cookieName string, transport http.RoundTripper) *httputil.ReverseProxy {
	targetOrigin := target.Scheme + "://" + target.Host
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			request.SetURL(&url.URL{Scheme: target.Scheme, Host: target.Host})
			request.Out.Host = target.Host
			request.Out.Header.Del("Forwarded")
			request.Out.Header["X-Forwarded-For"] = nil
			request.Out.Header.Del("X-Forwarded-Host")
			request.Out.Header.Del("X-Forwarded-Proto")
			removeCookie(request.Out, cookieName)
			rewriteRequestOrigin(request.Out, localOrigin, targetOrigin)
		},
		ModifyResponse: func(response *http.Response) error {
			rewriteLocation(response, target, localOrigin)
			rewriteResponseCookies(response)
			for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
				if value := response.Header.Get(name); value != "" {
					response.Header.Set(name, strings.ReplaceAll(value, targetOrigin, localOrigin))
				}
			}
			return nil
		},
		ErrorHandler: func(response http.ResponseWriter, _ *http.Request, err error) {
			response.Header().Set("Cache-Control", "no-store")
			response.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(response, "LabRemote 无法通过隔离隧道访问该资源。\n"+err.Error())
		},
	}
	return proxy
}

func rewriteLocation(response *http.Response, target *url.URL, localOrigin string) {
	value := response.Header.Get("Location")
	if value == "" {
		return
	}
	location, err := url.Parse(value)
	if err != nil || !location.IsAbs() {
		return
	}
	if strings.EqualFold(location.Scheme, target.Scheme) && strings.EqualFold(location.Host, target.Host) {
		response.Header.Set("Location", localOrigin+location.EscapedPath()+querySuffix(location.RawQuery)+fragmentSuffix(location.Fragment))
	}
}

func rewriteRequestOrigin(request *http.Request, localOrigin, targetOrigin string) {
	if strings.EqualFold(request.Header.Get("Origin"), localOrigin) {
		request.Header.Set("Origin", targetOrigin)
	}
	if referer := request.Header.Get("Referer"); strings.HasPrefix(referer, localOrigin) {
		request.Header.Set("Referer", targetOrigin+strings.TrimPrefix(referer, localOrigin))
	}
}

func removeCookie(request *http.Request, name string) {
	values := request.Cookies()
	request.Header.Del("Cookie")
	for _, value := range values {
		if value.Name != name {
			request.AddCookie(value)
		}
	}
}

func rewriteResponseCookies(response *http.Response) {
	values := response.Header.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}
	response.Header.Del("Set-Cookie")
	for _, value := range values {
		parts := strings.Split(value, ";")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			lower := strings.ToLower(trimmed)
			if strings.HasPrefix(lower, "domain=") || lower == "secure" {
				continue
			}
			if lower == "samesite=none" {
				trimmed = "SameSite=Lax"
			}
			result = append(result, trimmed)
		}
		response.Header.Add("Set-Cookie", strings.Join(result, "; "))
	}
}

func normalizeTargetURL(raw string) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, model.NewAppError("BROWSER_URL_INVALID", "请输入要访问的 HTTP 或 HTTPS 地址", "browser_proxy", false)
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	target, err := url.Parse(value)
	if err != nil || target.Hostname() == "" {
		return nil, model.NewAppError("BROWSER_URL_INVALID", "网页访问地址格式无效", "browser_proxy", false)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, model.NewAppError("BROWSER_URL_INVALID", "网页访问仅支持 http:// 或 https:// 地址", "browser_proxy", false)
	}
	if target.User != nil {
		return nil, model.NewAppError("BROWSER_URL_INVALID", "网页访问地址不能包含用户名或密码", "browser_proxy", false)
	}
	if target.Fragment != "" {
		target.Fragment = ""
	}
	hostname := strings.TrimSpace(target.Hostname())
	if ip := net.ParseIP(hostname); ip != nil {
		if ip.To4() == nil {
			return nil, model.NewAppError("BROWSER_TARGET_DENIED", "当前隔离隧道仅支持 IPv4 浏览目标", "browser_proxy", false)
		}
		if ip.IsUnspecified() || ip.IsMulticast() {
			return nil, model.NewAppError("BROWSER_TARGET_DENIED", "该浏览目标地址不允许通过隔离隧道访问", "browser_proxy", false)
		}
	}
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, model.NewAppError("BROWSER_URL_INVALID", "网页访问端口必须在 1 到 65535 之间", "browser_proxy", false)
	}
	target.Host = net.JoinHostPort(hostname, port)
	if (target.Scheme == "http" && port == "80") || (target.Scheme == "https" && port == "443") {
		target.Host = hostname
	}
	return target, nil
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func querySuffix(value string) string {
	if value == "" {
		return ""
	}
	return "?" + value
}

func fragmentSuffix(value string) string {
	if value == "" {
		return ""
	}
	return "#" + value
}
