package model

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeATrustAddress 仅接受 HTTPS 服务入口，不允许保存凭据、回调令牌或可执行协议。
func NormalizeATrustAddress(value string) (string, error) {
	invalid := func() (string, error) {
		return "", NewAppError("PROFILE_INVALID", "请输入有效的 aTrust HTTPS 服务器地址（仅主机名及可选端口）", "atrust", false)
	}
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n\t\\") {
		return invalid()
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || !validHost(u.Hostname()) {
		return invalid()
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return invalid()
		}
		host = net.JoinHostPort(u.Hostname(), strconv.Itoa(n))
	} else if strings.HasSuffix(u.Host, ":") {
		return invalid()
	}
	return "https://" + host, nil
}
