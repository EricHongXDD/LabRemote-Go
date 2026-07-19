package mcpserver

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type rateLimiter struct {
	mu     sync.Mutex
	window time.Time
	count  int
	limit  int
}

func newRateLimiter(limit int) *rateLimiter {
	return &rateLimiter{window: time.Now(), limit: limit}
}

func (l *rateLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.window) >= time.Minute {
		l.window = now
		l.count = 0
	}
	if l.count >= l.limit {
		return false
	}
	l.count++
	return true
}

func securityMiddleware(next http.Handler, token string, port int, limiter *rateLimiter) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			http.Error(response, "forbidden", http.StatusForbidden)
			return
		}
		allowedHost := request.Host == net.JoinHostPort("127.0.0.1", itoa(port)) || request.Host == net.JoinHostPort("localhost", itoa(port))
		if !allowedHost {
			http.Error(response, "forbidden host", http.StatusForbidden)
			return
		}
		if origin := request.Header.Get("Origin"); origin != "" {
			parsed, parseErr := url.Parse(origin)
			originHost := strings.ToLower(parsed.Hostname())
			if parseErr != nil || (originHost != "127.0.0.1" && originHost != "localhost") {
				http.Error(response, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		authorization := request.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(authorization, "Bearer ")), []byte(token)) != 1 {
			response.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !limiter.Allow() {
			response.Header().Set("Retry-After", "60")
			http.Error(response, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	buffer := [20]byte{}
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}
