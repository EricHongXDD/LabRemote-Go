package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) })
	handler := securityMiddleware(next, "correct-token", 38765, newRateLimiter(10))
	tests := []struct {
		name   string
		host   string
		origin string
		token  string
		want   int
	}{
		{"允许本机鉴权请求", "127.0.0.1:38765", "", "Bearer correct-token", http.StatusNoContent},
		{"拒绝错误令牌", "127.0.0.1:38765", "", "Bearer wrong", http.StatusUnauthorized},
		{"拒绝外部 Host", "evil.example:38765", "", "Bearer correct-token", http.StatusForbidden},
		{"拒绝外部 Origin", "127.0.0.1:38765", "https://evil.example", "Bearer correct-token", http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:38765/mcp", nil)
			request.RemoteAddr = "127.0.0.1:50000"
			request.Host = test.host
			request.Header.Set("Authorization", test.token)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("状态码 got %d, want %d", response.Code, test.want)
			}
		})
	}
}
