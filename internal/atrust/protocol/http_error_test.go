package atrust

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPErrorPreservesSessionCodeAndRedactsDetails(t *testing.T) {
	for _, body := range []string{
		`{"code":75500002,"message":"session expired secret-ticket-must-not-appear","data":{"sid":"secret-ticket-must-not-appear"}}`,
		`{"code":"75500002","message":"session expired secret-ticket-must-not-appear"}`,
	} {
		err := httpStatusError(http.StatusForbidden, pathClientResource, []byte(body))
		var status *HTTPStatusError
		var api *APIError
		if !errors.As(err, &status) || status.StatusCode != 403 || !errors.As(err, &api) || api.Code != 75500002 {
			t.Fatal("HTTP 错误丢失了网关业务码")
		}
		if !errors.Is(sessionCheckFailure("授权资源查询", err), ErrNoSession) {
			t.Fatal("明确的过期业务码没有触发会话更新")
		}
		if strings.Contains(err.Error(), "secret-ticket") {
			t.Fatal("错误说明泄露票据")
		}
	}
}

func TestUnknownHTTP403DoesNotForceAuthenticationOrExposeBody(t *testing.T) {
	for _, body := range []string{
		`<html>secret-ticket-must-not-appear</html>`,
		`{"code":75599999,"message":"permission denied","data":{"sid":"secret-ticket-must-not-appear"}}`,
		`{"code":"invalid","message":"secret-ticket-must-not-appear"}`,
	} {
		err := httpStatusError(http.StatusForbidden, pathClientResource, []byte(body))
		if errors.Is(sessionCheckFailure("授权资源查询", err), ErrNoSession) {
			t.Fatal("未知的 403 不应自动清除认证或重新登录")
		}
		if strings.Contains(err.Error(), "secret-ticket") {
			t.Fatal("未知响应正文泄露到错误信息")
		}
	}
}
