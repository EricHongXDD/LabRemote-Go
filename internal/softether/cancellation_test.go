package softether

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestProtocolExchangeRespectsCancellationAfterTLS(t *testing.T) {
	for _, enumerate := range []bool{false, true} {
		for _, deadline := range []bool{false, true} {
			name := "认证"
			if enumerate {
				name = "列举Hub"
			}
			if deadline {
				name += "期限"
			} else {
				name += "取消"
			}
			t.Run(name, func(t *testing.T) {
				entered := make(chan struct{}, 1)
				release := make(chan struct{})
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// 接收 TLS 后的协议请求，但不回复，模拟掉线后无法完成认证。
					select {
					case entered <- struct{}{}:
					default:
					}
					<-release
				}))
				defer func() { close(release); server.Close() }()
				parsed, err := url.Parse(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				port, _ := strconv.Atoi(parsed.Port())
				digest := sha256.Sum256(server.Certificate().Raw)
				config := Config{Server: parsed.Hostname(), Port: uint16(port), Hub: "test", Username: "test",
					CertificatePin: "SHA256:" + base64.StdEncoding.EncodeToString(digest[:])}
				ctx, cancel := context.WithCancel(context.Background())
				if deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
				}
				defer cancel()
				done := make(chan error, 1)
				go func() {
					if enumerate {
						_, err := EnumerateHubs(ctx, config)
						done <- err
					} else {
						_, err := Open(ctx, config)
						done <- err
					}
				}()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("未进入 TLS 后的协议等待")
				}
				if !deadline {
					cancel()
				}
				select {
				case err := <-done:
					if err == nil || ctx.Err() == nil {
						t.Fatalf("认证等待未正确取消: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("协议读写没有响应取消")
				}
			})
		}
	}
}
