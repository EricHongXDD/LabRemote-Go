//go:build windows

package browserproxy_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/browserproxy"
	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
)

func TestLiveBrowserResourceThroughIsolatedTunnel(t *testing.T) {
	profileID := os.Getenv("LABREMOTE_LIVE_PROFILE_ID")
	targetURL := os.Getenv("LABREMOTE_LIVE_WEB_URL")
	if profileID == "" || targetURL == "" {
		t.Skip("未设置 LABREMOTE_LIVE_PROFILE_ID 和 LABREMOTE_LIVE_WEB_URL")
	}
	configRoot, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	repository := profile.NewJSONRepository(filepath.Join(configRoot, "LabRemote", "profiles.json"))
	transport := vpn.NewIsolatedManager(repository, secrets.NewWindowsStore(), events.Nop{})
	sshManager := sshclient.NewManager(repository, secrets.NewWindowsStore(), sshclient.NewKnownHosts(filepath.Join(configRoot, "LabRemote", "known_hosts")), events.Nop{}, transport)
	manager := browserproxy.NewManager(sshManager)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	defer manager.CloseAll(context.Background())
	defer sshManager.CloseAll(context.Background())
	defer transport.Shutdown(context.Background())
	if _, err := transport.Connect(ctx, profileID); err != nil {
		t.Fatal(err)
	}
	if err := sshManager.Connect(ctx, profileID); err != nil {
		t.Fatal(err)
	}
	bootstrapURL, err := manager.Open(ctx, profileID, targetURL)
	if err != nil {
		t.Fatal(err)
	}
	localURL, err := url.Parse(bootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 25 * time.Second,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			// 验收请求不允许跳出本机隔离代理。
			if request.URL.Host != localURL.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	response, err := client.Get(bootstrapURL)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode == http.StatusBadGateway {
		t.Fatalf("隔离浏览器代理未能到达目标资源: %s", body)
	}
}
