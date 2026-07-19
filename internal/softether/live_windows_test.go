//go:build windows

package softether_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/softether"
)

func TestLiveIsolatedSSHTransport(t *testing.T) {
	profileID := os.Getenv("LABREMOTE_LIVE_PROFILE_ID")
	if profileID == "" {
		t.Skip("未设置 LABREMOTE_LIVE_PROFILE_ID")
	}
	configRoot, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	repository := profile.NewJSONRepository(filepath.Join(configRoot, "LabRemote", "profiles.json"))
	value, err := repository.Get(context.Background(), profileID)
	if err != nil {
		t.Fatal(err)
	}
	password, err := secrets.NewWindowsStore().Get(context.Background(), model.VPNPasswordKey(profileID))
	if err != nil {
		t.Fatal(err)
	}
	defer secrets.Zero(password)
	port := value.VPN.ServerPort
	if port == 0 {
		port = 992
	}
	config := softether.Config{
		Server: value.VPN.ServerAddress, Port: port, Hub: value.VPN.HubName,
		Username: value.VPN.Username, Password: password, CertificatePin: value.VPN.ServerCertificate,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	session, err := softether.Open(ctx, config)
	if config.CertificatePin == "" {
		var certificateError *softether.CertificateError
		if !errors.As(err, &certificateError) || certificateError.Kind != "unknown" {
			t.Fatalf("首次连接应返回可固定的服务器证书: %v", err)
		}
		config.CertificatePin = certificateError.Fingerprint
		session, err = softether.Open(ctx, config)
	}
	if err != nil {
		t.Fatal(err)
	}
	link, err := softether.NewLink(ctx, session)
	if err != nil {
		_ = session.Close()
		t.Fatal(err)
	}
	defer link.Close()
	lease := link.Lease()
	t.Logf("DHCP 租约: address=%s mask=%s gateway=%s dns=%s", lease.Address, net.IP(lease.Mask), lease.Gateway, lease.DNS)
	address := net.JoinHostPort(strings.Trim(value.SSH.ServerAddress, "[]"), strconv.Itoa(int(value.SSH.Port)))
	connection, err := link.DialContext(ctx, "tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	banner := make([]byte, 255)
	read, err := connection.Read(banner)
	if err != nil {
		t.Fatal(err)
	}
	if read < 4 || string(banner[:4]) != "SSH-" {
		t.Fatal("目标端口未返回 SSH banner")
	}
}
