//go:build windows

package vpn_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/softether"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
)

func TestLiveIsolatedManagerAndSSHAuthentication(t *testing.T) {
	profileID := os.Getenv("LABREMOTE_LIVE_PROFILE_ID")
	if profileID == "" {
		t.Skip("未设置 LABREMOTE_LIVE_PROFILE_ID")
	}
	configRoot, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	realRepository := profile.NewJSONRepository(filepath.Join(configRoot, "LabRemote", "profiles.json"))
	value, err := realRepository.Get(context.Background(), profileID)
	if err != nil {
		t.Fatal(err)
	}
	before, err := snapshotWindowsNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secretStore := secrets.NewWindowsStore()
	password, err := secretStore.Get(context.Background(), model.VPNPasswordKey(profileID))
	if err != nil {
		t.Fatal(err)
	}
	port := value.VPN.ServerPort
	if port == 0 {
		port = 992
	}
	probeContext, probeCancel := context.WithTimeout(context.Background(), 15*time.Second)
	_, err = softether.Open(probeContext, softether.Config{
		Server: value.VPN.ServerAddress, Port: port, Hub: value.VPN.HubName,
		Username: value.VPN.Username, Password: password,
	})
	probeCancel()
	secrets.Zero(password)
	var certificateError *softether.CertificateError
	if !errors.As(err, &certificateError) || certificateError.Kind != "unknown" {
		t.Fatalf("无法取得服务器证书指纹: %v", err)
	}
	value.VPN.ServerCertificate = certificateError.Fingerprint
	value.VPN.ServerPort = port
	value.VPN.Type = model.VPNTypeSoftEther
	value.VPN.SplitTunnel = true
	temporaryRepository := profile.NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	if err := temporaryRepository.Upsert(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	knownHosts := sshclient.NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
	transport := vpn.NewIsolatedManager(temporaryRepository, secretStore, events.Nop{})
	sshManager := sshclient.NewManager(temporaryRepository, secretStore, knownHosts, events.Nop{}, transport)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	defer transport.Shutdown(context.Background())
	defer sshManager.CloseAll(context.Background())
	if _, err := transport.Connect(ctx, profileID); err != nil {
		t.Fatal(err)
	}
	err = sshManager.Connect(ctx, profileID)
	var appError *model.AppError
	if !errors.As(err, &appError) || appError.Code != "SSH_HOST_KEY_UNKNOWN" {
		t.Fatalf("首次 SSH 连接应要求确认主机指纹: %v", err)
	}
	fingerprint, _ := appError.Details["fingerprint"].(string)
	if fingerprint == "" {
		t.Fatal("SSH 主机指纹为空")
	}
	if err := sshManager.AcceptHostKey(profileID, fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := sshManager.Connect(ctx, profileID); err != nil {
		t.Fatal(err)
	}
	if !sshManager.IsConnected(profileID) {
		t.Fatal("SSH 管理器未保持已认证连接")
	}
	middle, err := snapshotWindowsNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sshManager.CloseAll(context.Background())
	transport.Shutdown(context.Background())
	after, err := snapshotWindowsNetwork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, middle) {
		t.Fatal("隔离隧道运行期间 Windows VPN、路由或网卡状态发生变化")
	}
	if !bytes.Equal(before, after) {
		t.Fatal("隔离隧道断开后 Windows VPN、路由或网卡状态未恢复")
	}
}

func snapshotWindowsNetwork(ctx context.Context) ([]byte, error) {
	script := `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$vpn = @(Get-VpnConnection -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object Name,ConnectionStatus,ServerAddress,TunnelType,SplitTunneling)
$routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric,PolicyStore)
$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Sort-Object InterfaceIndex,Name | Select-Object InterfaceIndex,Name,Status,MacAddress,InterfaceDescription)
@{vpn=$vpn;routes=$routes;adapters=$adapters} | ConvertTo-Json -Compress -Depth 5`
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	return command.Output()
}
