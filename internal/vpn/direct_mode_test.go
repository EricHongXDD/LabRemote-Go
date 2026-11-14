package vpn

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

func TestHostNetworkModesDialOnlyConfiguredTarget(t *testing.T) {
	for _, mode := range []model.ConnectionMode{model.ConnectionModeDirectSSH} {
		t.Run(string(mode), func(t *testing.T) { testHostNetworkTarget(t, mode) })
	}
}

func testHostNetworkTarget(t *testing.T, mode model.ConnectionMode) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	repository := profile.NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	value := model.ConnectionProfile{
		ID: "direct", DisplayName: "直接 SSH", ConnectionMode: mode,
		VPN: model.VPNConfig{Type: model.VPNTypeATrust, ServerAddress: "https://vpn.example.com"},
		SSH: model.SSHConfig{ServerAddress: "127.0.0.1", Port: port, Username: "user"},
	}
	if err := repository.Upsert(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	manager := NewIsolatedManager(repository, secrets.NewMemoryStore(), events.Nop{})
	defer manager.Shutdown(context.Background())

	wantState, wantRouteReady := model.VPNNotRequired, true
	status, err := manager.Connect(context.Background(), value.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != wantState || status.RouteReady != wantRouteReady {
		t.Fatalf("仅 SSH 状态异常: %#v", status)
	}

	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			close(accepted)
		}
	}()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	connection, err := manager.DialContext(context.Background(), value.ID, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("直接 SSH 目标未收到连接")
	}

	_, err = manager.DialContext(context.Background(), value.ID, "tcp", "127.0.0.1:1")
	var appError *model.AppError
	if !errors.As(err, &appError) || appError.Code != "TUNNEL_TARGET_DENIED" {
		t.Fatalf("非配置目标应被拒绝: %v", err)
	}
	if err := manager.AcceptCertificate(context.Background(), value.ID, "unused"); !errors.As(err, &appError) || appError.Code != "TUNNEL_NOT_REQUIRED" {
		t.Fatalf("仅 SSH 模式不应接受隧道证书: %v", err)
	}
	if err := manager.Disconnect(context.Background(), value.ID, true); err != nil {
		t.Fatal(err)
	}
	status, err = manager.Status(context.Background(), value.ID)
	if err != nil || status.State != wantState || status.RouteReady != wantRouteReady {
		t.Fatalf("仅 SSH 断开后仍应显示无需隧道: %#v, %v", status, err)
	}
}
