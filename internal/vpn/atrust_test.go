package vpn

import (
	"context"
	"errors"
	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestATrustNeverFallsBackToSystemNetwork(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	repository := profile.NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	value := model.ConnectionProfile{ID: "isolated-atrust", DisplayName: "aTrust", ConnectionMode: model.ConnectionModeATrustSSH,
		VPN: model.VPNConfig{Type: model.VPNTypeATrust, ServerAddress: "https://vpn.example.com"}, SSH: model.SSHConfig{ServerAddress: "127.0.0.1", Port: uint16(port), Username: "test"}}
	if err := repository.Upsert(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	manager := NewIsolatedManager(repository, secrets.NewMemoryStore(), events.Nop{})
	_, err = manager.DialContext(context.Background(), value.ID, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	var appError *model.AppError
	if !errors.As(err, &appError) || appError.Code != "ATRUST_NOT_CONNECTED" {
		t.Fatalf("未认证时不能直连目标: %v", err)
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(80 * time.Millisecond))
	if connection, err := listener.Accept(); err == nil {
		_ = connection.Close()
		t.Fatal("SSH 目标收到了系统直连，隔离约束被违反")
	}
}
