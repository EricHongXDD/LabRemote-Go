//go:build windows && legacy_ras

package vpn

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

func TestLiveVPNConnectAndSSHRoute(t *testing.T) {
	if os.Getenv("LABREMOTE_LIVE_VPN") != "1" {
		t.Skip("设置 LABREMOTE_LIVE_VPN=1 后才执行真实 VPN 测试")
	}
	profileID := os.Getenv("LABREMOTE_LIVE_PROFILE_ID")
	if profileID == "" {
		t.Fatal("真实 VPN 测试需要 LABREMOTE_LIVE_PROFILE_ID")
	}

	configRoot, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("定位配置目录失败: %v", err)
	}
	repository := profile.NewJSONRepository(filepath.Join(configRoot, "LabRemote", "profiles.json"))
	value, err := repository.Get(context.Background(), profileID)
	if err != nil {
		t.Fatalf("读取测试 Profile 失败: %v", err)
	}
	manager := NewWindowsManager(repository, secrets.NewWindowsStore(), events.Nop{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	status, err := manager.Connect(ctx, profileID)
	if err != nil {
		t.Fatalf("连接 VPN 失败: %v", err)
	}
	defer func() {
		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer disconnectCancel()
		if disconnectErr := manager.Disconnect(disconnectCtx, profileID, true); disconnectErr != nil {
			t.Errorf("测试后断开 VPN 失败: %v", disconnectErr)
		}
	}()
	if status.State != model.VPNConnected || !status.RouteReady {
		t.Fatalf("VPN 状态不符合预期: state=%s route_ready=%t", status.State, status.RouteReady)
	}

	address := net.JoinHostPort(value.SSH.ServerAddress, strconv.Itoa(int(value.SSH.Port)))
	connection, err := net.DialTimeout("tcp", address, 8*time.Second)
	if err != nil {
		t.Fatalf("VPN 已连接但 SSH 目标不可达: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("关闭 SSH 可达性探测连接失败: %v", err)
	}
}
