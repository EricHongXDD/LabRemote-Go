//go:build windows

package atrust

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	protocol "github.com/EricHongXDD/LabRemote-Go/internal/atrust/protocol"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

// 只复核 LabRemote 自己保存的指定会话，不发起网页登录，也不访问其他客户端凭据。
func TestLiveRememberedSessionValidation(t *testing.T) {
	if os.Getenv("LABREMOTE_ATRUST_SESSION_INTEGRATION") != "1" {
		t.Skip("需要显式启用 aTrust 已保存会话集成测试")
	}
	server, err := model.NormalizeATrustAddress(os.Getenv("LABREMOTE_ATRUST_SERVER"))
	if err != nil {
		t.Fatal("需要指定有效的 aTrust 服务器")
	}
	profileID := os.Getenv("LABREMOTE_ATRUST_PROFILE_ID")
	if profileID == "" {
		t.Fatal("需要指定已授权的配置 ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	saved, err := loadRemembered(ctx, secrets.NewPlatformStore(), profileID, server)
	if err != nil || saved == nil || saved.State == nil {
		t.Fatal("指定配置没有可恢复的登录票据")
	}
	root, err := os.UserConfigDir()
	if err != nil {
		t.Fatal("无法定位应用配置")
	}
	value, err := profile.NewJSONRepository(filepath.Join(root, "LabRemote", "profiles.json")).Get(ctx, profileID)
	if err != nil || value.EffectiveConnectionMode() != model.ConnectionModeATrustSSH || value.VPN.ServerAddress != server {
		t.Fatal("指定配置与测试网关不一致")
	}
	client, err := protocol.NewClient(server, protocol.Options{GatewayTLS: func(address string) *tls.Config {
		return gatewayTLS(address, value.VPN.ServerCertificate)
	}})
	if err != nil {
		t.Fatal("无法创建 HTTPS 控制面客户端")
	}
	defer client.Close()
	client.SetDeviceID(saved.Device)
	if err := client.ResumeSession(ctx, *saved.State); err != nil {
		if code, ok := protocol.IsAPIError(err); ok {
			t.Fatalf("服务端会话查询业务码：%d", code)
		}
		var status *protocol.HTTPStatusError
		if errors.As(err, &status) {
			t.Fatalf("会话查询 HTTP 状态：%d", status.StatusCode)
		}
		t.Fatalf("已保存会话未通过数据授权校验，未发起重新认证：%v", err)
	}
	for index := 0; index < 3; index++ {
		if err := client.CheckSession(ctx, client.Username()); err != nil {
			t.Fatal("重复在线检查失败，未发起重新认证")
		}
	}
	connection, err := client.DialTCP(ctx, strings.Trim(value.SSH.ServerAddress, "[]"), int(value.SSH.Port))
	if err != nil {
		t.Fatalf("目标数据通道未建立：%v", err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(connection, buffer); err != nil || string(buffer) != "SSH-" {
		t.Fatal("未收到目标 SSH 握手标识")
	}
	t.Log("新客户端恢复、三次授权检查及新数据通道 SSH 握手成功，全程未调用登录入口")
}

// 明确预期票据已过期时，只验证是否转入认证；模拟认证入口，不打开真实登录页或改动系统票据。
func TestLiveExpiredSessionRequestsLogin(t *testing.T) {
	if os.Getenv("LABREMOTE_ATRUST_EXPECT_EXPIRED") != "1" {
		t.Skip("需要显式启用已过期票据的真实网关诊断")
	}
	server, err := model.NormalizeATrustAddress(os.Getenv("LABREMOTE_ATRUST_SERVER"))
	if err != nil {
		t.Fatal("需要有效的测试网关")
	}
	profileID := os.Getenv("LABREMOTE_ATRUST_PROFILE_ID")
	if profileID == "" {
		t.Fatal("需要指定已授权配置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	platform := secrets.NewPlatformStore()
	key := CredentialKey(profileID, server)
	before, err := platform.Get(ctx, key)
	if err != nil {
		t.Fatal("没有应用自身保存的测试票据")
	}
	defer secrets.Zero(before)
	memory := secrets.NewMemoryStore()
	if err := memory.Put(ctx, key, before); err != nil {
		t.Fatal(err)
	}
	var requested atomic.Int32
	auth := NewAuthBroker(nil)
	stop := errors.New("已进入待用户认证阶段")
	auth.open = func(context.Context, string, string) (string, error) {
		requested.Add(1)
		return "", stop
	}
	session, err := Open(ctx, Config{Server: server, ProfileID: profileID, Credentials: memory, Auth: auth})
	if session != nil {
		_ = session.Close()
	}
	if !errors.Is(err, stop) || requested.Load() != 1 {
		t.Fatalf("过期票据未正确转入认证：%v", err)
	}
	after, err := platform.Get(ctx, key)
	defer secrets.Zero(after)
	if err != nil || string(before) != string(after) {
		t.Fatal("诊断不应修改系统凭据")
	}
	t.Log("真实过期票据已触发一次认证，系统票据未被改动")
}
