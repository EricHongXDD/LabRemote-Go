package profile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

func repositoryProfile(id, connectionName string) model.ConnectionProfile {
	return model.ConnectionProfile{
		ID: id, DisplayName: connectionName,
		VPN:       model.VPNConfig{ConnectionName: connectionName, ServerAddress: "vpn.example.com", Type: model.VPNTypeL2TPPSK, Username: "user", SplitTunnel: true},
		SSH:       model.SSHConfig{ServerAddress: "192.168.190.10", Port: 22, Username: "lab"},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
}

func TestJSONRepositoryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	repository := NewJSONRepository(path)
	ctx := context.Background()
	if err := repository.Upsert(ctx, repositoryProfile("one", "实验室")); err != nil {
		t.Fatal(err)
	}
	values, err := repository.List(ctx)
	if err != nil || len(values) != 1 || values[0].ID != "one" {
		t.Fatalf("读取结果异常: %#v, %v", values, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2", "super-secret-psk", "ssh-secret"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("配置文件不应出现秘密值 %q", secret)
		}
	}
}

func TestJSONRepositoryRejectsDuplicateDisplayName(t *testing.T) {
	repository := NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	ctx := context.Background()
	if err := repository.Upsert(ctx, repositoryProfile("one", "同名 VPN")); err != nil {
		t.Fatal(err)
	}
	if err := repository.Upsert(ctx, repositoryProfile("two", "同名 VPN")); err == nil {
		t.Fatal("同名连接配置应被拒绝")
	}
}

func TestJSONRepositoryRejectsDuplicateDisplayNameAcrossModes(t *testing.T) {
	repository := NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	ctx := context.Background()
	first := repositoryProfile("one", "同名连接")
	if err := repository.Upsert(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := model.ConnectionProfile{
		ID: "two", DisplayName: "同名连接", ConnectionMode: model.ConnectionModeDirectSSH,
		SSH: model.SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "user"},
	}
	if err := repository.Upsert(ctx, second); err == nil {
		t.Fatal("不同连接方式也不应允许重复显示名称")
	}
}

func TestJSONRepositoryMigratesLegacyConnectionMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	legacy := repositoryProfile("legacy", "旧配置")
	data, err := json.Marshal([]model.ConnectionProfile{legacy})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := NewJSONRepository(path).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].ConnectionMode != model.ConnectionModeIsolatedTunnel || values[0].SSH.AuthMethod != model.SSHAuthPassword {
		t.Fatalf("旧配置连接方式迁移异常: %#v", values)
	}
}
