package profile

import (
	"context"
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

func TestJSONRepositoryRejectsDuplicateVPNName(t *testing.T) {
	repository := NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	ctx := context.Background()
	if err := repository.Upsert(ctx, repositoryProfile("one", "同名 VPN")); err != nil {
		t.Fatal(err)
	}
	if err := repository.Upsert(ctx, repositoryProfile("two", "同名 VPN")); err == nil {
		t.Fatal("同名 VPN 配置应被拒绝")
	}
}
