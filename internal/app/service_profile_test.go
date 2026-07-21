package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/profile"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"github.com/EricHongXDD/LabRemote-Go/internal/vpn"
	"golang.org/x/crypto/ssh"
)

func newProfileTestService(t *testing.T) (*Service, *secrets.MemoryStore) {
	t.Helper()
	repository := profile.NewJSONRepository(filepath.Join(t.TempDir(), "profiles.json"))
	secretStore := secrets.NewMemoryStore()
	knownHosts := sshclient.NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
	transport := vpn.NewIsolatedManager(repository, secretStore, events.Nop{})
	sshManager := sshclient.NewManager(repository, secretStore, knownHosts, events.Nop{}, transport)
	service := NewService(repository, secretStore, transport, sshManager, knownHosts)
	t.Cleanup(func() { service.Shutdown(context.Background()) })
	return service, secretStore
}

func TestSaveDirectSSHProfileRequiresOnlySSHPassword(t *testing.T) {
	service, secretStore := newProfileTestService(t)
	value, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "公网 SSH", ConnectionMode: model.ConnectionModeDirectSSH,
			SSH: model.SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "user"},
		},
		SSHPassword: "ssh-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.ConnectionMode != model.ConnectionModeDirectSSH {
		t.Fatalf("连接方式未保存: %#v", value)
	}
	if value.VPN.CredentialRef != "" {
		t.Fatalf("仅 SSH 配置不应生成隧道凭据引用: %q", value.VPN.CredentialRef)
	}
	sshPassword, err := secretStore.Get(context.Background(), model.SSHPasswordKey(value.ID))
	if err != nil || string(sshPassword) != "ssh-secret" {
		t.Fatalf("SSH 密码保存异常: %q, %v", sshPassword, err)
	}
	if _, err := secretStore.Get(context.Background(), model.VPNPasswordKey(value.ID)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("仅 SSH 配置不应保存隧道密码: %v", err)
	}
}

func TestSaveTunnelProfileStillRequiresTunnelPassword(t *testing.T) {
	service, _ := newProfileTestService(t)
	_, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "实验室", ConnectionMode: model.ConnectionModeIsolatedTunnel,
			VPN: model.VPNConfig{ServerAddress: "vpn.example.com", ServerPort: 992, Username: "vpn-user"},
			SSH: model.SSHConfig{ServerAddress: "192.168.1.10", Port: 22, Username: "ssh-user"},
		},
		SSHPassword: "ssh-secret",
	})
	if err == nil {
		t.Fatal("隔离隧道配置缺少隧道密码时不应保存")
	}
}

func TestSavePrivateKeyProfileStoresOnlyKeyPathAndPassphrase(t *testing.T) {
	service, secretStore := newProfileTestService(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "LabRemote test", []byte("key-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "密钥 SSH", ConnectionMode: model.ConnectionModeDirectSSH,
			SSH: model.SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "user", AuthMethod: model.SSHAuthPrivateKey},
		},
		SSHPrivateKeyPath: keyPath, SSHPrivateKeyPassphrase: "key-passphrase",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.SSH.CredentialRef != model.SSHPrivateKeyPathKey(value.ID) {
		t.Fatalf("私钥凭据引用异常: %q", value.SSH.CredentialRef)
	}
	profileJSON, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profileJSON), keyPath) || strings.Contains(string(profileJSON), "key-passphrase") {
		t.Fatal("Profile JSON 不应包含私钥路径或口令")
	}
	storedPath, err := secretStore.Get(context.Background(), model.SSHPrivateKeyPathKey(value.ID))
	if err != nil || string(storedPath) != keyPath {
		t.Fatalf("私钥路径保存异常: %q, %v", storedPath, err)
	}
	storedPassphrase, err := secretStore.Get(context.Background(), model.SSHPrivateKeyPassphraseKey(value.ID))
	if err != nil || string(storedPassphrase) != "key-passphrase" {
		t.Fatalf("私钥口令保存异常: %q, %v", storedPassphrase, err)
	}
	if _, err := secretStore.Get(context.Background(), model.SSHPasswordKey(value.ID)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("私钥认证配置不应要求 SSH 密码: %v", err)
	}
	if err := service.ClearCredential(context.Background(), value.ID, "ssh_private_key"); err != nil {
		t.Fatal(err)
	}
	if _, err := secretStore.Get(context.Background(), model.SSHPrivateKeyPathKey(value.ID)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("私钥路径未被清除: %v", err)
	}
	if _, err := secretStore.Get(context.Background(), model.SSHPrivateKeyPassphraseKey(value.ID)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("私钥口令未被清除: %v", err)
	}
}
