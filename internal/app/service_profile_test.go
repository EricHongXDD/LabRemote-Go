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

func TestSaveProfileCopyPreservesConfigurationCredentialsAndKnownHost(t *testing.T) {
	service, secretStore := newProfileTestService(t)
	source, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "实验室主机", Group: "课题组", ConnectionMode: model.ConnectionModeIsolatedTunnel,
			VPN: model.VPNConfig{
				ServerAddress: "vpn.example.com", ServerPort: 992, HubName: "LAB",
				ServerCertificate: "SHA256:tunnel", Username: "vpn-user",
			},
			SSH:       model.SSHConfig{ServerAddress: "192.168.1.20", Port: 22, Username: "ssh-user"},
			MCPPolicy: model.MCPPolicy{EnabledForProfile: true, AllowExec: true, AllowFileUpload: true},
		},
		VPNPreSharedKey: "legacy-psk", VPNPassword: "vpn-secret", SSHPassword: "ssh-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.knownHosts.Store(sshclient.HostKeyRecord{
		ProfileID: source.ID, Address: "192.168.1.20:22", KeyType: "ssh-ed25519", Fingerprint: "SHA256:ssh",
	}); err != nil {
		t.Fatal(err)
	}

	copyDraft := source
	copyDraft.ID = ""
	copyDraft.DisplayName = "实验室主机副本"
	copyDraft.SSH.Username = "new-ssh-user"
	copy, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: copyDraft, CopyFromProfileID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if copy.ID == "" || copy.ID == source.ID {
		t.Fatalf("副本应生成独立 ID: source=%q copy=%q", source.ID, copy.ID)
	}
	if copy.DisplayName != "实验室主机副本" || copy.Group != source.Group || copy.SSH.Username != "new-ssh-user" {
		t.Fatalf("副本配置或用户修改未保存: %#v", copy)
	}
	if copy.VPN.ServerAddress != source.VPN.ServerAddress || copy.VPN.HubName != source.VPN.HubName || copy.VPN.ServerCertificate != source.VPN.ServerCertificate {
		t.Fatalf("隔离隧道配置未完整复制: %#v", copy.VPN)
	}
	if copy.MCPPolicy != source.MCPPolicy {
		t.Fatalf("MCP 最小权限未复制: %#v", copy.MCPPolicy)
	}
	for _, item := range []struct {
		name string
		key  string
		want string
	}{
		{name: "兼容预共享密钥", key: model.VPNPSKKey(copy.ID), want: "legacy-psk"},
		{name: "隔离隧道密码", key: model.VPNPasswordKey(copy.ID), want: "vpn-secret"},
		{name: "SSH 密码", key: model.SSHPasswordKey(copy.ID), want: "ssh-secret"},
	} {
		actual, getErr := secretStore.Get(context.Background(), item.key)
		if getErr != nil || string(actual) != item.want {
			t.Fatalf("%s未安全复制: %q, %v", item.name, actual, getErr)
		}
		secrets.Zero(actual)
	}
	record, ok, err := service.knownHosts.Lookup(copy.ID)
	if err != nil || !ok || record.Fingerprint != "SHA256:ssh" {
		t.Fatalf("相同 SSH 端点的主机指纹信任未复制: %#v, %v", record, err)
	}
	changedTunnelDraft := source
	changedTunnelDraft.ID = ""
	changedTunnelDraft.DisplayName = "其他隧道副本"
	changedTunnelDraft.VPN.ServerAddress = "other-vpn.example.com"
	changedTunnel, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: changedTunnelDraft, CopyFromProfileID: source.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if changedTunnel.VPN.ServerCertificate != "" {
		t.Fatalf("修改隧道端点后不应复制旧服务器证书: %q", changedTunnel.VPN.ServerCertificate)
	}
	storedSource, err := service.GetProfile(context.Background(), source.ID)
	if err != nil || storedSource.DisplayName != "实验室主机" || storedSource.SSH.Username != "ssh-user" {
		t.Fatalf("复制不应修改来源连接: %#v, %v", storedSource, err)
	}
}

func TestSaveProfileCopySupportsEncryptedPrivateKeyAndCredentialOverride(t *testing.T) {
	service, secretStore := newProfileTestService(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "LabRemote copy test", []byte("source-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "密钥连接", ConnectionMode: model.ConnectionModeDirectSSH,
			SSH: model.SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "user", AuthMethod: model.SSHAuthPrivateKey},
		},
		SSHPrivateKeyPath: keyPath, SSHPrivateKeyPassphrase: "source-passphrase",
	})
	if err != nil {
		t.Fatal(err)
	}
	copyDraft := source
	copyDraft.ID = ""
	copyDraft.DisplayName = "密钥连接副本"
	copy, err := service.SaveProfile(context.Background(), SaveProfileRequest{Profile: copyDraft, CopyFromProfileID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	storedPath, err := secretStore.Get(context.Background(), model.SSHPrivateKeyPathKey(copy.ID))
	if err != nil || string(storedPath) != keyPath {
		t.Fatalf("私钥路径未复制: %q, %v", storedPath, err)
	}
	secrets.Zero(storedPath)
	storedPassphrase, err := secretStore.Get(context.Background(), model.SSHPrivateKeyPassphraseKey(copy.ID))
	if err != nil || string(storedPassphrase) != "source-passphrase" {
		t.Fatalf("私钥口令未复制: %q, %v", storedPassphrase, err)
	}
	secrets.Zero(storedPassphrase)

	overrideDraft := source
	overrideDraft.ID = ""
	overrideDraft.DisplayName = "密码连接副本"
	overrideDraft.SSH.AuthMethod = model.SSHAuthPassword
	override, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: overrideDraft, CopyFromProfileID: source.ID, SSHPassword: "new-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	overriddenPassword, err := secretStore.Get(context.Background(), model.SSHPasswordKey(override.ID))
	if err != nil || string(overriddenPassword) != "new-password" {
		t.Fatalf("修改认证方式后提供的新密码未保存: %q, %v", overriddenPassword, err)
	}
	secrets.Zero(overriddenPassword)
}

func TestSaveProfileCopyDoesNotReuseTrustForChangedEndpointOrAllowEditSource(t *testing.T) {
	service, _ := newProfileTestService(t)
	source, err := service.SaveProfile(context.Background(), SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "原连接", ConnectionMode: model.ConnectionModeDirectSSH,
			SSH: model.SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "user"},
		},
		SSHPassword: "ssh-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.knownHosts.Store(sshclient.HostKeyRecord{
		ProfileID: source.ID, Address: "ssh.example.com:22", KeyType: "ssh-ed25519", Fingerprint: "SHA256:source",
	}); err != nil {
		t.Fatal(err)
	}
	copyDraft := source
	copyDraft.ID = ""
	copyDraft.DisplayName = "新端点副本"
	copyDraft.SSH.ServerAddress = "other.example.com"
	copy, err := service.SaveProfile(context.Background(), SaveProfileRequest{Profile: copyDraft, CopyFromProfileID: source.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, lookupErr := service.knownHosts.Lookup(copy.ID); lookupErr != nil || ok {
		t.Fatalf("修改 SSH 端点后不应复制旧主机指纹信任: ok=%v err=%v", ok, lookupErr)
	}

	edit := source
	edit.DisplayName = "不允许伪装复制编辑"
	if _, err := service.SaveProfile(context.Background(), SaveProfileRequest{Profile: edit, CopyFromProfileID: source.ID}); err == nil {
		t.Fatal("编辑现有连接时不应接受复制来源 ID")
	}
}
