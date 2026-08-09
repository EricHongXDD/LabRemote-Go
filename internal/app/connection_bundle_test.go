package app

import (
	"bytes"
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
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"github.com/EricHongXDD/LabRemote-Go/internal/sshclient"
	"golang.org/x/crypto/ssh"
)

type bundleFailPutStore struct {
	secrets.Store
	suffix string
}

func (s *bundleFailPutStore) Put(ctx context.Context, key string, value []byte) error {
	if strings.HasSuffix(key, s.suffix) {
		return errors.New("测试凭据写入失败")
	}
	return s.Store.Put(ctx, key, value)
}

func TestConnectionBundleRoundTripIncludesCredentialsPrivateKeyAndTrust(t *testing.T) {
	service, secretStore := newProfileTestService(t)
	ctx := context.Background()
	passwordProfile, err := service.SaveProfile(ctx, SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "密码主机", Group: "共享实验室", ConnectionMode: model.ConnectionModeDirectSSH,
			SSH:       model.SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "alice"},
			MCPPolicy: model.MCPPolicy{EnabledForProfile: true, AllowExec: true},
		},
		SSHPassword: "ssh-password-value",
	})
	if err != nil {
		t.Fatal(err)
	}
	trusted := sshclient.HostKeyRecord{
		ProfileID: passwordProfile.ID, Address: "ssh.example.com:22", KeyType: "ssh-ed25519",
		Fingerprint: "SHA256:trusted-host", AcceptedAt: time.Now(),
	}
	if err := service.knownHosts.Store(trusted); err != nil {
		t.Fatal(err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "bundle test", []byte("private-key-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	privateKeyData := pem.EncodeToMemory(block)
	privateKeyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(privateKeyPath, privateKeyData, 0o600); err != nil {
		t.Fatal(err)
	}
	privateKeyProfile, err := service.SaveProfile(ctx, SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "密钥主机", ConnectionMode: model.ConnectionModeIsolatedTunnel,
			VPN: model.VPNConfig{ServerAddress: "vpn.example.com", ServerPort: 992, HubName: "LAB", Username: "vpn-user"},
			SSH: model.SSHConfig{ServerAddress: "192.168.10.8", Port: 22, Username: "bob", AuthMethod: model.SSHAuthPrivateKey},
		},
		VPNPreSharedKey: "legacy-psk-value", VPNPassword: "vpn-password-value",
		SSHPrivateKeyPath: privateKeyPath, SSHPrivateKeyPassphrase: "private-key-passphrase",
	})
	if err != nil {
		t.Fatal(err)
	}

	bundle, count, err := service.ExportConnectionBundle(ctx, []string{passwordProfile.ID, privateKeyProfile.ID}, "export-password")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("导出数量 = %d，期望 2", count)
	}
	for _, plaintext := range []string{"ssh-password-value", "vpn-password-value", "legacy-psk-value", "private-key-passphrase", "PRIVATE KEY"} {
		if bytes.Contains(bundle, []byte(plaintext)) {
			t.Fatalf("加密连接包泄露明文: %s", plaintext)
		}
	}
	if _, err := service.ImportConnectionBundle(ctx, bundle, "wrong-password", filepath.Join(t.TempDir(), "wrong")); err == nil {
		t.Fatal("错误密码不应成功导入")
	}
	// 删除来源凭据和私钥，证明导入不依赖原电脑上的路径或安全凭据库。
	if err := os.Remove(privateKeyPath); err != nil {
		t.Fatal(err)
	}
	for _, profileID := range []string{passwordProfile.ID, privateKeyProfile.ID} {
		for _, key := range profileSecretKeys(profileID) {
			if err := secretStore.Delete(ctx, key); err != nil {
				t.Fatal(err)
			}
		}
	}

	keyDirectory := filepath.Join(t.TempDir(), "imported-keys")
	result, err := service.ImportConnectionBundle(ctx, bundle, "export-password", keyDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 2 || result.Renamed != 2 {
		t.Fatalf("导入结果异常: %#v", result)
	}
	values, err := service.ListProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 4 {
		t.Fatalf("连接数量 = %d，期望 4", len(values))
	}
	var importedPassword, importedPrivateKey model.ConnectionProfile
	for _, value := range values {
		switch value.DisplayName {
		case "密码主机（导入）":
			importedPassword = value
		case "密钥主机（导入）":
			importedPrivateKey = value
		}
	}
	if importedPassword.ID == "" || importedPassword.ID == passwordProfile.ID || importedPrivateKey.ID == "" || importedPrivateKey.ID == privateKeyProfile.ID {
		t.Fatalf("导入连接没有生成独立 ID: password=%q key=%q", importedPassword.ID, importedPrivateKey.ID)
	}
	storedPassword, err := secretStore.Get(ctx, model.SSHPasswordKey(importedPassword.ID))
	if err != nil || string(storedPassword) != "ssh-password-value" {
		t.Fatalf("导入 SSH 密码异常: %q, %v", storedPassword, err)
	}
	storedVPNPassword, err := secretStore.Get(ctx, model.VPNPasswordKey(importedPrivateKey.ID))
	if err != nil || string(storedVPNPassword) != "vpn-password-value" {
		t.Fatalf("导入隧道密码异常: %q, %v", storedVPNPassword, err)
	}
	storedPSK, err := secretStore.Get(ctx, model.VPNPSKKey(importedPrivateKey.ID))
	if err != nil || string(storedPSK) != "legacy-psk-value" {
		t.Fatalf("导入预共享密钥异常: %q, %v", storedPSK, err)
	}
	storedPath, err := secretStore.Get(ctx, model.SSHPrivateKeyPathKey(importedPrivateKey.ID))
	if err != nil || !strings.HasPrefix(string(storedPath), keyDirectory) {
		t.Fatalf("导入私钥路径异常: %q, %v", storedPath, err)
	}
	importedKeyData, err := os.ReadFile(string(storedPath))
	if err != nil || !bytes.Equal(importedKeyData, privateKeyData) {
		t.Fatalf("导入私钥内容不一致: %v", err)
	}
	storedPassphrase, err := secretStore.Get(ctx, model.SSHPrivateKeyPassphraseKey(importedPrivateKey.ID))
	if err != nil || string(storedPassphrase) != "private-key-passphrase" {
		t.Fatalf("导入私钥口令异常: %q, %v", storedPassphrase, err)
	}
	importedTrust, ok, err := service.knownHosts.Lookup(importedPassword.ID)
	if err != nil || !ok || importedTrust.Fingerprint != trusted.Fingerprint || importedTrust.ProfileID != importedPassword.ID {
		t.Fatalf("导入主机信任记录异常: %#v, %v", importedTrust, err)
	}
}

func TestConnectionBundleRejectsTamperingAndMissingCredentials(t *testing.T) {
	service, secretStore := newProfileTestService(t)
	ctx := context.Background()
	value, err := service.SaveProfile(ctx, SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "待导出主机", ConnectionMode: model.ConnectionModeDirectSSH,
			SSH: model.SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "user"},
		},
		SSHPassword: "ssh-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, err := service.ExportConnectionBundle(ctx, []string{value.ID}, "export-password")
	if err != nil {
		t.Fatal(err)
	}
	var envelope encryptedConnectionBundle
	if err := json.Unmarshal(bundle, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext[len(envelope.Ciphertext)/2] ^= 0x80
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ImportConnectionBundle(ctx, tampered, "export-password", t.TempDir()); err == nil {
		t.Fatal("被篡改的连接包不应成功导入")
	}
	if err := secretStore.Delete(ctx, model.SSHPasswordKey(value.ID)); err != nil {
		t.Fatal(err)
	}
	_, _, err = service.ExportConnectionBundle(ctx, []string{value.ID}, "export-password")
	var appErr *model.AppError
	if !errors.As(err, &appErr) || appErr.Code != "CONNECTION_EXPORT_CREDENTIAL_MISSING" {
		t.Fatalf("缺少凭据时错误异常: %v", err)
	}
}

func TestConnectionBundleImportRollsBackPrivateKeyAndProfile(t *testing.T) {
	service, secretStore := newProfileTestService(t)
	ctx := context.Background()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "rollback test")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := service.SaveProfile(ctx, SaveProfileRequest{
		Profile: model.ConnectionProfile{
			DisplayName: "回滚测试", ConnectionMode: model.ConnectionModeIsolatedTunnel,
			VPN: model.VPNConfig{ServerAddress: "vpn.example.com", ServerPort: 992, Username: "vpn-user"},
			SSH: model.SSHConfig{ServerAddress: "192.168.20.8", Port: 22, Username: "ssh-user", AuthMethod: model.SSHAuthPrivateKey},
		},
		VPNPassword: "vpn-password", SSHPrivateKeyPath: keyPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, err := service.ExportConnectionBundle(ctx, []string{value.ID}, "export-password")
	if err != nil {
		t.Fatal(err)
	}
	service.secrets = &bundleFailPutStore{Store: secretStore, suffix: "/vpn-password"}
	keyDirectory := filepath.Join(t.TempDir(), "imported-keys")
	if _, err := service.ImportConnectionBundle(ctx, bundle, "export-password", keyDirectory); err == nil {
		t.Fatal("凭据写入失败时导入不应成功")
	}
	values, err := service.ListProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].ID != value.ID {
		t.Fatalf("失败导入留下了连接配置: %#v", values)
	}
	entries, err := os.ReadDir(keyDirectory)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("失败导入留下了私钥文件: %#v", entries)
	}
}
