package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/atrust"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

func TestATrustSaveAndBundleDoNotRequireVPNCredentials(t *testing.T) {
	service, store := newProfileTestService(t)
	ctx := context.Background()
	value, err := service.SaveProfile(ctx, SaveProfileRequest{
		Profile: model.ConnectionProfile{DisplayName: "客户端 VPN", ConnectionMode: model.ConnectionModeATrustSSH,
			VPN: model.VPNConfig{ServerAddress: "vpn.example.com/", Username: "旧账号", OpenVPNConfig: "旧配置"},
			SSH: model.SSHConfig{ServerAddress: "192.0.2.10", Port: 22, Username: "ubuntu"}},
		SSHPassword: "ssh-test", VPNPassword: "不应保存", VPNPreSharedKey: "不应保存",
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.VPN.ServerAddress != "https://vpn.example.com" || value.VPN.Type != model.VPNTypeATrust || value.VPN.Username != "" || value.VPN.OpenVPNConfig != "" || value.VPN.CredentialRef != "" {
		t.Fatalf("aTrust 配置未正确归一化: %+v", value.VPN)
	}
	for _, key := range []string{model.VPNPasswordKey(value.ID), model.VPNPSKKey(value.ID)} {
		if _, err := store.Get(ctx, key); !errors.Is(err, secrets.ErrNotFound) {
			t.Fatal("aTrust 不应保存 VPN 密码或预共享密钥")
		}
	}
	if err := store.Put(ctx, atrust.CredentialKey(value.ID, value.VPN.ServerAddress), []byte("session-must-not-be-exported")); err != nil {
		t.Fatal(err)
	}
	data, count, err := service.ExportConnectionBundle(ctx, []string{value.ID}, "bundle-test-password")
	if err != nil || count != 1 {
		t.Fatalf("导出 aTrust 不应要求 VPN 凭据: %v", err)
	}
	payload, err := decryptConnectionBundle(data, []byte("bundle-test-password"))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := json.Marshal(payload)
	if strings.Contains(string(plain), "session-must-not-be-exported") {
		t.Fatal("连接导出不应包含登录票据")
	}
	result, err := service.ImportConnectionBundle(ctx, data, "bundle-test-password", t.TempDir())
	if err != nil || result.Imported != 1 {
		t.Fatalf("导入 aTrust 失败: %v", err)
	}
}

func TestATrustTestCredentialSurvivesSaveAndIsRemovedOnForget(t *testing.T) {
	service, store := newProfileTestService(t)
	ctx := context.Background()
	draft := model.ConnectionProfile{DisplayName: "测试登录保持", ConnectionMode: model.ConnectionModeATrustSSH,
		VPN: model.VPNConfig{ServerAddress: "https://vpn.example"}, SSH: model.SSHConfig{ServerAddress: "192.0.2.10", Port: 22, Username: "ubuntu"}}
	entry, release, err := service.acquireConnectionTestSession(ctx, TestConnectionRequest{TestSessionID: "draft-test", Profile: draft})
	if err != nil {
		t.Fatal(err)
	}
	entry.aTrustScope, entry.aTrustStore = entry.id, store
	key := atrust.CredentialKey(entry.id, draft.VPN.ServerAddress)
	entry.aTrustDraftKeys = map[string]struct{}{key: {}}
	if err := store.Put(ctx, key, []byte("test-only-session")); err != nil {
		t.Fatal(err)
	}
	release()
	saved, err := service.SaveProfile(ctx, SaveProfileRequest{Profile: draft, TestSessionID: "draft-test", SSHPassword: "ssh-test"})
	if err != nil {
		t.Fatal(err)
	}
	service.CloseConnectionTestSession("draft-test")
	<-entry.done
	if _, err := store.Get(ctx, key); !errors.Is(err, secrets.ErrNotFound) {
		t.Error("测试结束后未清除临时票据")
	}
	key = atrust.CredentialKey(saved.ID, saved.VPN.ServerAddress)
	if data, err := store.Get(ctx, key); err != nil || string(data) != "test-only-session" {
		t.Fatal("保存后未接续测试票据")
	}
	if err := service.ClearCredential(ctx, saved.ID, "atrust_session"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatal("用户清除登录后仍留有票据")
	}
}

func TestATrustEndpointChangesAndDeletionRemoveRememberedCredentials(t *testing.T) {
	service, store := newProfileTestService(t)
	ctx := context.Background()
	value, err := service.SaveProfile(ctx, SaveProfileRequest{Profile: model.ConnectionProfile{DisplayName: "认证清理", ConnectionMode: model.ConnectionModeATrustSSH,
		VPN: model.VPNConfig{ServerAddress: "https://vpn.example"}, SSH: model.SSHConfig{ServerAddress: "192.0.2.10", Port: 22, Username: "ubuntu"}}, SSHPassword: "ssh-test"})
	if err != nil {
		t.Fatal(err)
	}
	oldKey := atrust.CredentialKey(value.ID, value.VPN.ServerAddress)
	_ = store.Put(ctx, oldKey, []byte("test-ticket"))
	value.VPN.ServerAddress = "https://other.example"
	entry, release, err := service.acquireConnectionTestSession(ctx, TestConnectionRequest{TestSessionID: "changed-gateway-test", Profile: value})
	if err != nil {
		t.Fatal(err)
	}
	entry.aTrustScope, entry.aTrustStore = entry.id, store
	draftKey := atrust.CredentialKey(entry.id, value.VPN.ServerAddress)
	entry.aTrustDraftKeys = map[string]struct{}{draftKey: {}}
	_ = store.Put(ctx, draftKey, []byte("new-gateway-ticket"))
	release()
	value, err = service.SaveProfile(ctx, SaveProfileRequest{Profile: value, TestSessionID: "changed-gateway-test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, oldKey); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatal("更换网关后未清理原票据")
	}
	key := atrust.CredentialKey(value.ID, value.VPN.ServerAddress)
	if data, err := store.Get(ctx, key); err != nil || string(data) != "new-gateway-ticket" {
		t.Fatal("更换网关保存后未接续新票据")
	}
	if err := service.DeleteProfile(ctx, value.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatal("删除配置后不应保留 aTrust 会话")
	}
}

func TestATrustWebResourceDoesNotRequireSSHOrReadVPNSecrets(t *testing.T) {
	service, _ := newProfileTestService(t)
	ctx := context.Background()
	value := model.ConnectionProfile{ID: "atrust-web", DisplayName: "网络资源", ConnectionMode: model.ConnectionModeATrustSSH,
		VPN: model.VPNConfig{Type: model.VPNTypeATrust, ServerAddress: "https://vpn.example.com"},
		SSH: model.SSHConfig{ServerAddress: "192.0.2.10", Port: 22, Username: "test"}}
	if err := service.profiles.Upsert(ctx, value); err != nil {
		t.Fatal(err)
	}
	probeContext, cancel := context.WithCancel(ctx)
	cancel()
	link, err := service.OpenBrowserResource(probeContext, value.ID, "intranet.example.com:8080/path")
	if err == nil || link != "" {
		t.Fatal("aTrust 网页访问必须通过 SSH 隧道，不得直接返回系统浏览器资源链接")
	}

	for _, target := range []string{"javascript://alert(1)", "file:///C:/data", "https://user:password@example.com"} {
		if _, err := service.OpenBrowserResource(ctx, value.ID, target); err == nil {
			t.Fatal("网页地址校验被绕过")
		}
	}
}
