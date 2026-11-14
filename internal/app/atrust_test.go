package app

import (
	"context"
	"errors"
	"testing"

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
	data, count, err := service.ExportConnectionBundle(ctx, []string{value.ID}, "bundle-test-password")
	if err != nil || count != 1 {
		t.Fatalf("导出 aTrust 不应要求 VPN 凭据: %v", err)
	}
	result, err := service.ImportConnectionBundle(ctx, data, "bundle-test-password", t.TempDir())
	if err != nil || result.Imported != 1 {
		t.Fatalf("导入 aTrust 失败: %v", err)
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
