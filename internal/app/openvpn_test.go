package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

func openVPNProfile(t *testing.T) model.ConnectionProfile {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	config := "client\ndev tun\nremote openvpn1.shu.edu.cn 443\nauth-user-pass\nremote-cert-tls server\nstatic-challenge \"Enter OTP Code:\" 1\n<ca>\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + "</ca>\n"
	return model.ConnectionProfile{DisplayName: "学校服务器", ConnectionMode: model.ConnectionModeOpenVPNSSH,
		VPN: model.VPNConfig{Username: "student", OpenVPNConfig: config},
		SSH: model.SSHConfig{ServerAddress: "192.0.2.7", Port: 22, Username: "lab"}}
}

func TestOpenVPNProfileSaveCopyAndEncryptedBundle(t *testing.T) {
	ctx := context.Background()
	service, secretStore := newProfileTestService(t)
	draft := openVPNProfile(t)
	if _, err := service.SaveProfile(ctx, SaveProfileRequest{Profile: draft, SSHPassword: "ssh-secret"}); err == nil {
		t.Fatal("OpenVPN 缺少密码时不能保存")
	}
	saved, err := service.SaveProfile(ctx, SaveProfileRequest{Profile: draft, VPNPassword: "vpn-secret", SSHPassword: "ssh-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if saved.VPN.Type != model.VPNTypeOpenVPN || saved.VPN.OpenVPNConfig != draft.VPN.OpenVPNConfig || !saved.UsesVPN() || !saved.UsesIsolatedTunnel() {
		t.Fatal("OpenVPN 方式或配置被隔离隧道默认值覆盖")
	}
	serialized, _ := json.Marshal(saved)
	if strings.Contains(string(serialized), "vpn-secret") || strings.Contains(string(serialized), "ssh-secret") {
		t.Fatal("明文配置不应包含密码")
	}
	draft.ID = ""
	draft.DisplayName = "学校服务器副本"
	copy, err := service.SaveProfile(ctx, SaveProfileRequest{Profile: draft, CopyFromProfileID: saved.ID})
	if err != nil {
		t.Fatal(err)
	}
	password, err := secretStore.Get(ctx, model.VPNPasswordKey(copy.ID))
	if err != nil || string(password) != "vpn-secret" {
		t.Fatal("复制配置未保留安全凭据")
	}
	bundle, count, err := service.ExportConnectionBundle(ctx, []string{saved.ID}, "bundle-password")
	if err != nil || count != 1 {
		t.Fatalf("导出失败: %v", err)
	}
	if strings.Contains(string(bundle), "vpn-secret") || strings.Contains(string(bundle), "openvpn1.shu.edu.cn") {
		t.Fatal("导出包未加密")
	}
	importedService, importedSecrets := newProfileTestService(t)
	result, err := importedService.ImportConnectionBundle(ctx, bundle, "bundle-password", t.TempDir())
	if err != nil || result.Imported != 1 {
		t.Fatalf("导入失败: %v", err)
	}
	profiles, _ := importedService.ListProfiles(ctx)
	if len(profiles) != 1 || profiles[0].VPN.OpenVPNConfig != saved.VPN.OpenVPNConfig || profiles[0].ConnectionMode != model.ConnectionModeOpenVPNSSH {
		t.Fatal("导入未保留 OpenVPN 配置")
	}
	password, err = importedSecrets.Get(ctx, model.VPNPasswordKey(profiles[0].ID))
	if err != nil || string(password) != "vpn-secret" {
		t.Fatal("导入未保留 OpenVPN 凭据")
	}
}
