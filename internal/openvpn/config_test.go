package openvpn

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	engine "github.com/buengese/go-openvpn"
)

func testConfig(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "测试 CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return "client\ndev tun\nproto tcp\n<connection>\nremote openvpn.example.com 443 # 仅显示\nremote backup.openvpn.example.com 443\n</connection>\nremote-random\ncomp-lzo\nnobind\nreneg-sec 0\nsetenv CLIENT_CERT 0\nauth-user-pass\nremote-cert-tls server\nverb 3\nstatic-challenge \"Enter OTP Code:\" 1\nsndbuf 0\nrcvbuf 0\nmssfix 0\ncipher none\n<ca>\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + "</ca>\n"
}

func TestImportZIPAndRejectUnsafeConfiguration(t *testing.T) {
	config := testConfig(t)
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	f, _ := w.Create("../../vpn.ovpn")
	_, _ = f.Write([]byte(config))
	_ = w.Close()
	path := filepath.Join(t.TempDir(), "vpn.ovpn.zip")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := Import(path)
	if err != nil || actual != config {
		t.Fatalf("导入失败: %v", err)
	}
	for _, directive := range []string{"up malicious.exe", "config other.ovpn", "management 0.0.0.0 9000", "auth-user-pass credentials.txt", "ca other.pem", "key private.key", "redirect-gateway def1", "route 0.0.0.0 0.0.0.0", "script-security 2", "plugin evil.dll", "<key>\nsecret\n</key>"} {
		t.Run(strings.Fields(directive)[0], func(t *testing.T) {
			if err := Validate(config + directive + "\n"); err == nil {
				t.Fatalf("不应接受配置指令: %s", directive)
			}
		})
	}
	if err := Validate(strings.Replace(config, "</ca>", "</ca> # 注释\nup evil\n</ca>", 1)); err == nil {
		t.Fatal("不应允许通过 CA 区块绕过指令检查")
	}
	if err := Validate(strings.Repeat("x", MaxConfigSize+1)); err == nil {
		t.Fatal("超大配置未拒绝")
	}
}

func TestImportRejectsAmbiguousZIP(t *testing.T) {
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	_, _ = w.Create("one.ovpn")
	_, _ = w.Create("two.ovpn")
	_ = w.Close()
	path := filepath.Join(t.TempDir(), "multiple.zip")
	_ = os.WriteFile(path, archive.Bytes(), 0600)
	if _, err := Import(path); err == nil {
		t.Fatal("多配置 ZIP 需要明确选择")
	}
}

func TestProvidedOpenVPNConfig(t *testing.T) {
	path := os.Getenv("LABREMOTE_TEST_OPENVPN_CONFIG")
	if path == "" {
		t.Skip("提供 VPN ZIP 路径后执行真实配置兼容性检查")
	}
	config, err := Import(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "static-challenge") || strings.Count(config, "remote ") < 2 {
		t.Fatal("OTP 或备用服务器配置缺失")
	}
	profile, prompt, err := parseProfile(config)
	if err != nil {
		t.Fatal(err)
	}
	if prompt != "Enter OTP Code:" || len(profile.Remotes) != 10 || !strings.EqualFold(profile.Cipher, "none") {
		t.Fatalf("协议配置解析失败或关键参数未保留: %v", err)
	}
	client := engine.New(profile)
	client.Device = &memoryBackend{}
	client.CredentialsFn = func(context.Context) (engine.Credentials, error) {
		return engine.Credentials{Username: "test", Password: "test"}, nil
	}
	if err := client.Preflight(); err != nil {
		t.Fatalf("配置无法通过协议预检: %v", err)
	}
}
