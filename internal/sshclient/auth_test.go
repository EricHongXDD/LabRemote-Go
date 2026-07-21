package sshclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"golang.org/x/crypto/ssh"
)

func writeTestPrivateKey(t *testing.T, encrypted bool, passphrase []byte) (string, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if encrypted {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "LabRemote test", passphrase)
	} else {
		block, err = ssh.MarshalPrivateKey(privateKey, "LabRemote test")
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, publicKey
}

func TestLoadPrivateKeyFile(t *testing.T) {
	path, publicKey := writeTestPrivateKey(t, false, nil)
	signer, encrypted, err := LoadPrivateKeyFile(path, nil)
	if err != nil || encrypted {
		t.Fatalf("读取未加密私钥失败: encrypted=%v err=%v", encrypted, err)
	}
	expected, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(expected) {
		t.Fatal("私钥对应的公钥不一致")
	}
}

func TestLoadEncryptedPrivateKeyRequiresCorrectPassphrase(t *testing.T) {
	path, _ := writeTestPrivateKey(t, true, []byte("correct-passphrase"))
	_, encrypted, err := LoadPrivateKeyFile(path, nil)
	var appError *model.AppError
	if !encrypted || !errors.As(err, &appError) || appError.Code != "SSH_KEY_PASSPHRASE_REQUIRED" {
		t.Fatalf("加密私钥缺少口令时错误异常: encrypted=%v err=%v", encrypted, err)
	}
	_, encrypted, err = LoadPrivateKeyFile(path, []byte("wrong-passphrase"))
	if !encrypted || !errors.As(err, &appError) || appError.Code != "SSH_KEY_PASSPHRASE_INVALID" {
		t.Fatalf("错误口令未被拒绝: encrypted=%v err=%v", encrypted, err)
	}
	if _, encrypted, err = LoadPrivateKeyFile(path, []byte("correct-passphrase")); err != nil || !encrypted {
		t.Fatalf("正确口令未能解析加密私钥: encrypted=%v err=%v", encrypted, err)
	}
}
