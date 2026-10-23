package sshclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"golang.org/x/crypto/ssh"
)

func TestKnownHostsStoreAndLookup(t *testing.T) {
	store := NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
	expected := HostKeyRecord{
		ProfileID:   "profile-a",
		Address:     "192.0.2.10:22",
		KeyType:     "ssh-ed25519",
		Fingerprint: "SHA256:test-fingerprint",
		AcceptedAt:  time.Now(),
	}
	if err := store.Store(expected); err != nil {
		t.Fatal(err)
	}
	actual, ok, err := store.Lookup(expected.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("未找到已写入的主机指纹")
	}
	if actual.Address != expected.Address || actual.KeyType != expected.KeyType || actual.Fingerprint != expected.Fingerprint {
		t.Fatalf("主机指纹记录不一致: %#v", actual)
	}
}

func TestKnownHostsStoreRejectsInvalidRecord(t *testing.T) {
	store := NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
	if err := store.Store(HostKeyRecord{}); err == nil {
		t.Fatal("无效主机指纹记录应被拒绝")
	}
}

func newHostPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func TestKnownHostsChangedKeyRequiresExplicitAcceptance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	store := NewKnownHosts(path)
	const id, address = "profile-a", "192.0.2.10:22"
	oldKey, newKey := newHostPublicKey(t), newHostPublicKey(t)
	oldFingerprint, newFingerprint := ssh.FingerprintSHA256(oldKey), ssh.FingerprintSHA256(newKey)
	if err := store.Store(HostKeyRecord{ProfileID: id, Address: address, KeyType: oldKey.Type(), Fingerprint: oldFingerprint}); err != nil {
		t.Fatal(err)
	}
	var appError *model.AppError
	err := store.Callback(id)(address, nil, newKey)
	if !errors.As(err, &appError) || appError.Code != "SSH_HOST_KEY_CHANGED" {
		t.Fatalf("变化后的密钥应阻断连接: %v", err)
	}
	if appError.Details["expected"] != oldFingerprint || appError.Details["actual"] != newFingerprint || appError.Details["address"] != address || appError.Details["key_type"] != newKey.Type() {
		t.Fatalf("缺少人工核验所需的新旧指纹和服务器信息: %#v", appError.Details)
	}
	// 未确认和错误确认都不得覆盖原信任记录。
	if err := store.AcceptPending(id, oldFingerprint); err == nil {
		t.Fatal("不得接受与候选密钥不符的指纹")
	}
	record, ok, err := NewKnownHosts(path).Lookup(id)
	if err != nil || !ok || record.Fingerprint != oldFingerprint {
		t.Fatalf("确认前应保留原信任: %#v, %v", record, err)
	}
	if err := store.AcceptPending(id, newFingerprint); err != nil {
		t.Fatal(err)
	}
	if err := NewKnownHosts(path).Callback(id)(address, nil, newKey); err != nil {
		t.Fatalf("确认后重新加载应信任新密钥: %v", err)
	}
	if err := store.AcceptPending(id, newFingerprint); err == nil {
		t.Fatal("已经消费的候选密钥不得重复确认")
	}
}

func TestKnownHostsRejectsStalePendingKey(t *testing.T) {
	for _, restoreTrusted := range []bool{false, true} {
		t.Run(map[bool]string{false: "候选密钥再次变化", true: "恢复原受信任密钥"}[restoreTrusted], func(t *testing.T) {
			store := NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
			const id, address = "profile-a", "192.0.2.10:22"
			oldKey, candidate, latest := newHostPublicKey(t), newHostPublicKey(t), newHostPublicKey(t)
			if err := store.Store(HostKeyRecord{ProfileID: id, Address: address, Fingerprint: ssh.FingerprintSHA256(oldKey)}); err != nil {
				t.Fatal(err)
			}
			if err := store.Callback(id)(address, nil, candidate); err == nil {
				t.Fatal("候选密钥应被阻断")
			}
			if restoreTrusted {
				latest = oldKey
			}
			err := store.Callback(id)(address, nil, latest)
			if (err == nil) != restoreTrusted {
				t.Fatalf("最新观测密钥校验结果错误: %v", err)
			}
			if err := store.AcceptPending(id, ssh.FingerprintSHA256(candidate)); err == nil {
				t.Fatal("旧弹窗不得确认已经过期的候选密钥")
			}
			if !restoreTrusted {
				if err := store.AcceptPending(id, ssh.FingerprintSHA256(latest)); err != nil {
					t.Fatalf("应允许确认最新候选密钥: %v", err)
				}
			}
		})
	}
}

func TestKnownHostsUnknownKeyStillRequiresAcceptance(t *testing.T) {
	store := NewKnownHosts(filepath.Join(t.TempDir(), "known_hosts"))
	key := newHostPublicKey(t)
	var appError *model.AppError
	if err := store.Callback("new-profile")("192.0.2.10:22", nil, key); !errors.As(err, &appError) || appError.Code != "SSH_HOST_KEY_UNKNOWN" {
		t.Fatalf("首次连接仍应要求确认: %v", err)
	}
	if err := store.AcceptPending("new-profile", ssh.FingerprintSHA256(key)); err != nil {
		t.Fatal(err)
	}
	if err := store.Callback("new-profile")("192.0.2.10:22", nil, key); err != nil {
		t.Fatalf("确认后应允许连接: %v", err)
	}
}
