package sshclient

import (
	"path/filepath"
	"testing"
	"time"
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
