package secrets

import (
	"context"
	"errors"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func TestKeyringStoreRoundTripAndDelete(t *testing.T) {
	values := make(map[string]string)
	backend := keyringBackend{
		set: func(service, user, password string) error {
			values[service+"\x00"+user] = password
			return nil
		},
		get: func(service, user string) (string, error) {
			value, ok := values[service+"\x00"+user]
			if !ok {
				return "", keyring.ErrNotFound
			}
			return value, nil
		},
		delete: func(service, user string) error {
			key := service + "\x00" + user
			if _, ok := values[key]; !ok {
				return keyring.ErrNotFound
			}
			delete(values, key)
			return nil
		},
	}
	store := newKeyringStore(backend)
	ctx := context.Background()
	secret := []byte{0, 1, 2, 0xff}
	if err := store.Put(ctx, "profile/password", secret); err != nil {
		t.Fatal(err)
	}
	value, err := store.Get(ctx, "profile/password")
	if err != nil || string(value) != string(secret) {
		t.Fatalf("系统钥匙串往返结果不一致: %v, %v", value, err)
	}
	if err := store.Delete(ctx, "profile/password"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "profile/password"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后应返回 ErrNotFound: %v", err)
	}
	if err := store.Delete(ctx, "profile/password"); err != nil {
		t.Fatalf("重复删除应保持幂等: %v", err)
	}
}

func TestKeyringStoreRejectsCorruptValueAndCancelledContext(t *testing.T) {
	store := newKeyringStore(keyringBackend{
		set:    func(_, _, _ string) error { return nil },
		get:    func(_, _ string) (string, error) { return "!invalid-base64!", nil },
		delete: func(_, _ string) error { return nil },
	})
	if _, err := store.Get(context.Background(), "key"); err == nil {
		t.Fatal("损坏的钥匙串内容应返回错误")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Put(ctx, "key", []byte("secret")); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消上下文应立即返回: %v", err)
	}
}
