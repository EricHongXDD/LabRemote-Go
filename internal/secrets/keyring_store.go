package secrets

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	keyring "github.com/zalando/go-keyring"
)

const keyringServiceName = "LabRemote"

type keyringBackend struct {
	set    func(service, user, password string) error
	get    func(service, user string) (string, error)
	delete func(service, user string) error
}

type KeyringStore struct {
	backend keyringBackend
}

func NewKeyringStore() *KeyringStore {
	return newKeyringStore(keyringBackend{
		set: keyring.Set, get: keyring.Get, delete: keyring.Delete,
	})
}

func newKeyringStore(backend keyringBackend) *KeyringStore {
	return &KeyringStore{backend: backend}
}

func (s *KeyringStore) Put(ctx context.Context, key string, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded := base64.RawStdEncoding.EncodeToString(secret)
	if err := s.backend.set(keyringServiceName, key, encoded); err != nil {
		return fmt.Errorf("写入系统钥匙串失败: %w", err)
	}
	return nil
}

func (s *KeyringStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := s.backend.get(keyringServiceName, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("读取系统钥匙串失败: %w", err)
	}
	value, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("系统钥匙串中的凭据格式无效: %w", err)
	}
	return value, nil
}

func (s *KeyringStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.backend.delete(keyringServiceName, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("删除系统钥匙串凭据失败: %w", err)
	}
	return nil
}

var _ Store = (*KeyringStore)(nil)
