package sshclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"golang.org/x/crypto/ssh"
)

type HostKeyRecord struct {
	ProfileID   string    `json:"profile_id"`
	Address     string    `json:"address"`
	KeyType     string    `json:"key_type"`
	Fingerprint string    `json:"fingerprint"`
	AcceptedAt  time.Time `json:"accepted_at"`
}

type KnownHosts struct {
	path    string
	mu      sync.Mutex
	pending map[string]HostKeyRecord
}

func NewKnownHosts(path string) *KnownHosts {
	return &KnownHosts{path: path, pending: make(map[string]HostKeyRecord)}
}

func (k *KnownHosts) Callback(profileID string) ssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		record := HostKeyRecord{
			ProfileID:   profileID,
			Address:     hostname,
			KeyType:     key.Type(),
			Fingerprint: fingerprint,
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		records, err := k.read()
		if err != nil {
			return err
		}
		known, ok := records[profileID]
		if !ok {
			k.pending[profileID] = record
			return model.NewAppError("SSH_HOST_KEY_UNKNOWN", "首次连接需要确认 SSH 主机指纹", "ssh_host_key", false).WithDetails(map[string]any{
				"address": hostname, "key_type": key.Type(), "fingerprint": fingerprint,
			})
		}
		if known.Fingerprint != fingerprint {
			return model.NewAppError("SSH_HOST_KEY_CHANGED", "SSH 主机指纹已变化，连接已阻断", "ssh_host_key", false).WithDetails(map[string]any{
				"address": hostname, "key_type": key.Type(), "expected": known.Fingerprint, "actual": fingerprint,
			})
		}
		return nil
	}
}

func (k *KnownHosts) AcceptPending(profileID, fingerprint string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	record, ok := k.pending[profileID]
	if !ok || record.Fingerprint != fingerprint {
		return model.NewAppError("SSH_HOST_KEY_UNKNOWN", "没有可确认的主机指纹，或指纹已变化", "ssh_host_key", false)
	}
	record.AcceptedAt = time.Now()
	records, err := k.read()
	if err != nil {
		return err
	}
	records[profileID] = record
	if err := k.write(records); err != nil {
		return err
	}
	delete(k.pending, profileID)
	return nil
}

// Lookup 返回指定连接已信任的主机指纹，不修改正式信任库。
func (k *KnownHosts) Lookup(profileID string) (HostKeyRecord, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	records, err := k.read()
	if err != nil {
		return HostKeyRecord{}, false, err
	}
	record, ok := records[profileID]
	return record, ok, nil
}

// Store 写入一条已验证的主机指纹记录，供临时连接测试复制正式信任状态。
func (k *KnownHosts) Store(record HostKeyRecord) error {
	if record.ProfileID == "" || record.Address == "" || record.Fingerprint == "" {
		return model.NewAppError("SSH_HOST_KEY_INVALID", "SSH 主机指纹记录无效", "ssh_host_key", false)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	records, err := k.read()
	if err != nil {
		return err
	}
	if record.AcceptedAt.IsZero() {
		record.AcceptedAt = time.Now()
	}
	records[record.ProfileID] = record
	return k.write(records)
}

func (k *KnownHosts) Remove(profileID string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	records, err := k.read()
	if err != nil {
		return err
	}
	delete(records, profileID)
	delete(k.pending, profileID)
	return k.write(records)
}

func (k *KnownHosts) read() (map[string]HostKeyRecord, error) {
	data, err := os.ReadFile(k.path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]HostKeyRecord), nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取主机指纹文件失败: %w", err)
	}
	values := make(map[string]HostKeyRecord)
	if len(data) == 0 {
		return values, nil
	}
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("解析主机指纹文件失败: %w", err)
	}
	return values, nil
}

func (k *KnownHosts) write(values map[string]HostKeyRecord) error {
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(k.path), "known-hosts-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, k.path)
}
