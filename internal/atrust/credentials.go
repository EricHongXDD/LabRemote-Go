package atrust

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	protocol "github.com/EricHongXDD/LabRemote-Go/internal/atrust/protocol"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

type rememberedSession struct {
	Version int                    `json:"version"`
	Server  string                 `json:"server"`
	Device  string                 `json:"device"`
	State   *protocol.SessionState `json:"state,omitempty"`
}

type credentialGate struct {
	ready chan struct{}
	refs  int
}

var credentialGates = struct {
	sync.Mutex
	entries map[string]*credentialGate
}{entries: make(map[string]*credentialGate)}

// 同一配置的正式连接与测试串行恢复，避免同时弹出两次登录窗口。
func lockCredential(ctx context.Context, key string) (func(), error) {
	credentialGates.Lock()
	gate := credentialGates.entries[key]
	if gate == nil {
		gate = &credentialGate{ready: make(chan struct{}, 1)}
		credentialGates.entries[key] = gate
	}
	gate.refs++
	credentialGates.Unlock()
	release := func() {
		credentialGates.Lock()
		gate.refs--
		if gate.refs == 0 {
			delete(credentialGates.entries, key)
		}
		credentialGates.Unlock()
	}
	select {
	case gate.ready <- struct{}{}:
		return func() { <-gate.ready; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

// ForgetCredential 等待正在结束的认证完成，确保取消连接后不会再次写回已清除的票据。
func ForgetCredential(ctx context.Context, store secrets.Store, scope, server string) error {
	key := CredentialKey(scope, server)
	unlock, err := lockCredential(ctx, key)
	if err != nil {
		return err
	}
	defer unlock()
	return store.Delete(ctx, key)
}

// CredentialKey 按配置及网关隔离认证，避免不同账号的连接意外共用登录身份。
func CredentialKey(scope, server string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(server)))
	return fmt.Sprintf("LabRemote/%s/atrust/%x", scope, digest[:16])
}

func loadRemembered(ctx context.Context, store secrets.Store, scope, server string) (*rememberedSession, error) {
	if store == nil || scope == "" {
		return nil, nil
	}
	raw, err := store.Get(ctx, CredentialKey(scope, server))
	if errors.Is(err, secrets.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("无法读取 aTrust 系统登录凭据，请解锁系统凭据库后重试")
	}
	defer secrets.Zero(raw)
	var saved rememberedSession
	decodeErr := json.Unmarshal(raw, &saved)
	device, deviceErr := hex.DecodeString(saved.Device)
	if decodeErr != nil || saved.Version != 1 || !strings.EqualFold(saved.Server, server) || deviceErr != nil || len(device) != 16 {
		if err := store.Delete(ctx, CredentialKey(scope, server)); err != nil {
			return nil, fmt.Errorf("无法清理无效的 aTrust 系统登录凭据")
		}
		return nil, nil
	}
	return &saved, nil
}

func saveRemembered(ctx context.Context, store secrets.Store, scope string, saved *rememberedSession) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || scope == "" {
		return nil
	}
	raw, err := json.Marshal(saved)
	if err != nil {
		return fmt.Errorf("无法编码 aTrust 登录凭据")
	}
	defer secrets.Zero(raw)
	if err := store.Put(ctx, CredentialKey(scope, saved.Server), raw); err != nil {
		return fmt.Errorf("无法保存 aTrust 登录票据到系统凭据库，请检查凭据库是否可用")
	}
	return nil
}
