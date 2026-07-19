//go:build windows

package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestWindowsCredentialManagerIntegration(t *testing.T) {
	if os.Getenv("LABREMOTE_WINDOWS_INTEGRATION") != "1" {
		t.Skip("设置 LABREMOTE_WINDOWS_INTEGRATION=1 后运行 Windows 凭据集成测试")
	}
	store := NewWindowsStore()
	ctx := context.Background()
	key := fmt.Sprintf("LabRemote/integration-test/%d", time.Now().UnixNano())
	defer store.Delete(ctx, key)
	secret := []byte("临时凭据-credential-smoke")
	if err := store.Put(ctx, key, secret); err != nil {
		t.Fatal(err)
	}
	value, err := store.Get(ctx, key)
	if err != nil || string(value) != string(secret) {
		t.Fatalf("Windows 凭据读取不一致: %q, %v", value, err)
	}
	Zero(value)
	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Windows 凭据删除后应不存在: %v", err)
	}
}
