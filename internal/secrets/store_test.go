package secrets

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryStoreCopiesAndDeletes(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	input := []byte("secret")
	if err := store.Put(ctx, "key", input); err != nil {
		t.Fatal(err)
	}
	input[0] = 'X'
	value, err := store.Get(ctx, "key")
	if err != nil || string(value) != "secret" {
		t.Fatalf("凭据未隔离复制: %q, %v", value, err)
	}
	if err := store.Delete(ctx, "key"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后应返回 ErrNotFound: %v", err)
	}
}
