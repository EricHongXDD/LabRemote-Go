package app

import (
	"path/filepath"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	store := NewSettingsStore(filepath.Join(t.TempDir(), "settings.json"))
	value := DefaultSettings()
	value.MCPPort = 40001
	value.MCPEnabled = true
	if err := store.Save(value); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded != value {
		t.Fatalf("设置往返异常: %#v, %v", loaded, err)
	}
}
