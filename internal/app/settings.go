package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Settings struct {
	MCPPort          int  `json:"mcp_port"`
	MCPEnabled       bool `json:"mcp_enabled"`
	DisconnectOnExit bool `json:"disconnect_on_exit"`
	TerminalBell     bool `json:"terminal_bell"`
}

func DefaultSettings() Settings {
	return Settings{MCPPort: 38765, MCPEnabled: false, DisconnectOnExit: false, TerminalBell: false}
}

type SettingsStore struct {
	path string
	mu   sync.Mutex
}

func NewSettingsStore(path string) *SettingsStore { return &SettingsStore{path: path} }

func (s *SettingsStore) Load() (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("读取设置失败: %w", err)
	}
	settings := DefaultSettings()
	if err := json.Unmarshal(data, &settings); err != nil {
		return Settings{}, fmt.Errorf("解析设置失败: %w", err)
	}
	if settings.MCPPort < 1024 || settings.MCPPort > 65535 {
		settings.MCPPort = 38765
	}
	return settings, nil
}

func (s *SettingsStore) Save(settings Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if settings.MCPPort < 1024 || settings.MCPPort > 65535 {
		return fmt.Errorf("MCP 端口必须为 1024-65535")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(s.path), "settings-*.tmp")
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
	return os.Rename(tempPath, s.path)
}
