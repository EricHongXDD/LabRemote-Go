package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

type JSONRepository struct {
	path string
	mu   sync.RWMutex
}

func NewJSONRepository(path string) *JSONRepository {
	return &JSONRepository{path: path}
}

func (r *JSONRepository) List(_ context.Context) ([]model.ConnectionProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	values, err := r.read()
	if err != nil {
		return nil, err
	}
	sort.Slice(values, func(i, j int) bool { return values[i].DisplayName < values[j].DisplayName })
	return values, nil
}

func (r *JSONRepository) Get(_ context.Context, id string) (model.ConnectionProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	values, err := r.read()
	if err != nil {
		return model.ConnectionProfile{}, err
	}
	for _, value := range values {
		if value.ID == id {
			return value, nil
		}
	}
	return model.ConnectionProfile{}, model.NewAppError("PROFILE_NOT_FOUND", "连接配置不存在", "profile", false)
}

func (r *JSONRepository) Upsert(_ context.Context, value model.ConnectionProfile) error {
	value.ConnectionMode = value.EffectiveConnectionMode()
	value.SSH.AuthMethod = value.SSH.EffectiveAuthMethod()
	if err := value.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	values, err := r.read()
	if err != nil {
		return err
	}
	for _, existing := range values {
		if existing.ID != value.ID && strings.EqualFold(strings.TrimSpace(existing.DisplayName), strings.TrimSpace(value.DisplayName)) {
			return model.NewAppError("PROFILE_INVALID", "连接名称已存在", "profile", false)
		}
	}
	found := false
	for index := range values {
		if values[index].ID == value.ID {
			values[index] = value
			found = true
			break
		}
	}
	if !found {
		values = append(values, value)
	}
	return r.write(values)
}

func (r *JSONRepository) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	values, err := r.read()
	if err != nil {
		return err
	}
	result := make([]model.ConnectionProfile, 0, len(values))
	for _, value := range values {
		if value.ID != id {
			result = append(result, value)
		}
	}
	return r.write(result)
}

func (r *JSONRepository) read() ([]model.ConnectionProfile, error) {
	data, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return []model.ConnectionProfile{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取连接配置失败: %w", err)
	}
	if len(data) == 0 {
		return []model.ConnectionProfile{}, nil
	}
	var values []model.ConnectionProfile
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("解析连接配置失败: %w", err)
	}
	for index := range values {
		values[index].ConnectionMode = values[index].EffectiveConnectionMode()
		values[index].SSH.AuthMethod = values[index].SSH.EffectiveAuthMethod()
	}
	return values, nil
}

func (r *JSONRepository) write(values []model.ConnectionProfile) error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	data, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化连接配置失败: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(r.path), "profiles-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时配置文件失败: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("写入连接配置失败: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, r.path); err != nil {
		return fmt.Errorf("替换连接配置失败: %w", err)
	}
	return nil
}
