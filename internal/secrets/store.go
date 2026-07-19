package secrets

import (
	"context"
	"sync"
)

type Store interface {
	Put(ctx context.Context, key string, secret []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

type MemoryStore struct {
	mu     sync.RWMutex
	values map[string][]byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{values: make(map[string][]byte)}
}

func (s *MemoryStore) Put(_ context.Context, key string, secret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = append([]byte(nil), secret...)
	return nil
}

func (s *MemoryStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (s *MemoryStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value, ok := s.values[key]; ok {
		Zero(value)
		delete(s.values, key)
	}
	return nil
}

func Zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
