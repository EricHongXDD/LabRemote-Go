package sshclient

import (
	"context"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

func (m *Manager) connectionSetupTimeout(ctx context.Context, profileID string) time.Duration {
	value, err := m.repository.Get(ctx, profileID)
	if err == nil {
		switch value.EffectiveConnectionMode() {
		case model.ConnectionModeATrustSSH:
			return 5 * time.Minute
		case model.ConnectionModeOpenVPNSSH:
			return 3 * time.Minute
		}
	}
	return 45 * time.Second
}
