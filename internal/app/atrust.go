package app

import (
	"context"
	"errors"

	"github.com/EricHongXDD/LabRemote-Go/internal/atrust"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

// normalizeATrustProfile 清除其他 VPN 类型的遗留字段，官方认证内容不进入 LabRemote。
func normalizeATrustProfile(value *model.ConnectionProfile) error {
	if value.EffectiveConnectionMode() != model.ConnectionModeATrustSSH {
		return nil
	}
	address, err := model.NormalizeATrustAddress(value.VPN.ServerAddress)
	if err != nil {
		return err
	}
	value.VPN = model.VPNConfig{Type: model.VPNTypeATrust, ConnectionName: value.DisplayName, ServerAddress: address, ServerCertificate: value.VPN.ServerCertificate}
	return nil
}

// adoptATrustTestCredential 保存配置时接续测试的认证，票据不经过前端。
func (s *Service) adoptATrustTestCredential(ctx context.Context, testID string, value model.ConnectionProfile) error {
	s.testMu.Lock()
	entry := s.testSessions[testID]
	s.testMu.Unlock()
	if entry == nil {
		return nil
	}
	select {
	case entry.gate <- struct{}{}:
		defer func() { <-entry.gate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-entry.ctx.Done():
		return nil
	}
	if entry.aTrustScope == "" || entry.ctx.Err() != nil {
		return nil
	}
	data, err := s.secrets.Get(ctx, atrust.CredentialKey(entry.aTrustScope, value.VPN.ServerAddress))
	if errors.Is(err, secrets.ErrNotFound) {
		return nil
	}
	if err != nil {
		return model.NewAppError("SECRET_STORE_FAILED", "无法读取测试取得的 aTrust 登录凭据", "profile", true)
	}
	defer secrets.Zero(data)
	if err := s.secrets.Put(ctx, atrust.CredentialKey(value.ID, value.VPN.ServerAddress), data); err != nil {
		return model.NewAppError("SECRET_STORE_FAILED", "无法保存 aTrust 登录凭据", "profile", true)
	}
	return nil
}

func (s *Service) forgetATrustCredential(ctx context.Context, value model.ConnectionProfile) error {
	if value.EffectiveConnectionMode() != model.ConnectionModeATrustSSH {
		return model.NewAppError("PROFILE_INVALID", "当前连接不使用 aTrust", "profile", false)
	}
	// 先停止仍可能更新票据的连接及测试，再从系统凭据库删除。
	s.testMu.Lock()
	var entries []*connectionTestSession
	for key, entry := range s.testSessions {
		// 测试的配置原始标识由创建请求记录，不依赖临时配置 ID。
		if entry.ownerProfileID == value.ID {
			delete(s.testSessions, key)
			entry.close()
			entries = append(entries, entry)
		}
	}
	s.testMu.Unlock()
	for _, entry := range entries {
		select {
		case <-entry.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.browser.CloseProfile(ctx, value.ID)
	s.ssh.CloseProfile(ctx, value.ID)
	_ = s.vpn.Disconnect(ctx, value.ID, true)
	if err := atrust.ForgetCredential(ctx, s.secrets, value.ID, value.VPN.ServerAddress); err != nil {
		return model.NewAppError("SECRET_STORE_FAILED", "无法清除 aTrust 登录凭据", "profile", true)
	}
	return nil
}
