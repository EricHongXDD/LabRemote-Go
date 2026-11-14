package app

import (
	"context"
	"fmt"
	"github.com/EricHongXDD/LabRemote-Go/internal/atrust"
)

// AcceptConnectionTestCertificate 仅信任当前测试会话实际观察到的指纹，不更改正式配置。
func (s *Service) AcceptConnectionTestCertificate(ctx context.Context, id, fingerprint string) error {
	s.testMu.Lock()
	entry := s.testSessions[id]
	s.testMu.Unlock()
	if entry == nil {
		return fmt.Errorf("测试会话已结束，请重新测试")
	}
	select {
	case entry.gate <- struct{}{}:
		defer func() { <-entry.gate }()
	case <-ctx.Done():
		return ctx.Err()
	case <-entry.ctx.Done():
		return entry.ctx.Err()
	}
	if err := entry.transport.AcceptCertificate(ctx, entry.id, fingerprint); err != nil {
		return err
	}
	entry.certificatePin = fingerprint
	return nil
}

func (s *Service) OpenATrustAuthWindow(id string) error {
	provider, ok := s.vpn.(interface{ ATrustAuthBroker() *atrust.AuthBroker })
	if !ok {
		return fmt.Errorf("当前环境不支持 aTrust 网页认证")
	}
	return provider.ATrustAuthBroker().Open(id)
}
func (s *Service) CancelATrustLogin(id string) {
	if p, ok := s.vpn.(interface{ ATrustAuthBroker() *atrust.AuthBroker }); ok {
		p.ATrustAuthBroker().Cancel(id)
	}
}
