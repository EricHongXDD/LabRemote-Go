package main

import "github.com/EricHongXDD/LabRemote-Go/internal/model"

// OpenATrustAuthWindow 只打开本次隔离连接的独立网页认证窗口，不启动官方 VPN。
func (a *DesktopApp) OpenATrustAuthWindow(requestID string) error {
	if err := a.service.OpenATrustAuthWindow(requestID); err != nil {
		return model.NewAppError("ATRUST_AUTH_WINDOW_FAILED", err.Error(), "atrust_auth", true)
	}
	return nil
}
func (a *DesktopApp) CancelATrustLogin(requestID string) { a.service.CancelATrustLogin(requestID) }

func (a *DesktopApp) AcceptConnectionTestCertificate(sessionID, fingerprint string) error {
	return a.service.AcceptConnectionTestCertificate(a.ctx, sessionID, fingerprint)
}
