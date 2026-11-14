package app

import (
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/openvpn"
)

func (s *Service) SubmitOpenVPNOTP(id, code string) error {
	provider, ok := s.vpn.(interface{ OTPBroker() *openvpn.OTPBroker })
	if !ok {
		return model.NewAppError("OPENVPN_OTP_UNAVAILABLE", "当前连接管理器不支持验证码", "openvpn", false)
	}
	if err := provider.OTPBroker().Submit(id, code); err != nil {
		return model.NewAppError("OPENVPN_OTP_INVALID", err.Error(), "openvpn", true)
	}
	return nil
}
