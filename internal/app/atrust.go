package app

import "github.com/EricHongXDD/LabRemote-Go/internal/model"

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
