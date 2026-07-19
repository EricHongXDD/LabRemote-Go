//go:build windows && legacy_ras

package vpn

import "github.com/EricHongXDD/LabRemote-Go/internal/model"

func mapRASError(code uint32) *model.AppError {
	switch code {
	case 691:
		return model.NewAppError("VPN_AUTH_FAILED", "VPN 用户名或密码错误", "vpn_dial", false)
	case 789:
		return model.NewAppError("VPN_IPSEC_FAILED", "L2TP/IPsec 安全协商失败，请检查预共享密钥", "vpn_dial", false)
	case 809:
		return model.NewAppError("VPN_SERVER_UNREACHABLE", "无法到达 VPN 服务器，可能被网络或防火墙阻止", "vpn_dial", true)
	default:
		return model.NewAppError("VPN_CONNECT_FAILED", "Windows VPN 连接失败", "vpn_dial", true).WithDetails(map[string]any{"ras_error": code})
	}
}
