package model

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type VPNType string

const (
	VPNTypeL2TPPSK   VPNType = "l2tp_psk"
	VPNTypeSoftEther VPNType = "softether"
	VPNTypePPTP      VPNType = "pptp"
	VPNTypeSSTP      VPNType = "sstp"
	VPNTypeIKEv2     VPNType = "ikev2"
)

type ConnectionProfile struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name"`
	Group       string    `json:"group,omitempty"`
	VPN         VPNConfig `json:"vpn"`
	SSH         SSHConfig `json:"ssh"`
	MCPPolicy   MCPPolicy `json:"mcp_policy"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type VPNConfig struct {
	ConnectionName    string  `json:"connection_name"`
	ServerAddress     string  `json:"server_address"`
	ServerPort        uint16  `json:"server_port,omitempty"`
	HubName           string  `json:"hub_name,omitempty"`
	ServerCertificate string  `json:"server_certificate,omitempty"`
	Type              VPNType `json:"type"`
	Username          string  `json:"username"`
	CredentialRef     string  `json:"credential_ref"`
	SplitTunnel       bool    `json:"split_tunnel"`
}

type SSHConfig struct {
	ServerAddress string `json:"server_address"`
	Port          uint16 `json:"port"`
	Username      string `json:"username"`
	CredentialRef string `json:"credential_ref"`
	HostKey       string `json:"host_key,omitempty"`
}

type MCPPolicy struct {
	EnabledForProfile bool `json:"enabled_for_profile"`
	AllowExec         bool `json:"allow_exec"`
	AllowInteractive  bool `json:"allow_interactive"`
	AllowDisconnect   bool `json:"allow_disconnect"`
}

func (p ConnectionProfile) Validate() error {
	if strings.TrimSpace(p.DisplayName) == "" || len([]rune(p.DisplayName)) > 64 {
		return NewAppError("PROFILE_INVALID", "连接名称必须为 1-64 个字符", "profile", false)
	}
	if strings.TrimSpace(p.VPN.ConnectionName) == "" || len([]rune(p.VPN.ConnectionName)) > 64 {
		return NewAppError("PROFILE_INVALID", "VPN 连接名称必须为 1-64 个字符", "profile", false)
	}
	if !validHost(p.VPN.ServerAddress) {
		return NewAppError("PROFILE_INVALID", "VPN 服务器名称或地址无效", "profile", false)
	}
	if p.VPN.Type != VPNTypeSoftEther && p.VPN.Type != VPNTypeL2TPPSK {
		return NewAppError("PROFILE_INVALID", "仅支持 SoftEther 原生隔离隧道", "profile", false)
	}
	if strings.TrimSpace(p.VPN.Username) == "" {
		return NewAppError("PROFILE_INVALID", "隔离隧道用户名不能为空", "profile", false)
	}
	if !p.VPN.SplitTunnel {
		return NewAppError("PROFILE_INVALID", "必须启用仅限目标连接的隔离传输", "profile", false)
	}
	if !validHost(p.SSH.ServerAddress) {
		return NewAppError("PROFILE_INVALID", "SSH 服务器地址无效", "profile", false)
	}
	if p.SSH.Port == 0 {
		return NewAppError("PROFILE_INVALID", "SSH 端口必须为 1-65535", "profile", false)
	}
	if strings.TrimSpace(p.SSH.Username) == "" {
		return NewAppError("PROFILE_INVALID", "SSH 用户名不能为空", "profile", false)
	}
	return nil
}

func validHost(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, " \\/'\"`;$|&<>") {
		return false
	}
	if net.ParseIP(strings.Trim(value, "[]")) != nil {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func VPNPSKKey(profileID string) string { return fmt.Sprintf("LabRemote/%s/vpn-psk", profileID) }
func VPNPasswordKey(profileID string) string {
	return fmt.Sprintf("LabRemote/%s/vpn-password", profileID)
}
func SSHPasswordKey(profileID string) string {
	return fmt.Sprintf("LabRemote/%s/ssh-password", profileID)
}
func MCPTokenKey() string { return "LabRemote/global/mcp-token" }
