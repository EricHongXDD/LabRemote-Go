package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validTestProfile() ConnectionProfile {
	return ConnectionProfile{
		ID: "profile-1", DisplayName: "实验室 GPU", Group: "实验室",
		VPN:       VPNConfig{ConnectionName: "Lab VPN", ServerAddress: "vpn.example.com", Type: VPNTypeL2TPPSK, Username: "vpn-user", CredentialRef: VPNPasswordKey("profile-1"), SplitTunnel: true},
		SSH:       SSHConfig{ServerAddress: "192.168.190.10", Port: 22, Username: "lab", CredentialRef: SSHPasswordKey("profile-1")},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
}

func TestConnectionProfileValidate(t *testing.T) {
	value := validTestProfile()
	if value.EffectiveConnectionMode() != ConnectionModeIsolatedTunnel {
		t.Fatal("旧配置应默认使用隔离隧道")
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("合法配置未通过校验: %v", err)
	}
	if value.SSH.EffectiveAuthMethod() != SSHAuthPassword {
		t.Fatal("旧配置应默认使用 SSH 密码认证")
	}
	value.VPN.SplitTunnel = false
	if err := value.Validate(); err == nil {
		t.Fatal("未启用分流路由的配置不应通过")
	}
}

func TestConnectionProfileValidatesSSHAuthMethod(t *testing.T) {
	value := validTestProfile()
	value.SSH.AuthMethod = SSHAuthPrivateKey
	if err := value.Validate(); err != nil {
		t.Fatalf("私钥认证配置未通过校验: %v", err)
	}
	value.SSH.AuthMethod = "unknown"
	if err := value.Validate(); err == nil {
		t.Fatal("未知 SSH 认证方式不应通过校验")
	}
}

func TestDirectSSHProfileDoesNotRequireVPNFields(t *testing.T) {
	value := ConnectionProfile{
		ID:             "direct-profile",
		DisplayName:    "公网 SSH",
		ConnectionMode: ConnectionModeDirectSSH,
		SSH:            SSHConfig{ServerAddress: "ssh.example.com", Port: 22, Username: "user"},
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("仅 SSH 配置不应要求隔离隧道字段: %v", err)
	}
	value.ConnectionMode = "unknown"
	if !value.UsesIsolatedTunnel() {
		t.Fatal("未知连接方式不得被当作直接 SSH")
	}
	if err := value.Validate(); err == nil {
		t.Fatal("未知连接方式不应通过校验")
	}
}

func TestConnectionProfileJSONDoesNotContainSecrets(t *testing.T) {
	value := validTestProfile()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(data))
	for _, forbidden := range []string{"pre_shared_key", "vpn_password", "ssh_password", "mcp_token"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("配置 JSON 包含敏感字段 %q", forbidden)
		}
	}
}

func TestSanitizeDetails(t *testing.T) {
	value := SanitizeDetails(map[string]any{"password": "secret", "stage": "vpn"})
	if value["password"] != "[REDACTED]" || value["stage"] != "vpn" {
		t.Fatalf("脱敏结果异常: %#v", value)
	}
}
