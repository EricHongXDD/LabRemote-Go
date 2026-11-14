package model

import "testing"

func TestATrustServerAddress(t *testing.T) {
	for _, value := range []string{"vpn.example.com", "https://vpn.example.com/", "https://vpn.example.com:8443", "https://[::1]:443"} {
		if _, err := NormalizeATrustAddress(value); err != nil {
			t.Fatalf("有效入口被拒绝 %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "http://vpn.example.com", "javascript:alert(1)", "https://user:password@vpn.example.com", "https://vpn.example.com/?token=secret", "https://vpn.example.com#token", "https://vpn.example.com/login", "https://vpn.example.com:0", "https://vpn.example.com:65536", "https://vpn.example.com:", "https://vpn.example.com\n" + "evil"} {
		if _, err := NormalizeATrustAddress(value); err == nil {
			t.Fatalf("危险或无效入口被接受 %q", value)
		}
	}
	value := validTestProfile()
	value.ConnectionMode = ConnectionModeATrustSSH
	value.VPN = VPNConfig{Type: VPNTypeATrust, ServerAddress: "https://vpn.example.com"}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	if !value.UsesIsolatedTunnel() || !value.UsesVPN() || value.NeedsVPNCredentials() {
		t.Fatal("aTrust 必须使用隔离通道，但不要求本应用处理 VPN 密码")
	}
}
