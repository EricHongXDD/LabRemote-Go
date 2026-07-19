//go:build windows && legacy_ras

package vpn

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestEnsureRouteScriptUsesSupportedVpnClientCommands(t *testing.T) {
	if strings.Contains(ensureRouteScript, "Get-VpnConnectionRoute") {
		t.Fatal("路由脚本不能调用 Windows VpnClient 模块不存在的 Get-VpnConnectionRoute")
	}
	if !strings.Contains(ensureRouteScript, "Get-VpnConnection -Name") {
		t.Fatal("路由脚本应通过 Get-VpnConnection 的 Routes 属性检查现有路由")
	}
}

func TestEnsureHostRouteRejectsInvalidInputBeforePowerShell(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		address    net.IP
	}{
		{name: "空连接名称", connection: "", address: net.ParseIP("192.0.2.1")},
		{name: "连接名称包含换行", connection: "lab\nremote", address: net.ParseIP("192.0.2.1")},
		{name: "无效地址", connection: "lab", address: net.IP{1, 2, 3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ensureHostRoute(context.Background(), test.connection, test.address); err == nil {
				t.Fatal("无效输入应在执行 PowerShell 前返回错误")
			}
		})
	}
}
