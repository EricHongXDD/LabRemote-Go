//go:build windows && legacy_ras

package vpn

import (
	"context"
	"fmt"
	"net"
	"strings"
)

const ensureRouteScript = `$ErrorActionPreference = 'Stop'
$inputValue = [Console]::In.ReadToEnd() | ConvertFrom-Json
$connection = Get-VpnConnection -Name $inputValue.name -ErrorAction Stop
$route = $connection.Routes | Where-Object { $_.DestinationPrefix -eq $inputValue.prefix }
if ($null -eq $route) {
  Add-VpnConnectionRoute -ConnectionName $inputValue.name -DestinationPrefix $inputValue.prefix -PassThru | Out-Null
  $connection = Get-VpnConnection -Name $inputValue.name -ErrorAction Stop
  $route = $connection.Routes | Where-Object { $_.DestinationPrefix -eq $inputValue.prefix }
  if ($null -eq $route) {
    throw "VPN route verification failed"
  }
}`

func ensureHostRoute(ctx context.Context, connectionName string, address net.IP) error {
	if strings.TrimSpace(connectionName) == "" || len([]rune(connectionName)) > 64 || strings.ContainsAny(connectionName, "\r\n") {
		return fmt.Errorf("VPN 连接名称无效")
	}
	prefix := ""
	if ipv4 := address.To4(); ipv4 != nil {
		prefix = ipv4.String() + "/32"
	} else if ipv6 := address.To16(); ipv6 != nil {
		prefix = ipv6.String() + "/128"
	} else {
		return fmt.Errorf("目标服务器 IP 地址无效")
	}
	_, err := runPowerShellJSON(ctx, ensureRouteScript, map[string]string{
		"name":   connectionName,
		"prefix": prefix,
	})
	return err
}
