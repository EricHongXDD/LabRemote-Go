package softether

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

type dnsDialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func lookupIPv4(ctx context.Context, host string, dial dnsDialFunc) ([]netip.Addr, error) {
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial:         dial,
	}
	// 追加根标签，避免使用 Windows 的 DNS 搜索后缀；实际查询仍由隧道内 DHCP DNS 完成。
	queryHost := strings.TrimSuffix(strings.TrimSpace(host), ".") + "."
	values, err := resolver.LookupNetIP(ctx, "ip4", queryHost)
	if err != nil {
		return nil, fmt.Errorf("通过隔离隧道解析 %s 失败: %w", host, err)
	}
	result := make([]netip.Addr, 0, len(values))
	seen := make(map[netip.Addr]struct{}, len(values))
	for _, value := range values {
		value = value.Unmap()
		if !value.Is4() {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("隔离隧道 DNS 未返回 %s 的 IPv4 地址", host)
	}
	return result, nil
}

func (link *Link) lookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	servers, err := tunnelDNSServers(link.lease)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, server := range servers {
		dnsAddress := net.JoinHostPort(server.String(), "53")
		lookupContext, cancel := context.WithTimeout(ctx, 4*time.Second)
		addresses, err := lookupIPv4(lookupContext, host, func(dialContext context.Context, network, _ string) (net.Conn, error) {
			transport := "udp4"
			if strings.HasPrefix(network, "tcp") {
				transport = "tcp4"
			}
			// 忽略 Go 解析器从 Windows 读取的 DNS 地址，始终使用选定的隧道内 DNS 服务器。
			return link.network.DialContext(dialContext, transport, dnsAddress)
		})
		cancel()
		if err == nil {
			return addresses, nil
		}
		lastErr = fmt.Errorf("DNS %s: %w", server, err)
	}
	return nil, lastErr
}

func tunnelDNSServers(lease Lease) ([]netip.Addr, error) {
	if dns, ok := netip.AddrFromSlice(lease.DNS.To4()); ok && dns.Is4() && !dns.IsUnspecified() {
		return []netip.Addr{dns}, nil
	}
	if gateway, ok := netip.AddrFromSlice(lease.Gateway.To4()); !ok || !gateway.Is4() || gateway.IsUnspecified() {
		return nil, fmt.Errorf("隔离隧道 DHCP 未提供 DNS 和默认网关，当前连接只能访问同一子网内的 IP 地址；请在 SoftEther DHCP 中配置 DNS/网关")
	}
	// DHCP 有默认网关但没有 option 6 时，使用公共 DNS；查询仍只通过用户态隧道发送。
	return []netip.Addr{netip.MustParseAddr("223.5.5.5"), netip.MustParseAddr("1.1.1.1")}, nil
}
