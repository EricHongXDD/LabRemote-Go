//go:build linux || android

// Bypass-route tests: parseRouteGateway, LookupGateway, and the netlink writes
// behind AddBypassRoute and DeleteBypassRoute.
//
// Under redirect-gateway a 0.0.0.0/0 route via tun0 makes the kernel
// re-evaluate the VPN server's own socket, find tun0 as the best path, and loop
// the traffic back through the tunnel. The /32 bypass route for the server IP,
// installed before the default route and removed on disconnect, is what
// prevents it.
package routing

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// buildFakeRouteReply builds a minimal RTM_NEWROUTE netlink response. An
// RTA_GATEWAY attribute is appended when gw is non-nil; otherwise the response
// models a direct-link route. The address family follows gw.
func buildFakeRouteReply(gw net.IP) []byte {
	const rtmsgSize = 12

	var gwAttr []byte
	family := byte(unix.AF_INET)
	if gw != nil {
		addr := gw.To4()
		if addr == nil {
			addr, family = gw.To16(), unix.AF_INET6
		}
		gwAttr = nlAttr(unix.RTA_GATEWAY, addr)
	}

	totalLen := nlmsgHdrSize + rtmsgSize + len(gwAttr)
	buf := make([]byte, totalLen)

	binary.LittleEndian.PutUint32(buf[0:4], uint32(totalLen))  // nlmsg_len
	binary.LittleEndian.PutUint16(buf[4:6], unix.RTM_NEWROUTE) // nlmsg_type
	buf[nlmsgHdrSize] = family                                 // rtmsg.Family

	copy(buf[nlmsgHdrSize+rtmsgSize:], gwAttr)
	return buf
}

// TestParseRouteGateway decodes a netlink route reply with and without an
// RTA_GATEWAY attribute: a direct-link route legitimately carries no gateway,
// so its absence is a nil result and not an error.
func TestParseRouteGateway(t *testing.T) {
	for _, tc := range []struct {
		name string
		want net.IP
	}{
		{"with gateway", net.IPv4(192, 168, 1, 1)},
		{"direct-link route", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRouteGateway(buildFakeRouteReply(tc.want))
			if err != nil {
				t.Fatalf("parseRouteGateway: %v", err)
			}
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("expected nil for a direct-link route, got %s", got)
			case tc.want != nil && got == nil:
				t.Fatal("expected a non-nil gateway, got nil")
			case tc.want != nil && !got.Equal(tc.want):
				t.Errorf("gateway: got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestLookupGateway_Loopback verifies that looking up the loopback address
// does not return an error.  127.0.0.1 is a local/loopback address so there
// is no gateway (returns nil), but the call must not fail.
func TestLookupGateway_Loopback(t *testing.T) {
	_, err := LookupGateway(net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatalf("LookupGateway(127.0.0.1): %v", err)
	}
}

// TestAddDeleteBypassRoute verifies that AddBypassRoute installs a /32 host
// route, that a second call is idempotent (EEXIST as success), and that
// DeleteBypassRoute removes it with the same guarantee. Requires root.
func TestAddDeleteBypassRoute(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root — re-run with sudo or in a privileged network namespace")
	}

	// Discover a real gateway so the kernel accepts the new route.
	// If there is no default gateway (direct-link host) the test is not
	// applicable and is skipped.
	gw, err := LookupGateway(net.IPv4(1, 1, 1, 1))
	if err != nil {
		t.Skipf("LookupGateway: %v — skipping netlink write test", err)
	}
	if gw == nil {
		t.Skip("no default gateway — direct-link host, bypass route not applicable")
	}

	// 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — reserved, safe to use in tests.
	serverIP := net.IPv4(203, 0, 113, 42)

	if err := AddBypassRoute(serverIP, gw); err != nil {
		t.Fatalf("AddBypassRoute: %v", err)
	}
	// Second call must be idempotent (EEXIST → nil).
	if err := AddBypassRoute(serverIP, gw); err != nil {
		t.Fatalf("AddBypassRoute (idempotent): %v", err)
	}

	if err := DeleteBypassRoute(serverIP, gw); err != nil {
		t.Fatalf("DeleteBypassRoute: %v", err)
	}
	// Second call must be idempotent (ESRCH → nil).
	if err := DeleteBypassRoute(serverIP, gw); err != nil {
		t.Fatalf("DeleteBypassRoute (idempotent): %v", err)
	}
}
