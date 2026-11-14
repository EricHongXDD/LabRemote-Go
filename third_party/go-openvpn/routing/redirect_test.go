// Tests for the redirect-gateway flag words and the routes they select.
// Nothing here needs root: the flag parsing is pure.
package routing

import (
	"net"
	"slices"
	"testing"
)

// TestParsePushReply_RedirectGatewayFlags covers the flag words after
// redirect-gateway: a server that says "!ipv4" or "local" must not be read as
// having said nothing (openvpn-2.6.22 src/openvpn/options.c:7202-7250).
func TestParsePushReply_RedirectGatewayFlags(t *testing.T) {
	for _, tc := range []struct {
		name      string
		msg       string
		wantFlags RedirectFlags
		want4     bool
		want6     bool
		unknown   []string
	}{
		{
			name:      "bare",
			msg:       "PUSH_REPLY,redirect-gateway",
			wantFlags: 0,
			want4:     true,
		},
		{
			name:      "def1 bypass-dhcp",
			msg:       "PUSH_REPLY,redirect-gateway def1 bypass-dhcp",
			wantFlags: RedirectDef1 | RedirectBypassDHCP,
			want4:     true,
		},
		{
			// "ipv6" adds the redirect to the IPv6 list without taking it off
			// the IPv4 one (options.c:7233-7236), so this is both families.
			name:      "ipv6 alone still redirects IPv4",
			msg:       "PUSH_REPLY,redirect-gateway ipv6",
			wantFlags: RedirectIPv6,
			want4:     true,
			want6:     true,
		},
		{
			// Only "!ipv4" takes IPv4 back off (options.c:7237-7240).
			name:      "ipv6 !ipv4 is IPv6 only",
			msg:       "PUSH_REPLY,redirect-gateway ipv6 !ipv4",
			wantFlags: RedirectIPv6 | RedirectNoIPv4,
			want4:     false,
			want6:     true,
		},
		{
			name:      "!ipv4 before the rest still wins",
			msg:       "PUSH_REPLY,redirect-gateway !ipv4 def1 ipv6",
			wantFlags: RedirectNoIPv4 | RedirectDef1 | RedirectIPv6,
			want4:     false,
			want6:     true,
		},
		{
			name:      "every flag word",
			msg:       "PUSH_REPLY,redirect-gateway def1 local autolocal bypass-dhcp bypass-dns block-local",
			wantFlags: RedirectDef1 | RedirectLocal | RedirectAutoLocal | RedirectBypassDHCP | RedirectBypassDNS | RedirectBlockLocal,
			want4:     true,
		},
		{
			// The reference refuses the option; a pushed one keeps the rest of
			// the directive and reports the word.
			name:      "unknown word",
			msg:       "PUSH_REPLY,redirect-gateway def1 sideways",
			wantFlags: RedirectDef1,
			want4:     true,
			unknown:   []string{"sideways"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := ParsePushReply(tc.msg)
			if err != nil {
				t.Fatalf("ParsePushReply: %v", err)
			}
			if opts.RedirectFlags != tc.wantFlags {
				t.Errorf("flags = %q (%d), want %q (%d)",
					opts.RedirectFlags, opts.RedirectFlags, tc.wantFlags, tc.wantFlags)
			}
			if opts.RedirectGateway != tc.want4 {
				t.Errorf("RedirectGateway = %v, want %v", opts.RedirectGateway, tc.want4)
			}
			if opts.RedirectsIPv6() != tc.want6 {
				t.Errorf("RedirectsIPv6() = %v, want %v", opts.RedirectsIPv6(), tc.want6)
			}
			if !slices.Equal(opts.RedirectUnknownFlags, tc.unknown) {
				t.Errorf("unknown flags = %v, want %v", opts.RedirectUnknownFlags, tc.unknown)
			}
		})
	}
}

// TestRedirectFlagsParsedAndIgnored pins that the flags no backend acts on are
// reportable rather than invisible, and that the ones that do something are
// not in that list.
func TestRedirectFlagsParsedAndIgnored(t *testing.T) {
	f := RedirectDef1 | RedirectLocal | RedirectBypassDHCP | RedirectBypassDNS | RedirectBlockLocal
	got := f.ParsedAndIgnored()
	want := []string{"bypass-dhcp", "bypass-dns", "block-local"}
	if !slices.Equal(got, want) {
		t.Errorf("ParsedAndIgnored() = %v, want %v", got, want)
	}
	if (RedirectDef1 | RedirectLocal | RedirectIPv6 | RedirectNoIPv4).ParsedAndIgnored() != nil {
		t.Error("flags this client acts on must not be reported as ignored")
	}
}

// TestRedirectRoutes4 pins the def1 pair: two /1 routes cover the whole IPv4
// space and are more specific than any 0.0.0.0/0, which is what lets them win
// without the host's default route being touched (openvpn-2.6.22
// src/openvpn/route.c:1072-1082).
func TestRedirectRoutes4(t *testing.T) {
	gw := net.IPv4(10, 8, 0, 1).To4()
	routes := RedirectRoutes4(gw)
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want 2", len(routes))
	}
	for i, want := range []struct {
		network string
		ones    int
	}{
		{"0.0.0.0", 1},
		{"128.0.0.0", 1},
	} {
		ones, bits := routes[i].Mask.Size()
		if routes[i].Network.String() != want.network || ones != want.ones || bits != 32 {
			t.Errorf("route %d = %s/%d (bits %d), want %s/%d",
				i, routes[i].Network, ones, bits, want.network, want.ones)
		}
		if !routes[i].Gateway.Equal(gw) {
			t.Errorf("route %d gateway = %s, want %s", i, routes[i].Gateway, gw)
		}
	}

	// The two halves must partition the space: every address falls in exactly
	// one, and neither is a 0.0.0.0/0 in disguise.
	for _, probe := range []string{"0.0.0.1", "10.0.0.1", "127.255.255.255", "128.0.0.0", "192.0.2.1", "255.255.255.255"} {
		ip := net.ParseIP(probe).To4()
		hits := 0
		for _, r := range routes {
			if (&net.IPNet{IP: r.Network, Mask: r.Mask}).Contains(ip) {
				hits++
			}
		}
		if hits != 1 {
			t.Errorf("%s is covered by %d of the two halves, want exactly 1", probe, hits)
		}
	}
}

// TestRedirectRoutes6 pins the IPv6 cover: the reference installs four
// more-specific prefixes rather than a ::/0, for the same reason def1 installs
// two /1s (openvpn-2.6.22 src/openvpn/init.c:1555-1566).
func TestRedirectRoutes6(t *testing.T) {
	gw := net.ParseIP("fe80::1")
	routes := RedirectRoutes6(gw)
	want := []struct {
		network string
		prefix  int
	}{
		{"::", 3},
		{"2000::", 4},
		{"3000::", 4},
		{"fc00::", 7},
	}
	if len(routes) != len(want) {
		t.Fatalf("got %d routes, want %d", len(routes), len(want))
	}
	for i, w := range want {
		if routes[i].Network.String() != w.network || routes[i].Prefix != w.prefix {
			t.Errorf("route %d = %s/%d, want %s/%d",
				i, routes[i].Network, routes[i].Prefix, w.network, w.prefix)
		}
		if !routes[i].Gateway.Equal(gw) {
			t.Errorf("route %d gateway = %s, want %s", i, routes[i].Gateway, gw)
		}
		if routes[i].Prefix == 0 {
			t.Errorf("route %d is a default route; the cover must be more specific than ::/0", i)
		}
	}
}
