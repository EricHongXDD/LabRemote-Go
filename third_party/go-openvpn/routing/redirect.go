// redirect-gateway: the flag words a server may attach to it, and the routes
// that carry the whole IPv4 address space into the tunnel.
//
// Reference: openvpn-2.6.22 src/openvpn/options.c:7202-7250 parses the flag
// words; src/openvpn/route.h:84-91 names the bits; src/openvpn/route.c:1069-1085
// (redirect_default_route_to_vpn) installs the routes.
package routing

import (
	"net"
	"strings"
)

// RedirectFlags is the set of flag words a pushed redirect-gateway carried. The
// bits mirror the RG_* flags in openvpn-2.6.22 src/openvpn/route.h:84-91 one for
// one; which of them this client acts on is a separate question, answered per
// flag below and by ParsedAndIgnored.
type RedirectFlags uint16

const (
	// RedirectDef1 is "def1": install two /1 routes instead of replacing the
	// host's default route (RG_DEF1). This client behaves as if it were
	// always set — see RedirectRoutes4.
	RedirectDef1 RedirectFlags = 1 << iota

	// RedirectLocal is "local": the VPN server is on the client's own LAN, so
	// no /1-proof host route around the tunnel is needed for it (RG_LOCAL).
	// Acted on: it suppresses the server bypass route.
	RedirectLocal

	// RedirectAutoLocal is "autolocal": decide RedirectLocal by testing whether
	// the server is reachable on-link (RG_AUTO_LOCAL). This client always
	// tests, so a server the route table calls direct-link gets no bypass route.
	RedirectAutoLocal

	// RedirectBypassDHCP is "bypass-dhcp" (RG_BYPASS_DHCP): keep the DHCP
	// server reachable outside the tunnel. Parsed and ignored — see
	// ParsedAndIgnored.
	RedirectBypassDHCP

	// RedirectBypassDNS is "bypass-dns" (RG_BYPASS_DNS): keep the DHCP-issued
	// DNS servers reachable outside the tunnel. Parsed and ignored.
	RedirectBypassDNS

	// RedirectBlockLocal is "block-local" (RG_BLOCK_LOCAL): pull the client's
	// own LAN subnets into the tunnel so they cannot be reached directly.
	// Parsed and ignored.
	RedirectBlockLocal

	// RedirectIPv6 is "ipv6": redirect the IPv6 default as well. Acted on; it
	// is what PushOptions.RedirectsIPv6 reports.
	RedirectIPv6

	// RedirectNoIPv4 is "!ipv4": do not redirect the IPv4 default. Acted on;
	// it clears PushOptions.RedirectGateway (options.c:7236-7239 clears
	// RG_REROUTE_GW and RG_ENABLE on the IPv4 route list).
	RedirectNoIPv4
)

// redirectFlagWords maps each flag to the word a server spells it with. The
// order is the order options.c:7206-7241 tests them in, which is the order
// String and ParsedAndIgnored report in.
var redirectFlagWords = []struct {
	flag RedirectFlags
	word string
}{
	{RedirectLocal, "local"},
	{RedirectAutoLocal, "autolocal"},
	{RedirectDef1, "def1"},
	{RedirectBypassDHCP, "bypass-dhcp"},
	{RedirectBypassDNS, "bypass-dns"},
	{RedirectBlockLocal, "block-local"},
	{RedirectIPv6, "ipv6"},
	{RedirectNoIPv4, "!ipv4"},
}

// redirectIgnored is the set this client parses and deliberately does not act
// on. See ParsedAndIgnored for why each one is in it.
const redirectIgnored = RedirectBypassDHCP | RedirectBypassDNS | RedirectBlockLocal

// Has reports whether every flag in want is set.
func (f RedirectFlags) Has(want RedirectFlags) bool { return f&want == want }

// String lists the flag words in the set, comma-separated, or "" for none.
func (f RedirectFlags) String() string {
	var words []string
	for _, fw := range redirectFlagWords {
		if f&fw.flag != 0 {
			words = append(words, fw.word)
		}
	}
	return strings.Join(words, ",")
}

// ParsedAndIgnored lists the flag words in the set that this client understood
// and deliberately did not act on, so that a caller can say so rather than let
// them vanish. It returns nil when there are none.
//
// bypass-dhcp and bypass-dns are ignored because the reference ignores them too
// off Windows: get_bypass_addresses is an empty function on every other platform
// (openvpn-2.6.22 src/openvpn/route.c:4042-4046). block-local is not about
// carrying traffic into the tunnel but about keeping the client off its own LAN
// while the tunnel is up (route.c:593-620, add_block_local), which needs
// host-interface enumeration this package does not do.
func (f RedirectFlags) ParsedAndIgnored() []string {
	if f&redirectIgnored == 0 {
		return nil
	}
	return strings.Split((f & redirectIgnored).String(), ",")
}

// parseRedirectFlags reads the words after a redirect-gateway directive and
// returns the recognised set and, separately, the words neither this client nor
// the reference knows. The reference fails the whole option on an unknown flag
// (options.c:7242-7246, "unknown --%s flag"); a pushed option is not a config
// file, and failing the reply would end a session over a flag word, so an
// unrecognised one is collected for the caller to report and the rest of the
// directive is honoured.
func parseRedirectFlags(words []string) (RedirectFlags, []string) {
	var flags RedirectFlags
	var unknown []string
	for _, w := range words {
		known := false
		for _, fw := range redirectFlagWords {
			// The reference compares with streq, which is case-sensitive;
			// folding case here only accepts more than it would.
			if strings.EqualFold(w, fw.word) {
				flags |= fw.flag
				known = true
				break
			}
		}
		if !known {
			unknown = append(unknown, w)
		}
	}
	return flags, unknown
}

// RedirectRoutes4 returns the IPv4 routes that carry the default into the
// tunnel: 0.0.0.0/1 and 128.0.0.0/1, both via gw. A nil gw makes them interface
// routes on the tunnel device.
//
// This is the reference's def1 behaviour (openvpn-2.6.22
// src/openvpn/route.c:1072-1082: add_route3(0x00000000, 0x80000000) and
// add_route3(0x80000000, 0x80000000)), used whether or not the server pushed
// the flag word. The alternative the reference offers without def1 — delete the
// host's default route, install a 0.0.0.0/0 of its own and put the old one back
// on teardown (route.c:1085-1096 and undo_redirect_default_route_to_vpn,
// route.c:1108-1150) — leaves the host with no default at all if the process
// dies between the two steps. Two /1 routes need no such window: they are more
// specific than any 0.0.0.0/0, so they win by longest-prefix match whatever
// metric the host's default carries, and removing them restores the host's
// routing exactly.
func RedirectRoutes4(gw net.IP) []Route {
	return []Route{
		{Network: net.IPv4(0, 0, 0, 0).To4(), Mask: net.CIDRMask(1, 32), Gateway: gw},
		{Network: net.IPv4(128, 0, 0, 0).To4(), Mask: net.CIDRMask(1, 32), Gateway: gw},
	}
}

// redirectPrefixes6 is the IPv6 cover the reference installs for
// "redirect-gateway ipv6": openvpn-2.6.22 src/openvpn/init.c:1555-1566 adds
// ::/3, 2000::/4, 3000::/4 and fc00::/7 to the route list rather than a ::/0.
//
// The reasoning is def1's: each is more specific than the host's ::/0, so it
// wins by longest-prefix match without the host's default having to be removed
// and put back. Between them they cover global unicast (2000::/3, as the two
// /4s), unique-local (fc00::/7) and the lower eighth of the space (::/3), which
// is every address a client routes off-link.
var redirectPrefixes6 = []Route6{
	{Network: net.ParseIP("::"), Prefix: 3},
	{Network: net.ParseIP("2000::"), Prefix: 4},
	{Network: net.ParseIP("3000::"), Prefix: 4},
	{Network: net.ParseIP("fc00::"), Prefix: 7},
}

// RedirectRoutes6 returns the IPv6 routes that carry off-link traffic into the
// tunnel, all via gw; a nil gw makes them interface routes on the tunnel device.
// See redirectPrefixes6 for what they are and why they are not a single ::/0.
func RedirectRoutes6(gw net.IP) []Route6 {
	routes := make([]Route6, len(redirectPrefixes6))
	for i, p := range redirectPrefixes6 {
		p.Gateway = gw
		routes[i] = p
	}
	return routes
}
