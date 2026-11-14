// Package routing parses OpenVPN PUSH_REPLY routing options and applies them
// to the host routing table: Linux and Android through rtnetlink(7)
// (netlink.go), macOS through route(8) (netlink_darwin.go), and on iOS not at
// all — the OS applies them from NEPacketTunnelNetworkSettings (netlink_ios.go).
//
// ParsePushReply recognises the directives below and skips every other one.
//
// # Addressing and routes
//
//   - topology <subnet|net30> — how ifconfig's second argument reads
//   - ifconfig <local> <mask|peer> — TUN interface IPv4 address
//   - ifconfig-ipv6 <addr/prefix> [gw] — TUN interface IPv6 address
//   - route-gateway <gw|vpn_gateway|dhcp> — next hop for IPv4 route directives
//   - route <net> [<mask> [gw]] — explicit IPv4 network route
//   - route-ipv6 <net/prefix> [gw] — explicit IPv6 network route
//   - redirect-gateway [flags...] — default-route replacement, per family
//
// # Data channel
//
//   - cipher <name> — negotiated data-channel cipher
//   - auth <digest> — data-channel HMAC digest
//   - compress [alg], comp-lzo [mode] — compression framing
//   - protocol-flags <flags...> — tls-ekm and the flags beside it
//   - key-derivation tls-ekm — the same flag, spelled on its own
//
// # Session and timers
//
//   - ping <n>, ping-restart <n> — keepalive interval and dead-link timeout
//   - inactive <n> [bytes] — idle disconnect
//   - tun-mtu <n> — tunnel MTU
//   - mssfix <n> — TCP MSS clamp
//   - auth-token <token> — credential for later renegotiations
//
// push-continuation, which frames a reply the server split across several
// control messages, is handled by PushAccumulator in push_continuation.go.
//
// Parsing is pure Go and requires no special privileges. Applying routes
// requires CAP_NET_ADMIN on Linux and root on macOS.
//
// Reference: openvpn3-core tun/client/tunprop.hpp
package routing

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/buengese/go-openvpn/internal/compress"
)

// Topology is the OpenVPN P2P topology mode pushed by the server.
type Topology int

const (
	// TopologyNet30 is the traditional /30 point-to-point topology.
	// ifconfig local peer — peer is the P2P gateway address.
	TopologyNet30 Topology = iota
	// TopologySubnet is the modern subnet topology.
	// ifconfig local mask — mask is the subnet mask; route-gateway carries the gateway.
	TopologySubnet
)

// Ifconfig holds the TUN interface address pushed by the server.
type Ifconfig struct {
	// Local is the IP address assigned to the client's TUN interface.
	Local net.IP
	// Mask is the subnet mask for subnet topology; for net30 it is /30.
	Mask net.IPMask
	// Gateway is the next-hop gateway (route-gateway for subnet; peer addr for net30).
	Gateway net.IP
}

// Ifconfig6 holds the TUN interface IPv6 address pushed by the server.
// Corresponds to the "ifconfig-ipv6 <addr/prefix> <gw>" directive.
//
// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_ifconfig_ipv6().
type Ifconfig6 struct {
	// Local is the IPv6 address assigned to the client's TUN interface.
	Local net.IP
	// Prefix is the prefix length (e.g. 64 for a /64 network).
	Prefix int
	// Gateway is the IPv6 next-hop (may be nil when not pushed).
	Gateway net.IP
}

// Route represents a single network route pushed by the server.
type Route struct {
	// Network is the destination network address.
	Network net.IP
	// Mask is the destination network mask.
	Mask net.IPMask
	// Gateway is the next-hop address.
	// If nil, Ifconfig.Gateway is used.
	Gateway net.IP
	// Symbolic is the gateway the server named symbolically, when it did.
	// OpenVPN lets a pushed route say vpn_gateway, net_gateway or
	// remote_host instead of an address, and resolves each at install time
	// (openvpn-2.6.22 src/openvpn/route.c:236-300; options.c:7034-7038
	// admits them through is_special_addr). net_gateway is how a server says
	// "this destination goes around the tunnel, not through it" — the
	// standard LAN or split-exclude push.
	Symbolic SymbolicGateway
}

// SymbolicGateway is a next hop a server named rather than addressed.
type SymbolicGateway int

const (
	// SymbolicNone means Gateway holds an address, or the route takes the
	// tunnel's own gateway.
	SymbolicNone SymbolicGateway = iota
	// SymbolicVPNGateway is the tunnel's remote endpoint — the same next hop
	// an omitted gateway selects.
	SymbolicVPNGateway
	// SymbolicNetGateway is the host's pre-existing default gateway: this
	// destination is to be reached around the tunnel.
	SymbolicNetGateway
	// SymbolicRemoteHost is the VPN server's own address, which likewise must
	// stay reachable outside the tunnel.
	SymbolicRemoteHost
)

// String returns a stable lowercase token for reports and logs.
func (g SymbolicGateway) String() string {
	switch g {
	case SymbolicVPNGateway:
		return "vpn_gateway"
	case SymbolicNetGateway:
		return "net_gateway"
	case SymbolicRemoteHost:
		return "remote_host"
	default:
		return ""
	}
}

// AroundTunnel reports whether this next hop means the destination must not be
// routed through the tunnel.
func (g SymbolicGateway) AroundTunnel() bool {
	return g == SymbolicNetGateway || g == SymbolicRemoteHost
}

// parseSymbolicGateway recognises the three names OpenVPN accepts in place of
// a gateway address.
func parseSymbolicGateway(s string) (SymbolicGateway, bool) {
	switch s {
	case "vpn_gateway":
		return SymbolicVPNGateway, true
	case "net_gateway":
		return SymbolicNetGateway, true
	case "remote_host":
		return SymbolicRemoteHost, true
	default:
		return SymbolicNone, false
	}
}

// Route6 represents a single IPv6 network route pushed by the server.
// Corresponds to a "route-ipv6 <net/prefix> [gateway]" directive.
//
// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_route_ipv6().
type Route6 struct {
	// Network is the destination IPv6 network address.
	Network net.IP
	// Prefix is the prefix length (0–128).
	Prefix int
	// Gateway is the IPv6 next-hop (may be nil; use Ifconfig6.Gateway).
	Gateway net.IP
}

// KeyDerivation selects the data-channel key derivation method.
//
// Reference: openvpn3-core ssl/proto.hpp parse_pushed_protocol_flags() line ~836:
//
//	"tls-ekm"  → TLS RFC 5705 ExportKeyingMaterial (openvpn3-core 3.x default)
//	(absent)   → legacy OpenVPN PRF (HMAC-SHA256 over TLS master secret + randoms)
type KeyDerivation int

const (
	// KeyDerivationTLSEKM uses RFC 5705 ExportKeyingMaterial.
	// This is the default for servers that push "protocol-flags tls-ekm" or
	// "key-derivation tls-ekm". AWS Client VPN and openvpn3-core 3.x use this.
	KeyDerivationTLSEKM KeyDerivation = iota
	// KeyDerivationOpenVPNPRF uses the legacy OpenVPN HMAC-SHA256 PRF over the
	// TLS 1.2 master secret and client/server randoms.
	// Used by stock OpenVPN 2.x servers that do not push "protocol-flags tls-ekm".
	KeyDerivationOpenVPNPRF
)

// PushOptions holds all routing-relevant options extracted from a PUSH_REPLY.
type PushOptions struct {
	// Topology is the tunnel topology mode.
	Topology Topology

	// Ifconfig holds the TUN interface IPv4 addressing, if present.
	Ifconfig *Ifconfig

	// Ifconfig6 holds the TUN interface IPv6 addressing, if present.
	// Populated by "ifconfig-ipv6 <addr/prefix> <gw>".
	//
	// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_ifconfig_ipv6().
	Ifconfig6 *Ifconfig6

	// Routes is the list of explicit IPv4 routes from "route" directives.
	Routes []Route

	// Routes6 is the list of explicit IPv6 routes from "route-ipv6" directives.
	//
	// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_route_ipv6().
	Routes6 []Route6

	// RedirectGateway is true when the server pushed "redirect-gateway" (IPv4).
	// This means all IPv4 traffic (0.0.0.0/0) should be routed through the tunnel.
	RedirectGateway bool

	// RedirectFlags is the set of flag words the pushed redirect-gateway
	// carried. "ipv6" and "!ipv4" have already been folded into
	// RedirectGateway and RedirectsIPv6; what a backend does with the rest is
	// the backend's business, and RedirectFlags.ParsedAndIgnored names the
	// ones no backend acts on, so that a client can report them.
	RedirectFlags RedirectFlags

	// RedirectUnknownFlags holds redirect-gateway flag words this client did
	// not recognise. The reference refuses the whole option on one
	// (options.c:7242-7246); a pushed option gets the rest of the directive
	// honoured and the word reported instead.
	RedirectUnknownFlags []string

	// Cipher is the data-channel cipher negotiated with the server (e.g. "AES-256-GCM").
	// Empty means the server did not push a cipher directive; the client falls back
	// to AES-256-GCM (the only cipher advertised in IV_CIPHERS).
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_data_channel_options()
	// line ~753: parses "cipher <name>" and validates it against IV_NCP.
	Cipher string

	// Auth is the data-channel HMAC digest pushed by the server (e.g. "SHA512").
	// Empty means the server did not push one; the client falls back to the
	// profile's digest, which is SHA1 when the profile is silent too (see
	// profile.Profile.Auth). A pushed digest outranks it: the server names the
	// digest it will actually compute packet HMACs with, so a client that keeps
	// its own authenticates with the wrong algorithm and, for a differing digest
	// length, the wrong number of key bytes. Unused for AEAD ciphers, and kept
	// verbatim as Cipher is.
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_data_channel_options()
	// line ~753 takes the pushed cipher off this same option list.
	Auth string

	// Compression is the compression framing the server pushed, and only that.
	// Most servers push none — OpenVPN 2's server does not push its own setting
	// at all — so this is ModeNone far more often than the session is
	// uncompressed, and it is not the mode the data channel installs:
	// compress.EffectiveMode reconciles it with Profile.Compression.
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_compression() line ~875:
	//   parses "compress lz4[-v2]" and "comp-lzo" from the PUSH_REPLY option list.
	Compression compress.Mode

	// PingInterval is the keepalive send interval in seconds (from "ping N").
	// 0 means keepalive is disabled.
	//
	// Reference: openvpn3-core ssl/proto.hpp ProtoConfig::load_common(),
	// load_duration_parm(keepalive_ping, "ping", ...) line ~1254.
	PingInterval int

	// PingRestart is the keepalive receive timeout in seconds (from "ping-restart N").
	// If no data arrives within this window the tunnel should be considered dead.
	// 0 means no restart on idle.
	//
	// Reference: openvpn3-core ssl/proto.hpp ProtoConfig::load_common(),
	// load_duration_parm(keepalive_timeout, "ping-restart", ...) line ~1255.
	PingRestart int

	// Mssfix is the MSS clamp value in bytes pushed by the server (from "mssfix N").
	// 0 means not pushed; client should use profile value or default (1492 for TCP, 1450 for UDP).
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_mssfix() line ~925.
	Mssfix int

	// TunMTU is the tunnel MTU the server pushed, from "tun-mtu N". 0 means
	// it pushed none. A value outside 68..65535 is treated as none, the way
	// the profile parser treats one.
	TunMTU int

	// InactiveTimeout is the maximum idle time in seconds before disconnecting (from "inactive N [bytes]").
	// 0 means no inactive timeout.
	//
	// Reference: openvpn3-core client/cliproto.hpp process_inactive().
	InactiveTimeout int

	// InactiveBytes is the minimum bytes that must flow within InactiveTimeout seconds.
	// If 0, any byte resets the timer.
	//
	// Reference: openvpn3-core client/cliproto.hpp process_inactive() second arg.
	InactiveBytes int

	// AuthToken is a server-issued credential for subsequent key
	// renegotiations. It is sensitive and must never be logged.
	//
	// Reference: openvpn3-core client/cliproto.hpp extract_auth_token().
	AuthToken string

	// KeyDerivation is the method used to derive data-channel keys.
	// Defaults to KeyDerivationTLSEKM (RFC 5705), set to KeyDerivationOpenVPNPRF
	// when the server does not push "protocol-flags tls-ekm" or "key-derivation tls-ekm".
	//
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_protocol_flags() line ~836.
	KeyDerivation KeyDerivation
}

// ParsePushReply extracts routing options from a PUSH_REPLY control message.
//
// The message is a comma-separated list of key-value directives, for example:
//
//	PUSH_REPLY,topology subnet,ifconfig 172.16.77.4 255.255.255.224,
//	  route-gateway 172.16.77.1,route 10.130.0.0 255.255.0.0,
//	  dhcp-option DNS 10.130.0.2,cipher AES-256-GCM
//
// ParsePushReply silently skips directives it does not recognise (forward
// compatibility). It returns an error only when a recognised directive is
// syntactically malformed. The result does not depend on the order the
// directives arrive in: directives that only make sense together are collected
// in the loop and interpreted in the second pass after it.
func ParsePushReply(msg string) (*PushOptions, error) {

	// Default to legacy PRF; switched to EKM when "protocol-flags tls-ekm" or
	// "key-derivation tls-ekm" is parsed below.
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_protocol_flags() line ~836:
	// servers that support EKM push "protocol-flags ... tls-ekm"; stock OpenVPN 2.x
	// does not, so the absence of the flag means legacy PRF.
	opts := &PushOptions{KeyDerivation: KeyDerivationOpenVPNPRF}

	// Directives whose meaning is settled by another directive are held here
	// and interpreted in the second pass after the loop, because the one they
	// depend on may still be ahead of them in the reply and nothing in the
	// protocol fixes the order a server sends its directives in.
	//
	// routeGateway overrides the gateway ifconfig would otherwise imply;
	// ifcLocal and ifcSecond are the two ifconfig arguments, whose second is a
	// subnet mask or the P2P peer address according to topology, and
	// ifcSecondRaw keeps it as the server wrote it for the error message. The
	// reference splits it the same way: add_option() (openvpn-2.6.22
	// src/openvpn/options.c) records the arguments as strings and init_tun()
	// (src/openvpn/tun.c) is where the two finally meet.
	var (
		routeGateway net.IP
		ifcLocal     net.IP
		ifcSecond    net.IP
		ifcSecondRaw string
	)

	for _, field := range PushFields(msg) {
		parts := strings.Fields(field)
		if len(parts) == 0 {
			continue
		}

		switch strings.ToLower(parts[0]) {
		case "topology":
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: topology: expected argument")
			}
			switch strings.ToLower(parts[1]) {
			case "subnet":
				opts.Topology = TopologySubnet
			case "net30":
				opts.Topology = TopologyNet30
			default:
				return nil, fmt.Errorf("routing: topology: unknown value %q (want subnet or net30)", parts[1])
			}

		case "route-gateway":
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: route-gateway: expected argument")
			}
			// Two symbolic values are legal here and neither is an address.
			// "vpn_gateway" means the ifconfig gateway, resolved after all
			// directives are parsed. "dhcp" asks the platform for the gateway
			// its DHCP lease named (openvpn-2.6.22 src/openvpn/options.c:7072,
			// route_gateway_via_dhcp) — a Windows TAP notion with no meaning
			// for a tun device, so it falls back to the ifconfig gateway
			// rather than failing the whole reply.
			if v := strings.ToLower(parts[1]); v != "vpn_gateway" && v != "dhcp" {
				gw := net.ParseIP(parts[1])
				if gw == nil {
					return nil, fmt.Errorf("routing: route-gateway: invalid IP %q", parts[1])
				}
				routeGateway = gw.To4()
			}

		case "ifconfig":
			if len(parts) < 3 {
				return nil, fmt.Errorf("routing: ifconfig: expected 2 args, got %d", len(parts)-1)
			}
			local := net.ParseIP(parts[1])
			if local == nil {
				return nil, fmt.Errorf("routing: ifconfig: invalid local IP %q", parts[1])
			}
			// parts[2] is either the subnet mask (topology subnet) or the P2P
			// peer (net30). Which it is belongs to topology, so both arguments
			// are only checked for being addresses here.
			second := net.ParseIP(parts[2])
			if second == nil {
				return nil, fmt.Errorf("routing: ifconfig: invalid second arg %q", parts[2])
			}
			ifcLocal, ifcSecond, ifcSecondRaw = local, second, parts[2]

		case "route":
			// route <network> [<mask> [gateway]]
			// A single-arg form (no mask) is a host route (/32), pushed by
			// stock OpenVPN CE in net30 topology for the P2P peer address.
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: route: expected at least a network address, got 0 arg(s)")
			}
			netIP := net.ParseIP(parts[1])
			if netIP == nil {
				return nil, fmt.Errorf("routing: route: invalid network %q", parts[1])
			}
			var routeMask net.IPMask
			if len(parts) >= 3 {
				maskIP := net.ParseIP(parts[2])
				if maskIP == nil {
					return nil, fmt.Errorf("routing: route: invalid mask %q", parts[2])
				}
				mask4 := maskIP.To4()
				if mask4 == nil {
					return nil, fmt.Errorf("routing: route: mask must be IPv4, got %q", parts[2])
				}
				routeMask = net.IPMask(mask4)
			} else {
				routeMask = net.CIDRMask(32, 32)
			}
			r := Route{
				Network: netIP.To4(),
				Mask:    routeMask,
			}
			if len(parts) >= 4 {
				if sym, ok := parseSymbolicGateway(parts[3]); ok {
					r.Symbolic = sym
				} else {
					gw := net.ParseIP(parts[3])
					if gw == nil {
						return nil, fmt.Errorf("routing: route: invalid gateway %q", parts[3])
					}
					r.Gateway = gw.To4()
				}
			}
			opts.Routes = append(opts.Routes, r)

		case "cipher":
			// Reference: openvpn3-core ssl/proto.hpp
			// parse_pushed_data_channel_options() line ~753: server pushes the
			// negotiated cipher after NCP. Client validates it is in IV_CIPHERS.
			if len(parts) >= 2 {
				opts.Cipher = parts[1]
			}

		case "auth":
			// The pushed digest outranks the profile's; see PushOptions.Auth.
			// This switch matches the whole keyword, so "auth-token" below
			// cannot land here and set the digest.
			if len(parts) >= 2 {
				opts.Auth = parts[1]
			}

		case "compress", "comp-lzo":
			// Which framing a directive selects is decided by the option
			// flags it sets rather than by the algorithm it names, and
			// compress.ModeForDirective is the single place that table
			// lives — the same one the profile parser goes through, so the
			// profile and the reply cannot disagree about it. "compress
			// stub-v2" and "compress lz4" are not one mode: stub-v2 puts no
			// byte on the wire and lz4 replaces the payload's first byte
			// with one (docker/COMPRESSION-VECTORS.md §6). A value OpenVPN
			// would refuse leaves Compression alone rather than failing the
			// whole push.
			arg := ""
			if len(parts) >= 2 {
				arg = parts[1]
			}
			if mode, ok := compress.ModeForDirective(parts[0], arg); ok {
				opts.Compression = mode
			}

		case "ifconfig-ipv6":
			// ifconfig-ipv6 <addr/prefix> <gateway>
			// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_ifconfig_ipv6().
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: ifconfig-ipv6: expected addr/prefix")
			}
			ip6, prefix6, err := net.ParseCIDR(parts[1])
			if err != nil {
				return nil, fmt.Errorf("routing: ifconfig-ipv6: invalid addr/prefix %q: %w", parts[1], err)
			}
			ones, _ := prefix6.Mask.Size()
			ifc6 := &Ifconfig6{Local: ip6, Prefix: ones}
			if len(parts) >= 3 {
				gw6 := net.ParseIP(parts[2])
				if gw6 == nil {
					return nil, fmt.Errorf("routing: ifconfig-ipv6: invalid gateway %q", parts[2])
				}
				ifc6.Gateway = gw6
			}
			opts.Ifconfig6 = ifc6

		case "route-ipv6":
			// route-ipv6 <net/prefix> [gateway]
			// Reference: openvpn3-core tun/client/tunprop.hpp tun_prop_route_ipv6().
			if len(parts) < 2 {
				return nil, fmt.Errorf("routing: route-ipv6: expected net/prefix")
			}
			_, net6, err := net.ParseCIDR(parts[1])
			if err != nil {
				return nil, fmt.Errorf("routing: route-ipv6: invalid net/prefix %q: %w", parts[1], err)
			}
			ones6, _ := net6.Mask.Size()
			r6 := Route6{Network: net6.IP, Prefix: ones6}
			if len(parts) >= 3 {
				gw6 := net.ParseIP(parts[2])
				if gw6 == nil {
					return nil, fmt.Errorf("routing: route-ipv6: invalid gateway %q", parts[2])
				}
				r6.Gateway = gw6
			}
			opts.Routes6 = append(opts.Routes6, r6)

		case "redirect-gateway":
			// The flag words decide what "redirect" means: "!ipv4" inverts
			// the IPv4 half of the directive outright.
			//
			// Reference: openvpn-2.6.22 src/openvpn/options.c:7202-7250.
			// The bare directive sets RG_REROUTE_GW on the IPv4 list;
			// "ipv6" adds it to the IPv6 list without taking it off IPv4,
			// so "redirect-gateway ipv6" redirects both and only
			// "redirect-gateway ipv6 !ipv4" is IPv6-only.
			flags, unknown := parseRedirectFlags(parts[1:])
			opts.RedirectFlags |= flags
			opts.RedirectUnknownFlags = append(opts.RedirectUnknownFlags, unknown...)

			opts.RedirectGateway = true
			// "!ipv4" clears RG_REROUTE_GW and RG_ENABLE on the IPv4 route
			// list (options.c:7236-7239), whatever order it appears in.
			if flags.Has(RedirectNoIPv4) {
				opts.RedirectGateway = false
			}

		case "ping":
			// keepalive send interval — openvpn3-core ssl/proto.hpp
			// ProtoConfig::load_common() line ~1254:
			//   load_duration_parm(keepalive_ping, "ping", opt, 1, false, false)
			if len(parts) >= 2 {
				var v int
				if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v > 0 {
					opts.PingInterval = v
				}
			}

		case "ping-restart":
			// dead-link timeout — openvpn3-core ssl/proto.hpp
			// ProtoConfig::load_common() line ~1255:
			//   load_duration_parm(keepalive_timeout, "ping-restart", opt, 1, false, false)
			if len(parts) >= 2 {
				var v int
				if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v > 0 {
					opts.PingRestart = v
				}
			}

		case "tun-mtu":
			if len(parts) >= 2 {
				if v, err := strconv.Atoi(parts[1]); err == nil && v >= 68 && v <= 65535 {
					opts.TunMTU = v
				}
			}

		case "mssfix":
			// Reference: openvpn3-core ssl/proto.hpp parse_pushed_mssfix() line ~925.
			if len(parts) >= 2 {
				var v int
				if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v >= 68 && v <= 65535 {
					opts.Mssfix = v
				}
			}

		case "protocol-flags":
			// Reference: openvpn3-core ssl/proto.hpp parse_pushed_protocol_flags()
			// line ~836: flag list may include "tls-ekm", "cc-exit", "dyn-tls-crypt".
			// Only "tls-ekm" affects key derivation.
			for _, flag := range parts[1:] {
				if strings.EqualFold(flag, "tls-ekm") {
					opts.KeyDerivation = KeyDerivationTLSEKM
				}
			}

		case "key-derivation":
			// Reference: openvpn3-core ssl/proto.hpp line ~863:
			// "key-derivation tls-ekm" is an alternative form of the same flag.
			if len(parts) >= 2 && strings.EqualFold(parts[1], "tls-ekm") {
				opts.KeyDerivation = KeyDerivationTLSEKM
			}

		case "inactive":
			// Reference: openvpn3-core client/cliproto.hpp process_inactive():
			// "inactive <timeout_secs> [bytes]"
			if len(parts) >= 2 {
				var v int
				if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v > 0 {
					opts.InactiveTimeout = v
				}
				if len(parts) >= 3 {
					var b int
					if _, err := fmt.Sscanf(parts[2], "%d", &b); err == nil && b >= 0 {
						opts.InactiveBytes = b
					}
				}
			}

		case "auth-token":
			// A server-issued auth token replaces the original password on
			// subsequent renegotiations. Retain it verbatim; it is deliberately
			// not surfaced in logs or diagnostic output.
			if len(parts) >= 2 {
				opts.AuthToken = parts[1]
			}
		}
		// All other directives (dhcp-option, peer-id, route-metric, etc.) are
		// ignored.
	}

	// Second pass, now that topology is final whichever end of the reply the
	// server put it at. The IPv4 addressing goes first, because route-gateway
	// below amends it.
	if ifcLocal != nil {
		if opts.Topology == TopologySubnet {
			mask4 := ifcSecond.To4()
			if mask4 == nil {
				return nil, fmt.Errorf("routing: ifconfig: subnet mask must be IPv4, got %q", ifcSecondRaw)
			}
			opts.Ifconfig = &Ifconfig{
				Local: ifcLocal.To4(),
				Mask:  net.IPMask(mask4),
			}
		} else {
			// Net30: second arg is the P2P peer; mask is /30.
			opts.Ifconfig = &Ifconfig{
				Local:   ifcLocal.To4(),
				Mask:    net.CIDRMask(30, 32),
				Gateway: ifcSecond.To4(),
			}
		}
	}

	// Apply the explicit route-gateway to subnet-topology Ifconfig.
	if opts.Ifconfig != nil && opts.Topology == TopologySubnet && routeGateway != nil {
		opts.Ifconfig.Gateway = routeGateway
	}

	return opts, nil
}

// RedirectsIPv6 reports whether the pushed redirect-gateway asked for the IPv6
// cover, which is the "ipv6" flag word. It is read from the flags rather than
// kept beside them, which two ways to say one thing would let disagree.
func (o *PushOptions) RedirectsIPv6() bool {
	return o != nil && o.RedirectFlags.Has(RedirectIPv6)
}

// PushFields splits a PUSH_REPLY into its raw directives, without interpreting
// any of them: it strips the "PUSH_REPLY," prefix, the trailing NUL, the comma
// separators and the whitespace around each field.
func PushFields(msg string) []string {
	body := strings.TrimPrefix(strings.TrimRight(msg, "\x00"), "PUSH_REPLY,")
	var out []string
	for _, field := range strings.Split(body, ",") {
		if field = strings.TrimSpace(field); field != "" {
			out = append(out, field)
		}
	}
	return out
}
