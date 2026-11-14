// Unit tests for the routing package: the pure-Go PUSH_REPLY parser, which
// needs no privileges, and the netlink paths, which skip unless run as root.
package routing

import (
	"net"
	"testing"

	"github.com/buengese/go-openvpn/internal/compress"
)

// ---- ParsePushReply ----------------------------------------------------------

func TestParsePushReply_Basic(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,route 10.8.0.0 255.255.0.0," +
		"dhcp-option DNS 10.8.0.1,cipher AES-256-GCM\x00"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}

	if opts.Ifconfig == nil {
		t.Fatal("expected Ifconfig to be set")
	}
	if !opts.Ifconfig.Local.Equal(net.ParseIP("10.8.0.6")) {
		t.Errorf("local IP: got %s, want 10.8.0.6", opts.Ifconfig.Local)
	}
	// Net30 topology: second ifconfig arg is the P2P peer, stored as Gateway.
	if !opts.Ifconfig.Gateway.Equal(net.ParseIP("10.8.0.5")) {
		t.Errorf("gateway IP: got %s, want 10.8.0.5", opts.Ifconfig.Gateway)
	}

	if len(opts.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(opts.Routes))
	}
	r := opts.Routes[0]
	if !r.Network.Equal(net.ParseIP("10.8.0.0")) {
		t.Errorf("route network: got %s, want 10.8.0.0", r.Network)
	}
	wantMask := net.IPMask(net.ParseIP("255.255.0.0").To4())
	if r.Mask.String() != wantMask.String() {
		t.Errorf("route mask: got %s, want %s", r.Mask, wantMask)
	}
	if opts.RedirectGateway {
		t.Error("RedirectGateway should be false")
	}
}

func TestParsePushReply_RedirectGateway(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,redirect-gateway def1 bypass-dhcp"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if !opts.RedirectGateway {
		t.Error("expected RedirectGateway=true")
	}
}

func TestParsePushReply_RouteWithGateway(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,route 192.168.0.0 255.255.0.0 10.0.0.5"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if len(opts.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(opts.Routes))
	}
	if !opts.Routes[0].Gateway.Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("gateway: got %s, want 10.0.0.5", opts.Routes[0].Gateway)
	}
}

func TestParsePushReply_Empty(t *testing.T) {
	opts, err := ParsePushReply("PUSH_REPLY")
	if err != nil {
		t.Fatalf("ParsePushReply empty: %v", err)
	}
	if opts.Ifconfig != nil {
		t.Error("expected nil Ifconfig")
	}
	if len(opts.Routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(opts.Routes))
	}
}

// TestParsePushReply_MalformedIfconfig pins that a bad ifconfig fails the whole
// reply rather than yielding a half-configured tunnel: the local address is
// what the interface is brought up with.
func TestParsePushReply_MalformedIfconfig(t *testing.T) {
	for _, tc := range []struct{ name, msg string }{
		{"truncated", "PUSH_REPLY,ifconfig 10.0.0.1"},
		{"not an ip", "PUSH_REPLY,ifconfig not-an-ip 10.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePushReply(tc.msg); err == nil {
				t.Errorf("ParsePushReply(%q) succeeded, want an error", tc.msg)
			}
		})
	}
}

func TestParsePushReply_SubnetTopology(t *testing.T) {
	// AWS Client VPN typical PUSH_REPLY with subnet topology.
	msg := "PUSH_REPLY,topology subnet,ifconfig 172.16.77.4 255.255.255.224," +
		"route-gateway 172.16.77.1,route 10.130.0.0 255.255.0.0," +
		"dhcp-option DNS 10.130.0.2,peer-id 0,cipher AES-256-GCM\x00"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.Topology != TopologySubnet {
		t.Errorf("topology: got %v, want TopologySubnet", opts.Topology)
	}
	if opts.Ifconfig == nil {
		t.Fatal("expected Ifconfig to be set")
	}
	if !opts.Ifconfig.Local.Equal(net.ParseIP("172.16.77.4")) {
		t.Errorf("local IP: got %s, want 172.16.77.4", opts.Ifconfig.Local)
	}
	wantMask := net.IPMask(net.ParseIP("255.255.255.224").To4())
	if opts.Ifconfig.Mask.String() != wantMask.String() {
		t.Errorf("mask: got %s, want %s", opts.Ifconfig.Mask, wantMask)
	}
	if !opts.Ifconfig.Gateway.Equal(net.ParseIP("172.16.77.1")) {
		t.Errorf("gateway: got %s, want 172.16.77.1", opts.Ifconfig.Gateway)
	}
	if len(opts.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(opts.Routes))
	}
	if !opts.Routes[0].Network.Equal(net.ParseIP("10.130.0.0")) {
		t.Errorf("route: got %s, want 10.130.0.0", opts.Routes[0].Network)
	}
}

func TestParsePushReply_UnknownDirectivesIgnored(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,comp-lzo no,tun-mtu 1500"
	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply with unknown directives: %v", err)
	}
	if opts.Ifconfig == nil {
		t.Error("expected Ifconfig to be set")
	}
}

// TestParsePushReply_Compression pins the pushed-directive half of the
// compression seam. The mapping lives in compress.ModeForDirective, which the
// profile parser also goes through, so this asserts the delegation rather than
// the table: "compress stub-v2" and "compress lz4" are distinct modes, and one
// of them replaces the payload's first byte.
func TestParsePushReply_Compression(t *testing.T) {
	cases := []struct {
		push string
		want compress.Mode
	}{
		{"PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5", compress.ModeNone},
		{"PUSH_REPLY,comp-lzo", compress.ModeLZO},
		{"PUSH_REPLY,comp-lzo yes", compress.ModeLZO},
		{"PUSH_REPLY,comp-lzo no", compress.ModeStubNoSwap},
		{"PUSH_REPLY,compress", compress.ModeStub},
		{"PUSH_REPLY,compress stub-v2", compress.ModeStubV2},
		{"PUSH_REPLY,compress lz4", compress.ModeLZ4},
		{"PUSH_REPLY,compress lz4-v2", compress.ModeLZ4v2},
		// An algorithm OpenVPN would refuse leaves the field alone and does
		// not fail the whole reply.
		{"PUSH_REPLY,compress snappy", compress.ModeNone},
	}
	for _, tc := range cases {
		opts, err := ParsePushReply(tc.push)
		if err != nil {
			t.Errorf("ParsePushReply(%q): %v", tc.push, err)
			continue
		}
		if opts.Compression != tc.want {
			t.Errorf("ParsePushReply(%q).Compression = %v, want %v", tc.push, opts.Compression, tc.want)
		}
	}
}

// TestParsePushReply_Mssfix covers the accepted range. A value outside
// [68, 65535] is silently ignored rather than rejected: the rest of the reply
// is still usable.
func TestParsePushReply_Mssfix(t *testing.T) {
	for _, tc := range []struct {
		directive string
		want      int
	}{
		{"mssfix 1400", 1400},
		{"mssfix 10", 0},
		{"mssfix 70000", 0},
		{"mssfix 0", 0},
	} {
		t.Run(tc.directive, func(t *testing.T) {
			opts, err := ParsePushReply("PUSH_REPLY," + tc.directive)
			if err != nil {
				t.Fatalf("ParsePushReply(%q): %v", tc.directive, err)
			}
			if opts.Mssfix != tc.want {
				t.Errorf("Mssfix for %q: got %d, want %d", tc.directive, opts.Mssfix, tc.want)
			}
		})
	}
}

// TestParsePushReply_Inactive covers both forms of the directive. The second
// argument is an optional byte threshold: "inactive 300" alone must leave
// InactiveBytes at zero rather than inheriting the timeout, which would tear
// the tunnel down almost immediately.
func TestParsePushReply_Inactive(t *testing.T) {
	for _, tc := range []struct {
		directive   string
		wantTimeout int
		wantBytes   int64
	}{
		{"inactive 300", 300, 0},
		{"inactive 300 100", 300, 100},
	} {
		t.Run(tc.directive, func(t *testing.T) {
			opts, err := ParsePushReply("PUSH_REPLY," + tc.directive)
			if err != nil {
				t.Fatalf("ParsePushReply(%q): %v", tc.directive, err)
			}
			if opts.InactiveTimeout != tc.wantTimeout {
				t.Errorf("InactiveTimeout: got %d, want %d", opts.InactiveTimeout, tc.wantTimeout)
			}
			if int64(opts.InactiveBytes) != tc.wantBytes {
				t.Errorf("InactiveBytes: got %d, want %d", opts.InactiveBytes, tc.wantBytes)
			}
		})
	}
}

func TestParsePushReply_AuthToken(t *testing.T) {
	opts, err := ParsePushReply("PUSH_REPLY,auth-token server-session-token,cipher AES-256-GCM")
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.AuthToken != "server-session-token" {
		t.Errorf("AuthToken = %q, want server-session-token", opts.AuthToken)
	}
}

// TestParsePushReply_DataChannelCipherAndDigest covers the two data-channel
// crypto options a server pushes. Both outrank the profile, so an empty field
// has to mean "the server said nothing" and never "the server chose the
// default". The auth-token case is the trap: it is a credential, not a digest,
// and the two directives share a prefix.
func TestParsePushReply_DataChannelCipherAndDigest(t *testing.T) {
	tests := []struct {
		name       string
		msg        string
		wantCipher string
		wantAuth   string
		wantToken  string
	}{
		{
			name:       "cipher and digest both pushed",
			msg:        "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,cipher AES-256-CBC,auth SHA512",
			wantCipher: "AES-256-CBC",
			wantAuth:   "SHA512",
		},
		{
			name:     "digest only",
			msg:      "PUSH_REPLY,auth SHA1",
			wantAuth: "SHA1",
		},
		{
			name:       "cipher only leaves the digest empty",
			msg:        "PUSH_REPLY,cipher AES-256-GCM",
			wantCipher: "AES-256-GCM",
		},
		{
			name: "neither pushed",
			msg:  "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,ping 10",
		},
		{
			name:       "values are kept verbatim, as the cipher is",
			msg:        "PUSH_REPLY,cipher aes-128-gcm,auth sha256",
			wantCipher: "aes-128-gcm",
			wantAuth:   "sha256",
		},
		{
			name:       "auth-token is a credential and must not set the digest",
			msg:        "PUSH_REPLY,auth-token server-session-token,cipher AES-256-GCM",
			wantCipher: "AES-256-GCM",
			wantToken:  "server-session-token",
		},
		{
			name: "bare auth with no argument leaves the digest empty",
			msg:  "PUSH_REPLY,auth",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := ParsePushReply(tt.msg)
			if err != nil {
				t.Fatalf("ParsePushReply: %v", err)
			}
			if opts.Cipher != tt.wantCipher {
				t.Errorf("Cipher = %q, want %q", opts.Cipher, tt.wantCipher)
			}
			if opts.Auth != tt.wantAuth {
				t.Errorf("Auth = %q, want %q", opts.Auth, tt.wantAuth)
			}
			if opts.AuthToken != tt.wantToken {
				t.Errorf("AuthToken = %q, want %q", opts.AuthToken, tt.wantToken)
			}
		})
	}
}

func TestParsePushReply_Keepalive(t *testing.T) {
	// AWS Client VPN typical push with ping/ping-restart.
	msg := "PUSH_REPLY,topology subnet,ifconfig 172.16.77.135 255.255.255.224," +
		"route-gateway 172.16.77.129,route 10.130.0.0 255.255.0.0," +
		"dhcp-option DNS 10.130.0.2,ping 1,ping-restart 20,peer-id 0,cipher AES-256-GCM\x00"

	opts, err := ParsePushReply(msg)
	if err != nil {
		t.Fatalf("ParsePushReply: %v", err)
	}
	if opts.PingInterval != 1 {
		t.Errorf("PingInterval: got %d, want 1", opts.PingInterval)
	}
	if opts.PingRestart != 20 {
		t.Errorf("PingRestart: got %d, want 20", opts.PingRestart)
	}
}

// TestParsePushReply_KeyDerivation covers the two ways a server can ask for the
// TLS keying-material exporter and the default when it asks for neither. Stock
// OpenVPN 2.x pushes neither, and a client that read that silence as tls-ekm
// would derive keys the server never derived — undecryptable data packets
// rather than a handshake error.
func TestParsePushReply_KeyDerivation(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  string
		want KeyDerivation
	}{
		{
			name: "protocol-flags",
			msg:  "PUSH_REPLY,protocol-flags cc-exit tls-ekm dyn-tls-crypt,cipher AES-256-GCM",
			want: KeyDerivationTLSEKM,
		},
		{
			name: "key-derivation directive",
			msg:  "PUSH_REPLY,key-derivation tls-ekm,cipher AES-256-GCM",
			want: KeyDerivationTLSEKM,
		},
		{
			name: "neither, so the classic PRF",
			msg:  "PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,cipher AES-256-CBC",
			want: KeyDerivationOpenVPNPRF,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := ParsePushReply(tc.msg)
			if err != nil {
				t.Fatalf("ParsePushReply: %v", err)
			}
			if opts.KeyDerivation != tc.want {
				t.Errorf("KeyDerivation: got %v, want %v", opts.KeyDerivation, tc.want)
			}
		})
	}
}

// TestPushedSymbolicGatewaysDoNotEndTheSession covers the three names OpenVPN
// accepts in place of a gateway address, and the one it accepts for
// route-gateway. A name that failed net.ParseIP would fail the whole
// PUSH_REPLY and end the session, and net_gateway is the standard way a server
// excludes a destination from the tunnel.
//
// Reference: openvpn-2.6.22 src/openvpn/options.c:7034-7038 admits them via
// is_special_addr; route.c:236-300 resolves each at install time;
// options.c:7072 takes "dhcp" for route-gateway.
func TestPushedSymbolicGatewaysDoNotEndTheSession(t *testing.T) {
	for _, tc := range []struct {
		push       string
		wantSym    SymbolicGateway
		wantAround bool
	}{
		{"route 10.0.0.0 255.0.0.0 vpn_gateway", SymbolicVPNGateway, false},
		{"route 192.168.1.0 255.255.255.0 net_gateway", SymbolicNetGateway, true},
		{"route 203.0.113.5 255.255.255.255 remote_host", SymbolicRemoteHost, true},
	} {
		opts, err := ParsePushReply("PUSH_REPLY," + tc.push)
		if err != nil {
			t.Fatalf("%q ended the session: %v", tc.push, err)
		}
		if len(opts.Routes) != 1 {
			t.Fatalf("%q produced %d routes, want 1", tc.push, len(opts.Routes))
		}
		if got := opts.Routes[0].Symbolic; got != tc.wantSym {
			t.Errorf("%q: symbolic = %v, want %v", tc.push, got, tc.wantSym)
		}
		if got := opts.Routes[0].Symbolic.AroundTunnel(); got != tc.wantAround {
			t.Errorf("%q: AroundTunnel = %t, want %t", tc.push, got, tc.wantAround)
		}
	}
	if _, err := ParsePushReply("PUSH_REPLY,route-gateway dhcp"); err != nil {
		t.Errorf("route-gateway dhcp ended the session: %v", err)
	}
	if _, err := ParsePushReply("PUSH_REPLY,route 10.0.0.0 255.0.0.0 not_an_address"); err == nil {
		t.Error("an unrecognised gateway name was accepted; only the three OpenVPN names are")
	}
}
