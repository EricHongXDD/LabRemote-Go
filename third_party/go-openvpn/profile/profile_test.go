package profile_test

import (
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/profile"
)

const minimal = `
client
remote vpn.example.com 443
proto tcp-client
cipher AES-256-GCM
auth SHA256
reneg-sec 3600

<ca>
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
</ca>

<cert>
-----BEGIN CERTIFICATE-----
MIIC...
-----END CERTIFICATE-----
</cert>

<key>
-----BEGIN RSA PRIVATE KEY-----
MIIE...
-----END RSA PRIVATE KEY-----
</key>
`

func TestParseMinimal(t *testing.T) {
	p, err := profile.ParseString(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if p.Remote != "vpn.example.com" {
		t.Errorf("Remote = %q", p.Remote)
	}
	if p.Port != 443 {
		t.Errorf("Port = %d, want 443", p.Port)
	}
	if p.Proto != profile.ProtoTCP {
		t.Errorf("Proto = %v, want TCP", p.Proto)
	}
	if p.Cipher != "AES-256-GCM" {
		t.Errorf("Cipher = %q", p.Cipher)
	}
	if p.Auth != "SHA256" || !p.AuthSet {
		t.Errorf("Auth = %q (set %v), want SHA256 (set true)", p.Auth, p.AuthSet)
	}
	if p.RenegSec != 3600 {
		t.Errorf("RenegSec = %d, want 3600", p.RenegSec)
	}
	if !strings.Contains(string(p.CA), "BEGIN CERTIFICATE") {
		t.Error("CA PEM not parsed")
	}
	if !strings.Contains(string(p.Cert), "BEGIN CERTIFICATE") {
		t.Error("Cert PEM not parsed")
	}
	if !strings.Contains(string(p.Key), "BEGIN RSA PRIVATE KEY") {
		t.Error("Key PEM not parsed")
	}
}

func TestParseDefaults(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	if p.Port != 1194 {
		t.Errorf("default Port = %d, want 1194", p.Port)
	}
	if p.Proto != profile.ProtoUDP {
		t.Errorf("default Proto = %v, want UDP", p.Proto)
	}
	if p.Cipher != "AES-256-GCM" {
		t.Errorf("default Cipher = %q", p.Cipher)
	}
	if p.Auth != "SHA1" {
		t.Errorf("default Auth = %q, want SHA1 (OpenVPN's built-in default)", p.Auth)
	}
	if p.AuthSet {
		t.Error("default AuthSet = true, want false: the profile said nothing about auth")
	}
	if p.Verb != 3 {
		t.Errorf("default Verb = %d, want 3", p.Verb)
	}
}

// TestParseAuthDigest pins the digest for every shape of 'auth', absent
// included (SHA1).
func TestParseAuthDigest(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    string
		wantSet bool
	}{
		{
			name:   "absent yields the SHA1 default",
			config: "remote vpn.example.test 443\n",
			want:   "SHA1",
		},
		{
			name:   "absent with a CBC cipher still yields SHA1",
			config: "remote vpn.example.test 443\ncipher AES-256-CBC\n",
			want:   "SHA1",
		},
		{
			name:    "explicit SHA1 is indistinguishable in value, not in AuthSet",
			config:  "remote vpn.example.test 443\nauth SHA1\n",
			want:    "SHA1",
			wantSet: true,
		},
		{
			name:    "explicit SHA256",
			config:  "remote vpn.example.test 443\nauth SHA256\n",
			want:    "SHA256",
			wantSet: true,
		},
		{
			name:    "explicit SHA512",
			config:  "remote vpn.example.test 443\nauth SHA512\n",
			want:    "SHA512",
			wantSet: true,
		},
		{
			name:    "lowercase is upcased",
			config:  "remote vpn.example.test 443\nauth sha512\n",
			want:    "SHA512",
			wantSet: true,
		},
		{
			name:    "the last directive wins, as it does in OpenVPN",
			config:  "remote vpn.example.test 443\nauth SHA1\nauth SHA512\n",
			want:    "SHA512",
			wantSet: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := profile.ParseString(tt.config)
			if err != nil {
				t.Fatal(err)
			}
			if p.Auth != tt.want {
				t.Errorf("Auth = %q, want %q", p.Auth, tt.want)
			}
			if p.AuthSet != tt.wantSet {
				t.Errorf("AuthSet = %v, want %v", p.AuthSet, tt.wantSet)
			}
		})
	}
}

// TestParseAuthPrefixedDirectivesLeaveDigestAlone pins that directives merely
// beginning with "auth" do not set the digest.
func TestParseAuthPrefixedDirectivesLeaveDigestAlone(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"auth-user-pass", "auth-user-pass"},
		{"auth-user-pass with a file argument", "auth-user-pass creds.txt"},
		{"auth-nocache", "auth-nocache"},
		{"auth-retry", "auth-retry nointeract"},
		{"auth-federate", "auth-federate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.test 443\n" + tt.line + "\n")
			if err != nil {
				t.Fatal(err)
			}
			if p.AuthSet {
				t.Errorf("AuthSet = true: %q was mistaken for an auth directive", tt.line)
			}
			if p.Auth != "SHA1" {
				t.Errorf("Auth = %q, want the SHA1 default: %q must not set the digest", p.Auth, tt.line)
			}
			keyword := strings.Fields(tt.line)[0]
			var seen bool
			for _, d := range p.Directives {
				if d.Name == keyword {
					seen = true
				}
			}
			if !seen {
				t.Errorf("%q not recorded on Directives", keyword)
			}
		})
	}
}

// TestParseNumericDirectives covers numeric directives and their absent value.
func TestParseNumericDirectives(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		get  func(*profile.Profile) int64
		want int64
	}{
		{"verb", "verb 4\n", func(p *profile.Profile) int64 { return int64(p.Verb) }, 4},
		{"reneg-sec", "reneg-sec 7200\n", func(p *profile.Profile) int64 { return int64(p.RenegSec) }, 7200},
		{
			// Zero is not "unset": it disables client-initiated rekey.
			name: "reneg-sec 0 disables client rekey",
			src:  "reneg-sec 0\n",
			get:  func(p *profile.Profile) int64 { return int64(p.RenegSec) },
			want: 0,
		},
		{
			name: "absent reneg-sec takes OpenVPN's default",
			src:  "",
			get:  func(p *profile.Profile) int64 { return int64(p.RenegSec) },
			want: 3600,
		},
		{"reneg-bytes", "reneg-bytes 10485760\n", func(p *profile.Profile) int64 { return p.RenegBytes }, 10485760},
		{"become-primary", "become-primary 5\n", func(p *profile.Profile) int64 { return int64(p.BecomePrimarySec) }, 5},
		{"tun-mtu", "tun-mtu 1400\n", func(p *profile.Profile) int64 { return int64(p.TunMTU) }, 1400},
		{
			// Zero means unset.
			name: "absent tun-mtu leaves the field unset",
			src:  "",
			get:  func(p *profile.Profile) int64 { return int64(p.TunMTU) },
			want: 0,
		},
		{"mssfix", "mssfix 1200\n", func(p *profile.Profile) int64 { return int64(p.MSSFix) }, 1200},
		{"ping", "ping 5\n", func(p *profile.Profile) int64 { return int64(p.PingInterval) }, 5},
		{
			// Zero means unset.
			name: "absent ping leaves the interval unset",
			src:  "",
			get:  func(p *profile.Profile) int64 { return int64(p.PingInterval) },
			want: 0,
		},
		{
			name: "absent ping-restart leaves the timeout unset",
			src:  "",
			get:  func(p *profile.Profile) int64 { return int64(p.PingTimeout) },
			want: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.test 443\n" + tc.src)
			if err != nil {
				t.Fatalf("ParseString(%q): %v", tc.src, err)
			}
			if got := tc.get(p); got != tc.want {
				t.Errorf("%q parsed to %d, want %d", tc.src, got, tc.want)
			}
		})
	}
}

// TestParseRejectsOutOfRangeArguments pins that out-of-range or non-numeric
// arguments are parse errors, not clamped.
func TestParseRejectsOutOfRangeArguments(t *testing.T) {
	for _, src := range []string{
		"verb 12\n",
		"tun-mtu 0\n",
		"tun-mtu abc\n",
		"tun-mtu 65536\n",
		"tun-mtu -1\n",
		"mssfix abc\n",
		"mssfix -1\n",
		"ping\n",
		"ping abc\n",
		"ping -1\n",
		"ping-restart -1\n",
		"ping-exit abc\n",
		// Reference: OpenVPN 2.6.22 src/openvpn/options.c line 6952 and
		// src/openvpn/helper.c lines 521-524.
		"keepalive\n",
		"keepalive 10\n",
		"keepalive 0 60\n",
		"keepalive 10 0\n",
		"keepalive abc 60\n",
	} {
		t.Run(strings.TrimSpace(src), func(t *testing.T) {
			if _, err := profile.ParseString("remote vpn.example.test 443\n" + src); err == nil {
				t.Errorf("ParseString(%q) succeeded, want an error", src)
			}
		})
	}
}

// TestParseMSSFixSetSeparatesZeroFromAbsent pins that "mssfix 0" and a bare
// "mssfix" are distinguishable.
func TestParseMSSFixSetSeparatesZeroFromAbsent(t *testing.T) {
	explicit, err := profile.ParseString("remote vpn.example.test 443\nmssfix 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if !explicit.MSSFixSet {
		t.Error("MSSFixSet = false for an explicit mssfix 0")
	}
	bare, err := profile.ParseString("remote vpn.example.test 443\nmssfix\n")
	if err != nil {
		t.Fatal(err)
	}
	if bare.MSSFixSet {
		t.Error("MSSFixSet = true for a bare mssfix, which names no value")
	}
}

// TestParseKeepaliveOutranksPingDirectives pins that keepalive wins over ping
// and ping-restart wherever it appears.
// Reference: openvpn3-core ssl/proto.hpp lines 1278-1294.
func TestParseKeepaliveOutranksPingDirectives(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"keepalive first", "keepalive 10 120\nping 5\nping-restart 30\n"},
		{"keepalive last", "ping 5\nping-restart 30\nkeepalive 10 120\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.test 443\n" + tc.src)
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			if p.PingInterval != 10 {
				t.Errorf("PingInterval = %d, want 10 from the keepalive helper", p.PingInterval)
			}
			if p.PingTimeout != 120 {
				t.Errorf("PingTimeout = %d, want 120 from the keepalive helper", p.PingTimeout)
			}
			if p.PingExit {
				t.Error("PingExit = true, but keepalive expands to ping-restart")
			}
		})
	}
}

// TestParsePingTimeoutSetSeparatesZeroFromAbsent pins that "ping-restart 0",
// which disables the dead-link timer, is distinguishable from no directive.
func TestParsePingTimeoutSetSeparatesZeroFromAbsent(t *testing.T) {
	for _, tc := range []struct {
		src     string
		wantSet bool
	}{
		{"", false},
		{"ping 15\n", false},
		{"ping-restart 0\n", true},
		{"ping-exit 0\n", true},
		{"ping-restart 60\n", true},
		{"keepalive 10 60\n", true},
	} {
		p, err := profile.ParseString("remote vpn.example.test 443\n" + tc.src)
		if err != nil {
			t.Fatalf("ParseString(%q): %v", tc.src, err)
		}
		if p.PingTimeoutSet != tc.wantSet {
			t.Errorf("%q: PingTimeoutSet = %v, want %v", tc.src, p.PingTimeoutSet, tc.wantSet)
		}
	}
}

// TestParsePingExitIsNotPingRestart pins the action bit separating two
// directives that share a timeout.
// Reference: OpenVPN 2.6.22 src/openvpn/options.c lines 6963-6975.
func TestParsePingExitIsNotPingRestart(t *testing.T) {
	exit, err := profile.ParseString("remote vpn.example.test 443\nping-exit 60\n")
	if err != nil {
		t.Fatal(err)
	}
	if exit.PingTimeout != 60 || !exit.PingExit {
		t.Errorf("ping-exit 60 parsed to timeout %d exit %v, want 60 true", exit.PingTimeout, exit.PingExit)
	}
	restart, err := profile.ParseString("remote vpn.example.test 443\nping-restart 60\n")
	if err != nil {
		t.Fatal(err)
	}
	if restart.PingTimeout != 60 || restart.PingExit {
		t.Errorf("ping-restart 60 parsed to timeout %d exit %v, want 60 false", restart.PingTimeout, restart.PingExit)
	}
}

func TestParseStaticDNSOptions(t *testing.T) {
	p, err := profile.ParseString(`
remote vpn.example.test
dhcp-option DNS 10.130.0.2
dhcp-option DOMAIN corp.example.test
dhcp-option DOMAIN-ROUTE internal.company.com
dhcp-option DOMAIN-ROUTE us-east-2.eks.amazonaws.com
`)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(p.DNS.Servers), 1; got != want || p.DNS.Servers[0].String() != "10.130.0.2" {
		t.Errorf("DNS servers = %v, want [10.130.0.2]", p.DNS.Servers)
	}
	if got, want := p.DNS.SearchDomains, []string{"corp.example.test"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("search domains = %v, want %v", got, want)
	}
	if got, want := p.DNS.RouteDomains, []string{"internal.company.com", "us-east-2.eks.amazonaws.com"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("route domains = %v, want %v", got, want)
	}
}

// TestParseExplicitExitNotify covers the optional count; a negative or
// unparseable one disables the notification.
// Reference: OpenVPN 2.4.12 options.c line 4210, positive_atoi.
func TestParseExplicitExitNotify(t *testing.T) {
	for _, tc := range []struct {
		directive string
		want      int
	}{
		{"proto udp", 0},
		{"proto udp\nexplicit-exit-notify", 1},
		{"proto udp\nexplicit-exit-notify 5", 5},
		{"proto udp\nexplicit-exit-notify 0", 0},
		{"proto udp\nexplicit-exit-notify -3", 0},
		{"proto udp\nexplicit-exit-notify garbage", 0},
		// Stock openvpn refuses this over TCP; we parse it and decline to
		// send. Reference: OpenVPN 2.4.12 options.c line 2181.
		{"proto tcp-client\nexplicit-exit-notify 5", 5},
	} {
		t.Run(tc.directive, func(t *testing.T) {
			p, err := profile.ParseString("remote h 1194\n" + tc.directive + "\n")
			if err != nil {
				t.Fatalf("ParseString(%q): %v", tc.directive, err)
			}
			if p.ExplicitExitNotify != tc.want {
				t.Errorf("%q: ExplicitExitNotify = %d, want %d",
					tc.directive, p.ExplicitExitNotify, tc.want)
			}
		})
	}
}

func TestParsePathMissing(t *testing.T) {
	_, err := profile.ParsePath("/nonexistent/path/test.ovpn")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestZeroAuthFlowIsTheOrdinaryOne pins that the zero AuthFlow is a plain
// handshake.
func TestZeroAuthFlowIsTheOrdinaryOne(t *testing.T) {
	var zero profile.AuthFlow
	if zero != profile.FlowCertAuth {
		t.Errorf("the zero AuthFlow is %v, want %v", zero, profile.FlowCertAuth)
	}
	for _, tc := range []struct {
		flow profile.AuthFlow
		want string
	}{
		{profile.FlowCertAuth, "cert"},
		{profile.FlowUserPass, "user-pass"},
		{profile.FlowFederated, "federated"},
	} {
		if got := tc.flow.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

// TestAuthFederateIsWhatSaysFederated pins auth-federate as the directive that
// selects the federated flow.
func TestAuthFederateIsWhatSaysFederated(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.test 443\nauth-federate\n")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Federated {
		t.Fatal("Federated = false, want true")
	}
	if got := p.AuthFlow(); got != profile.FlowFederated {
		t.Errorf("AuthFlow() = %v, want FlowFederated", got)
	}
}

// TestAuthFlowPrefersCredentialsOverACertificate pins that auth-user-pass
// beats an embedded <cert>/<key>.
func TestAuthFlowPrefersCredentialsOverACertificate(t *testing.T) {
	const cert = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
	const key = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"

	tests := []struct {
		name       string
		config     string
		withCert   bool
		wantFlow   profile.AuthFlow
		wantNeeded bool
	}{
		{
			name:     "certificate alone is cert auth",
			config:   "remote vpn.example.test 443\n",
			withCert: true,
			wantFlow: profile.FlowCertAuth,
		},
		{
			name:       "auth-user-pass alone is user-pass",
			config:     "remote vpn.example.test 443\nauth-user-pass\n",
			wantFlow:   profile.FlowUserPass,
			wantNeeded: true,
		},
		{
			name:       "both is user-pass",
			config:     "remote vpn.example.test 443\nauth-user-pass\n",
			withCert:   true,
			wantFlow:   profile.FlowUserPass,
			wantNeeded: true,
		},
		{
			name:     "neither falls back to user-pass",
			config:   "remote vpn.example.test 443\n",
			wantFlow: profile.FlowUserPass,
		},
		{
			name:       "the federated flow wins over both",
			config:     "remote vpn.example.test 443\nauth-federate\nauth-user-pass\n",
			withCert:   true,
			wantFlow:   profile.FlowFederated,
			wantNeeded: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := profile.ParseString(tc.config)
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			if tc.withCert {
				p.Cert, p.Key = []byte(cert), []byte(key)
			}
			if got := p.AuthFlow(); got != tc.wantFlow {
				t.Errorf("AuthFlow() = %v, want %v", got, tc.wantFlow)
			}
			if got := p.RequiresCredentials(); got != tc.wantNeeded {
				t.Errorf("RequiresCredentials() = %t, want %t", got, tc.wantNeeded)
			}
		})
	}
}

// tlsAuthProfile carries a full 256-byte key whose block opens on line 7.
var tlsAuthProfile = `client
dev tun
proto udp
remote vpn.example.com 1194
cipher AES-256-CBC
key-direction 1
<tls-auth>
` + staticKeyBlock(testKeyFill) + `</tls-auth>
<ca>
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
</ca>
`

func TestParseRecordsDirectives(t *testing.T) {
	p, err := profile.ParseString(minimal)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"client", "remote", "proto", "cipher", "auth", "reneg-sec"}
	if len(p.Directives) != len(want) {
		t.Fatalf("Directives = %v, want %d entries", p.Directives, len(want))
	}
	for i, name := range want {
		if p.Directives[i].Name != name {
			t.Errorf("Directives[%d].Name = %q, want %q", i, p.Directives[i].Name, name)
		}
		if p.Directives[i].Line <= 0 {
			t.Errorf("Directives[%d].Line = %d, want positive", i, p.Directives[i].Line)
		}
	}
	if got := p.Directives[1].String(); got != "remote vpn.example.com 443" {
		t.Errorf("Directives[1].String() = %q", got)
	}
	if len(p.Directives[0].Args) != 0 {
		t.Errorf("bare directive kept args: %v", p.Directives[0].Args)
	}
}

func TestParseRecordsUnrecognisedDirectives(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com 443\nfast-io\nsndbuf 524288\n")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, d := range p.Directives {
		got[d.Name] = d.Args
	}
	if _, ok := got["fast-io"]; !ok {
		t.Error("fast-io not recorded")
	}
	if args := got["sndbuf"]; len(args) != 1 || args[0] != "524288" {
		t.Errorf("sndbuf args = %v, want [524288]", args)
	}
}

// TestParseRecordsInlineBlocksNotTheirBodies pins that each opening tag is
// recorded with its line, and no body line reaches the directive list.
func TestParseRecordsInlineBlocksNotTheirBodies(t *testing.T) {
	p, err := profile.ParseString(tlsAuthProfile)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, d := range p.Directives {
		if strings.HasPrefix(d.Name, "-----") || len(d.Name) == 32 {
			t.Errorf("inline block body parsed as directive: %q at line %d", d.Name, d.Line)
		}
		names = append(names, d.Name)
	}
	want := "client dev proto remote cipher key-direction"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("directives = %q, want %q", got, want)
	}

	if len(p.InlineBlocks) != 2 {
		t.Fatalf("InlineBlocks = %v, want 2 entries", p.InlineBlocks)
	}
	if p.InlineBlocks[0].Tag != "tls-auth" || p.InlineBlocks[1].Tag != "ca" {
		t.Errorf("InlineBlocks = %v, want tls-auth then ca", p.InlineBlocks)
	}
	if p.InlineBlocks[0].Line != 7 {
		t.Errorf("tls-auth block line = %d, want 7", p.InlineBlocks[0].Line)
	}
	if len(p.CA) == 0 {
		t.Error("CA not loaded")
	}
	if strings.Contains(string(p.CA), "OpenVPN Static key") {
		t.Error("tls-auth body leaked into CA")
	}
}

// TestParseInlineBlockTagsAreCaseInsensitive pins case-folded tags for the
// loaded blocks; openvpn3-core matches verbatim.
// Reference: openvpn3-core common/options.hpp update_map.
func TestParseInlineBlockTagsAreCaseInsensitive(t *testing.T) {
	const body = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	for _, tc := range []struct {
		tag  string
		want func(*profile.Profile) int
	}{
		{"CA", func(p *profile.Profile) int { return len(p.CA) }},
		{"Cert", func(p *profile.Profile) int { return len(p.Cert) }},
		{"KEY", func(p *profile.Profile) int { return len(p.Key) }},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.com 443\n" +
				"<" + tc.tag + ">\n" + body + "</" + tc.tag + ">\n")
			if err != nil {
				t.Fatal(err)
			}
			if tc.want(p) == 0 {
				t.Errorf("<%s> was recorded as present but its body was loaded nowhere", tc.tag)
			}
			if len(p.InlineBlocks) != 1 || p.InlineBlocks[0].Tag != tc.tag {
				t.Errorf("InlineBlocks = %v, want the tag as the file spelled it", p.InlineBlocks)
			}
		})
	}

	// Check nil, not len: len of a nil *[256]byte is still 256.
	for _, tc := range []struct {
		tag  string
		want func(*profile.Profile) *profile.StaticKey
	}{
		{"TLS-AUTH", func(p *profile.Profile) *profile.StaticKey { return p.TLSAuth }},
		{"Tls-Crypt", func(p *profile.Profile) *profile.StaticKey { return p.TLSCrypt }},
	} {
		t.Run(tc.tag, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.com 443\n" +
				"<" + tc.tag + ">\n" + staticKeyBlock(testKeyFill) + "</" + tc.tag + ">\n")
			if err != nil {
				t.Fatal(err)
			}
			if tc.want(p) == nil {
				t.Errorf("<%s> was recorded as present but its key was loaded nowhere", tc.tag)
			}
		})
	}
}

// TestParseInlineBlockClosesOnlyOnItsOwnTag pins exact closing-tag matching.
// Reference: openvpn3-core common/options.hpp is_close_tag.
func TestParseInlineBlockClosesOnlyOnItsOwnTag(t *testing.T) {
	for _, closer := range []string{"</CA>", "</cert>", "</x>"} {
		t.Run(closer, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.com 443\n" +
				"<ca>\nMIIB...\n" + closer + "\nfast-io\n")
			if err != nil {
				t.Fatal(err)
			}
			// Unterminated: the block consumed "fast-io" too.
			if len(p.CA) != 0 {
				t.Errorf("%s closed the <ca> block: CA = %q", closer, p.CA)
			}
			for _, d := range p.Directives {
				if d.Name == "fast-io" {
					t.Errorf("%s closed the <ca> block: %q escaped the body", closer, d.Name)
				}
			}
		})
	}
}

func TestParseRemoteRandomHostname(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com 443\nremote-random-hostname\n")
	if err != nil {
		t.Fatal(err)
	}
	if !p.RandomHostname {
		t.Error("RandomHostname = false, want true")
	}
	if p.RemoteRandom {
		t.Error("RemoteRandom = true: remote-random-hostname is not remote-random")
	}

	q, err := profile.ParseString("remote vpn.example.com 443\nremote-random\n")
	if err != nil {
		t.Fatal(err)
	}
	if q.RandomHostname {
		t.Error("remote-random set RandomHostname")
	}
	if !q.RemoteRandom {
		t.Error("RemoteRandom = false, want true")
	}
}

// TestParseFlowDirectiveAsksForSAML pins that only "x-go-openvpn-flow saml",
// or its old x-openlawsvpn-flow spelling, selects the federated flow.
func TestParseFlowDirectiveAsksForSAML(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"x-go-openvpn-flow saml", true},
		{"x-go-openvpn-flow SAML", true},
		{"x-go-openvpn-flow Saml", true},
		{"x-go-openvpn-flow", false},
		{"x-go-openvpn-flow cert", false},
		{"x-go-openvpn-flow samlx", false},

		{"x-openlawsvpn-flow saml", true},
		{"x-openlawsvpn-flow SAML", true},
		{"x-openlawsvpn-flow Saml", true},
		{"x-openlawsvpn-flow", false},
		{"x-openlawsvpn-flow cert", false},
		{"x-openlawsvpn-flow samlx", false},
	} {
		t.Run(tc.line, func(t *testing.T) {
			p, err := profile.ParseString("remote vpn.example.com 443\n" + tc.line + "\n")
			if err != nil {
				t.Fatal(err)
			}
			if p.Federated != tc.want {
				t.Errorf("Federated = %t, want %t", p.Federated, tc.want)
			}
			wantFlow := profile.FlowUserPass
			if tc.want {
				wantFlow = profile.FlowFederated
			}
			if got := p.AuthFlow(); got != wantFlow {
				t.Errorf("AuthFlow() = %v, want %v", got, wantFlow)
			}
		})
	}
}

func TestParseMalformedTagsAreNeitherBlocksNorDirectives(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.com 443\n<>\n< ca >\n</ca>\nfast-io\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.InlineBlocks) != 0 {
		t.Errorf("InlineBlocks = %v, want none", p.InlineBlocks)
	}
	var names []string
	for _, d := range p.Directives {
		if strings.HasPrefix(d.Name, "<") {
			t.Errorf("markup recorded as directive: %q", d.Name)
		}
		names = append(names, d.Name)
	}
	if got := strings.Join(names, " "); got != "remote fast-io" {
		t.Errorf("directives = %q, want \"remote fast-io\"", got)
	}
}

// TestParseVerifyX509NameMatchType covers the match type; omitted means
// "subject".
func TestParseVerifyX509NameMatchType(t *testing.T) {
	for _, tc := range []struct {
		line string
		want profile.X509NameMatch
	}{
		{"verify-x509-name Server-1", profile.X509NameSubject},
		{"verify-x509-name Server-1 subject", profile.X509NameSubject},
		{"verify-x509-name Server-1 name", profile.X509NameCN},
		{"verify-x509-name Server-1 name-prefix", profile.X509NameCNPrefix},
	} {
		t.Run(tc.line, func(t *testing.T) {
			p, err := profile.ParseString("remote h 443\n" + tc.line + "\n")
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			if p.VerifyX509Name != "Server-1" {
				t.Errorf("VerifyX509Name = %q, want %q", p.VerifyX509Name, "Server-1")
			}
			if p.VerifyX509NameMatch != tc.want {
				t.Errorf("VerifyX509NameMatch = %v, want %v", p.VerifyX509NameMatch, tc.want)
			}
		})
	}
}

func TestParseVerifyX509NameRejectsAnUnknownMatchType(t *testing.T) {
	_, err := profile.ParseString("remote h 443\nverify-x509-name Server-1 san\n")
	if err == nil {
		t.Fatal("an unrecognised verify-x509-name match type parsed")
	}
	if !strings.Contains(err.Error(), "verify-x509-name") {
		t.Errorf("error does not name the directive: %v", err)
	}
}

func TestX509NameMatchRoundTrips(t *testing.T) {
	for _, m := range []profile.X509NameMatch{
		profile.X509NameSubject, profile.X509NameCN, profile.X509NameCNPrefix,
	} {
		got, ok := profile.ParseX509NameMatch(m.String())
		if !ok || got != m {
			t.Errorf("ParseX509NameMatch(%q) = %v, %v; want %v, true", m.String(), got, ok, m)
		}
	}
}

func TestParseHandWindow(t *testing.T) {
	p, err := profile.ParseString("client\nremote vpn.example.com 1194 udp\nhand-window 25\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.HandWindowSec != 25 {
		t.Fatalf("HandWindowSec = %d, want 25", p.HandWindowSec)
	}

	for _, bad := range []string{"hand-window", "hand-window 0", "hand-window -5", "hand-window soon"} {
		if _, err := profile.ParseString("client\nremote vpn.example.com 1194 udp\n" + bad + "\n"); err == nil {
			t.Errorf("Parse(%q) accepted a value that decides when keys turn over", bad)
		}
	}
}

// TestMSSFixModeParsesTheSecondWord pins the mssfix mode word.
func TestMSSFixModeParsesTheSecondWord(t *testing.T) {
	for _, tc := range []struct {
		directive string
		wantMode  profile.MSSFixMode
	}{
		{"mssfix 1400", profile.MSSFixLink},
		{"mssfix 1400 mtu", profile.MSSFixEncap},
		{"mssfix 1400 fixed", profile.MSSFixFixed},
		// Unknown word keeps the default.
		// Reference: OpenVPN options.c:7341-7343.
		{"mssfix 1400 nonsense", profile.MSSFixLink},
	} {
		t.Run(tc.directive, func(t *testing.T) {
			p, err := profile.ParseString("client\nremote example.com 1194\n" + tc.directive + "\n")
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.directive, err)
			}
			if !p.MSSFixSet || p.MSSFix != 1400 {
				t.Fatalf("MSSFix = %d (set=%v), want 1400 set", p.MSSFix, p.MSSFixSet)
			}
			if p.MSSFixMode != tc.wantMode {
				t.Errorf("MSSFixMode = %v, want %v", p.MSSFixMode, tc.wantMode)
			}
		})
	}
}

// compressionProfile wraps src in the smallest profile ParseString accepts.
func compressionProfile(src string) string {
	return strings.Join([]string{"client", "dev tun", "remote host.example.test 1194", src}, "\n") + "\n"
}

// TestParseCompressionDirectives covers every spelling OpenVPN accepts. Bare
// "compress" swaps and "comp-lzo no" does not, though both are stubs.
func TestParseCompressionDirectives(t *testing.T) {
	cases := []struct {
		src  string
		want compress.Mode
	}{
		{"", compress.ModeNone},
		{"comp-lzo", compress.ModeLZO},
		{"comp-lzo yes", compress.ModeLZO},
		{"comp-lzo adaptive", compress.ModeLZO},
		{"comp-lzo no", compress.ModeStubNoSwap},
		{"compress", compress.ModeStub},
		{"compress stub", compress.ModeStub},
		{"compress stub-v2", compress.ModeStubV2},
		{"compress lzo", compress.ModeLZO},
		{"compress lz4", compress.ModeLZ4},
		{"compress lz4-v2", compress.ModeLZ4v2},
		// Last one wins.
		{"comp-lzo\ncompress stub-v2", compress.ModeStubV2},
		{"COMPRESS LZ4", compress.ModeLZ4},
	}
	for _, tc := range cases {
		p, err := profile.ParseString(compressionProfile(tc.src))
		if err != nil {
			t.Errorf("ParseString(%q): %v", tc.src, err)
			continue
		}
		if p.Compression != tc.want {
			t.Errorf("%q parsed to %v, want %v", tc.src, p.Compression, tc.want)
		}
	}
}

func TestParseAllowCompressionDirective(t *testing.T) {
	cases := []struct {
		src  string
		want compress.AllowCompression
	}{
		{"", compress.AllowUnset},
		{"allow-compression no", compress.AllowNo},
		{"allow-compression asym", compress.AllowAsym},
		{"allow-compression yes", compress.AllowYes},
	}
	for _, tc := range cases {
		p, err := profile.ParseString(compressionProfile(tc.src))
		if err != nil {
			t.Errorf("ParseString(%q): %v", tc.src, err)
			continue
		}
		if p.AllowCompression != tc.want {
			t.Errorf("%q parsed to %v, want %v", tc.src, p.AllowCompression, tc.want)
		}
	}
}

func TestParseCompressionRefusesWhatOpenVPNRefuses(t *testing.T) {
	for _, src := range []string{
		"comp-lzo maybe",
		"compress snappy",
		"compress lzo-v9",
		"allow-compression",
		"allow-compression sometimes",
	} {
		if _, err := profile.ParseString(compressionProfile(src)); err == nil {
			t.Errorf("ParseString(%q) succeeded; OpenVPN refuses this directive", src)
		}
	}
}

// TestCompressionSurvivesAllowCompressionNo pins that the parser records both
// fields as written; compress.EffectiveMode reconciles them.
func TestCompressionSurvivesAllowCompressionNo(t *testing.T) {
	p, err := profile.ParseString(compressionProfile("comp-lzo\nallow-compression no"))
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if p.Compression != compress.ModeLZO {
		t.Errorf("Compression = %v, want %v: the parser records what the file said",
			p.Compression, compress.ModeLZO)
	}
	if p.AllowCompression != compress.AllowNo {
		t.Errorf("AllowCompression = %v, want %v", p.AllowCompression, compress.AllowNo)
	}
	if _, err := compress.EffectiveMode(p.Compression, compress.ModeNone, p.AllowCompression); err == nil {
		t.Error("EffectiveMode accepted comp-lzo under allow-compression no; that " +
			"combination must fail rather than downgrade silently")
	}
}
