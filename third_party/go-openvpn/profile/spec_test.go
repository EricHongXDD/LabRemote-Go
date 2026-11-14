package profile_test

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/profile"
)

// render is Spec.Render, failing the test on error.
func render(t *testing.T, s profile.Spec) string {
	t.Helper()
	out, err := s.Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out
}

// stripLines clears Line, which Build numbers in emit order.
func stripLines(p *profile.Profile) {
	for i := range p.Directives {
		p.Directives[i].Line = 0
	}
	for i := range p.InlineBlocks {
		p.InlineBlocks[i].Line = 0
	}
}

// 512 hex digits, which is the only length ParseStaticKey accepts.
var testStaticKey = "-----BEGIN OpenVPN Static key V1-----\n" +
	strings.Repeat("abcdef0123456789", 32) + "\n" +
	"-----END OpenVPN Static key V1-----\n"

const testCA = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKZ1x2Y3Z4Q5MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
-----END CERTIFICATE-----
`

// TestBuildEqualsParse pins that Build matches parsing the equivalent file.
func TestBuildEqualsParse(t *testing.T) {
	specs := map[string]profile.Spec{
		"bare remote": {
			Remotes: []profile.Endpoint{{Host: "vpn.example.test"}},
		},
		"certificate auth": {
			Remotes:             []profile.Endpoint{{Host: "vpn.example.test", Port: 1194}},
			CA:                  []byte(testCA),
			RemoteCertTLSServer: true,
		},
		"username and password over tcp": {
			Remotes:      []profile.Endpoint{{Host: "vpn.example.test", Port: 443, Proto: "tcp"}},
			CA:           []byte(testCA),
			AuthUserPass: true,
			Cipher:       "AES-256-CBC",
			Auth:         "SHA256",
			Compression:  "comp-lzo",
		},
		"tls-crypt wrapped": {
			Remotes:  []profile.Endpoint{{Host: "vpn.example.test"}},
			CA:       []byte(testCA),
			TLSCrypt: []byte(testStaticKey),
		},
		"tls-auth with a key direction": {
			Remotes:      []profile.Endpoint{{Host: "vpn.example.test"}},
			CA:           []byte(testCA),
			TLSAuth:      []byte(testStaticKey),
			KeyDirection: profile.KeyDirection1,
			Auth:         "SHA1",
		},
		"several remotes": {
			Remotes: []profile.Endpoint{
				{Host: "a.example.test"},
				{Host: "b.example.test", Port: 8443},
				{Host: "c.example.test", Proto: "tcp"},
			},
			RemoteRandom: true,
		},
		"timers": {
			Remotes:     []profile.Endpoint{{Host: "vpn.example.test"}},
			Ping:        10,
			PingTimeout: 60,
		},
		"timers ending the session": {
			Remotes:     []profile.Endpoint{{Host: "vpn.example.test"}},
			Ping:        10,
			PingTimeout: 60,
			PingExit:    true,
		},
		"a timeout alone": {
			Remotes:     []profile.Endpoint{{Host: "vpn.example.test"}},
			PingTimeout: 60,
		},
		"the tri-state opt-outs": {
			Remotes:   []profile.Endpoint{{Host: "vpn.example.test"}},
			MSSFixOff: true,
			NoReneg:   true,
		},
		"mssfix with a mode word": {
			Remotes:    []profile.Endpoint{{Host: "vpn.example.test"}},
			MSSFix:     1400,
			MSSFixMode: profile.MSSFixFixed,
			TunMTU:     1400,
		},
		"dns and x509 name": {
			Remotes:             []profile.Endpoint{{Host: "vpn.example.test"}},
			VerifyX509Name:      "server-1",
			VerifyX509NameMatch: profile.X509NameCN,
			DNS: profile.DNSOptions{
				Servers:       []string{"10.0.0.1", "10.0.0.2"},
				SearchDomains: []string{"corp.example.test"},
				RouteDomains:  []string{"internal.example.test"},
			},
		},
		"x509 name prefix": {
			Remotes:             []profile.Endpoint{{Host: "vpn.example.test"}},
			VerifyX509Name:      "server-",
			VerifyX509NameMatch: profile.X509NameCNPrefix,
		},
		// The parser case-folds directive names.
		"an upper-case compression directive": {
			Remotes:     []profile.Endpoint{{Host: "vpn.example.test"}},
			Compression: "COMP-LZO",
		},
		"everything else": {
			Remotes:              []profile.Endpoint{{Host: "vpn.example.test"}},
			AuthFederate:         true,
			NSCertTypeServer:     true,
			AllowCompression:     "no",
			RenegSec:             1800,
			RenegBytes:           1 << 20,
			HandWindow:           90,
			BecomePrimary:        45,
			ExplicitExitNotify:   1,
			RemoteRandomHostname: true,
			Extra:                []profile.Directive{{Name: "tls-version-min", Args: []string{"1.2"}}},
		},
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			built, err := spec.Build()
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			text := render(t, spec)
			parsed, err := profile.ParseString(text)
			if err != nil {
				t.Fatalf("ParseString of the equivalent file: %v\n%s", err, text)
			}
			stripLines(built)
			stripLines(parsed)
			if !reflect.DeepEqual(built, parsed) {
				t.Errorf("Build and ParseString disagree.\nfile:\n%s\nbuilt:  %+v\nparsed: %+v", text, built, parsed)
			}
		})
	}
}

// TestBuildRefusesWhatAFileCouldNotSay covers Specs no file could express.
func TestBuildRefusesWhatAFileCouldNotSay(t *testing.T) {
	base := func() profile.Spec {
		return profile.Spec{Remotes: []profile.Endpoint{{Host: "vpn.example.test"}}}
	}
	for name, mutate := range map[string]func(*profile.Spec){
		"no remote":                 func(s *profile.Spec) { s.Remotes = nil },
		"mssfix set and off":        func(s *profile.Spec) { s.MSSFix, s.MSSFixOff = 1400, true },
		"reneg set and disabled":    func(s *profile.Spec) { s.RenegSec, s.NoReneg = 1800, true },
		"ping timeout set and off":  func(s *profile.Spec) { s.PingTimeout, s.PingTimeoutOff = 60, true },
		"ping-exit with no timeout": func(s *profile.Spec) { s.PingExit = true },
		"extra carries a field's directive": func(s *profile.Spec) {
			s.Extra = []profile.Directive{{Name: "ping-restart", Args: []string{"60"}}}
		},
		"extra names a block":            func(s *profile.Spec) { s.Extra = []profile.Directive{{Name: "ca", Args: []string{"x"}}} },
		"argument with whitespace":       func(s *profile.Spec) { s.Extra = []profile.Directive{{Name: "setenv", Args: []string{"a b"}}} },
		"unparseable proto":              func(s *profile.Spec) { s.Remotes[0].Proto = "tcp-server" },
		"unusable static key":            func(s *profile.Spec) { s.TLSAuth = []byte("not a key") },
		"compression is only whitespace": func(s *profile.Spec) { s.Compression = " " },
		"compression spans two lines":    func(s *profile.Spec) { s.Compression = "comp-lzo\nno" },
		"extra name carries its argument": func(s *profile.Spec) {
			s.Extra = []profile.Directive{{Name: "tls-version-min 1.2"}}
		},
		"extra name opens an inline block": func(s *profile.Spec) {
			s.Extra = []profile.Directive{{Name: "<ca>"}}
		},
		"extra name is a comment": func(s *profile.Spec) {
			s.Extra = []profile.Directive{{Name: "#tls-version-min", Args: []string{"1.2"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := base()
			mutate(&s)
			if _, err := s.Build(); err == nil {
				t.Error("Build accepted a spec no profile could express")
			}
		})
	}
}

// FuzzBuildEqualsParse drives TestBuildEqualsParse over generated specs.
// Build may reject a spec; it must never accept one the parser reads differently.
func FuzzBuildEqualsParse(f *testing.F) {
	f.Add("vpn.example.test", 1194, "udp", "AES-256-GCM", "SHA256", 1500, 1400, 3600, 10, 60, true, false,
		"comp-lzo", "tls-version-min", "1.2")
	f.Add("a.test", 0, "", "", "", 0, 0, 0, 0, 0, false, false, "", "", "")
	f.Add("b.test", 443, "tcp", "AES-128-CBC", "SHA1", 1400, 0, 0, 5, 30, false, true,
		"compress lz4-v2", "", "")
	// Hosts that do not render as one whitespace-free word.
	f.Add("", 1130, "", "", "", 0, 0, 0, 0, 0, false, false, "", "", "")
	f.Add(" 0", 443, "", "0", "0", 1400, 0, 0, 153, 30, true, true, "", "", "")
	// Compression and Extra text that a file would read differently.
	f.Add("c.test", 0, "", "", "", 0, 0, 0, 0, 0, false, false, " ", "", "")
	f.Add("d.test", 0, "", "", "", 0, 0, 0, 0, 0, false, false, "COMP-LZO", "", "")
	f.Add("0", 13, "", "", "0", 0, 0, 0, 0, 91, true, false, "0\n0", "1", "0")
	f.Add("e.test", 0, "", "", "", 0, 0, 0, 0, 0, false, false, "", "tls-version-min 1.2", "")

	f.Fuzz(func(t *testing.T, host string, port int, proto, cipher, auth string,
		mtu, mssfix, reneg, ping, keepalive int, userpass, certtls bool,
		compression, extraName, extraArg string) {
		s := profile.Spec{
			Remotes:             []profile.Endpoint{{Host: host, Port: port, Proto: proto}},
			Cipher:              cipher,
			Auth:                auth,
			TunMTU:              mtu,
			MSSFix:              mssfix,
			RenegSec:            reneg,
			Ping:                ping,
			AuthUserPass:        userpass,
			RemoteCertTLSServer: certtls,
			Compression:         compression,
		}
		s.PingTimeout = keepalive
		// An empty name with an argument is the Extra shape Build refuses.
		if extraName != "" || extraArg != "" {
			d := profile.Directive{Name: extraName}
			if extraArg != "" {
				d.Args = []string{extraArg}
			}
			s.Extra = []profile.Directive{d}
		}
		built, err := s.Build()
		if err != nil {
			return // stricter than a file is allowed; wrong is not
		}
		text, err := s.Render()
		if err != nil {
			t.Fatalf("Build accepted a spec Render refuses: %v", err)
		}
		parsed, perr := profile.ParseString(text)
		if perr != nil {
			t.Fatalf("Build accepted a spec the parser refuses: %v\n%s", perr, text)
		}
		stripLines(built)
		stripLines(parsed)
		if !reflect.DeepEqual(built, parsed) {
			t.Fatalf("Build and ParseString disagree.\nfile:\n%s\nbuilt:  %+v\nparsed: %+v", text, built, parsed)
		}
	})
}

// ExampleSpec_Build shows the defaults the assembler fills in around a Spec.
func ExampleSpec_Build() {
	p, err := profile.Spec{
		Remotes:             []profile.Endpoint{{Host: "vpn.example.test"}},
		CA:                  []byte(testCA),
		AuthUserPass:        true,
		RemoteCertTLSServer: true,
	}.Build()
	if err != nil {
		fmt.Println("build:", err)
		return
	}
	fmt.Printf("dial      %s:%d over %v\n", p.Remote, p.Port, p.Proto)
	fmt.Printf("cipher    %s, auth %s (explicit: %t)\n", p.Cipher, p.Auth, p.AuthSet)
	fmt.Printf("reneg-sec %d\n", p.RenegSec)
	fmt.Printf("needs credentials: %t\n", p.RequiresCredentials())
	// Output:
	// dial      vpn.example.test:1194 over udp
	// cipher    AES-256-GCM, auth SHA1 (explicit: false)
	// reneg-sec 3600
	// needs credentials: true
}

// TestSpecJSONRoundTrip pins that a Spec survives JSON, enums included.
func TestSpecJSONRoundTrip(t *testing.T) {
	want := profile.Spec{
		Remotes:             []profile.Endpoint{{Host: "a.test", Port: 443, Proto: "tcp"}, {Host: "b.test"}},
		CA:                  []byte(testCA),
		Cert:                []byte(testCA),
		Key:                 []byte("-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"),
		KeyDirection:        profile.KeyDirection1,
		Cipher:              "AES-128-CBC",
		Auth:                "SHA256",
		VerifyX509Name:      "vpn.example.test",
		VerifyX509NameMatch: profile.X509NameCNPrefix,
		Compression:         "comp-lzo no",
		MSSFix:              1400,
		MSSFixMode:          profile.MSSFixFixed,
		Ping:                10,
		PingTimeout:         60,
		DNS:                 profile.DNSOptions{Servers: []string{"10.0.0.1"}, SearchDomains: []string{"corp.test"}},
		Extra:               []profile.Directive{{Name: "verb", Args: []string{"4"}}},
	}

	doc, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got profile.Spec
	if err := json.Unmarshal(doc, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip differs\n got %+v\nwant %+v", got, want)
	}

	// Keys are directive spellings; an absent directive is an absent key.
	for _, key := range []string{
		`"key_direction":"1"`, `"verify_x509_name_match":"name-prefix"`, `"mssfix_mode":"fixed"`,
	} {
		if !strings.Contains(string(doc), key) {
			t.Errorf("document is missing %s:\n%s", key, doc)
		}
	}
	for _, absent := range []string{"tun_mtu", "no_reneg", "auth_federate", "remote_random"} {
		if strings.Contains(string(doc), `"`+absent+`"`) {
			t.Errorf("document carries %q, which was never set:\n%s", absent, doc)
		}
	}
}

// TestSpecEnumTextForms pins the enums' serialised names; changing one is a
// data migration.
func TestSpecEnumTextForms(t *testing.T) {
	cases := []struct {
		v    encoding.TextMarshaler
		want string
	}{
		{profile.KeyDirectionAbsent, "absent"},
		{profile.KeyDirection0, "0"},
		{profile.KeyDirection1, "1"},
		{profile.X509NameSubject, "subject"},
		{profile.X509NameCN, "name"},
		{profile.X509NameCNPrefix, "name-prefix"},
		{profile.MSSFixLink, "link"},
		{profile.MSSFixEncap, "mtu"},
		{profile.MSSFixFixed, "fixed"},
	}
	for _, tc := range cases {
		b, err := tc.v.MarshalText()
		if err != nil {
			t.Errorf("%T(%v).MarshalText: %v", tc.v, tc.v, err)
			continue
		}
		if string(b) != tc.want {
			t.Errorf("%T(%v) marshals as %q, want %q", tc.v, tc.v, b, tc.want)
		}
	}
}

// TestSpecEnumsRefuseUnknownText pins that unknown names are refused and
// out-of-range values marshal to a placeholder that is refused in turn.
func TestSpecEnumsRefuseUnknownText(t *testing.T) {
	var kd profile.KeyDirection
	var x5 profile.X509NameMatch
	var mf profile.MSSFixMode

	for _, name := range []string{"nonesuch", "", "2", "LINK"} {
		if err := kd.UnmarshalText([]byte(name)); err == nil {
			t.Errorf("KeyDirection accepted %q", name)
		}
		if err := x5.UnmarshalText([]byte(name)); err == nil {
			t.Errorf("X509NameMatch accepted %q", name)
		}
		if err := mf.UnmarshalText([]byte(name)); err == nil {
			t.Errorf("MSSFixMode accepted %q", name)
		}
	}

	outOfRange := []struct {
		name string
		text func() ([]byte, error)
		back func([]byte) error
	}{
		{"KeyDirection", profile.KeyDirection(99).MarshalText, func(b []byte) error {
			var v profile.KeyDirection
			return v.UnmarshalText(b)
		}},
		{"X509NameMatch", profile.X509NameMatch(99).MarshalText, func(b []byte) error {
			var v profile.X509NameMatch
			return v.UnmarshalText(b)
		}},
		{"MSSFixMode", profile.MSSFixMode(99).MarshalText, func(b []byte) error {
			var v profile.MSSFixMode
			return v.UnmarshalText(b)
		}},
	}
	for _, tc := range outOfRange {
		b, err := tc.text()
		if err != nil {
			t.Errorf("%s(99).MarshalText returned an error: %v", tc.name, err)
			continue
		}
		if err := tc.back(b); err == nil {
			t.Errorf("%s(99) marshalled as %q and was accepted back; an out-of-range "+
				"value must not become a valid one", tc.name, b)
		}
	}

	// The real defaults must still be accepted, or the guard has gone too far.
	if err := mf.UnmarshalText([]byte("link")); err != nil || mf != profile.MSSFixLink {
		t.Errorf(`MSSFixMode "link" = %v, err %v; want MSSFixLink`, mf, err)
	}
	if err := kd.UnmarshalText([]byte("absent")); err != nil || kd != profile.KeyDirectionAbsent {
		t.Errorf(`KeyDirection "absent" = %v, err %v; want KeyDirectionAbsent`, kd, err)
	}
}
