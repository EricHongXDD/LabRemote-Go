package profile_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/profile"
)

// specRoundTrip takes p's Spec and requires it to build back to p.
func specRoundTrip(t *testing.T, p *profile.Profile) profile.Spec {
	t.Helper()
	s, err := p.Spec()
	if err != nil {
		t.Fatalf("Spec(): %v", err)
	}
	back, err := s.Build()
	if err != nil {
		t.Fatalf("Build: %v\nspec: %+v", err, s)
	}
	if diff := profileDiff(p, back); diff != "" {
		t.Errorf("Spec round-trip changed the profile:\n%s", diff)
	}
	return s
}

// TestRoundTripsEveryFixture pins, for every fixture, that its Spec builds
// back to it and renders to text that parses back to it.
func TestRoundTripsEveryFixture(t *testing.T) {
	for _, f := range fixtures(t) {
		if f.refused {
			continue
		}
		t.Run(f.id(), func(t *testing.T) {
			p, _, err := parseFixture(f.path)
			if err != nil {
				t.Fatalf("parse the fixture: %v", err)
			}
			if _, err := p.Spec(); err != nil && strings.Contains(err.Error(), "names a key file") {
				t.Skipf("no Spec by design: %v", err)
			}
			out := render(t, specRoundTrip(t, p))
			back, err := profile.ParseString(out)
			if err != nil {
				t.Fatalf("reparse: %v\n%s", err, out)
			}
			if diff := profileDiff(p, back); diff != "" {
				t.Errorf("render round-trip changed the profile:\n%s\nrendered:\n%s", diff, out)
			}
		})
	}
}

func TestSpecFields(t *testing.T) {
	const head = "remote a.test 1194\n<ca>\n" + testCA + "</ca>\n"

	cases := []struct {
		name string
		src  string
		want func(*testing.T, profile.Spec)
	}{{
		name: "defaults stay zero",
		src:  head + "cipher AES-256-GCM\nreneg-sec 3600\nremote b.test 1194 udp\n",
		want: func(t *testing.T, s profile.Spec) {
			if s.Cipher != "" || s.RenegSec != 0 {
				t.Errorf("Cipher=%q RenegSec=%d, want both zero", s.Cipher, s.RenegSec)
			}
			for _, e := range s.Remotes {
				if e.Port != 0 || e.Proto != "" {
					t.Errorf("endpoint %+v, want port and proto zero", e)
				}
			}
		},
	}, {
		name: "an explicit auth is kept",
		src:  head + "auth SHA1\n",
		want: func(t *testing.T, s profile.Spec) {
			if s.Auth != "SHA1" {
				t.Errorf("Auth = %q, want SHA1", s.Auth)
			}
		},
	}, {
		name: "profile-level port and proto land on the endpoint",
		src:  "proto tcp\nport 443\nremote a.test\n<ca>\n" + testCA + "</ca>\n",
		want: func(t *testing.T, s profile.Spec) {
			if len(s.Remotes) != 1 || s.Remotes[0] != (profile.Endpoint{Host: "a.test", Port: 443, Proto: "tcp"}) {
				t.Errorf("Remotes = %+v", s.Remotes)
			}
		},
	}, {
		name: "mssfix 0 is the opt-out",
		src:  head + "mssfix 0 mtu\n",
		want: func(t *testing.T, s profile.Spec) {
			if !s.MSSFixOff || s.MSSFixMode != profile.MSSFixEncap {
				t.Errorf("MSSFixOff=%v MSSFixMode=%v", s.MSSFixOff, s.MSSFixMode)
			}
		},
	}, {
		name: "ping-restart 0 disables the dead-link timer",
		src:  head + "ping 15\nping-restart 0\n",
		want: func(t *testing.T, s profile.Spec) {
			if s.Ping != 15 || !s.PingTimeoutOff || s.PingTimeout != 0 {
				t.Errorf("Ping=%d PingTimeout=%d PingTimeoutOff=%v", s.Ping, s.PingTimeout, s.PingTimeoutOff)
			}
		},
	}, {
		name: "reneg-sec 0 disables renegotiation",
		src:  head + "reneg-sec 0\n",
		want: func(t *testing.T, s profile.Spec) {
			if !s.NoReneg || s.RenegSec != 0 {
				t.Errorf("NoReneg=%v RenegSec=%d", s.NoReneg, s.RenegSec)
			}
		},
	}, {
		name: "timers",
		src:  head + "ping 10\nping-exit 60\n",
		want: func(t *testing.T, s profile.Spec) {
			if s.Ping != 10 || s.PingTimeout != 60 || !s.PingExit {
				t.Errorf("Ping=%d PingTimeout=%d PingExit=%v", s.Ping, s.PingTimeout, s.PingExit)
			}
		},
	}, {
		name: "compression is the resolved mode",
		src:  head + "comp-lzo\ncompress lz4\n",
		want: func(t *testing.T, s profile.Spec) {
			if s.Compression != "compress lz4" {
				t.Errorf("Compression = %q", s.Compression)
			}
		},
	}, {
		name: "a bare explicit-exit-notify is one",
		src:  head + "explicit-exit-notify\n",
		want: func(t *testing.T, s profile.Spec) {
			if s.ExplicitExitNotify != 1 {
				t.Errorf("ExplicitExitNotify = %d", s.ExplicitExitNotify)
			}
		},
	}, {
		name: "flags recorded from directives",
		src:  head + "auth-user-pass\nremote-cert-tls SERVER\nns-cert-type server\nx-go-openvpn-flow saml\n",
		want: func(t *testing.T, s profile.Spec) {
			if !s.AuthUserPass || !s.RemoteCertTLSServer || !s.NSCertTypeServer || !s.AuthFederate {
				t.Errorf("flags = %+v", s)
			}
			if len(s.Extra) != 0 {
				t.Errorf("Extra = %+v, want empty", s.Extra)
			}
		},
	}, {
		name: "both wrap keys",
		src: head + "<tls-auth>\n" + testStaticKey + "</tls-auth>\n" +
			"<tls-crypt>\n" + testStaticKey + "</tls-crypt>\n",
		want: func(t *testing.T, s profile.Spec) {
			if len(s.TLSAuth) == 0 || len(s.TLSCrypt) == 0 {
				t.Error("a wrap key was dropped")
			}
		},
	}, {
		name: "uncovered directives ride Extra in file order",
		src:  head + "verb 4\nnobind\ntls-version-min 1.2\n",
		want: func(t *testing.T, s profile.Spec) {
			var got []string
			for _, d := range s.Extra {
				got = append(got, d.String())
			}
			want := []string{"verb 4", "nobind", "tls-version-min 1.2"}
			if !slices.Equal(got, want) {
				t.Errorf("Extra = %v, want %v", got, want)
			}
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := profile.ParseString(tc.src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			tc.want(t, specRoundTrip(t, p))
		})
	}
}

func TestSpecTimerFormsRoundTrip(t *testing.T) {
	head := "remote a.test 1194\n<ca>\n" + testCA + "</ca>\n"
	for _, src := range []string{
		"ping-restart 30\nping-exit 60\n",
		"ping-exit 60\nping-restart 30\n",
		"ping-exit 0\n",
		"ping-restart 0\n",
		"keepalive 10 60\nping-exit 30\n",
		"keepalive 10 60\nping 5\n",
		"ping 10\nping-restart 60\n",
		"ping 10\n",
		"ping 15\nping-restart 0\n",
		"ping-restart 0\nkeepalive 5 30\n",
	} {
		t.Run(strings.ReplaceAll(strings.TrimSpace(src), "\n", " + "), func(t *testing.T) {
			p, err := profile.ParseString(head + src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			specRoundTrip(t, p)
		})
	}
}

func TestSpecRefusesAWrapKeyNamedInAFile(t *testing.T) {
	p, err := profile.ParseString("remote a.test 1194\n<ca>\n" + testCA + "</ca>\ntls-auth ta.key 1\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := p.Spec(); err == nil || !strings.Contains(err.Error(), "names a key file") {
		t.Errorf("Spec() error = %v, want the key file named as the cause", err)
	}
}

func TestSpecNilProfile(t *testing.T) {
	var p *profile.Profile
	s, err := p.Spec()
	if err != nil || len(s.Remotes) != 0 {
		t.Errorf("nil Profile: %+v, %v; want the zero Spec", s, err)
	}
}

// renderProfile writes p out through its Spec.
func renderProfile(t *testing.T, p *profile.Profile) string {
	t.Helper()
	s, err := p.Spec()
	if err != nil {
		t.Fatalf("Spec(): %v", err)
	}
	return render(t, s)
}

// A profile that named its CA in a file renders as text that stands alone.
func TestRenderInlinesAFileReference(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ca.crt", caPEM)
	p, err := profile.ParsePath(writeProfile(t, dir, "remote vpn.example.test 1194\nca ca.crt\n"))
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	out := renderProfile(t, p)
	if strings.Contains(out, "ca ca.crt") || !strings.Contains(out, "<ca>") {
		t.Errorf("the CA was not inlined:\n%s", out)
	}
	back, err := profile.ParseString(out)
	if err != nil {
		t.Fatalf("reparse: %v\n%s", err, out)
	}
	if string(back.CA) != string(p.CA) {
		t.Error("the inlined CA is not the material the file held")
	}
}

func TestRenderWritesTheWrapKey(t *testing.T) {
	p, err := profile.ParseString("remote a.test 1194\n<ca>\n" + testCA + "</ca>\n" +
		"<tls-auth>\n" + testStaticKey + "</tls-auth>\nkey-direction 1\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	back, err := profile.ParseString(renderProfile(t, p))
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if back.TLSAuth == nil || *back.TLSAuth != *p.TLSAuth {
		t.Error("the wrap key did not survive byte-for-byte")
	}
}

func TestRenderRefusesABodyHoldingItsClosingTag(t *testing.T) {
	s := profile.Spec{
		Remotes: []profile.Endpoint{{Host: "a.test"}},
		CA:      []byte(testCA + "</ca>\nremote evil.test\n"),
	}
	if _, err := s.Render(); err == nil {
		t.Error("Render wrote a CA body that closes its own block")
	}
}
