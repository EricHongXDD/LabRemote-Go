// Unit tests for the --remote triple.
package profile_test

import (
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/profile"
)

// mustParse parses src and fails the test if it does not.
func mustParse(t *testing.T, src string) *profile.Profile {
	t.Helper()
	p, err := profile.ParseString(src)
	if err != nil {
		t.Fatalf("ParseString(%q): %v", src, err)
	}
	return p
}

func TestParseProtoSpellings(t *testing.T) {
	tests := []struct {
		in    string
		want  profile.Proto
		valid bool
	}{
		{"udp", profile.ProtoUDP, true},
		{"UDP", profile.ProtoUDP, true},
		{"udp4", profile.ProtoUDP, true},
		{"udp6", profile.ProtoUDP, true},
		{"tcp", profile.ProtoTCP, true},
		// Stock openvpn refuses upper case; we accept.
		{"TCP", profile.ProtoTCP, true},
		{"tcp-client", profile.ProtoTCP, true},
		{"tcp4-client", profile.ProtoTCP, true},
		{"tcp6-client", profile.ProtoTCP, true},
		{"tcp4", profile.ProtoTCP, true},
		{"tcp6", profile.ProtoTCP, true},
		// The -server spellings ask this process to listen.
		{"tcp-server", 0, false},
		{"tcp4-server", 0, false},
		{"kcp", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		got, ok := profile.ParseProto(tt.in)
		if ok != tt.valid {
			t.Errorf("ParseProto(%q) ok = %v, want %v", tt.in, ok, tt.valid)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("ParseProto(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestRemoteTriple(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantHost  string
		wantPort  int
		wantProto profile.Proto
		wantSet   bool
	}{
		{
			name:      "host only takes the profile defaults",
			src:       "remote vpn.example.test\n",
			wantHost:  "vpn.example.test",
			wantPort:  1194,
			wantProto: profile.ProtoUDP,
		},
		{
			name:      "host and port",
			src:       "remote vpn.example.test 443\n",
			wantHost:  "vpn.example.test",
			wantPort:  443,
			wantProto: profile.ProtoUDP,
		},
		{
			name:      "host, port and tcp-client",
			src:       "remote vpn.example.test 443 tcp-client\n",
			wantHost:  "vpn.example.test",
			wantPort:  443,
			wantProto: profile.ProtoTCP,
			wantSet:   true,
		},
		{
			name:      "an explicit udp is recorded as explicit",
			src:       "remote vpn.example.test 1194 udp\n",
			wantHost:  "vpn.example.test",
			wantPort:  1194,
			wantProto: profile.ProtoUDP,
			wantSet:   true,
		},
		{
			name:      "the remote's own protocol beats the profile's",
			src:       "proto udp\nremote vpn.example.test 443 tcp-client\n",
			wantHost:  "vpn.example.test",
			wantPort:  443,
			wantProto: profile.ProtoTCP,
			wantSet:   true,
		},
		{
			name:      "a proto directive below the remote still applies",
			src:       "remote vpn.example.test 443\nproto tcp\n",
			wantHost:  "vpn.example.test",
			wantPort:  443,
			wantProto: profile.ProtoTCP,
		},
		{
			name:      "a port directive below the remote still applies",
			src:       "remote vpn.example.test\nport 8443\n",
			wantHost:  "vpn.example.test",
			wantPort:  8443,
			wantProto: profile.ProtoUDP,
		},
		{
			name:      "upper-case TCP in the third field",
			src:       "remote vpn.example.test 1195 TCP\n",
			wantHost:  "vpn.example.test",
			wantPort:  1195,
			wantProto: profile.ProtoTCP,
			wantSet:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustParse(t, tt.src)
			if len(p.Remotes) != 1 {
				t.Fatalf("got %d remotes, want 1", len(p.Remotes))
			}
			r := p.Remotes[0]
			if r.Host != tt.wantHost || r.Port != tt.wantPort || r.Proto != tt.wantProto {
				t.Errorf("Remotes[0] = %+v, want {%s %d %v}",
					r, tt.wantHost, tt.wantPort, tt.wantProto)
			}
			if r.ProtoSet != tt.wantSet {
				t.Errorf("ProtoSet = %v, want %v", r.ProtoSet, tt.wantSet)
			}
			if p.Remote != r.Host || p.Port != r.Port || p.Proto != r.Proto {
				t.Errorf("compat fields {%s %d %v} disagree with Remotes[0] %+v",
					p.Remote, p.Port, p.Proto, r)
			}
		})
	}
}

// TestRemoteFirstWins pins that the first remote is dialed.
func TestRemoteFirstWins(t *testing.T) {
	p := mustParse(t, strings.Join([]string{
		"proto udp",
		"remote a.example.test 443",
		"remote 203.0.113.9 443",
		"remote a.example.test 1194",
		"remote 203.0.113.9 1194",
		"",
	}, "\n"))

	if len(p.Remotes) != 4 {
		t.Fatalf("got %d remotes, want 4 — every line is retained", len(p.Remotes))
	}
	if p.Remote != "a.example.test" || p.Port != 443 {
		t.Errorf("dialed endpoint = %s:%d, want a.example.test:443 (the first line)",
			p.Remote, p.Port)
	}
	want := []struct {
		host string
		port int
	}{
		{"a.example.test", 443},
		{"203.0.113.9", 443},
		{"a.example.test", 1194},
		{"203.0.113.9", 1194},
	}
	for i, w := range want {
		if p.Remotes[i].Host != w.host || p.Remotes[i].Port != w.port {
			t.Errorf("Remotes[%d] = %s:%d, want %s:%d",
				i, p.Remotes[i].Host, p.Remotes[i].Port, w.host, w.port)
		}
		if p.Remotes[i].Proto != profile.ProtoUDP {
			t.Errorf("Remotes[%d].Proto = %v, want udp from the profile",
				i, p.Remotes[i].Proto)
		}
	}
}

func TestRemotesMayDisagreeOnTransport(t *testing.T) {
	p := mustParse(t, "remote a.example.test 1194 udp\nremote b.example.test 443 tcp-client\n")
	if len(p.Remotes) != 2 {
		t.Fatalf("got %d remotes, want 2", len(p.Remotes))
	}
	if p.Remotes[0].Proto != profile.ProtoUDP || p.Remotes[1].Proto != profile.ProtoTCP {
		t.Errorf("protocols = %v, %v; want udp, tcp", p.Remotes[0].Proto, p.Remotes[1].Proto)
	}
	if p.Proto != profile.ProtoUDP {
		t.Errorf("Proto = %v, want the first remote's udp", p.Proto)
	}
}

func TestRemoteRejectsBadFields(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"missing hostname", "remote\n"},
		{"port out of range", "remote host 99999\n"},
		{"port not a number", "remote host https\n"},
		{"unknown protocol", "remote host 443 kcp\n"},
		{"server protocol", "remote host 443 tcp-server\n"},
		{"unknown proto directive", "remote host 443\nproto kcp\n"},
		{"server proto directive", "remote host 443\nproto tcp-server\n"},
		{"no remote at all", "proto udp\n"},
		{"no remote, only other directives", "cipher AES-256-GCM\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := profile.ParseString(tt.src); err == nil {
				t.Errorf("ParseString(%q) succeeded, want an error", tt.src)
			}
		})
	}
}
