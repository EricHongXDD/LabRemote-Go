// SPDX-License-Identifier: LGPL-2.1-or-later

// Assembling a Profile from directives. The parser and Spec.Build both
// feed this one assembler, which applies the defaults, normalisers and
// end-of-file resolution.

package profile

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/dns"
	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/internal/crypto"
)

// defaultPort is the port a profile dials when no directive names one.
const defaultPort = 1194

// defaultCipher and defaultRenegSec are the values a profile starts from when
// no directive names them.
const (
	defaultCipher   = "AES-256-GCM"
	defaultRenegSec = 3600
)

// assembler builds a Profile from directives and inline blocks. Start from
// newAssembler.
type assembler struct {
	p    *Profile
	refs []pendingFileRef

	// keepalive is resolved in finish because it outranks ping and
	// ping-restart wherever they appear.
	keepalivePing    int
	keepaliveTimeout int
	keepaliveSeen    bool
}

// newAssembler returns an assembler holding a profile's defaults.
func newAssembler() *assembler {
	return &assembler{p: &Profile{
		Port:   defaultPort,
		Proto:  ProtoUDP,
		Cipher: defaultCipher,
		// OpenVPN's built-in digest default is SHA1 (openvpn(8) --auth).
		Auth: crypto.DefaultAuthName,
		Verb: 3,
		// openvpn3-core ssl/proto.hpp's default; an explicit reneg-sec,
		// including 0, overrides it.
		RenegSec: defaultRenegSec,
	}}
}

// openBlock records that an inline <tag> block began. An unterminated block
// still counts as present.
func (a *assembler) openBlock(tag string, line int) {
	a.p.InlineBlocks = append(a.p.InlineBlocks, InlineBlock{Tag: tag, Line: line})
}

// closeBlock takes the body of a completed inline block, keeping <ca>,
// <cert>, <key>, <tls-auth> and <tls-crypt>. The tag is folded, so <CA>
// loads as <ca>.
func (a *assembler) closeBlock(tag string, body []byte) error {
	p := a.p
	tag = strings.ToLower(tag)
	switch tag {
	case "ca":
		p.CA = append([]byte{}, body...)
	case "cert":
		p.Cert = append([]byte{}, body...)
	case "key":
		p.Key = append([]byte{}, body...)
	case "tls-auth", "tls-crypt":
		key, err := ParseStaticKey(body)
		if err != nil {
			// The error never quotes the key.
			return diag.Wrap(diag.ClassConfig, diag.StageParse, err,
				"<"+tag+"> is not a usable OpenVPN static key")
		}
		if tag == "tls-auth" {
			p.TLSAuth = key
		} else {
			p.TLSCrypt = key
		}
	}
	return nil
}

// directive folds one directive into the profile, recording it whether or
// not the switch acts on it.
func (a *assembler) directive(d Directive) error {
	p := a.p
	p.Directives = append(p.Directives, d)

	fields := append([]string{d.Name}, d.Args...)
	directive := d.Name
	lineNo := d.Line
	switch directive {
	case "remote":
		// remote <host> [port] [proto]. Port and proto are resolved in
		// finish, since --port and --proto may come later in the file.
		if len(fields) < 2 {
			return fmt.Errorf("profile: remote: missing hostname")
		}
		rem := Remote{Host: fields[1]}
		if len(fields) >= 3 {
			port, err := strconv.Atoi(fields[2])
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("profile: remote: invalid port %q", fields[2])
			}
			rem.Port = port
		}
		if len(fields) >= 4 {
			proto, ok := ParseProto(fields[3])
			if !ok {
				return fmt.Errorf("profile: remote: unknown protocol %q", fields[3])
			}
			rem.Proto, rem.ProtoSet = proto, true
		}
		p.Remotes = append(p.Remotes, rem)
	case "port":
		if len(fields) < 2 {
			return fmt.Errorf("profile: port: missing value")
		}
		port, err := strconv.Atoi(fields[1])
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("profile: port: invalid %q", fields[1])
		}
		p.Port = port
	case "proto":
		if len(fields) < 2 {
			return fmt.Errorf("profile: proto: missing value")
		}
		proto, ok := ParseProto(fields[1])
		if !ok {
			return fmt.Errorf("profile: proto: unknown %q", fields[1])
		}
		p.Proto = proto
	case "cipher":
		// Upper-cased so one profile has one spelling in reports.
		if len(fields) < 2 {
			return fmt.Errorf("profile: cipher: missing value")
		}
		p.Cipher = strings.ToUpper(fields[1])
	case "auth":
		if len(fields) < 2 {
			return fmt.Errorf("profile: auth: missing value")
		}
		p.Auth = strings.ToUpper(fields[1])
		p.AuthSet = true
	case "verb":
		if len(fields) < 2 {
			return fmt.Errorf("profile: verb: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 || n > 11 {
			return fmt.Errorf("profile: verb: invalid %q", fields[1])
		}
		p.Verb = n
	case "reneg-sec":
		if len(fields) < 2 {
			return fmt.Errorf("profile: reneg-sec: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 {
			return fmt.Errorf("profile: reneg-sec: invalid %q", fields[1])
		}
		p.RenegSec = n
	case "reneg-bytes":
		if len(fields) < 2 {
			return fmt.Errorf("profile: reneg-bytes: missing value")
		}
		n, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("profile: reneg-bytes: invalid %q", fields[1])
		}
		p.RenegBytes = n
	case "ping":
		// Reference: openvpn-2.6.22 src/openvpn/options.c:6958.
		if len(fields) < 2 {
			return fmt.Errorf("profile: ping: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 {
			return fmt.Errorf("profile: ping: invalid %q", fields[1])
		}
		p.PingInterval = n
	case "ping-restart", "ping-exit":
		// Both set the one timeout; see Profile.PingTimeout.
		if len(fields) < 2 {
			return fmt.Errorf("profile: %s: missing value", directive)
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 {
			return fmt.Errorf("profile: %s: invalid %q", directive, fields[1])
		}
		p.PingTimeout = n
		p.PingTimeoutSet = true
		p.PingExit = directive == "ping-exit"
	case "keepalive":
		// Expands to ping N and ping-restart M in finish. Both arguments
		// must be positive (openvpn-2.6.22 src/openvpn/options.c:6952,
		// src/openvpn/helper.c:521-524).
		if len(fields) < 3 {
			return fmt.Errorf("profile: keepalive: want 'keepalive <interval> <timeout>'")
		}
		ping, err := strconv.Atoi(fields[1])
		if err != nil || ping <= 0 {
			return fmt.Errorf("profile: keepalive: invalid interval %q", fields[1])
		}
		timeout, err := strconv.Atoi(fields[2])
		if err != nil || timeout <= 0 {
			return fmt.Errorf("profile: keepalive: invalid timeout %q", fields[2])
		}
		a.keepalivePing, a.keepaliveTimeout, a.keepaliveSeen = ping, timeout, true
	case "hand-window":
		if len(fields) < 2 {
			return fmt.Errorf("profile: hand-window: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n <= 0 {
			return fmt.Errorf("profile: hand-window: invalid %q", fields[1])
		}
		p.HandWindowSec = n
	case "become-primary":
		if len(fields) < 2 {
			return fmt.Errorf("profile: become-primary: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 0 {
			return fmt.Errorf("profile: become-primary: invalid %q", fields[1])
		}
		p.BecomePrimarySec = n
	case "explicit-exit-notify":
		// A malformed count disables the notification rather than
		// refusing the profile, as OpenVPN's positive_atoi does
		// (openvpn-2.4.12 src/openvpn/options.c:4210).
		n := 1
		if len(fields) > 1 {
			n = 0
			if v, err := strconv.Atoi(fields[1]); err == nil && v > 0 {
				n = v
			}
		}
		p.ExplicitExitNotify = n
	case "comp-lzo", "compress":
		// compress.ModeForDirective maps the directive and argument to a
		// framing, shared with the PUSH_REPLY parser.
		arg := ""
		if len(fields) > 1 {
			arg = fields[1]
		}
		mode, ok := compress.ModeForDirective(directive, arg)
		if !ok {
			return fmt.Errorf("profile: %s: unknown compression %q", directive, arg)
		}
		p.Compression = mode
	case "allow-compression":
		if len(fields) < 2 {
			return fmt.Errorf("profile: allow-compression: missing value")
		}
		allow, ok := compress.ParseAllowCompression(fields[1])
		if !ok {
			return fmt.Errorf("profile: allow-compression: invalid %q", fields[1])
		}
		p.AllowCompression = allow
	case "tun-mtu":
		if len(fields) < 2 {
			return fmt.Errorf("profile: tun-mtu: missing value")
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil || n < 68 || n > 65535 {
			return fmt.Errorf("profile: tun-mtu: invalid %q", fields[1])
		}
		p.TunMTU = n
	case "mssfix":
		// A bare mssfix is the default, as if absent; a numeric 0 is an
		// explicit opt-out.
		if len(fields) >= 2 {
			n, err := strconv.Atoi(fields[1])
			if err != nil || n < 0 {
				return fmt.Errorf("profile: mssfix: invalid %q", fields[1])
			}
			p.MSSFix = n
			p.MSSFixSet = true
			// An unknown mode word only warns in OpenVPN, so it is ignored
			// here (openvpn-2.6.22 src/openvpn/options.c:7314-7344, openvpn3
			// ssl/proto.hpp:2713).
			if len(fields) >= 3 {
				switch fields[2] {
				case "mtu":
					p.MSSFixMode = MSSFixEncap
				case "fixed":
					p.MSSFixMode = MSSFixFixed
				}
			}
		}
	case "key-direction":
		if len(fields) < 2 {
			return fmt.Errorf("profile: key-direction: missing value")
		}
		dir, err := ParseKeyDirection(fields[1])
		if err != nil {
			return fmt.Errorf("profile: key-direction: invalid %q", fields[1])
		}
		p.KeyDirection = dir
	case "auth-user-pass":
		p.AuthUserPass = true
	case "remote-cert-tls":
		if len(fields) > 1 && strings.EqualFold(fields[1], "server") {
			p.RemoteCertTLSServer = true
		}
	case "ns-cert-type":
		if len(fields) > 1 && strings.EqualFold(fields[1], "server") {
			p.NSCertTypeServer = true
		}
	case "remote-random":
		p.RemoteRandom = true
	case "remote-random-hostname":
		p.RandomHostname = true
	case "auth-federate":
		p.Federated = true
	// x-openlawsvpn-flow is the former spelling of x-go-openvpn-flow.
	case "x-go-openvpn-flow", "x-openlawsvpn-flow":
		if len(fields) >= 2 && strings.ToLower(fields[1]) == "saml" {
			p.Federated = true
		}
	case "verify-x509-name":
		if len(fields) >= 2 {
			var typeArg string
			if len(fields) >= 3 {
				typeArg = fields[2]
			}
			match, ok := ParseX509NameMatch(typeArg)
			if !ok {
				return fmt.Errorf("profile: verify-x509-name: unrecognised match type %q, want subject, name or name-prefix", typeArg)
			}
			p.VerifyX509Name = fields[1]
			p.VerifyX509NameMatch = match
		}
	case "dhcp-option":
		if err := dns.ParseDHCPOption(&p.DNS, fields); err != nil {
			return fmt.Errorf("profile: %w", err)
		}
	case "ca", "cert", "key":
		// A file reference; an inline block may still supersede it, so
		// resolveFileRefs decides.
		if len(fields) < 2 {
			return fmt.Errorf("profile: %s: missing file name", directive)
		}
		a.refs = append(a.refs, pendingFileRef{tag: directive, name: fields[1], line: lineNo})
	}
	return nil
}

// finish resolves what needs the whole file, then returns the profile.
func (a *assembler) finish(res fileResolver) (*Profile, error) {
	p := a.p

	// keepalive wins over ping and ping-restart anywhere in the file, as in
	// openvpn3 ssl/proto.hpp:1278-1294 (openvpn-2.6.22 refuses the pair,
	// src/openvpn/helper.c:531-534), and a client expands it to exactly
	// ping N and ping-restart M (openvpn-2.6.22 src/openvpn/helper.c:540-543).
	if a.keepaliveSeen {
		p.PingInterval = a.keepalivePing
		p.PingTimeout = a.keepaliveTimeout
		p.PingTimeoutSet = true
		p.PingExit = false
	}

	if len(p.Remotes) == 0 {
		return nil, fmt.Errorf("profile: missing 'remote' directive")
	}

	for i := range p.Remotes {
		if p.Remotes[i].Port == 0 {
			p.Remotes[i].Port = p.Port
		}
		if !p.Remotes[i].ProtoSet {
			p.Remotes[i].Proto = p.Proto
		}
	}

	p.Remote = p.Remotes[0].Host
	p.Port = p.Remotes[0].Port
	p.Proto = p.Remotes[0].Proto

	// Last: the only step that reads outside the file.
	if err := p.resolveFileRefs(a.refs, res); err != nil {
		return nil, err
	}

	return p, nil
}
