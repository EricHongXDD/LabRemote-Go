// SPDX-License-Identifier: LGPL-2.1-or-later

package profile

import (
	"fmt"
	"strconv"
	"strings"
)

// Spec describes a tunnel programmatically, one field per setting. A zero
// field is an absent directive and takes the parser's default.
//
// A Spec serialises to JSON with its enums as names. A stored Spec is key
// material: CA, Cert, Key, TLSAuth and TLSCrypt round-trip verbatim.
type Spec struct {
	// Remotes is the --remote list, in dial order. At least one is required.
	Remotes []Endpoint `json:"remotes,omitempty"`

	// CA, Cert and Key are the PEM bodies of the <ca>, <cert> and <key>
	// blocks.
	CA   []byte `json:"ca,omitempty"`
	Cert []byte `json:"cert,omitempty"`
	Key  []byte `json:"key,omitempty"`

	// TLSAuth and TLSCrypt are the bodies of <tls-auth> and <tls-crypt>, as
	// "openvpn --genkey" writes them.
	TLSAuth  []byte `json:"tls_auth,omitempty"`
	TLSCrypt []byte `json:"tls_crypt,omitempty"`
	// KeyDirection is --key-direction. KeyDirectionAbsent uses the whole key
	// in both directions.
	KeyDirection KeyDirection `json:"key_direction,omitempty"`

	// AuthUserPass asks for a username and password, which the client's
	// CredentialsFn supplies.
	AuthUserPass bool `json:"auth_user_pass,omitempty"`
	// AuthFederate is auth-federate: use the SAML/CRV1 flow.
	AuthFederate bool `json:"auth_federate,omitempty"`

	// Cipher is --cipher; empty means AES-256-GCM.
	Cipher string `json:"cipher,omitempty"`
	// Auth is --auth; empty means absent, and SHA1 applies.
	Auth string `json:"auth,omitempty"`

	// RemoteCertTLSServer is "remote-cert-tls server"; NSCertTypeServer is
	// "ns-cert-type server".
	RemoteCertTLSServer bool `json:"remote_cert_tls_server,omitempty"`
	NSCertTypeServer    bool `json:"ns_cert_type_server,omitempty"`
	// VerifyX509Name and VerifyX509NameMatch are --verify-x509-name.
	VerifyX509Name      string        `json:"verify_x509_name,omitempty"`
	VerifyX509NameMatch X509NameMatch `json:"verify_x509_name_match,omitempty"`

	// Compression is the compression directive: "comp-lzo", "comp-lzo no",
	// "compress", "compress lz4", "compress lz4-v2" or "compress stub-v2".
	// Empty means none.
	Compression string `json:"compression,omitempty"`
	// AllowCompression is --allow-compression: "no", "asym" or "yes".
	AllowCompression string `json:"allow_compression,omitempty"`

	// TunMTU is --tun-mtu.
	TunMTU int `json:"tun_mtu,omitempty"`
	// MSSFix is --mssfix N, with MSSFixMode its optional second word.
	// MSSFixOff is an explicit "mssfix 0".
	MSSFix     int        `json:"mssfix,omitempty"`
	MSSFixMode MSSFixMode `json:"mssfix_mode,omitempty"`
	MSSFixOff  bool       `json:"mssfix_off,omitempty"`

	// RenegSec is --reneg-sec; zero means 3600. NoReneg is an explicit
	// "reneg-sec 0", which disables client-initiated renegotiation.
	RenegSec   int   `json:"reneg_sec,omitempty"`
	NoReneg    bool  `json:"no_reneg,omitempty"`
	RenegBytes int64 `json:"reneg_bytes,omitempty"`
	// HandWindow is --hand-window; BecomePrimary is --become-primary.
	HandWindow    int `json:"hand_window,omitempty"`
	BecomePrimary int `json:"become_primary,omitempty"`

	// Ping is the keepalive send interval and PingTimeout the dead-link
	// timeout, in seconds. PingTimeoutOff is an explicit "ping-restart 0",
	// which disables the dead-link timer. PingExit ends the session on
	// timeout instead of restarting it, and needs PingTimeout or
	// PingTimeoutOff.
	Ping           int  `json:"ping,omitempty"`
	PingTimeout    int  `json:"ping_timeout,omitempty"`
	PingTimeoutOff bool `json:"ping_timeout_off,omitempty"`
	PingExit       bool `json:"ping_exit,omitempty"`
	// ExplicitExitNotify is how many exit notifications a disconnect sends.
	ExplicitExitNotify int `json:"explicit_exit_notify,omitempty"`

	// RemoteRandom is --remote-random; RemoteRandomHostname is
	// --remote-random-hostname.
	RemoteRandom         bool `json:"remote_random,omitempty"`
	RemoteRandomHostname bool `json:"remote_random_hostname,omitempty"`

	// DNS is the resolver configuration, as dhcp-option DNS, DOMAIN and
	// DOMAIN-ROUTE.
	DNS DNSOptions `json:"dns,omitzero"`

	// Extra carries directives no field above covers, applied after them. A
	// directive a field covers is refused.
	Extra []Directive `json:"extra,omitempty"`
}

// Endpoint is one --remote line.
type Endpoint struct {
	// Host is the hostname or address. Required.
	Host string `json:"host"`
	// Port is zero for 1194.
	Port int `json:"port,omitempty"`
	// Proto is the transport in OpenVPN's spelling; empty means UDP.
	Proto string `json:"proto,omitempty"`
}

// DNSOptions is the resolver configuration to push through dhcp-option.
type DNSOptions struct {
	// Servers are dhcp-option DNS addresses, in preference order.
	Servers []string `json:"servers,omitempty"`
	// SearchDomains are dhcp-option DOMAIN; RouteDomains are DOMAIN-ROUTE.
	SearchDomains []string `json:"search_domains,omitempty"`
	RouteDomains  []string `json:"route_domains,omitempty"`
}

// Build assembles the profile through the parser's own assembler, so it
// makes every check the parser makes.
func (s Spec) Build() (*Profile, error) {
	blocks, ds, err := s.directives()
	if err != nil {
		return nil, err
	}
	a := newAssembler()
	line := 0
	for _, b := range blocks {
		line++
		a.openBlock(b.tag, line)
		if err := a.closeBlock(b.tag, b.body); err != nil {
			return nil, err
		}
	}
	for _, d := range ds {
		line++
		d.Line = line
		if err := a.directive(d); err != nil {
			return nil, err
		}
	}
	return a.finish(nil)
}

// specOwned is every directive name a Spec field covers. Extra may not carry
// one, and Profile.Spec leaves them out of Extra.
var specOwned = map[string]struct{}{
	"remote": {}, "port": {}, "proto": {},
	"ca": {}, "cert": {}, "key": {}, "tls-auth": {}, "tls-crypt": {}, "key-direction": {},
	"auth-user-pass": {}, "auth-federate": {}, "x-go-openvpn-flow": {}, "x-openlawsvpn-flow": {},
	"cipher": {}, "auth": {},
	"remote-cert-tls": {}, "ns-cert-type": {}, "verify-x509-name": {},
	"comp-lzo": {}, "compress": {}, "allow-compression": {},
	"tun-mtu": {}, "mssfix": {},
	"reneg-sec": {}, "reneg-bytes": {}, "hand-window": {}, "become-primary": {},
	"ping": {}, "ping-restart": {}, "ping-exit": {}, "keepalive": {},
	"explicit-exit-notify": {}, "remote-random": {}, "remote-random-hostname": {}, "dhcp-option": {},
}

// specBlock is one inline block a Spec renders.
type specBlock struct {
	tag  string
	body []byte
}

// directives renders the fields into the blocks and directives a file would
// carry. It is the only place a setting is given a spelling.
func (s Spec) directives() ([]specBlock, []Directive, error) {
	var blocks []specBlock
	for _, b := range []specBlock{
		{"ca", s.CA}, {"cert", s.Cert}, {"key", s.Key},
		{"tls-auth", s.TLSAuth}, {"tls-crypt", s.TLSCrypt},
	} {
		if len(b.body) > 0 {
			blocks = append(blocks, b)
		}
	}
	if s.MSSFix > 0 && s.MSSFixOff {
		return nil, nil, fmt.Errorf("profile: spec: MSSFix and MSSFixOff both set")
	}
	if s.RenegSec > 0 && s.NoReneg {
		return nil, nil, fmt.Errorf("profile: spec: RenegSec and NoReneg both set")
	}
	if s.PingTimeout > 0 && s.PingTimeoutOff {
		return nil, nil, fmt.Errorf("profile: spec: PingTimeout and PingTimeoutOff both set")
	}
	if s.PingExit && s.PingTimeout == 0 && !s.PingTimeoutOff {
		return nil, nil, fmt.Errorf("profile: spec: PingExit needs PingTimeout or PingTimeoutOff")
	}
	if s.MSSFixMode < MSSFixLink || int(s.MSSFixMode) >= len(mssFixModeNames) {
		return nil, nil, fmt.Errorf("profile: spec: MSSFixMode %d is not a mode", int(s.MSSFixMode))
	}
	if s.VerifyX509NameMatch < X509NameSubject || s.VerifyX509NameMatch > X509NameCNPrefix {
		return nil, nil, fmt.Errorf("profile: spec: VerifyX509NameMatch %d is not a match type",
			int(s.VerifyX509NameMatch))
	}

	var ds []Directive
	add := func(name string, args ...string) {
		// Bare directives carry nil Args, as the line parser produces them.
		if len(args) == 0 {
			args = nil
		}
		ds = append(ds, Directive{Name: name, Args: args})
	}
	itoa := strconv.Itoa

	for _, r := range s.Remotes {
		args := []string{r.Host}
		if r.Port != 0 || r.Proto != "" {
			port := r.Port
			if port == 0 {
				port = defaultPort
			}
			args = append(args, itoa(port))
		}
		if r.Proto != "" {
			args = append(args, r.Proto)
		}
		add("remote", args...)
	}
	if s.KeyDirection != KeyDirectionAbsent {
		add("key-direction", s.KeyDirection.String())
	}
	if s.AuthUserPass {
		add("auth-user-pass")
	}
	if s.AuthFederate {
		add("auth-federate")
	}
	if s.Cipher != "" {
		add("cipher", s.Cipher)
	}
	if s.Auth != "" {
		add("auth", s.Auth)
	}
	if s.RemoteCertTLSServer {
		add("remote-cert-tls", "server")
	}
	if s.NSCertTypeServer {
		add("ns-cert-type", "server")
	}
	if s.VerifyX509Name != "" {
		args := []string{s.VerifyX509Name}
		if w := x509MatchWord(s.VerifyX509NameMatch); w != "" {
			args = append(args, w)
		}
		add("verify-x509-name", args...)
	}
	if s.Compression != "" {
		// strings.Fields would weld two lines into one directive.
		if strings.ContainsRune(s.Compression, '\n') {
			return nil, nil, fmt.Errorf("profile: spec: Compression %q is more than one line", s.Compression)
		}
		f := strings.Fields(s.Compression)
		if len(f) == 0 {
			return nil, nil, fmt.Errorf("profile: spec: Compression %q names no directive", s.Compression)
		}
		// Folded the way the line parser folds a keyword.
		add(strings.ToLower(f[0]), f[1:]...)
	}
	if s.AllowCompression != "" {
		add("allow-compression", s.AllowCompression)
	}
	if s.TunMTU != 0 {
		add("tun-mtu", itoa(s.TunMTU))
	}
	if s.MSSFixOff || s.MSSFix > 0 {
		args := []string{itoa(s.MSSFix)}
		if w := mssFixModeWord(s.MSSFixMode); w != "" {
			args = append(args, w)
		}
		add("mssfix", args...)
	}
	switch {
	case s.NoReneg:
		add("reneg-sec", "0")
	case s.RenegSec != 0:
		add("reneg-sec", itoa(s.RenegSec))
	}
	if s.RenegBytes != 0 {
		add("reneg-bytes", strconv.FormatInt(s.RenegBytes, 10))
	}
	if s.HandWindow != 0 {
		add("hand-window", itoa(s.HandWindow))
	}
	if s.BecomePrimary != 0 {
		add("become-primary", itoa(s.BecomePrimary))
	}
	switch {
	case s.PingExit:
		if s.Ping != 0 {
			add("ping", itoa(s.Ping))
		}
		add("ping-exit", itoa(s.PingTimeout))
	case s.Ping > 0 && s.PingTimeout > 0:
		add("keepalive", itoa(s.Ping), itoa(s.PingTimeout))
	default:
		if s.Ping != 0 {
			add("ping", itoa(s.Ping))
		}
		if s.PingTimeout != 0 || s.PingTimeoutOff {
			add("ping-restart", itoa(s.PingTimeout))
		}
	}
	if s.ExplicitExitNotify != 0 {
		add("explicit-exit-notify", itoa(s.ExplicitExitNotify))
	}
	if s.RemoteRandom {
		add("remote-random")
	}
	if s.RemoteRandomHostname {
		add("remote-random-hostname")
	}
	for _, v := range s.DNS.Servers {
		add("dhcp-option", "DNS", v)
	}
	for _, v := range s.DNS.SearchDomains {
		add("dhcp-option", "DOMAIN", v)
	}
	for _, v := range s.DNS.RouteDomains {
		add("dhcp-option", "DOMAIN-ROUTE", v)
	}

	for _, d := range s.Extra {
		name := strings.ToLower(d.Name)
		if name == "" {
			return nil, nil, fmt.Errorf("profile: spec: Extra carries a directive with no name")
		}
		if _, owned := specOwned[name]; owned {
			return nil, nil, fmt.Errorf("profile: spec: Extra carries %q, which a field covers", name)
		}
		ds = append(ds, Directive{Name: name, Args: append([]string(nil), d.Args...)})
	}

	for _, d := range ds {
		if err := roundTrips(d); err != nil {
			return nil, nil, err
		}
	}
	return blocks, ds, nil
}

// roundTrips checks that a directive reads back as itself from a file: the
// name and every argument must be one whitespace-free word, and the name must
// not start a comment or a block.
func roundTrips(d Directive) error {
	if f := strings.Fields(d.Name); len(f) != 1 || f[0] != d.Name {
		return fmt.Errorf("profile: spec: directive name %q is not a single word", d.Name)
	}
	switch d.Name[0] {
	case '#', ';', '<':
		return fmt.Errorf("profile: spec: directive name %q begins a comment or a block", d.Name)
	}
	for _, a := range d.Args {
		if f := strings.Fields(a); len(f) != 1 || f[0] != a {
			return fmt.Errorf("profile: spec: %s: argument %q is not a single word", d.Name, a)
		}
	}
	return nil
}

// x509MatchWord is the profile spelling of a match type, or "" for the default
// that a file leaves unwritten.
func x509MatchWord(m X509NameMatch) string {
	switch m {
	case X509NameCN:
		return "name"
	case X509NameCNPrefix:
		return "name-prefix"
	default:
		return ""
	}
}

// mssFixModeWord is the profile spelling of an mssfix mode, or "" for the
// default that a file leaves unwritten.
func mssFixModeWord(m MSSFixMode) string {
	switch m {
	case MSSFixEncap:
		return "mtu"
	case MSSFixFixed:
		return "fixed"
	default:
		return ""
	}
}
