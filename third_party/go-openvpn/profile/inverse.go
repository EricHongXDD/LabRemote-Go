// SPDX-License-Identifier: LGPL-2.1-or-later

package profile

import (
	"fmt"

	"github.com/buengese/go-openvpn/internal/compress"
)

// Spec returns a Spec that builds a profile equivalent to p. Settings at their
// default are left zero, and directives no Spec field covers are carried on
// Extra in file order.
//
// It fails only for a profile that names its tls-auth or tls-crypt key in a
// file, since the key is not in p to carry.
func (p *Profile) Spec() (Spec, error) {
	if p == nil {
		return Spec{}, nil
	}
	if p.TLSAuth == nil && p.hasDirective("tls-auth") ||
		p.TLSCrypt == nil && p.hasDirective("tls-crypt") {
		return Spec{}, fmt.Errorf("profile: spec: the profile names a key file, which a Spec cannot carry")
	}

	s := Spec{
		CA:                   orNil(p.CA),
		Cert:                 orNil(p.Cert),
		Key:                  orNil(p.Key),
		KeyDirection:         p.KeyDirection,
		AuthUserPass:         p.AuthUserPass,
		AuthFederate:         p.Federated,
		RemoteCertTLSServer:  p.RemoteCertTLSServer,
		NSCertTypeServer:     p.NSCertTypeServer,
		VerifyX509Name:       p.VerifyX509Name,
		TunMTU:               p.TunMTU,
		RenegBytes:           p.RenegBytes,
		HandWindow:           p.HandWindowSec,
		BecomePrimary:        p.BecomePrimarySec,
		Ping:                 p.PingInterval,
		PingTimeout:          p.PingTimeout,
		PingTimeoutOff:       p.PingTimeoutSet && p.PingTimeout == 0,
		PingExit:             p.PingExit,
		ExplicitExitNotify:   p.ExplicitExitNotify,
		RemoteRandom:         p.RemoteRandom,
		RemoteRandomHostname: p.RandomHostname,
		DNS: DNSOptions{
			SearchDomains: p.DNS.SearchDomains,
			RouteDomains:  p.DNS.RouteDomains,
		},
	}

	for _, r := range p.Remotes {
		e := Endpoint{Host: r.Host}
		if r.Port != defaultPort {
			e.Port = r.Port
		}
		if r.Proto != ProtoUDP {
			e.Proto = r.Proto.String()
		}
		s.Remotes = append(s.Remotes, e)
	}
	if p.TLSAuth != nil {
		s.TLSAuth = p.TLSAuth.Encode()
	}
	if p.TLSCrypt != nil {
		s.TLSCrypt = p.TLSCrypt.Encode()
	}
	if p.Cipher != defaultCipher {
		s.Cipher = p.Cipher
	}
	if p.AuthSet {
		s.Auth = p.Auth
	}
	if p.VerifyX509Name != "" {
		s.VerifyX509NameMatch = p.VerifyX509NameMatch
	}
	if p.Compression != compress.ModeNone {
		s.Compression = p.Compression.String()
	}
	if p.AllowCompression != compress.AllowUnset {
		s.AllowCompression = p.AllowCompression.String()
	}
	if p.MSSFixSet {
		s.MSSFix, s.MSSFixMode, s.MSSFixOff = p.MSSFix, p.MSSFixMode, p.MSSFix == 0
	}
	switch p.RenegSec {
	case 0:
		s.NoReneg = true
	case defaultRenegSec:
	default:
		s.RenegSec = p.RenegSec
	}
	for _, ip := range p.DNS.Servers {
		s.DNS.Servers = append(s.DNS.Servers, ip.String())
	}

	for _, d := range p.Directives {
		if _, owned := specOwned[d.Name]; !owned {
			s.Extra = append(s.Extra, Directive{Name: d.Name, Args: append([]string(nil), d.Args...)})
		}
	}
	return s, nil
}

func (p *Profile) hasDirective(name string) bool {
	for _, d := range p.Directives {
		if d.Name == name {
			return true
		}
	}
	return false
}

// orNil maps an empty slice to nil, since a zero Spec field is an absent block.
func orNil(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
