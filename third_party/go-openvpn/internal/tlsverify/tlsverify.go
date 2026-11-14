// SPDX-License-Identifier: LGPL-2.1-or-later

// Package tlsverify builds the control channel's TLS config and performs the
// server verification OpenVPN performs, in place of the one crypto/tls
// performs.
//
// The whole package is policy over a *profile.Profile and the x509 material a
// handshake presents. Nothing here reads client state.
package tlsverify

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/buengese/go-openvpn/profile"
)

// ErrNoUsableCA is returned for a profile that carries no certificate
// authority the server can be verified against.
//
// It is a configuration fault, not a TLS fault: it is knowable before a socket
// is opened, and the attempt is refused at the StageParse boundary so that an
// unverified tunnel is never built. The alternative — InsecureSkipVerify with
// nothing in its place — is a handshake against an empty trust store with
// verification switched off.
var ErrNoUsableCA = errors.New("profile carries no usable CA certificate")

// RootCAs builds the trust store the server certificate is verified
// against. Only the profile's own CA is trusted: the host trust store is
// deliberately not consulted, because an OpenVPN server certificate is issued
// by the deployment's private CA and a publicly-rooted chain proves nothing
// about it.
func RootCAs(p *profile.Profile) (*x509.CertPool, error) {
	if len(p.CA) == 0 {
		return nil, ErrNoUsableCA
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.CA) {
		return nil, fmt.Errorf("%w: the ca block contains no parseable certificate", ErrNoUsableCA)
	}
	return pool, nil
}

// Verifier performs the verification OpenVPN performs, in place of
// the verification crypto/tls performs.
//
// The difference that matters is hostname matching. Go verifies the endpoint
// hostname against the certificate's SANs; OpenVPN does not, and never has. It
// verifies the chain against the CA, checks the extended key usage when
// remote-cert-tls server is configured, and matches the subject only when
// verify-x509-name says to. Asking Go for its check is not a stricter version
// of OpenVPN's — it is a different property, and it rejects any deployment
// whose certificate is issued for something other than the endpoint it is
// reached at, with "certificate is not valid for any names".
//
// What it does check, on the leaf and nowhere else, is the chain, the
// serverAuth extended key usage and a present key usage extension when
// remote-cert-tls server asks for them, the subject when verify-x509-name asks
// for it, and the SSL-server purpose when ns-cert-type server asks for it.
// Those are the checks OpenVPN's verify_cert makes at cert_depth 0
// (openvpn-2.6.22 src/openvpn/ssl_verify.c:330-395), and none of them is a
// hostname.
type Verifier struct {
	roots *x509.CertPool

	// requireRemoteCertTLS is "remote-cert-tls server", which asks for the
	// serverAuth extended key usage and for a key usage extension to be
	// present. One directive, two checks.
	requireRemoteCertTLS bool

	// verifyName is the value of verify-x509-name, empty when the profile
	// carries no such directive, and verifyNameMatch says which part of the
	// subject it is compared against. Neither is ever compared to a SAN.
	verifyName      string
	verifyNameMatch profile.X509NameMatch

	// requireNSCertType is ns-cert-type server.
	requireNSCertType bool

	mu       sync.Mutex
	verified bool
}

// Verify is installed as tls.Config.VerifyPeerCertificate. crypto/tls calls it
// after its own verification has been switched off, so this is the only
// verification the control channel gets: it must never return nil for a
// certificate it has not actually checked.
func (v *Verifier) Verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("server presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for i, der := range rawCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse server certificate %d: %w", i, err)
		}
		certs = append(certs, cert)
	}

	// Everything after the leaf is an intermediate the server offered. They are
	// candidates for chain building, never trust anchors: only the profile's CA
	// is that, which is why they go in a separate pool.
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		// DNSName is left empty on purpose. It is the hostname check OpenVPN
		// does not perform, and leaving it unset is the reason this callback
		// exists rather than an omission from it.
		//
		// KeyUsages is ExtKeyUsageAny for the same reason: Go's default would
		// require serverAuth on the whole chain unconditionally, where OpenVPN
		// requires it on the leaf only when the profile asks. That check is
		// below, where the profile can be consulted.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("server certificate chain: %w", err)
	}

	if v.requireRemoteCertTLS {
		// The key usage check comes first because verify_peer_cert makes it
		// first (ssl_verify.c:349-360, then 362-374). remote_cert_ku[0] is
		// OPENVPN_KU_REQUIRED, which x509_verify_cert_ku reads as "the
		// extension must be there, its bits are the TLS library's business"
		// (ssl_verify_openssl.c:678-695), so presence is the whole test.
		if !hasExtension(certs[0], oidKeyUsage) {
			return errors.New("server certificate has no key usage extension, " +
				"which remote-cert-tls server requires")
		}
		if !hasServerAuthEKU(certs[0]) {
			return errors.New("server certificate carries no TLS Web Server Authentication " +
				"extended key usage, which remote-cert-tls server requires")
		}
	}

	if v.verifyName != "" && !matchesX509Name(certs[0], v.verifyName, v.verifyNameMatch) {
		// The certificate's own subject is deliberately not quoted back. It
		// is the one field a measurement run aggregates across corpora, and
		// the directive's value is enough to say which check failed.
		return fmt.Errorf("server certificate %s does not match verify-x509-name %q",
			v.verifyNameMatch.String(), v.verifyName)
	}

	if v.requireNSCertType && !usableAsTLSServer(certs[0]) {
		return errors.New("server certificate is not usable as a TLS server and carries " +
			"no Netscape certificate-type extension with the SSL-server bit, which " +
			"ns-cert-type server requires")
	}

	v.mu.Lock()
	v.verified = true
	v.mu.Unlock()
	return nil
}

// OK reports whether Verify has accepted a chain. It is read after the
// handshake so the certificate log states what was actually checked rather
// than inferring it from the handshake having succeeded.
func (v *Verifier) OK() bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.verified
}

// X509Name reports the verify-x509-name value this verifier was built with,
// and which part of the subject it is compared against. Both are empty when
// the profile carried no such directive.
//
// It lets a caller assert the loop from a parsed profile to the verifier is
// closed — the comparison implemented, and the field feeding it never read.
func (v *Verifier) X509Name() (string, profile.X509NameMatch) {
	return v.verifyName, v.verifyNameMatch
}

// RequiresNSCertType reports whether ns-cert-type server reached this
// verifier, for the same reason X509Name exists.
func (v *Verifier) RequiresNSCertType() bool {
	return v.requireNSCertType
}

// hasServerAuthEKU reports whether the certificate carries the serverAuth
// extended key usage.
//
// anyExtendedKeyUsage deliberately does not satisfy this. OpenVPN's
// verify_cert_eku walks the EKU extension looking for that one OID and fails
// when the extension is absent altogether, so a certificate with no EKU and a
// certificate with only anyExtendedKeyUsage are both rejected — matching
// OpenVPN rather than being more permissive than it.
func hasServerAuthEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// matchesX509Name reports whether the certificate satisfies verify-x509-name.
//
// The three comparisons are OpenVPN's, byte for byte: subject is string
// equality against the whole DN, name is string equality against the common
// name, and name-prefix is a prefix test on the common name. All three are
// case-sensitive, because strcmp is.
//
// A certificate with no common name fails both name forms rather than matching
// an empty string. OpenVPN gets there by a different route — x509_get_username
// returns an error and verify_cert rejects the peer before the comparison —
// but the outcome is the one that matters: an absent field is not a match.
func matchesX509Name(cert *x509.Certificate, want string, match profile.X509NameMatch) bool {
	cn := cert.Subject.CommonName
	switch match {
	case profile.X509NameSubject:
		return SubjectDN(cert) == want
	case profile.X509NameCN:
		return cn != "" && cn == want
	case profile.X509NameCNPrefix:
		return cn != "" && strings.HasPrefix(cn, want)
	default:
		// An unknown match type refuses. It cannot arrive through the parser,
		// which rejects the profile, and a check nobody can name is not a
		// check to wave through.
		return false
	}
}

// SubjectDN renders a certificate subject the way OpenVPN renders it, because
// the subject form of verify-x509-name is a string comparison and the string
// on the other side of it is whatever OpenVPN produced.
//
// OpenVPN's x509_get_subject calls X509_NAME_print_ex with
// XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN, which means: attributes in the order
// the certificate stores them, short names where OpenSSL has one and the
// dotted OID where it does not, "=" between name and value, ", " between
// attributes and " + " within a multi-valued RDN. Notably it is *not* RFC
// 2253, which is what pkix.Name.String returns: that reverses the order, drops
// the spaces and escapes separators, so using it here would compare a
// correctly-configured profile against a string OpenVPN never emits.
//
// Where an exotic attribute type renders differently from OpenSSL's, the error
// is fail-closed: the connection is refused, never accepted on a subject that
// does not match.
func SubjectDN(cert *x509.Certificate) string {
	return renderDN(cert.RawSubject, cert.Subject)
}

// IssuerDN renders a certificate issuer the same way. It exists for the
// verb>=4 log, which prints subject and issuer side by side and should spell
// them alike.
func IssuerDN(cert *x509.Certificate) string {
	return renderDN(cert.RawIssuer, cert.Issuer)
}

// renderDN walks a raw distinguished name in the order the certificate
// carries it, naming each attribute as OpenSSL does.
//
// The order matters: the attributes are rendered as they appear rather than
// sorted into a fixed list, which is what makes this comparable with what
// `openssl x509` prints and with what a verify-x509-name subject must match.
func renderDN(raw []byte, parsed pkix.Name) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw, &rdns); err != nil {
		// Fall back to what Go parsed. A name Go accepted but asn1 will
		// not re-read is not a shape any real certificate has, and returning
		// something that cannot match is better than returning "".
		return parsed.String()
	}
	var b strings.Builder
	for i, rdn := range rdns {
		if i > 0 {
			b.WriteString(", ")
		}
		for j, atv := range rdn {
			if j > 0 {
				b.WriteString(" + ")
			}
			b.WriteString(attributeShortName(atv.Type))
			b.WriteByte('=')
			fmt.Fprintf(&b, "%v", atv.Value)
		}
	}
	return b.String()
}

// attributeShortName is OpenSSL's OBJ_nid2sn for the attribute types that
// appear in a certificate subject, and the dotted OID for anything else —
// which is also what OpenSSL falls back to.
//
// The table is written out rather than derived because crypto/x509 has no
// exported equivalent: pkix.Name.String knows a handful of these and spells
// the rest "OID.2.5.4.12", which is not the spelling OpenSSL emits.
func attributeShortName(oid asn1.ObjectIdentifier) string {
	if len(oid) == 4 && oid[0] == 2 && oid[1] == 5 && oid[2] == 4 {
		switch oid[3] {
		case 3:
			return "CN"
		case 4:
			return "SN"
		case 5:
			return "serialNumber"
		case 6:
			return "C"
		case 7:
			return "L"
		case 8:
			return "ST"
		case 9:
			return "street"
		case 10:
			return "O"
		case 11:
			return "OU"
		case 12:
			return "title"
		case 15:
			return "businessCategory"
		case 17:
			return "postalCode"
		case 42:
			return "GN"
		case 43:
			return "initials"
		case 46:
			return "dnQualifier"
		case 65:
			return "pseudonym"
		}
	}
	switch {
	case oid.Equal(OIDEmailAddress):
		return "emailAddress"
	case oid.Equal(oidDomainComponent):
		return "DC"
	case oid.Equal(oidUserID):
		return "UID"
	}
	return oid.String()
}

// The three subject attribute types outside the 2.5.4 arc that a provider CA
// realistically puts in a subject.
var (
	// OIDEmailAddress is PKCS#9 emailAddress, which OpenVPN's own sample CA
	// puts in every subject it issues.
	OIDEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	// oidDomainComponent is the RFC 4519 domainComponent, spelled DC.
	oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}
	// oidUserID is the RFC 4519 uid, spelled UID.
	oidUserID = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
)

// NSCertTypeOID is the legacy Netscape certificate-type extension,
// 2.16.840.1.113730.1.1. Nothing but OpenVPN's --ns-cert-type reads it and it
// has been deprecated since OpenVPN 2.4.
//
// testenv keeps its own copy for the matrix entry that issues the extension.
// The duplication is deliberate: one shared constant between the rig that
// writes the OID and the client that reads it would let a wrong OID pass.
var NSCertTypeOID = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}

// nsCertTypeSSLServer is the SSL-server bit of that extension, 0x40 in the
// first content byte of the BIT STRING. OpenSSL caches exactly that byte as
// X509->ex_nscert and OpenVPN's verify_nsCertType tests it against
// NS_SSL_SERVER, so testing the byte is testing what OpenVPN tests.
const nsCertTypeSSLServer = 0x40

// usableAsTLSServer answers ns-cert-type server the way OpenVPN answers it.
//
// The extension is the *fallback*, not the check. Since 2.4,
// x509_verify_ns_cert_type asks X509_check_purpose(X509_PURPOSE_SSL_SERVER)
// first and only consults the raw Netscape bit when that fails
// (openvpn-2.6.22 src/openvpn/ssl_verify_openssl.c:611-676; the same code in
// 2.4.12). A modern server certificate — easy-rsa 3 has emitted no nsCertType
// since 2015 — therefore satisfies ns-cert-type server without carrying the
// extension at all, so requiring it outright would refuse certificates
// OpenVPN accepts.
//
// The bit is still honoured: a certificate that fails the purpose check for
// some other reason and carries nsSslServer is accepted by the reference with
// a deprecation warning.
func usableAsTLSServer(cert *x509.Certificate) bool {
	return satisfiesSSLServerPurpose(cert) || hasNSCertTypeServer(cert)
}

// satisfiesSSLServerPurpose is X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 0).
//
// OpenSSL's check_purpose_ssl_server is three rejections and no requirements,
// which is why a certificate carrying none of the three extensions passes:
//
//   - xku_reject: an extended key usage extension that names neither serverAuth
//     nor either server-gated-crypto OID.
//   - ku_reject: a key usage extension with none of digitalSignature,
//     keyEncipherment or keyAgreement.
//   - ns_reject: a Netscape certificate-type extension without the SSL-server
//     bit.
//
// require_ca is 0 at this call site, so the CA branch is not reached and no
// basic-constraints test is part of the answer.
//
// Each rejection turns on the extension being *present*, which is why presence
// is read off cert.Extensions rather than inferred from the parsed fields:
// crypto/x509 leaves KeyUsage zero and ExtKeyUsage empty both for an absent
// extension and for a present one it could not use, and those two cases give
// opposite answers here. The table was checked against `openssl x509 -purpose`
// on OpenSSL 3.6, one certificate per branch.
func satisfiesSSLServerPurpose(cert *x509.Certificate) bool {
	if hasExtension(cert, oidExtendedKeyUsage) && !hasSSLServerEKU(cert) {
		return false
	}
	if hasExtension(cert, oidKeyUsage) && cert.KeyUsage&keyUsageTLS == 0 {
		return false
	}
	if bits, present := nsCertTypeBits(cert); present && bits&nsCertTypeSSLServer == 0 {
		return false
	}
	return true
}

// keyUsageTLS is OpenSSL's KU_TLS: the key usages a TLS server can be doing
// something with. A key usage extension naming none of them fails ku_reject.
const keyUsageTLS = x509.KeyUsageDigitalSignature |
	x509.KeyUsageKeyEncipherment |
	x509.KeyUsageKeyAgreement

// The two extensions whose presence, not value, decides a branch above.
var (
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtendedKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// hasExtension reports whether the certificate carries the extension at all,
// regardless of whether crypto/x509 made anything of it.
func hasExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// hasSSLServerEKU is the XKU_SSL_SERVER|XKU_SGC mask xku_reject tests against.
// The two server-gated-crypto OIDs are OpenSSL's: museum pieces, but dropping
// them would refuse a certificate the reference accepts.
func hasSSLServerEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageNetscapeServerGatedCrypto,
			x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			return true
		}
	}
	return false
}

// hasNSCertTypeServer reports whether the certificate carries the Netscape
// certificate-type extension with the SSL-server bit set. It is the fallback
// half of usableAsTLSServer, and on its own is the whole of what OpenVPN 2.3
// checked.
func hasNSCertTypeServer(cert *x509.Certificate) bool {
	bits, present := nsCertTypeBits(cert)
	return present && bits&nsCertTypeSSLServer != 0
}

// nsCertTypeBits returns the first content byte of the Netscape
// certificate-type extension, and whether the certificate carries it.
//
// A present extension that will not decode reports present with no bits set,
// so both callers refuse it. OpenSSL flags such a certificate EXFLAG_INVALID
// and X509_check_purpose returns -1, which OpenVPN's `? SUCCESS : FAILURE`
// reads as success; that is a truthiness accident rather than a decision, and
// a verifier is the wrong place to reproduce it.
func nsCertTypeBits(cert *x509.Certificate) (byte, bool) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(NSCertTypeOID) {
			continue
		}
		var bits asn1.BitString
		if _, err := asn1.Unmarshal(ext.Value, &bits); err != nil || len(bits.Bytes) == 0 {
			return 0, true
		}
		return bits.Bytes[0], true
	}
	return 0, false
}

// BuildConfig constructs a crypto/tls.Config from the profile, along with
// the verifier that will authenticate the server.
//
// A profile with no usable CA is an error here and the caller never opens a
// socket; see ErrNoUsableCA.
func BuildConfig(p *profile.Profile) (*tls.Config, *Verifier, error) {
	roots, err := RootCAs(p)
	if err != nil {
		return nil, nil, err
	}
	verifier := &Verifier{
		roots:                roots,
		requireRemoteCertTLS: p.RemoteCertTLSServer,
		verifyName:           p.VerifyX509Name,
		verifyNameMatch:      p.VerifyX509NameMatch,
		requireNSCertType:    p.NSCertTypeServer,
	}

	cfg := &tls.Config{
		// ServerName is SNI and nothing else: some deployments select a
		// certificate from it, so it is sent, but nothing verifies against it.
		// verify-x509-name never reaches this field — routing it here would
		// turn a directive about a subject DN into a match against SANs. It is
		// honoured above, on the verifier, against the subject.
		ServerName:             p.Remote,
		MinVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
		// InsecureSkipVerify switches off *Go's* verification, not verification.
		// VerifyPeerCertificate immediately below replaces it with the check
		// OpenVPN makes: chain against the profile CA, serverAuth EKU when the
		// profile asks, and no hostname match. The two fields are a pair and
		// this is the only place either is set — deleting the callback without
		// putting an equivalent check in its place would leave the control
		// channel unauthenticated.
		InsecureSkipVerify:    true, //nolint:gosec // not unverified: VerifyPeerCertificate below performs OpenVPN's own chain and EKU verification
		VerifyPeerCertificate: verifier.Verify,
	}

	// 禁用环境变量触发的 TLS 密钥落盘，仅允许 PRF 在内存中捕获握手材料。

	// Load client certificate if present.
	if len(p.Cert) > 0 && len(p.Key) > 0 {
		cert, err := tls.X509KeyPair(p.Cert, p.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("vpn: load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, verifier, nil
}

// keyLogFiles holds the SSLKEYLOGFILE handles this process has opened, keyed by
// the path the environment named.
//
// The lifetime of the handle is the process, and it is the only lifetime that
// fits. A tls.Config has no Close, so nothing downstream can give the
// descriptor back, and opening per BuildConfig call spends one descriptor per
// connect attempt and per rekey on a file that names one destination. Closing
// on some earlier boundary is worse than leaking: a config outlives the call
// that built it, and crypto/tls fails the handshake when KeyLogWriter.Write
// returns an error, so a handle closed under a live session turns a debugging
// aid into a dropped tunnel.
//
// The map has one entry in practice — SSLKEYLOGFILE is read from the process
// environment and does not change — and is keyed rather than single-slot so
// that a caller who does change it gets the file it now names.
var keyLogFiles struct {
	mu    sync.Mutex
	files map[string]*os.File
}

// keyLogFile returns the process-wide append handle on path, opening it on
// first use and announcing it once.
//
// A nil return means the file could not be opened. That is not fatal and is not
// reported: the key log is a debugging facility, and a tunnel that would
// otherwise connect is not refused because a debug destination is unwritable.
func keyLogFile(path string) *os.File {
	keyLogFiles.mu.Lock()
	defer keyLogFiles.mu.Unlock()

	if f, ok := keyLogFiles.files[path]; ok {
		return f
	}
	// O_APPEND, so that the primary session and a concurrent rekey writing
	// through the same handle each land a whole line.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil
	}
	if keyLogFiles.files == nil {
		keyLogFiles.files = make(map[string]*os.File, 1)
	}
	keyLogFiles.files[path] = f
	fmt.Fprintf(os.Stderr, "vpn: TLS key log: %s\n", path)
	return f
}
