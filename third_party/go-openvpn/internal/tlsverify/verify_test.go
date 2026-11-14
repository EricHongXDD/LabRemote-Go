// SPDX-License-Identifier: LGPL-2.1-or-later

package tlsverify

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/profile"
)

// The tests in this file cover one property: the client verifies a server
// certificate the way OpenVPN verifies it, rather than the way crypto/tls does.
// Go checks that the endpoint hostname appears in the certificate's SANs;
// OpenVPN checks the chain and, on request, the extended key usage, the subject
// and the legacy Netscape certificate type — and never looks at the hostname at
// all.

// verifierFor builds the verifier a profile would install.
func verifierFor(t *testing.T, p *testCA, remoteCertTLS bool) *Verifier {
	t.Helper()
	prof := &profile.Profile{Remote: "vpn.example.com", Port: 1194, CA: p.caPEM,
		RemoteCertTLSServer: remoteCertTLS}
	return verifierForProfile(t, prof)
}

// verifierForProfile builds the verifier a given profile would install, and
// asserts the two fields that must always travel together: Go's own
// verification switched off, and a replacement installed in its place.
func verifierForProfile(t *testing.T, prof *profile.Profile) *Verifier {
	t.Helper()
	cfg, verifier, err := BuildConfig(prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is not set; Go's hostname verification is still in effect")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("InsecureSkipVerify is set with no replacement verifier: the tunnel would be unverified")
	}
	return verifier
}

// TestVerifierAcceptsHostnameMismatch is the point of the whole unit: the
// certificate names nothing the client dialled. Go would reject it with
// "certificate is not valid for any names"; OpenVPN accepts it, because
// hostname-to-SAN matching is not part of its model, and so must we.
func TestVerifierAcceptsHostnameMismatch(t *testing.T) {
	pki := newTestCA(t, "Example VPN CA")
	chain := pki.issueServer(t, "some-internal-name",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)

	v := verifierFor(t, pki, true)
	if err := v.Verify(chain, nil); err != nil {
		t.Fatalf("a valid chain naming a different host must be accepted, got: %v", err)
	}
	if !v.OK() {
		t.Error("verifier accepted the chain but does not report it as verified")
	}
}

// TestVerifierRejectsUnrelatedCA covers the property that must survive
// dropping Go's verification: a chain that does not lead to the profile's CA
// is refused.
func TestVerifierRejectsUnrelatedCA(t *testing.T) {
	trusted := newTestCA(t, "Trusted CA")
	unrelated := newTestCA(t, "Unrelated CA")
	chain := unrelated.issueServer(t, "vpn.example.com",
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"vpn.example.com"})

	v := verifierFor(t, trusted, true)
	err := v.Verify(chain, nil)
	if err == nil {
		t.Fatal("a certificate signed by an unrelated CA was accepted")
	}
	if v.OK() {
		t.Error("verifier rejected the chain but reports it as verified")
	}
}

// TestVerifierServerAuthEKU checks that remote-cert-tls server is what decides
// whether the extended key usage is required — in both directions.
func TestVerifierServerAuthEKU(t *testing.T) {
	for _, tc := range []struct {
		name          string
		eku           []x509.ExtKeyUsage
		remoteCertTLS bool
		wantAccepted  bool
	}{
		{"serverAuth with remote-cert-tls", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true, true},
		{"no EKU with remote-cert-tls", nil, true, false},
		{"clientAuth only with remote-cert-tls", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, true, false},
		// anyExtendedKeyUsage does not satisfy OpenVPN's check, which looks for
		// the serverAuth OID specifically.
		{"anyExtendedKeyUsage with remote-cert-tls", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, true, false},
		{"no EKU without remote-cert-tls", nil, false, true},
		{"clientAuth only without remote-cert-tls", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newTestCA(t, "Example VPN CA")
			chain := pki.issueServer(t, "vpn.example.com", tc.eku, []string{"vpn.example.com"})
			v := verifierFor(t, pki, tc.remoteCertTLS)
			err := v.Verify(chain, nil)
			if tc.wantAccepted && err != nil {
				t.Errorf("chain should be accepted, got: %v", err)
			}
			if !tc.wantAccepted && err == nil {
				t.Error("chain should be rejected, was accepted")
			}
		})
	}
}

// TestVerifierRejectsMalformedInput covers the two shapes that must not panic
// on a path a measurement sweep drives thousands of times.
func TestVerifierRejectsMalformedInput(t *testing.T) {
	pki := newTestCA(t, "Example VPN CA")
	v := verifierFor(t, pki, false)

	if err := v.Verify(nil, nil); err == nil {
		t.Error("a peer presenting no certificate was accepted")
	}
	if err := v.Verify([][]byte{{0x01, 0x02, 0x03}}, nil); err == nil {
		t.Error("an unparseable certificate was accepted")
	}
}

// TestBuildTLSConfigRejectsProfilesWithNoUsableCA covers the removal of the
// InsecureSkipVerify fallback. Both shapes of "no usable CA" must be refused:
// the field absent, and the field present but holding nothing parseable.
func TestBuildTLSConfigRejectsProfilesWithNoUsableCA(t *testing.T) {
	for _, tc := range []struct {
		name string
		ca   []byte
	}{
		{"absent", nil},
		{"empty", []byte{}},
		{"not a certificate", []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")},
		{"not PEM at all", []byte("ca /etc/openvpn/ca.crt\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := BuildConfig(&profile.Profile{Remote: "vpn.example.com", CA: tc.ca})
			if err == nil {
				t.Fatal("a profile with no usable CA produced a TLS config")
			}
			if !errors.Is(err, ErrNoUsableCA) {
				t.Errorf("error does not wrap ErrNoUsableCA: %v", err)
			}
		})
	}
}

// TestVerifyX509NameNoLongerFeedsSNI pins that verify-x509-name stays out of
// ServerName: it matches a subject DN or CN, while ServerName is matched
// against SANs — a different check on a different field. An AWS profile
// therefore sends its endpoint hostname as SNI, not its certificate CN.
func TestVerifyX509NameNoLongerFeedsSNI(t *testing.T) {
	pki := newTestCA(t, "Example VPN CA")
	cfg, _, err := BuildConfig(&profile.Profile{
		Remote:         "cvpn-endpoint-0123.prod.clientvpn.eu-central-1.amazonaws.com",
		CA:             pki.caPEM,
		VerifyX509Name: "mtlab.ai",
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if cfg.ServerName == "mtlab.ai" {
		t.Error("verify-x509-name still feeds ServerName")
	}
	if cfg.ServerName != "cvpn-endpoint-0123.prod.clientvpn.eu-central-1.amazonaws.com" {
		t.Errorf("ServerName = %q, want the profile's remote", cfg.ServerName)
	}
}

// What follows is the two certificate checks OpenVPN makes on top of the chain:
// verify-x509-name and ns-cert-type.

// nsCertTypeExt builds the legacy Netscape certificate-type extension holding
// one bit. The DER is written out by hand because the value is a BIT STRING
// whose first content byte is the whole of what OpenSSL caches and OpenVPN
// tests, so the byte that has to be right stays visible where it is chosen.
// unused is how many of the low bits of that byte are not part of the string.
func nsCertTypeExt(bit byte, unused byte) pkix.Extension {
	return pkix.Extension{
		Id:    NSCertTypeOID,
		Value: []byte{0x03, 0x02, unused, bit},
	}
}

// x509NameProfile is a profile carrying verify-x509-name and nothing else
// interesting, so that the verifier under test differs from the plain one in
// exactly that field.
func x509NameProfile(pki *testCA, name string, match profile.X509NameMatch) *profile.Profile {
	return &profile.Profile{
		Remote: "vpn.example.com", Port: 1194, CA: pki.caPEM,
		VerifyX509Name: name, VerifyX509NameMatch: match,
	}
}

// TestVerifyX509NameMatchTypes is the acceptance table for all three types
// OpenVPN defines, in both directions. The name-prefix rows separate a real
// implementation from an equality test wearing a different name: "matrix-serv"
// must be accepted against a CN of "matrix-server" and "matrix-server-2" not.
func TestVerifyX509NameMatchTypes(t *testing.T) {
	const cn = "matrix-server"
	// The full subject the leaf below carries, rendered the way OpenVPN
	// renders it. Written out rather than computed, so that a change in
	// SubjectDN fails this test instead of being blessed by it.
	const wantDN = "C=KG, ST=NA, L=BISHKEK, O=OpenVPN-TEST, CN=matrix-server"

	subject := pkix.Name{
		Country:      []string{"KG"},
		Province:     []string{"NA"},
		Locality:     []string{"BISHKEK"},
		Organization: []string{"OpenVPN-TEST"},
		CommonName:   cn,
	}

	for _, tc := range []struct {
		name    string
		value   string
		match   profile.X509NameMatch
		wantOK  bool
		comment string
	}{
		{"subject matches", wantDN, profile.X509NameSubject, true, ""},
		{"subject differs", "C=KG, CN=matrix-server", profile.X509NameSubject, false,
			"a DN that is a subset of the certificate's is not the certificate's DN"},
		{"subject given the bare CN", cn, profile.X509NameSubject, false,
			"the subject form compares the whole DN, so the CN alone must not satisfy it"},
		{"name matches", cn, profile.X509NameCN, true, ""},
		{"name differs", "no-such-server", profile.X509NameCN, false, ""},
		{"name is case sensitive", "Matrix-Server", profile.X509NameCN, false,
			"OpenVPN compares with strcmp"},
		{"name given the whole DN", wantDN, profile.X509NameCN, false,
			"the name form compares the CN, so the DN must not satisfy it"},
		{"name-prefix matches a strict prefix", "matrix-serv", profile.X509NameCNPrefix, true,
			"the acceptance case: a prefix that is not the whole CN"},
		{"name-prefix matches the whole CN", cn, profile.X509NameCNPrefix, true,
			"a CN is a prefix of itself"},
		{"name-prefix is longer than the CN", "matrix-server-2", profile.X509NameCNPrefix, false,
			"the comparison runs one way: the CN must start with the value, not the value with the CN"},
		{"name-prefix of a different name", "no-such", profile.X509NameCNPrefix, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newTestCA(t, "Example VPN CA")
			chain := pki.issueLeaf(t, &x509.Certificate{
				Subject:     subject,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			v := verifierForProfile(t, x509NameProfile(pki, tc.value, tc.match))
			err := v.Verify(chain, nil)
			switch {
			case tc.wantOK && err != nil:
				t.Errorf("chain should be accepted, got: %v (%s)", err, tc.comment)
			case !tc.wantOK && err == nil:
				t.Errorf("chain should be rejected, was accepted (%s)", tc.comment)
			}
			if v.OK() != tc.wantOK {
				t.Errorf("OK() = %v after a %v verdict", v.OK(), tc.wantOK)
			}
		})
	}
}

// TestVerifyX509NameNeverMatchesASAN guards the field the directive checks: the
// certificate's SANs carry the value the directive names and its subject does
// not, so routing verify-x509-name into ServerName would accept it. Every one
// of the three match types must refuse it.
func TestVerifyX509NameNeverMatchesASAN(t *testing.T) {
	const wanted = "san-only.example.test"
	for _, match := range []profile.X509NameMatch{
		profile.X509NameSubject, profile.X509NameCN, profile.X509NameCNPrefix,
	} {
		t.Run(match.String(), func(t *testing.T) {
			pki := newTestCA(t, "Example VPN CA")
			chain := pki.issueLeaf(t, &x509.Certificate{
				Subject:     pkix.Name{CommonName: "some-internal-name"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    []string{wanted},
			})
			v := verifierForProfile(t, x509NameProfile(pki, wanted, match))
			if err := v.Verify(chain, nil); err == nil {
				t.Error("a certificate matching only in its SAN was accepted; " +
					"verify-x509-name is being matched against the wrong field")
			}
		})
	}
}

// TestVerifyX509NameNeedsACommonName covers the certificate that has no CN at
// all. An absent field is not a match, and in particular is not a match for
// the empty prefix.
func TestVerifyX509NameNeedsACommonName(t *testing.T) {
	for _, match := range []profile.X509NameMatch{profile.X509NameCN, profile.X509NameCNPrefix} {
		t.Run(match.String(), func(t *testing.T) {
			pki := newTestCA(t, "Example VPN CA")
			chain := pki.issueLeaf(t, &x509.Certificate{
				Subject:     pkix.Name{Organization: []string{"OpenVPN-TEST"}},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			v := verifierForProfile(t, x509NameProfile(pki, "matrix-server", match))
			if err := v.Verify(chain, nil); err == nil {
				t.Error("a certificate with no common name satisfied a CN check")
			}
		})
	}
}

// TestSubjectDNIsOpenVPNsRendering pins the string the subject match type
// compares against, which is not Go's. pkix.Name.String returns RFC 2253 —
// attributes reversed, no spaces, separators escaped — while OpenVPN's
// x509_get_subject returns OpenSSL's XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_FN_SN
// rendering: forward order, ", " separators, short names. Asserting that the
// two differ is what stops a later simplification reaching for the built-in.
func TestSubjectDNIsOpenVPNsRendering(t *testing.T) {
	pki := newTestCA(t, "Example VPN CA")
	chain := pki.issueLeaf(t, &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"KG"},
			Province:     []string{"NA"},
			Locality:     []string{"BISHKEK"},
			Organization: []string{"OpenVPN-TEST"},
			CommonName:   "Test-Server",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: OIDEmailAddress, Value: "me@myhost.mydomain"},
			},
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	cert, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	const want = "C=KG, ST=NA, L=BISHKEK, O=OpenVPN-TEST, CN=Test-Server, " +
		"emailAddress=me@myhost.mydomain"
	if got := SubjectDN(cert); got != want {
		t.Errorf("SubjectDN =\n  %q\nwant\n  %q", got, want)
	}
	if cert.Subject.String() == want {
		t.Error("pkix.Name.String now renders OpenVPN's format; this test no longer " +
			"proves the two are different and SubjectDN may have become redundant")
	}
}

// TestNSCertTypeServer covers ns-cert-type server in both directions. The
// directive is named after an extension it stopped requiring in OpenVPN 2.4:
// x509_verify_ns_cert_type asks X509_check_purpose for the SSL-server purpose
// first and reads the raw Netscape bit only when that fails (openvpn-2.6.22
// src/openvpn/ssl_verify_openssl.c:611-676), so the rows that matter are the
// ones with no Netscape extension at all. The purpose check is three rejections
// rather than three requirements, which is why "nothing at all" passes and
// "clientAuth" does not.
func TestNSCertTypeServer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		eku        []x509.ExtKeyUsage
		ku         x509.KeyUsage
		ext        []pkix.Extension
		nsCertType bool
		wantOK     bool
	}{
		// The certificate a modern CA issues: serverAuth, a key usage, and no
		// Netscape extension anywhere. X509_check_purpose says SSL server, so
		// the directive is satisfied.
		{"no Netscape extension on a serverAuth certificate", serverAuthEKU(),
			x509.KeyUsageDigitalSignature, nil, true, true},
		// Nothing to reject is not the same as nothing to check: a leaf with
		// no EKU, no KU and no nsCertType passes all three of the purpose
		// check's rejections.
		{"a certificate carrying none of the three extensions", nil, 0, nil, true, true},
		{"ssl-server bit beside a serverAuth certificate", serverAuthEKU(),
			x509.KeyUsageDigitalSignature, []pkix.Extension{nsCertTypeExt(0x40, 6)}, true, true},
		// The fallback earning its place: the purpose check rejects a
		// clientAuth EKU, and the raw bit accepts the certificate anyway —
		// which is what the reference does, with a deprecation warning.
		{"ssl-server bit rescues a clientAuth certificate",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			x509.KeyUsageDigitalSignature, []pkix.Extension{nsCertTypeExt(0x40, 6)}, true, true},
		// A Netscape extension that is present and says something else is a
		// rejection in the purpose check and a miss in the fallback.
		{"ssl-client bit only", serverAuthEKU(),
			x509.KeyUsageDigitalSignature, []pkix.Extension{nsCertTypeExt(0x80, 7)}, true, false},
		// A CA certificate's bits are a different set; none of them is the
		// SSL-server bit, so nsSslCa must not satisfy an nsSslServer check.
		{"ssl-ca bit only", serverAuthEKU(),
			x509.KeyUsageDigitalSignature, []pkix.Extension{nsCertTypeExt(0x04, 5)}, true, false},
		{"clientAuth and no Netscape extension",
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			x509.KeyUsageDigitalSignature, nil, true, false},
		// ku_reject: a key usage extension naming none of digitalSignature,
		// keyEncipherment or keyAgreement is not a TLS server's.
		{"a key usage a TLS server cannot use", serverAuthEKU(),
			x509.KeyUsageCertSign | x509.KeyUsageCRLSign, nil, true, false},
		// Without the directive none of it is looked at.
		{"no Netscape extension without ns-cert-type", serverAuthEKU(),
			x509.KeyUsageDigitalSignature, nil, false, true},
		{"ssl-client bit only without ns-cert-type", serverAuthEKU(),
			x509.KeyUsageDigitalSignature, []pkix.Extension{nsCertTypeExt(0x80, 7)}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newTestCA(t, "Example VPN CA")
			chain := pki.issueLeafVerbatim(t, &x509.Certificate{
				Subject:         pkix.Name{CommonName: "matrix-server"},
				ExtKeyUsage:     tc.eku,
				KeyUsage:        tc.ku,
				ExtraExtensions: tc.ext,
			})
			prof := &profile.Profile{Remote: "vpn.example.com", Port: 1194, CA: pki.caPEM,
				NSCertTypeServer: tc.nsCertType}
			v := verifierForProfile(t, prof)
			err := v.Verify(chain, nil)
			if tc.wantOK && err != nil {
				t.Errorf("chain should be accepted, got: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Error("chain should be rejected, was accepted")
			}
		})
	}
}

// serverAuthEKU is the one-element extended key usage most rows above carry. It
// is a function rather than a package variable because a table row hands the
// slice to a certificate template, and a shared slice is a shared field.
func serverAuthEKU() []x509.ExtKeyUsage {
	return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
}

// TestRemoteCertTLSRequiresAKeyUsageExtension covers the half of
// remote-cert-tls server that is not the extended key usage: the directive also
// sets remote_cert_ku[0] to OPENVPN_KU_REQUIRED (openvpn-2.6.22
// src/openvpn/options.c:9159-9170, and 2.4.12 options.c:7999-8005), and
// verify_peer_cert refuses a leaf whose key usage extension is absent
// (ssl_verify_openssl.c:678-695).
//
// OPENVPN_KU_REQUIRED means present, not particular: the bits are left to the
// TLS library, so a keyEncipherment-only certificate must pass. The last two
// rows keep the check tied to the directive rather than applied always.
func TestRemoteCertTLSRequiresAKeyUsageExtension(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ku            x509.KeyUsage
		remoteCertTLS bool
		wantOK        bool
	}{
		{"digitalSignature with remote-cert-tls", x509.KeyUsageDigitalSignature, true, true},
		{"no key usage extension with remote-cert-tls", 0, true, false},
		{"keyEncipherment alone with remote-cert-tls", x509.KeyUsageKeyEncipherment, true, true},
		// Any bits satisfy OPENVPN_KU_REQUIRED, including ones no TLS server
		// uses: the reference tests presence and stops.
		{"an unrelated key usage with remote-cert-tls", x509.KeyUsageCRLSign, true, true},
		{"no key usage extension without remote-cert-tls", 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newTestCA(t, "Example VPN CA")
			chain := pki.issueLeafVerbatim(t, &x509.Certificate{
				Subject:     pkix.Name{CommonName: "matrix-server"},
				ExtKeyUsage: serverAuthEKU(),
				KeyUsage:    tc.ku,
			})
			v := verifierFor(t, pki, tc.remoteCertTLS)
			err := v.Verify(chain, nil)
			if tc.wantOK && err != nil {
				t.Errorf("chain should be accepted, got: %v", err)
			}
			if !tc.wantOK {
				if err == nil {
					t.Fatal("chain should be rejected, was accepted")
				}
				// The refusal must name the extension that is missing, so a
				// failure for any other reason cannot stand in for this one.
				if !strings.Contains(err.Error(), "key usage extension") {
					t.Errorf("refusal = %v, want it to name the key usage extension", err)
				}
			}
		})
	}
}

// TestNSCertTypeOnlyHonoursTheServerForm records that "ns-cert-type client" is
// not read. It is valid OpenVPN and would demand the SSL-client bit of the
// server's own certificate, which no server deployment sets out to satisfy; the
// capability registry reports it as degraded rather than supported.
func TestNSCertTypeOnlyHonoursTheServerForm(t *testing.T) {
	pki := newTestCA(t, "Example VPN CA")
	chain := pki.issueLeaf(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "matrix-server"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	prof, err := profile.ParseString("remote vpn.example.com 1194\nns-cert-type client\n<ca>\n" +
		string(pki.caPEM) + "</ca>\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	v := verifierForProfile(t, prof)
	if err := v.Verify(chain, nil); err != nil {
		t.Errorf("the client form is not checked, so it must not refuse: %v", err)
	}
}

// TestVerifierChecksTheLeafOnly keeps the two checks where OpenVPN makes them.
// verify_cert runs them at cert_depth 0: an intermediate that satisfies them
// must not stand in for a leaf that does not, or a chain could be built to pass
// a check the server certificate fails.
func TestVerifierChecksTheLeafOnly(t *testing.T) {
	pki := newTestCA(t, "Example VPN CA")
	leaf := pki.issueLeaf(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "some-internal-name"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	// A second certificate offered alongside the leaf, carrying the name the
	// directive asks for. It is not the leaf, so it must not be consulted.
	other := pki.issueLeaf(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "matrix-server"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	v := verifierForProfile(t, x509NameProfile(pki, "matrix-server", profile.X509NameCN))
	if err := v.Verify([][]byte{leaf[0], other[0]}, nil); err == nil {
		t.Error("a name carried by something other than the leaf satisfied verify-x509-name")
	}
}

// TestVerifyX509NameIsWiredFromTheProfile closes the loop from a parsed
// profile to the verifier, which is where this check's own bug would live: it
// is implemented, and the field feeding it is never read.
func TestVerifyX509NameIsWiredFromTheProfile(t *testing.T) {
	pki := newTestCA(t, "Example VPN CA")
	p, err := profile.ParseString("client\ndev tun\nremote vpn.example.com 1194\n" +
		"verify-x509-name matrix-serv name-prefix\nns-cert-type server\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	p.CA = pki.caPEM

	v := verifierForProfile(t, p)
	if name, match := v.X509Name(); name != "matrix-serv" || match != profile.X509NameCNPrefix {
		t.Errorf("verifier carries %q/%v, want %q/%v",
			name, match, "matrix-serv", profile.X509NameCNPrefix)
	}
	if !v.RequiresNSCertType() {
		t.Error("ns-cert-type server did not reach the verifier")
	}

	chain := pki.issueLeaf(t, &x509.Certificate{
		Subject:         pkix.Name{CommonName: "matrix-server"},
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{nsCertTypeExt(0x40, 6)},
	})
	if err := v.Verify(chain, nil); err != nil {
		t.Errorf("a certificate satisfying both directives was refused: %v", err)
	}
}

// ---- how a certificate is rendered ----------------------------------------

// TestCertificateSerialNumberPreservesDERLeadingZero reads the serial out of
// the DER rather than from the parsed big.Int. A serial is an arbitrary byte
// string, not a number: 0x06 and 0x0006 are different serials that parse to the
// same integer, and a CRL or a support ticket is matched on the bytes.
func TestCertificateSerialNumberPreservesDERLeadingZero(t *testing.T) {
	// Certificate ::= SEQUENCE { TBSCertificate, signatureAlgorithm, signature }
	// TBSCertificate starts with version [0] then the serial-number INTEGER.
	raw := []byte{
		0x30, 0x0f, // Certificate sequence
		0x30, 0x08, // TBSCertificate sequence
		0xa0, 0x03, 0x02, 0x01, 0x02, // version v3
		0x02, 0x01, 0x06, // serial number 06
		0x30, 0x00, // signature algorithm
		0x03, 0x01, 0x00, // signature value
	}
	if got := SerialNumber(&x509.Certificate{Raw: raw, SerialNumber: big.NewInt(6)}); got != "06" {
		t.Errorf("SerialNumber() = %q, want 06", got)
	}
}
