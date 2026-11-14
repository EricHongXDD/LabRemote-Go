// SPDX-License-Identifier: LGPL-2.1-or-later

package tlsverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/profile"
)

// keylogProfile 用于验证环境变量无法触发 TLS 密钥落盘。
func keylogProfile(t *testing.T, path string, ca []byte) *profile.Profile {
	t.Helper()
	t.Setenv("SSLKEYLOGFILE", path)
	return &profile.Profile{Remote: "vpn.example.com", Port: 1194, CA: ca}
}

type testCA struct {
	key   *ecdsa.PrivateKey
	cert  *x509.Certificate
	caPEM []byte
}

// newTestCA generates a self-signed CA. The common name is a parameter because
// two CAs in one test have to be distinguishable in a failure message.
func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{
		key:   key,
		cert:  cert,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// serverCert issues a leaf the CA signs, for a tls.Server the verifier will
// accept. It carries no DNS name, because the verifier does not look at one.
func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "vpn.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// issueServer issues a server leaf. dnsNames may be empty, which is the case
// that matters: a certificate naming nothing the client dialled.
func (ca *testCA) issueServer(t *testing.T, commonName string, eku []x509.ExtKeyUsage, dnsNames []string) [][]byte {
	t.Helper()
	return ca.issueLeaf(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: commonName},
		ExtKeyUsage: eku,
		DNSNames:    dnsNames,
	})
}

// issueLeaf issues a server leaf from a caller-supplied template, filling in the
// serial, validity and key usage every leaf needs. It exists for the subject and
// ns-cert-type checks, which issueServer has no parameter for.
func (ca *testCA) issueLeaf(t *testing.T, tmpl *x509.Certificate) [][]byte {
	t.Helper()
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	return ca.issueLeafVerbatim(t, tmpl)
}

// issueLeafVerbatim issues a leaf without filling in a key usage, so that a
// template asking for none produces a certificate with no key usage extension at
// all — crypto/x509 emits the extension only for a non-zero KeyUsage. That shape
// is a case in its own right, because the SSL-server purpose check waves it
// through and remote-cert-tls server does not.
func (ca *testCA) issueLeafVerbatim(t *testing.T, tmpl *x509.Certificate) [][]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl.SerialNumber = big.NewInt(2)
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return [][]byte{der}
}

// testCAPEM returns a CA for tests whose subject is not certificate
// verification but whose profile must still carry one, because a profile
// without a CA is ErrNoUsableCA before BuildConfig reaches the key log.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	sharedCAOnce.Do(func() { sharedCA = newTestCA(t, "tlsverify test CA") })
	return sharedCA.caPEM
}

var (
	sharedCAOnce sync.Once
	sharedCA     *testCA
)
