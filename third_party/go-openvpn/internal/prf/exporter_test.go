// Known-answer tests for the RFC 5705 exporter, against the only oracle there
// is: crypto/tls itself.
//
// The subject is a TLS 1.2 session *without* Extended Master Secret, which
// crypto/tls will not export from and which cannot be built here — Go's client
// always offers EMS and Go's server always accepts it. What can be built is a
// session where both exporters work, and RFC 7627 Section 4 is why that is
// enough: EMS changes how the master secret is computed and nothing about the
// export.
//
// TestExporterAgreesWithGoOnEverySuite pins the PRF digest choice: every suite
// Go will negotiate for TLS 1.2 goes through it, so a suite mapped to the wrong
// digest cannot pass.
package prf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// exporterLabel is the label the client exports data-channel keys under
// (openvpn3 ssl/proto.hpp generate_datachannel_keys()). Running the tests under
// the real one keeps the reserved-label refusals below honest.
const exporterLabel = "EXPORTER-OpenVPN-datakeys"

func TestExporterAgreesWithGoOnEverySuite(t *testing.T) {
	suites := append(slices.Clone(tls.CipherSuites()), tls.InsecureCipherSuites()...)

	var sha256Suites, sha384Suites int
	for _, suite := range suites {
		if !slices.Contains(suite.SupportedVersions, tls.VersionTLS12) {
			continue
		}
		t.Run(suite.Name, func(t *testing.T) {
			session, cs := handshakeTLS12(t, suite.ID)

			// 32 is the length the report's EKM probe asks for and 256 the
			// length the key block needs, so both of the client's export
			// lengths are compared.
			for _, n := range []int{32, dataKeyBlockLen} {
				want, err := cs.ExportKeyingMaterial(exporterLabel, nil, n)
				if err != nil {
					t.Fatalf("crypto/tls declined to export %d bytes from a TLS 1.2 "+
						"session with EMS, so there is no oracle here: %v", n, err)
				}
				got, err := ExportKeyingMaterialTLS12(session, exporterLabel, n)
				if err != nil {
					t.Fatalf("ExportKeyingMaterialTLS12(%d): %v", n, err)
				}
				if hex.EncodeToString(got) != hex.EncodeToString(want) {
					t.Fatalf("export of %d bytes disagrees with crypto/tls:\n got %x\nwant %x",
						n, got, want)
				}
			}
			if strings.HasSuffix(suite.Name, "_SHA384") {
				sha384Suites++
			} else {
				sha256Suites++
			}
		})
	}

	// A run in which every SHA-384 suite happened to be unnegotiable would pass
	// while testing one digest, and the digest is the part of the export that
	// is not a constant.
	if sha256Suites == 0 || sha384Suites == 0 {
		t.Errorf("covered %d SHA-256 suites and %d SHA-384 suites; both digests "+
			"must be exercised or the digest choice is untested",
			sha256Suites, sha384Suites)
	}
	t.Logf("agreed with crypto/tls on %d SHA-256 and %d SHA-384 suites",
		sha256Suites, sha384Suites)
}

// dataKeyBlockLen is the client's export length, repeated here so the oracle
// runs at the length that matters.
const dataKeyBlockLen = 256

func TestExporterRefusesMaterialItCannotUse(t *testing.T) {
	// One good session, so that each case below differs from something that
	// works by exactly the field under test.
	good, _ := handshakeTLS12(t, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	shorten := func(b []byte) []byte { return b[:len(b)-1] }

	cases := []struct {
		name    string
		mutate  func(*TLS12Session)
		label   string
		n       int
		wantErr string
	}{
		{
			// The refusal that matters most: TLS 1.3 exports through
			// HKDF-Expand-Label over a different secret, and Go performs it
			// itself, so this function must never be the one that answers.
			name:    "TLS 1.3",
			mutate:  func(s *TLS12Session) { s.Version = tls.VersionTLS13 },
			wantErr: "TLS 1.2 only",
		},
		{
			name:    "TLS 1.1",
			mutate:  func(s *TLS12Session) { s.Version = tls.VersionTLS11 },
			wantErr: "TLS 1.2 only",
		},
		{
			name:    "short master secret",
			mutate:  func(s *TLS12Session) { s.MasterSecret = shorten(s.MasterSecret) },
			wantErr: "master secret must be 48 bytes",
		},
		{
			name:    "short client random",
			mutate:  func(s *TLS12Session) { s.ClientRandom = shorten(s.ClientRandom) },
			wantErr: "client random must be 32 bytes",
		},
		{
			name:    "short server random",
			mutate:  func(s *TLS12Session) { s.ServerRandom = shorten(s.ServerRandom) },
			wantErr: "server random must be 32 bytes",
		},
		{
			// A suite crypto/tls cannot name carries no way to know its PRF
			// digest, and guessing one derives bytes the peer disagrees with.
			name:    "unknown cipher suite",
			mutate:  func(s *TLS12Session) { s.CipherSuite = 0xfafa },
			wantErr: "PRF digest cannot be determined",
		},
		{
			name:    "zero length",
			n:       0,
			wantErr: "length must be positive",
		},
		{
			name:    "reserved label",
			label:   "master secret",
			wantErr: "reserved by TLS",
		},
		{
			name:    "reserved finished label",
			label:   "client finished",
			wantErr: "reserved by TLS",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := good
			if tc.mutate != nil {
				tc.mutate(&session)
			}
			label := exporterLabel
			if tc.label != "" {
				label = tc.label
			}
			n := dataKeyBlockLen
			if tc.wantErr == "length must be positive" {
				n = tc.n
			}
			out, err := ExportKeyingMaterialTLS12(session, label, n)
			if err == nil {
				t.Fatalf("exported %d bytes from material that should have been refused", len(out))
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// ---- the oracle rig --------------------------------------------------------

// handshakeTLS12 completes one TLS 1.2 handshake over net.Pipe with suite
// negotiated, and returns the session material an export needs alongside the
// client's connection state. The material is gathered the way production
// gathers it — master secret and client random from a key log, server random
// off the wire — but by code written here, because reusing the capture's own
// parser could not tell a wrong parser from a wrong exporter.
func handshakeTLS12(t *testing.T, suite uint16) (TLS12Session, tls.ConnectionState) {
	t.Helper()

	clientEnd, serverEnd := net.Pipe()
	t.Cleanup(func() {
		clientEnd.Close() //nolint:errcheck
		serverEnd.Close() //nolint:errcheck
	})

	keylog := &keyLogReader{}
	tap := &serverHelloReader{Conn: clientEnd}

	clientCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{suite},
		InsecureSkipVerify: true, //nolint:gosec // a net.Pipe to a certificate generated in this process
		KeyLogWriter:       keylog,
	}
	serverCfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{suite},
		Certificates: testCertificates(t),
	}

	client := tls.Client(tap, clientCfg)
	server := tls.Server(serverEnd, serverCfg)

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	go func() {
		defer wg.Done()
		serverErr = server.Handshake()
	}()
	clientErr := client.Handshake()
	wg.Wait()

	if clientErr != nil || serverErr != nil {
		// Not every suite in the table can be negotiated by every build: RSA
		// key exchange and 3DES sit behind GODEBUG settings. A suite that
		// cannot be negotiated is not a failure of the exporter, and the
		// caller's coverage assertion catches a run that skipped everything.
		t.Skipf("suite %s did not negotiate (client %v, server %v)",
			tls.CipherSuiteName(suite), clientErr, serverErr)
	}

	cs := client.ConnectionState()
	clientRandom, masterSecret := keylog.material(t)
	return TLS12Session{
		Version:      cs.Version,
		CipherSuite:  cs.CipherSuite,
		MasterSecret: masterSecret,
		ClientRandom: clientRandom,
		ServerRandom: tap.serverRandom(t),
	}, cs
}

// keyLogReader collects the CLIENT_RANDOM line crypto/tls writes for a
// TLS 1.2 handshake.
type keyLogReader struct {
	mu    sync.Mutex
	lines []string
}

func (k *keyLogReader) Write(p []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.lines = append(k.lines, string(p))
	return len(p), nil
}

func (k *keyLogReader) material(t *testing.T) (clientRandom, masterSecret []byte) {
	t.Helper()
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, line := range k.lines {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "CLIENT_RANDOM" {
			continue
		}
		random, err := hex.DecodeString(fields[1])
		if err != nil {
			t.Fatalf("key log client random: %v", err)
		}
		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			t.Fatalf("key log master secret: %v", err)
		}
		return random, secret
	}
	t.Fatalf("no CLIENT_RANDOM line in %d key log lines", len(k.lines))
	return nil, nil
}

// serverHelloReader keeps the first bytes the server sends, which for a
// TLS 1.2 handshake begin with the ServerHello.
type serverHelloReader struct {
	net.Conn
	mu    sync.Mutex
	first []byte
}

func (s *serverHelloReader) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	if n > 0 {
		s.mu.Lock()
		if len(s.first) < 128 {
			s.first = append(s.first, b[:n]...)
		}
		s.mu.Unlock()
	}
	return n, err
}

// serverRandom reads ServerHello.random out of the first inbound record:
// 5 bytes of record header, 4 of handshake header, 2 of version, then the
// random (RFC 5246 Sections 6.2.1 and 7.4.1.3).
func (s *serverHelloReader) serverRandom(t *testing.T) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	const offset = 5 + 4 + 2
	if len(s.first) < offset+tlsRandomLen {
		t.Fatalf("only %d bytes of the server's first flight were seen", len(s.first))
	}
	if s.first[0] != 22 {
		t.Fatalf("the server's first record has content type %d, want 22 (handshake)", s.first[0])
	}
	if s.first[5] != 2 {
		t.Fatalf("the server's first handshake message has type %d, want 2 (ServerHello)", s.first[5])
	}
	return slices.Clone(s.first[offset : offset+tlsRandomLen])
}

// testCertificates returns one ECDSA and one RSA self-signed certificate, so
// that the server can satisfy whichever key exchange the suite under test
// asks for.
func testCertificates(t *testing.T) []tls.Certificate {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return []tls.Certificate{
		selfSigned(t, ecKey, ecKey.Public()),
		selfSigned(t, rsaKey, rsaKey.Public()),
	}
}

func selfSigned(t *testing.T, key crypto.Signer, pub any) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "prf exporter test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
