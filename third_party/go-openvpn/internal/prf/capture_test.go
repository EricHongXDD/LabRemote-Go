// SPDX-License-Identifier: LGPL-2.1-or-later

package prf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Capture exists for the pushed tls-ekm export, which crypto/tls refuses on a
// TLS 1.2 session that negotiated no Extended Master Secret. These tests cover
// the export decision, the wire reading it rests on, agreement with crypto/tls
// on the bytes, and an empty capture afterwards.

// tls12Session is one completed TLS 1.2 handshake over net.Pipe with the
// client side wired the way tlsHandshake wires it: a capture installed on the
// config, and crypto/tls reading the connection through Capture.Wrap.
type tls12Session struct {
	capture *Capture
	client  *tls.Conn
	server  *tls.Conn
}

// newTLS12Session completes the handshake. renegotiation is the client's
// Config.Renegotiation, the only knob crypto/tls offers for producing a TLS 1.2
// session it will refuse to export from: Go's client always offers Extended
// Master Secret and Go's server always accepts it, so a genuinely EMS-less
// session cannot be built out of two crypto/tls endpoints.
//
// NewCapture on the config and Capture.Wrap on the connection are the
// production lines; the rest is hand-built because the TLS version and the
// renegotiation setting have no profile directive behind them.
func newTLS12Session(t *testing.T, renegotiation tls.RenegotiationSupport) tls12Session {
	t.Helper()

	clientEnd, serverEnd := net.Pipe()
	t.Cleanup(func() {
		clientEnd.Close() //nolint:errcheck
		serverEnd.Close() //nolint:errcheck
	})

	clientCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // a net.Pipe to a certificate generated in this process
		Renegotiation:      renegotiation,
	}
	capture := NewCapture(clientCfg)

	client := tls.Client(capture.Wrap(clientEnd), clientCfg)
	server := tls.Server(serverEnd, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{selfSignedTLSServerCert(t)},
	})

	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = server.Handshake()
	}()
	clientErr := client.Handshake()
	wg.Wait()
	if clientErr != nil || serverErr != nil {
		t.Fatalf("TLS 1.2 handshake: client %v, server %v", clientErr, serverErr)
	}
	return tls12Session{capture: capture, client: client, server: server}
}

// selfSignedTLSServerCert returns a throwaway ECDSA server certificate.
func selfSignedTLSServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "capture test server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestCaptureHoldsNothingAfterTheKeysAreDerived pins that the wipe zeroes the
// master secret in place rather than dropping the slice, that a later key-log
// line cannot refill it, and that a nil capture is safe on every entry point.
func TestCaptureHoldsNothingAfterTheKeysAreDerived(t *testing.T) {
	s := newTLS12Session(t, tls.RenegotiateNever)
	cs := s.client.ConnectionState()

	s.capture.mu.Lock()
	secret := s.capture.masterSecret
	s.capture.mu.Unlock()
	if len(secret) != 48 {
		t.Fatalf("captured master secret is %d bytes, want 48", len(secret))
	}
	if bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("the captured master secret is all zeroes before the wipe")
	}

	s.capture.Wipe()

	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Errorf("the master secret's bytes survived the wipe: %x", secret)
	}
	if _, err := s.capture.ExportKeyingMaterial(cs, ExporterLabel, DataKeyBlockLen); err == nil {
		t.Error("a wiped capture still exported a key block")
	}
	// A key-log line arriving after the wipe — a later handshake on a
	// config the capture is still attached to — must not refill it.
	s.capture.Write([]byte("CLIENT_RANDOM " + strings.Repeat("aa", 32) + " " + strings.Repeat("bb", 48) + "\n")) //nolint:errcheck
	s.capture.mu.Lock()
	refilled := len(s.capture.masterSecret)
	s.capture.mu.Unlock()
	if refilled != 0 {
		t.Errorf("a key-log line refilled the capture after it was wiped (%d bytes)", refilled)
	}

	// Wipe is called through a nil capture on every entry point that runs no
	// handshake, and deriveDataKeys defers it unconditionally.
	var absent *Capture
	absent.Wipe()
	if absent.EMSRefusal(cs) {
		t.Error("emsRefusal on a nil capture")
	}
	if _, err := absent.ExportKeyingMaterial(cs, ExporterLabel, DataKeyBlockLen); err == nil {
		t.Error("a nil capture exported a key block")
	}
}

// TestKeyLogAndWireMustBeTheSameHandshake covers the pairing check: the master
// secret comes from the key log and the randoms from the wire, and nothing else
// binds them to the same handshake. A mismatch derives 256 well-formed bytes
// the peer disagrees with, which surfaces as a data channel carrying nothing.
func TestKeyLogAndWireMustBeTheSameHandshake(t *testing.T) {
	s := newTLS12Session(t, tls.RenegotiateNever)
	cs := s.client.ConnectionState()

	s.capture.mu.Lock()
	s.capture.keyLogRandom[0] ^= 0xff
	s.capture.mu.Unlock()

	_, err := s.capture.ExportKeyingMaterial(cs, ExporterLabel, DataKeyBlockLen)
	if err == nil {
		t.Fatal("exported from a master secret and a client random that came from " +
			"different handshakes")
	}
	if !strings.Contains(err.Error(), "two different handshakes") {
		t.Errorf("error = %q, want it to name the mismatch", err)
	}
}

// TestServerHelloEMSDetection pins the parser the export decision rests on. A
// parser that mistakes a malformed ServerHello for one carrying no
// extended_master_secret exports where crypto/tls was right to refuse, so every
// case checks both return values rather than only the interesting one.
func TestServerHelloEMSDetection(t *testing.T) {
	// A minimal well-formed ServerHello body: version, random, empty session
	// id, cipher suite, compression method, then the extension block.
	body := func(extensions ...byte) []byte {
		msg := []byte{0x03, 0x03}
		msg = append(msg, bytes.Repeat([]byte{0x11}, 32)...)
		msg = append(msg, 0x00)       // session_id length
		msg = append(msg, 0xc0, 0x2f) // cipher_suite
		msg = append(msg, 0x00)       // compression_method
		if len(extensions) == 0 {
			return msg
		}
		msg = append(msg, byte(len(extensions)>>8), byte(len(extensions)))
		return append(msg, extensions...)
	}
	emsExt := []byte{0x00, 0x17, 0x00, 0x00}
	otherExt := []byte{0x00, 0x0b, 0x00, 0x01, 0x00} // ec_point_formats

	cases := []struct {
		name         string
		msg          []byte
		want, parsed bool
	}{
		{"extension present", body(emsExt...), true, true},
		{"extension present after another", body(append(slices.Clone(otherExt), emsExt...)...), true, true},
		{"extension absent", body(otherExt...), false, true},
		{"no extension block at all", body(), false, true},
		{"empty extension block", append(body(), 0x00, 0x00), false, true},
		{"truncated before the randoms", []byte{0x03, 0x03, 0x00}, false, false},
		{"a byte too many in the extension block", append(slices.Clone(body(emsExt...)), 0x00), false, false},
		{"nothing captured", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			present, parsed := serverHelloNegotiatedEMS(tc.msg)
			if present != tc.want || parsed != tc.parsed {
				t.Errorf("present=%t parsed=%t, want present=%t parsed=%t",
					present, parsed, tc.want, tc.parsed)
			}
		})
	}
}

// TestHandshakeScanSurvivesFragmentation feeds the same bytes one at a time.
// The control channel hands crypto/tls whatever a 1024-byte P_CONTROL_V1
// segment happened to carry, so neither record nor handshake-message boundaries
// line up with the reads.
func TestHandshakeScanSurvivesFragmentation(t *testing.T) {
	s := newTLS12Session(t, tls.RenegotiateNever)
	s.capture.mu.Lock()
	hello := slices.Clone(s.capture.serverHello.msg)
	s.capture.mu.Unlock()
	if len(hello) == 0 {
		t.Fatal("no ServerHello was captured from a completed handshake")
	}

	// The record the scan reassembled it from, rebuilt: record header,
	// handshake header, body.
	record := []byte{recordTypeHandshake, 0x03, 0x03, byte((len(hello) + 4) >> 8), byte(len(hello) + 4)}
	record = append(record, handshakeServerHello,
		byte(len(hello)>>16), byte(len(hello)>>8), byte(len(hello)))
	record = append(record, hello...)

	feeds := map[string]func(*handshakeScan){
		"one byte at a time": func(scan *handshakeScan) {
			for i := range record {
				scan.feed(record[i : i+1])
			}
		},
		"split mid-header": func(scan *handshakeScan) {
			scan.feed(record[:3])
			scan.feed(record[3:])
		},
		"all at once, with a second record behind it": func(scan *handshakeScan) {
			scan.feed(append(slices.Clone(record), record...))
		},
	}
	for name, feed := range feeds {
		t.Run(name, func(t *testing.T) {
			scan := handshakeScan{want: handshakeServerHello}
			feed(&scan)
			if !bytes.Equal(scan.msg, hello) {
				t.Errorf("reassembled %d bytes, want the %d-byte ServerHello",
					len(scan.msg), len(hello))
			}
		})
	}

	// A stream that opens with something other than a handshake record has
	// nothing to offer, and waiting for more of it would wait for ever.
	scan := handshakeScan{want: handshakeServerHello}
	scan.feed([]byte{23, 0x03, 0x03, 0x00, 0x01, 0x00})
	if !scan.done || scan.msg != nil {
		t.Errorf("scan of an application-data record: done=%t captured=%d bytes",
			scan.done, len(scan.msg))
	}

	// So does one whose first handshake message is not the wanted one.
	scan = handshakeScan{want: handshakeServerHello}
	scan.feed([]byte{recordTypeHandshake, 0x03, 0x03, 0x00, 0x05, handshakeClientHello, 0x00, 0x00, 0x01, 0x00})
	if !scan.done || scan.msg != nil {
		t.Errorf("scan of the wrong first message: done=%t captured=%d bytes",
			scan.done, len(scan.msg))
	}

	// And a ServerHello that declares more than the scan will ever buffer is
	// given up on rather than waited for: the tap stays in the read path for
	// the life of the connection, so a scan that never finishes is a buffer
	// that never stops growing.
	scan = handshakeScan{want: handshakeServerHello}
	scan.feed([]byte{recordTypeHandshake, 0x03, 0x03, 0x00, 0x04, handshakeServerHello, 0xff, 0xff, 0xff})
	if !scan.done || scan.msg != nil {
		t.Errorf("scan of a 16 MiB ServerHello: done=%t captured=%d bytes",
			scan.done, len(scan.msg))
	}
}

// withoutEMSExtension rewrites a ServerHello body with the
// extended_master_secret extension removed and the extension block's length
// corrected, which is what a server that does not implement RFC 7627 sends.
func withoutEMSExtension(t *testing.T, msg []byte) []byte {
	t.Helper()
	const fixed = 2 + 32
	sessionIDLen := int(msg[fixed])
	extStart := fixed + 1 + sessionIDLen + 3
	head := slices.Clone(msg[:extStart])
	exts := msg[extStart+2:]

	var kept []byte
	for len(exts) > 0 {
		extLen := int(exts[2])<<8 | int(exts[3])
		if exts[0] == 0x00 && exts[1] == extensionEMS {
			exts = exts[4+extLen:]
			continue
		}
		kept = append(kept, exts[:4+extLen]...)
		exts = exts[4+extLen:]
	}
	if len(kept) == 0 {
		return head
	}
	head = append(head, byte(len(kept)>>8), byte(len(kept)))
	return append(head, kept...)
}

// exportKeysForTest is ExportDataChannelKeys with the fallback flag dropped,
// so a test that cares only about the bytes reads like the caller does.
func exportKeysForTest(t *testing.T, cs tls.ConnectionState, capture *Capture) ([]byte, error) {
	t.Helper()
	keys, _, err := ExportDataChannelKeys(cs, capture)
	return keys, err
}

// TestCaptureExportsWhatCryptoTLSExports is the known-answer test, and the
// oracle is crypto/tls. The session negotiates Extended Master Secret so both
// exporters work; RFC 7627 §4 is why that is evidence about the sessions where
// only one of them does, since EMS changes how the master secret is computed
// and nothing about the export that consumes it.
func TestCaptureExportsWhatCryptoTLSExports(t *testing.T) {
	s := newTLS12Session(t, tls.RenegotiateNever)
	cs := s.client.ConnectionState()

	want, err := cs.ExportKeyingMaterial(ExporterLabel, nil, DataKeyBlockLen)
	if err != nil {
		t.Fatalf("crypto/tls refused to export from a TLS 1.2 session with EMS, "+
			"so this test has no oracle: %v", err)
	}
	got, err := s.capture.ExportKeyingMaterial(cs, ExporterLabel, DataKeyBlockLen)
	if err != nil {
		t.Fatalf("export from the captured material: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the two exporters disagree:\n captured %x\n crypto/tls %x", got, want)
	}
	t.Logf("256 bytes agree, first 16: %x", got[:16])

	// The same session, from the other end. RFC 5705 material is symmetric,
	// which is the property the data channel depends on and the reason a
	// server that exports differently would not decrypt anything we send.
	peerState := s.server.ConnectionState()
	peer, err := peerState.ExportKeyingMaterial(ExporterLabel, nil, DataKeyBlockLen)
	if err != nil {
		t.Fatalf("peer export: %v", err)
	}
	if !bytes.Equal(got, peer) {
		t.Errorf("the captured export does not match the peer's:\n ours %x\n peer %x", got, peer)
	}

	// EMS was negotiated here, so the fallback must not consider itself
	// applicable — the decision, not just the arithmetic.
	if s.capture.EMSRefusal(cs) {
		t.Error("emsRefusal on a session whose ServerHello carried extended_master_secret")
	}
}

// TestEMSAvailableTakesTheGoPath fails if the fallback runs when it should not.
// The capture's master secret is corrupted first, so getting crypto/tls's
// answer back out of ExportDataChannelKeys is proof that crypto/tls answered
// rather than proof that both paths happen to agree.
func TestEMSAvailableTakesTheGoPath(t *testing.T) {
	s := newTLS12Session(t, tls.RenegotiateNever)
	cs := s.client.ConnectionState()

	want, err := cs.ExportKeyingMaterial(ExporterLabel, nil, DataKeyBlockLen)
	if err != nil {
		t.Fatalf("crypto/tls export: %v", err)
	}

	s.capture.mu.Lock()
	s.capture.masterSecret[0] ^= 0xff
	s.capture.mu.Unlock()

	got, err := exportKeysForTest(t, cs, s.capture)
	if err != nil {
		t.Fatalf("exportDataChannelKeys: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the key block did not come from crypto/tls, so the fallback ran "+
			"on a session that did not need it:\n got %x\nwant %x", got, want)
	}
	if _, usedFallback, _ := ExportDataChannelKeys(cs, s.capture); usedFallback {
		t.Error("the fallback ran for a session crypto/tls exported normally")
	}
}

// TestARefusalThatIsNotTheEMSOneIsNotWorkedAround pins the other half of the
// decision: crypto/tls also declines to export for a Config with renegotiation
// enabled. The ServerHello here did negotiate EMS, so the fallback must decline
// and the refusal must reach the caller. The two refusals differ only in the
// wording of an unexported error, which is why the decision reads the wire.
func TestARefusalThatIsNotTheEMSOneIsNotWorkedAround(t *testing.T) {
	s := newTLS12Session(t, tls.RenegotiateOnceAsClient)
	cs := s.client.ConnectionState()

	if _, err := cs.ExportKeyingMaterial(ExporterLabel, nil, DataKeyBlockLen); err == nil {
		t.Skip("this crypto/tls exports with renegotiation enabled; the case cannot be built")
	}
	if s.capture.EMSRefusal(cs) {
		t.Fatal("emsRefusal on a session whose ServerHello carried extended_master_secret")
	}

	if _, err := exportKeysForTest(t, cs, s.capture); err == nil {
		t.Fatal("exportDataChannelKeys worked around a refusal that was not about EMS")
	}
	if _, usedFallback, _ := ExportDataChannelKeys(cs, s.capture); usedFallback {
		t.Error("the fallback ran for a refusal that was not about EMS")
	}
}

// TestTheFallbackRunsForTheEMSRefusalAndMatchesThePeer is the composition:
// crypto/tls refuses, the wire says no EMS was negotiated, and the key block
// comes from the captured material.
//
// The refusal is real; the missing extension is surgery — the ServerHello the
// capture read is rewritten without extended_master_secret, because no
// crypto/tls server will send one. Delete that rewrite and the test cannot
// fail. The expected bytes are the peer's own export of the same session.
func TestTheFallbackRunsForTheEMSRefusalAndMatchesThePeer(t *testing.T) {
	s := newTLS12Session(t, tls.RenegotiateOnceAsClient)
	cs := s.client.ConnectionState()

	if _, err := cs.ExportKeyingMaterial(ExporterLabel, nil, DataKeyBlockLen); err == nil {
		t.Skip("this crypto/tls exports with renegotiation enabled; the case cannot be built")
	}
	peerState := s.server.ConnectionState()
	want, err := peerState.ExportKeyingMaterial(ExporterLabel, nil, DataKeyBlockLen)
	if err != nil {
		t.Fatalf("the peer could not export, so this test has no oracle: %v", err)
	}

	s.capture.mu.Lock()
	if present, parsed := serverHelloNegotiatedEMS(s.capture.serverHello.msg); !parsed || !present {
		s.capture.mu.Unlock()
		t.Fatalf("the captured ServerHello parsed=%t ems=%t; a crypto/tls server "+
			"negotiates EMS, so both must be true before it is taken away", parsed, present)
	}
	s.capture.serverHello.msg = withoutEMSExtension(t, s.capture.serverHello.msg)
	present, parsed := serverHelloNegotiatedEMS(s.capture.serverHello.msg)
	s.capture.mu.Unlock()
	if !parsed || present {
		t.Fatalf("after removing the extension the ServerHello parsed=%t ems=%t, "+
			"want parsed with no EMS", parsed, present)
	}
	if !s.capture.EMSRefusal(cs) {
		t.Fatal("emsRefusal is false for a TLS 1.2 session whose ServerHello negotiated no EMS")
	}

	got, err := exportKeysForTest(t, cs, s.capture)
	if err != nil {
		t.Fatalf("exportDataChannelKeys: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the fallback's key block is not the one the peer derived:\n got %x\nwant %x", got, want)
	}
	if _, usedFallback, _ := ExportDataChannelKeys(cs, s.capture); !usedFallback {
		t.Error("the fallback ran but was not reported as such; the caller records it from this flag")
	}
	t.Logf("fallback agrees with the peer's export, first 16: %x", got[:16])
}
