// SPDX-License-Identifier: LGPL-2.1-or-later

package prf

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// ExporterLabel is the RFC 5705 exporter label OpenVPN uses for data-channel
// keys, and the label the EKMAvailable probe uses, so the probe answers the
// question the client cares about (openvpn3-core ssl/proto.hpp
// generate_datachannel_keys()).
const ExporterLabel = "EXPORTER-OpenVPN-datakeys"

// ---- TLS secret capture, and the one export it exists for -------------------
//
// This capture feeds one path and one only: a pushed `key-derivation tls-ekm`,
// which is an RFC 5705 export off the TLS session. Go's crypto/tls refuses that
// export on a TLS 1.2 session that negotiated no RFC 7627 Extended Master
// Secret; OpenSSL exports anyway, and where the two disagree about what is
// connectable this client matches stock openvpn. The classic derivation needs
// no TLS internals and touches none of this — see DeriveKeyBlock.
//
// The capture is scoped by lifetime and by use, which is the only scoping
// available. The KeyLogWriter has to be installed before the handshake, and
// whether the export will be refused is not known until the PUSH_REPLY arrives
// several stages later, so every connection captures; deriveDataKeys empties
// the capture as soon as the key block exists, used or not, and nothing else
// can reach it.

// DataKeyBlockLen is the data-channel key block every derivation produces:
// the same 256 bytes as DeriveKeyBlock (openvpn3 crypto/static_key.hpp:97,
// OpenVPNStaticKey::KEY_SIZE).
const DataKeyBlockLen = 256

// Record and handshake layer constants, RFC 5246 §6.2.1 and §7.4.
const (
	recordHeaderLen      = 5  // ContentType, ProtocolVersion, uint16 length
	recordTypeHandshake  = 22 // ContentType.handshake
	handshakeHeaderLen   = 4  // HandshakeType, uint24 length
	handshakeClientHello = 1
	handshakeServerHello = 2
	// extensionEMS is RFC 7627 §5.1's extended_master_secret. Its presence in
	// the *ServerHello* is the negotiation: a client may offer it and be
	// ignored.
	extensionEMS = 23
	// maxScanBytes bounds how much of each direction is buffered while looking
	// for the first handshake message: a peer that never completes one gets
	// the capture given up on rather than a growing buffer.
	maxScanBytes = 1 << 16
)

// Capture collects the four values an RFC 5705 export needs from a TLS 1.2
// session that crypto/tls will not export from. Two come from a KeyLogWriter,
// the only route crypto/tls offers to a TLS 1.2 master secret:
//
//	CLIENT_RANDOM <client_random_hex> <master_secret_hex>
//
// The server random is in neither the key log nor tls.ConnectionState, so it is
// read off the wire from the ServerHello, along with the fact the export
// decision turns on: whether the server negotiated Extended Master Secret.
//
// Reference: NSS key log format —
// https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
type Capture struct {
	mu sync.Mutex
	// masterSecret and keyLogRandom are one key-log line, kept together
	// because that is the only thing binding the secret to a handshake.
	masterSecret []byte
	keyLogRandom []byte
	// clientHello and serverHello reassemble each direction's first handshake
	// message from the record stream.
	clientHello handshakeScan
	serverHello handshakeScan
	// wiped records that the capture has been emptied, so that a key-log line
	// from a later handshake on the same config cannot refill it.
	wiped bool
}

// NewCapture installs a capture on cfg and returns it.
//
// An existing KeyLogWriter is chained rather than replaced: SSLKEYLOGFILE has
// its own reason to exist (tlsverify.BuildConfig) and a debugging session is
// not a reason to lose the export.
func NewCapture(cfg *tls.Config) *Capture {
	capture := &Capture{}
	capture.clientHello.want = handshakeClientHello
	capture.serverHello.want = handshakeServerHello
	if cfg.KeyLogWriter != nil {
		cfg.KeyLogWriter = io.MultiWriter(cfg.KeyLogWriter, capture)
	} else {
		cfg.KeyLogWriter = capture
	}
	return capture
}

// Write implements io.Writer so the capture can be a tls.Config.KeyLogWriter.
//
// Anything that is not a well-formed TLS 1.2 CLIENT_RANDOM line is ignored,
// including every TLS 1.3 label: a 1.3 session leaves the capture empty, whose
// export crypto/tls always performs itself.
func (capture *Capture) Write(p []byte) (int, error) {
	fields := strings.Fields(strings.TrimSpace(string(p)))
	if len(fields) != 3 || fields[0] != "CLIENT_RANDOM" {
		return len(p), nil
	}
	random, errRandom := hex.DecodeString(fields[1])
	secret, errSecret := hex.DecodeString(fields[2])
	if errRandom != nil || errSecret != nil {
		return len(p), nil
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.wiped {
		return len(p), nil
	}
	capture.keyLogRandom = random
	capture.masterSecret = secret
	return len(p), nil
}

// Wrap returns conn with the capture reading the handshake bytes that cross
// it. Only the first handshake message of each direction is looked at, so
// after both have been seen the wrapper is a pass-through.
func (capture *Capture) Wrap(conn net.Conn) net.Conn {
	return &handshakeTap{Conn: conn, capture: capture}
}

// handshakeTap is the net.Conn crypto/tls is given, so that the ServerHello
// can be read on its way past. The embedded Conn carries every other method,
// deadlines included — tlsHandshake sets one.
type handshakeTap struct {
	net.Conn
	capture *Capture
}

// Read implements net.Conn.
func (t *handshakeTap) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.capture.mu.Lock()
		t.capture.serverHello.feed(b[:n])
		t.capture.mu.Unlock()
	}
	return n, err
}

// Write implements net.Conn.
func (t *handshakeTap) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	if n > 0 {
		t.capture.mu.Lock()
		t.capture.clientHello.feed(b[:n])
		t.capture.mu.Unlock()
	}
	return n, err
}

// handshakeScan reassembles one direction's first TLS handshake message out of
// the record stream, and stops wanting bytes as soon as it has it — or as soon
// as it can tell it never will. A hello can be split across records and a
// record can hold several messages, so neither layer's boundaries line up with
// the reads and writes that carry them.
type handshakeScan struct {
	want uint8  // the message type this direction's first message must be
	rec  []byte // record-layer bytes not yet split into messages
	body []byte // handshake-message bytes reassembled from record payloads
	msg  []byte // the complete message body, once there is one
	done bool   // nothing further is wanted from this direction
}

// feed absorbs bytes as they cross the connection.
func (s *handshakeScan) feed(p []byte) {
	if s.done {
		return
	}
	s.rec = append(s.rec, p...)
	defer func() {
		// The budget applies to what is left over — an incomplete record or
		// message — rather than to the bytes on the way in: a single read can
		// deliver more than one 16 KiB record, and aborting on the size of a
		// read would abort on a hello sitting at the front of it.
		if !s.done && len(s.rec)+len(s.body) > maxScanBytes {
			s.stop()
		}
	}()
	for !s.done {
		if len(s.rec) < recordHeaderLen {
			return
		}
		// The message wanted here is the first thing either peer sends, so it
		// is in a plaintext handshake record or it is nowhere: any other
		// content type means this stream has nothing to offer and waiting for
		// more of it is waiting forever.
		if s.rec[0] != recordTypeHandshake {
			s.stop()
			return
		}
		length := int(binary.BigEndian.Uint16(s.rec[3:recordHeaderLen]))
		if len(s.rec) < recordHeaderLen+length {
			return
		}
		s.body = append(s.body, s.rec[recordHeaderLen:recordHeaderLen+length]...)
		s.rec = s.rec[recordHeaderLen+length:]
		s.take()
	}
}

// take moves the first complete handshake message out of the reassembly
// buffer, or gives up when the buffer proves it will never hold the wanted
// one.
func (s *handshakeScan) take() {
	if len(s.body) < handshakeHeaderLen {
		return
	}
	if s.body[0] != s.want {
		s.stop()
		return
	}
	length := int(s.body[1])<<16 | int(s.body[2])<<8 | int(s.body[3])
	if handshakeHeaderLen+length > maxScanBytes {
		s.stop()
		return
	}
	if len(s.body) < handshakeHeaderLen+length {
		return
	}
	// Copied out, because the buffers it came from are released here and a
	// sub-slice of them would keep the whole reassembly alive.
	s.msg = append([]byte(nil), s.body[handshakeHeaderLen:handshakeHeaderLen+length]...)
	s.stop()
}

// stop releases the reassembly buffers and closes the scan to further bytes.
func (s *handshakeScan) stop() {
	s.rec = nil
	s.body = nil
	s.done = true
}

// helloRandom returns the 32-byte random of a ClientHello or ServerHello body.
// Both begin with a 2-byte version followed by it (RFC 5246 §7.4.1.2, §7.4.1.3).
func helloRandom(msg []byte) ([]byte, bool) {
	const versionLen = 2
	if len(msg) < versionLen+32 {
		return nil, false
	}
	return msg[versionLen : versionLen+32], true
}

// serverHelloNegotiatedEMS reports whether a ServerHello body carries the
// extended_master_secret extension, and whether the body could be parsed at
// all.
//
// The distinction matters: "no EMS extension" is the fact the export decision
// turns on, and "this ServerHello did not parse" must never be read as it.
func serverHelloNegotiatedEMS(msg []byte) (present, parsed bool) {
	// version, random, session_id, cipher_suite, compression_method, then the
	// optional extension block (RFC 5246 §7.4.1.3).
	const fixed = 2 + 32
	if len(msg) < fixed+1 {
		return false, false
	}
	rest := msg[fixed:]
	sessionIDLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < sessionIDLen+3 {
		return false, false
	}
	rest = rest[sessionIDLen+3:] // cipher_suite (2) and compression_method (1)
	if len(rest) == 0 {
		// A ServerHello with no extension block at all is well formed, and
		// negotiates no EMS.
		return false, true
	}
	if len(rest) < 2 {
		return false, false
	}
	if int(binary.BigEndian.Uint16(rest)) != len(rest)-2 {
		return false, false
	}
	rest = rest[2:]
	for len(rest) > 0 {
		if len(rest) < 4 {
			return false, false
		}
		extType := binary.BigEndian.Uint16(rest)
		extLen := int(binary.BigEndian.Uint16(rest[2:]))
		rest = rest[4:]
		if len(rest) < extLen {
			return false, false
		}
		if extType == extensionEMS {
			return true, true
		}
		rest = rest[extLen:]
	}
	return false, true
}

// EMSRefusal reports whether Go's refusal to export is the one this file
// exists for: a TLS 1.2 session whose ServerHello negotiated no Extended
// Master Secret.
//
// It is decided from the wire rather than from the error crypto/tls returned:
// that error is an unexported errors.New whose wording is not API, and Go
// refuses export for a second reason as well — a Config with renegotiation
// enabled — which this must not mistake for the EMS case. A nil capture answers
// false, because a handshake with no capture installed has nothing to export
// from and that is a caller mistake rather than an export failure.
func (capture *Capture) EMSRefusal(cs tls.ConnectionState) bool {
	if capture == nil || cs.Version != tls.VersionTLS12 {
		return false
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	present, parsed := serverHelloNegotiatedEMS(capture.serverHello.msg)
	return parsed && !present
}

// ExportKeyingMaterial performs the RFC 5705 export crypto/tls declined, over
// the captured session material.
func (capture *Capture) ExportKeyingMaterial(cs tls.ConnectionState, label string, n int) ([]byte, error) {
	if capture == nil {
		return nil, fmt.Errorf("no TLS secret capture was installed for this handshake")
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.wiped {
		return nil, fmt.Errorf("the TLS secret capture was already emptied")
	}
	if len(capture.masterSecret) == 0 {
		return nil, fmt.Errorf("no CLIENT_RANDOM key-log line was written for this handshake")
	}
	clientRandom, ok := helloRandom(capture.clientHello.msg)
	if !ok {
		return nil, fmt.Errorf("the ClientHello of this handshake was not captured")
	}
	serverRandom, ok := helloRandom(capture.serverHello.msg)
	if !ok {
		return nil, fmt.Errorf("the ServerHello of this handshake was not captured")
	}
	// The secret comes from the key log and the randoms from the wire, so this
	// is the one place the two can be checked to be one handshake's. A mismatch
	// — a renegotiated session, or a capture that outlived the handshake it was
	// installed for — would derive 256 well-formed bytes the peer disagrees
	// with, surfacing as a data channel that carries nothing, not as an error.
	if !bytes.Equal(clientRandom, capture.keyLogRandom) {
		return nil, fmt.Errorf("the key-log client random does not match the ClientHello on the wire, " +
			"so the capture holds material from two different handshakes")
	}
	return ExportKeyingMaterialTLS12(TLS12Session{
		Version:      cs.Version,
		CipherSuite:  cs.CipherSuite,
		MasterSecret: capture.masterSecret,
		ClientRandom: clientRandom,
		ServerRandom: serverRandom,
	}, label, n)
}

// Wipe empties the capture, once the key block exists and whether the capture
// was used or not. The master secret is zeroed rather than dropped: releasing
// it to the collector leaves the bytes in a freed block for as long as that
// block goes unreused, in a library driven thousands of times in one process.
func (capture *Capture) Wipe() {
	if capture == nil {
		return
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	for i := range capture.masterSecret {
		capture.masterSecret[i] = 0
	}
	capture.masterSecret = nil
	capture.keyLogRandom = nil
	capture.clientHello.stop()
	capture.serverHello.stop()
	capture.clientHello.msg = nil
	capture.serverHello.msg = nil
	capture.wiped = true
}

// Wiped reports whether Wipe has emptied this capture.
//
// It exists so a caller can assert its own teardown ran: the master secret must
// not outlive the session that produced it, and the code guaranteeing that is
// the caller's.
func (capture *Capture) Wiped() bool {
	if capture == nil {
		return true
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.wiped
}

// ExportDataChannelKeys produces the key block the pushed tls-ekm derivation
// asks for: from crypto/tls wherever crypto/tls will produce it, and from the
// captured session material on the one combination where it refuses. Every
// other path — TLS 1.3, TLS 1.2 with Extended Master Secret, and the classic
// derivation, which does not come through here at all — is still Go's.
func ExportDataChannelKeys(cs tls.ConnectionState, capture *Capture) (keys []byte, usedFallback bool, err error) {
	keyMat, err := cs.ExportKeyingMaterial(ExporterLabel, nil, DataKeyBlockLen)
	if err == nil {
		return keyMat, false, nil
	}
	if !capture.EMSRefusal(cs) {
		return nil, false, err
	}

	// Go refuses this export because RFC 5705 keying material without RFC 7627
	// Extended Master Secret is what the triple-handshake attack exploits: two
	// TLS 1.2 sessions can be steered into sharing a master secret, so anything
	// exported from one of them fails to identify the session it came from.
	//
	// What bounds it: it happens only where the peer asked for this derivation
	// and its own session cannot safely support it, the control channel is
	// authenticated against the profile's CA either way, and the report records
	// every session derived this way — so it is a measurable property of an
	// endpoint, not a silent weakening of every connection.
	fallback, exportErr := capture.ExportKeyingMaterial(cs, ExporterLabel, DataKeyBlockLen)
	if exportErr != nil {
		return nil, false, fmt.Errorf("%w; and no export from captured material either: %w", err, exportErr)
	}
	return fallback, true, nil
}
