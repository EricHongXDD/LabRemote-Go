// SPDX-License-Identifier: LGPL-2.1-or-later
//
// authpacket.go: the packet itself, in both framings — what the client writes
// after the TLS handshake and what it reads back.

package keymethod2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/buengese/go-openvpn/internal/prf"
)

// Framing selects the wire format of the key-method-2 auth packet. It is a
// property of the peer being authenticated to, not of the client, so it
// belongs to whatever decides how to authenticate. A peer that is sent the
// packet in the other shape answers AUTH_FAILED.
type Framing int

const (
	// FramingStock is stock OpenVPN's format: a zero prefix and uint16_be
	// string lengths. It is the zero value because it is what an unpatched
	// server speaks, which is every server but one kind.
	FramingStock Framing = iota
	// FramingAWSLargeToken is AWS Client VPN's patched format: a uint32_le
	// total length followed by uint32_be string lengths. A SAML assertion
	// does not fit the uint16 prefix stock OpenVPN uses, which is why the
	// patch exists.
	FramingAWSLargeToken
)

// String names the framing for a log line or a report.
func (f Framing) String() string {
	if f == FramingAWSLargeToken {
		return "aws-large-token"
	}
	return "stock"
}

// SendAuth sends the OpenVPN key-method-2 auth packet over the TLS
// connection immediately after the TLS handshake completes. ivProto is the
// value the peer-info block advertises; see PeerInfo, and see Framing for
// which of the two wire formats below applies.
//
// Wire format — FramingAWSLargeToken (key_method_2_write patch in AWS ssl.c):
//
//	[total_len uint32_le]         first 4 bytes = total packet length (LE)
//	[0x02]                        key_method byte
//	[pre_master 48B][random1 32B][random2 32B]   112 bytes client TLSPRF
//	[uint32_be(len+1)][options\0]
//	[uint32_be(len+1)][username\0]
//	[uint32_be(len+1)][password\0]
//	[uint32_be(len+1)][peer_info\0]
//
// Wire format — FramingStock:
//
//	[0x00 0x00 0x00 0x00]         literal zero prefix (key_method_2 legacy header)
//	[0x02]                        key_method byte
//	[pre_master 48B][random1 32B][random2 32B]   112 bytes client TLSPRF
//	[uint16_be(len+1)][options\0]
//	[uint16_be(len+1)][username\0]
//	[uint16_be(len+1)][password\0]
//	[uint16_be(len+1)][peer_info\0]
func SendAuth(w io.Writer, params TunnelParams, username, password string, framing Framing, ivProto uint32) (prf.KeySource, error) {
	optionsStr := TunnelOptions(params)
	peerInfoBlock := PeerInfo(ivProto)

	// TLSPRF client data: pre_master (48B) + random1 (32B) + random2 (32B).
	rnd := make([]byte, clientKeySourceLen)
	if _, err := rand.Read(rnd); err != nil {
		return prf.KeySource{}, fmt.Errorf("SendAuth: rand: %w", err)
	}
	// Keep what is about to be sent. The classic derivation consumes it after
	// PUSH_REPLY, so these bytes have to outlive the packet; the caller retains
	// the result and reset clears it. Copies, because rnd is emptied below —
	// it is the pre-master secret, and it has no more use here once cloned.
	ks := prf.KeySource{
		PreMaster: bytes.Clone(rnd[0:preMasterLen]),
		Random1:   bytes.Clone(rnd[preMasterLen : preMasterLen+randomLen]),
		Random2:   bytes.Clone(rnd[preMasterLen+randomLen:]),
	}
	defer clear(rnd)

	// One buffer, sized before anything is written into it, and zeroed on
	// every return: the packet holds the credential, and appending into a
	// growing slice orphans an uncleared copy of it every time the backing
	// array is replaced (docs/security-architecture.md).
	//
	// The length is fixed rather than a pre-sized append target on purpose. A
	// wrong size then produces a wrong-length packet, which
	// TestSendAuthPacketIsByteExact fails on, instead of a quiet reallocation
	// that orphans the credential.
	prefixLen := stockFieldPrefixLen
	if framing == FramingAWSLargeToken {
		prefixLen = awsFieldPrefixLen
	}
	// fieldLen and putField below must agree; they are written next to each
	// other for that reason.
	fieldLen := func(s string) int {
		if len(s) == 0 {
			return prefixLen
		}
		return prefixLen + len(s) + 1 // the declared length counts the NUL
	}
	total := authHeaderLen + 1 + clientKeySourceLen +
		fieldLen(optionsStr) + fieldLen(username) +
		fieldLen(password) + fieldLen(peerInfoBlock)

	packet := make([]byte, total)
	defer func() { clear(packet) }()

	// Header. Stock is a literal four-byte zero prefix, which make has already
	// written; AWS carries the total length, counting the prefix itself.
	if framing == FramingAWSLargeToken {
		binary.LittleEndian.PutUint32(packet[:authHeaderLen], uint32(total))
	}
	n := authHeaderLen
	packet[n] = 0x02 // key_method
	n++
	n += copy(packet[n:], rnd)

	putField := func(s string) {
		if len(s) == 0 {
			// A length of zero and no bytes at all, which the zeroed buffer
			// already holds. write_empty_string is a bare u16(0)
			// (openvpn-2.6.22 src/openvpn/ssl.c:1952-1959), and it is what the
			// reference sends for a cert-only profile's username and password
			// (ssl.c:2305-2314). u16(1)+NUL says "present, and empty", a
			// different statement from "absent" and one a server is entitled
			// to treat differently. The AWS framing follows the same rule with
			// a four-byte prefix.
			n += prefixLen
			return
		}
		declared := len(s) + 1
		if framing == FramingAWSLargeToken {
			binary.BigEndian.PutUint32(packet[n:], uint32(declared))
		} else {
			binary.BigEndian.PutUint16(packet[n:], uint16(declared))
		}
		n += prefixLen
		n += copy(packet[n:], s)
		n++ // the NUL, already zero
	}
	putField(optionsStr)
	putField(username)
	putField(password)
	putField(peerInfoBlock)

	_, err := w.Write(packet)
	return ks, err
}

// Auth-packet framing widths. The header is four bytes in both framings — a
// literal zero prefix for stock, a uint32_le total length for AWS — and the
// per-field length prefix is what the two actually differ by.
const (
	authHeaderLen       = 4
	stockFieldPrefixLen = 2
	awsFieldPrefixLen   = 4
)

// Key-method-2 material sizes. The client contributes a pre-master and two
// randoms; the server contributes the two randoms alone, because only the
// client generates a pre-master (OpenVPN 2.4 src/openvpn/ssl.c,
// key_source2_randomize_write()).
const (
	// preMasterLen is the client pre-master secret, stage one's secret.
	preMasterLen = 48
	// randomLen is one peer random. random1 seeds stage one, random2 stage two.
	randomLen = 32
	// clientKeySourceLen is what SendAuth generates: 48 + 32 + 32.
	clientKeySourceLen = preMasterLen + 2*randomLen
	// serverKeySourceLen is what the server sends: 32 + 32.
	serverKeySourceLen = 2 * randomLen
)

// serverAuthMaxStringLen bounds one length-prefixed string in a server auth
// packet — options, username, password or peer_info. The AWS large-token
// format exists precisely because SAML assertions outgrow the stock uint16
// field, so the bound is generous; it is here so that a hostile or confused
// peer cannot make this allocate arbitrarily.
//
// Only the AWS framing can reach it, and that asymmetry is why
// readServerAuthString consults it *before* the allocation rather than leaning
// on the short read that is bound to follow. A stock uint16_be prefix cannot
// declare more than 65535, sixteen times under the bound, so there the framing
// is its own limit; an AWS uint32_be prefix can declare four gigabytes inside
// a packet whose declared total length is at most one megabyte, and the short
// read comes only after everything the peer asked for has been allocated.
const serverAuthMaxStringLen = 1 << 20

// awsServerAuthMinLen is the smallest uint32_le header value that is read as a
// total length rather than as the stock four-byte zero prefix. A key-method-2
// server packet is at least key_method(1) + randoms(64) + four length-prefixed
// strings, so anything shorter cannot be an AWS-framed total length, and the
// stock prefix decodes as zero.
const awsServerAuthMinLen = 85

// ConsumeServerAuth reads the server's key-method-2 auth packet, which
// arrives over TLS immediately after the handshake, and returns the server's
// key material and its own options string.
//
// The key source is the point of parsing rather than draining: those 64 bytes
// are half the input to the classic key derivation. The options string is the
// other point — it carries the deployment's link-mtu, cipher, auth and
// key-method, and is the best available fingerprint of what a server runs.
//
// Stock OpenVPN CE framing:
//
//	[0x00 0x00 0x00 0x00]         literal zero prefix
//	[0x02]                        key_method byte
//	[random1 32B][random2 32B]    64 bytes server TLSPRF
//	[uint16_be(len+1)][options\0][username\0-block][password\0-block][peer_info\0-block]
//
// Some AWS deployments use the large-token patched format, which prefixes the
// packet with its total length as uint32_le and widens the string prefixes to
// uint32_be. Both are tolerated and auto-detected from the 4-byte header: a
// plausible LE total length means AWS framing, anything else is the stock zero
// prefix.
//
// Every field is read for its declared length rather than drained into a
// scratch buffer, so the stream is left on the first byte of the next control
// message. A truncated packet is an error, which every caller maps to
// diag.ClassProtocol at diag.StageAuth; the options string is returned
// alongside it where it was read successfully, so a report keeps the
// fingerprint of a server that misframes something after it.
func ConsumeServerAuth(r io.Reader) (ks prf.KeySource, serverOpts string, err error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return ks, "", fmt.Errorf("ConsumeServerAuth: read header: %w", err)
	}
	totalLen := int(binary.LittleEndian.Uint32(hdr))

	prefixLen := 2
	body := r
	if totalLen >= awsServerAuthMinLen && totalLen <= 1<<20 {
		// AWS large-token patched format: hdr is uint32_le total length, and
		// the string prefixes widen to uint32_be. The declared length bounds
		// the read, so the packet cannot run into the next control message
		// even if a field inside it is misframed.
		prefixLen = 4
		buf := make([]byte, totalLen-4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return ks, "", fmt.Errorf("ConsumeServerAuth: read body: %w", err)
		}
		body = bytes.NewReader(buf)
	}

	km := make([]byte, 1)
	if _, err := io.ReadFull(body, km); err != nil {
		return ks, "", fmt.Errorf("ConsumeServerAuth: read key_method: %w", err)
	}
	if km[0] != 0x02 {
		return ks, "", fmt.Errorf("ConsumeServerAuth: unexpected key_method byte 0x%02x", km[0])
	}

	randoms := make([]byte, serverKeySourceLen)
	if _, err := io.ReadFull(body, randoms); err != nil {
		return ks, "", fmt.Errorf("ConsumeServerAuth: read server randoms: %w", err)
	}
	// PreMaster stays nil: the server does not generate one, and
	// prf.DeriveMasterSecret rejects a server key source that carries one.
	ks = prf.KeySource{
		Random1: bytes.Clone(randoms[0:randomLen]),
		Random2: bytes.Clone(randoms[randomLen:serverKeySourceLen]),
	}

	// The four length-prefixed strings: options, username, password,
	// peer_info. Only the first is wanted, but all four are consumed so the
	// stream is left at the start of the next control message. A short read
	// means the packet was truncated, and continuing from an unknown stream
	// position is worse than failing here.
	for i, field := range []string{"options", "username", "password", "peer_info"} {
		s, err := readServerAuthString(body, prefixLen)
		if err != nil {
			return ks, serverOpts, fmt.Errorf(
				"ConsumeServerAuth: read %s (string %d of 4): %w", field, i+1, err)
		}
		if i == 0 {
			serverOpts = s
		}
	}
	return ks, serverOpts, nil
}

// readServerAuthString reads one length-prefixed, NUL-terminated string from a
// server key-method-2 packet.
//
// prefixLen is 2 for the stock uint16_be framing and 4 for the AWS uint32_be
// one. The declared length includes the trailing NUL, which is stripped. An
// empty string arrives either as a zero length or as a length of 1 holding
// only the NUL; both yield "".
func readServerAuthString(r io.Reader, prefixLen int) (string, error) {
	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return "", fmt.Errorf("read length prefix: %w", err)
	}
	var declared int
	switch prefixLen {
	case 2:
		declared = int(binary.BigEndian.Uint16(prefix))
	case 4:
		declared = int(binary.BigEndian.Uint32(prefix))
	default:
		return "", fmt.Errorf("unsupported length prefix width %d", prefixLen)
	}
	if declared == 0 {
		return "", nil
	}
	if declared > serverAuthMaxStringLen {
		return "", fmt.Errorf("declared length %d exceeds the %d-byte bound",
			declared, serverAuthMaxStringLen)
	}
	buf := make([]byte, declared)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read %d declared bytes: %w", declared, err)
	}
	// declared counts the NUL terminator; the text is one byte shorter.
	return string(buf[:declared-1]), nil
}
