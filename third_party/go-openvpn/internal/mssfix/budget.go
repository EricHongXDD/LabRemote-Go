// SPDX-License-Identifier: LGPL-2.1-or-later

package mssfix

// Overhead is everything between a TCP payload byte and the wire, for one
// negotiated tunnel. It is the input to MaxMSS.
//
// Reference: openvpn-2.6.22 src/openvpn/mss.c:286-332 (frame_calculate_mssfix),
// mtu.c:70-104 (frame_calculate_protocol_header_size) and crypto.c:670-716
// (calculate_crypto_overhead), with occ=false throughout — the OCC variant
// counts bytes that are not on the wire.
type Overhead struct {
	// TCPTransport is true when the OpenVPN link runs over TCP, which adds
	// the two-byte length prefix (mtu.c:88-91).
	TCPTransport bool
	// PeerID is true for P_DATA_V2, whose opcode and peer-id are four bytes
	// rather than one (mtu.c:94-97).
	PeerID bool
	// AEAD selects the AEAD arithmetic: the packet id is not part of the
	// encrypted payload, and the tag is added (crypto.c:676-688).
	AEAD bool
	// TagLen is the AEAD tag length in bytes, when AEAD.
	TagLen int
	// IVLen is the CBC initialisation vector length in bytes, when not AEAD.
	IVLen int
	// DigestLen is the CBC HMAC length in bytes, when not AEAD.
	DigestLen int
	// BlockLen is the CBC block size, used to round the payload down to a
	// whole number of blocks. Zero for AEAD, which is a stream construction.
	BlockLen int
	// CompressionFraming is true when a one-byte compression header rides on
	// every payload (crypto.c/mtu.c:119-128).
	CompressionFraming bool
	// OuterIPv6 is true when the transport socket is IPv6, whose header is
	// 20 bytes larger than IPv4's.
	OuterIPv6 bool
	// EncapCounted is true when the mssfix budget is meant to include the
	// outer IP and transport headers, which is OpenVPN's default
	// (`mssfix N` without `mtu`). mss.c:313-317.
	EncapCounted bool
}

// Fixed sizes the reference names inline.
const (
	tcpLengthPrefix = 2
	opcodeV1        = 1
	opcodeV2        = 4
	packetIDLen     = 4
	innerIPv4Header = 20
	innerTCPHeader  = 20
	// innerIPv6Extra is how much longer an IPv6 header is than an IPv4 one.
	// MaxMSS returns an IPv4 allowance and Clamp takes this off for a v6
	// payload, which is the split the reference uses.
	innerIPv6Extra  = 20
	outerIPv4Header = 20
	outerIPv6Header = 40
	outerUDPHeader  = 8
	outerTCPHeader  = 20
	compressionByte = 1
)

// MaxMSS returns the TCP MSS a SYN may advertise so that the resulting
// encapsulated packet fits in budget bytes.
//
// budget is the `mssfix` value, and it is a *link* budget — the size of the
// whole encapsulated packet — not an MSS: `mssfix 1400` derives 1308 for
// AES-GCM over UDP with a peer-id, not 1400. The result is the allowance for an
// IPv4 payload; Clamp takes off the 20 bytes an IPv6 header costs on top, which
// is where the reference applies it too (mss.c:133).
func MaxMSS(budget int, o Overhead) int {
	if budget <= 0 {
		return 0
	}

	overhead := 0
	if o.TCPTransport {
		overhead += tcpLengthPrefix
	}
	if o.PeerID {
		overhead += opcodeV2
	} else {
		overhead += opcodeV1
	}
	if o.AEAD {
		// Not CBC, so the packet id sits outside the encrypted payload and
		// counts as header; the tag is the rest.
		overhead += packetIDLen + o.TagLen
	} else {
		overhead += o.IVLen + o.DigestLen
	}
	if o.EncapCounted {
		if o.OuterIPv6 {
			overhead += outerIPv6Header
		} else {
			overhead += outerIPv4Header
		}
		if o.TCPTransport {
			overhead += outerTCPHeader
		} else {
			overhead += outerUDPHeader
		}
	}

	target := budget - overhead
	if target <= 0 {
		return 0
	}

	// CBC carries whole blocks and encrypts the packet id with the payload.
	// Round down, then give up one more byte: PKCS#7 always pads, so a
	// payload that is already a whole number of blocks gains a further
	// complete block. The reference reserves that byte in
	// adjust_payload_max_cbc (openvpn-2.6.22 src/openvpn/mss.c:210-227) and
	// charges the packet id in frame_calculate_payload_overhead
	// (mtu.c:137-143).
	if !o.AEAD && o.BlockLen > 0 {
		target = (target/o.BlockLen)*o.BlockLen - 1 - packetIDLen
	}

	payloadOverhead := innerIPv4Header + innerTCPHeader
	if o.CompressionFraming {
		payloadOverhead += compressionByte
	}

	if mss := target - payloadOverhead; mss > 0 {
		return mss
	}
	return 0
}
