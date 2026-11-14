// SPDX-License-Identifier: LGPL-2.1-or-later

package mssfix

import "testing"

// TestMaxMSSMatchesTheReferenceArithmetic works the reference's own sum by
// hand for each shape, because the value is a number and the only way to be
// wrong about a number is to compute a different one.
//
// mssfix is a link budget: the size of the whole encapsulated packet. Applying
// it as an MSS clamps `mssfix 1400` to 1400 where the reference derives 1308
// for AES-GCM over UDP with a peer-id, and every full segment then fragments
// on the path the directive exists to avoid.
//
// Reference: openvpn-2.6.22 src/openvpn/mss.c:286-332, mtu.c:70-104,
// crypto.c:670-716.
func TestMaxMSSMatchesTheReferenceArithmetic(t *testing.T) {
	gcm := Overhead{PeerID: true, AEAD: true, TagLen: 16, EncapCounted: true}
	cbcSHA1 := Overhead{PeerID: true, IVLen: 16, DigestLen: 20, BlockLen: 16, EncapCounted: true}

	for _, tc := range []struct {
		name   string
		budget int
		o      Overhead
		want   int
	}{
		// 1400 - (4 opcode+peerid + 4 pktid + 16 tag + 20 IPv4 + 8 UDP) = 1348
		// 1348 - (20 + 20) = 1308
		{"gcm/udp/v2", 1400, gcm, 1308},

		// IPv6 outer costs 20 more.
		{"gcm/udp6/v2", 1400, func() Overhead { o := gcm; o.OuterIPv6 = true; return o }(), 1288},

		// TCP: +2 length prefix and +20 outer TCP instead of +8 UDP.
		{"gcm/tcp/v2", 1400, func() Overhead { o := gcm; o.TCPTransport = true; return o }(), 1294},

		// P_DATA_V1 saves three bytes of opcode.
		{"gcm/udp/v1", 1400, func() Overhead { o := gcm; o.PeerID = false; return o }(), 1311},

		// A compression framing byte comes off every payload.
		{"gcm/udp/v2/comp", 1400, func() Overhead { o := gcm; o.CompressionFraming = true; return o }(), 1307},

		// CBC+SHA1: 1400 - (4 + 16 IV + 20 HMAC + 20 + 8) = 1332, rounded down
		// to 1328 whole blocks, less one byte reserved for padding = 1327,
		// less the 4-byte packet id it encrypts = 1323, less 40 = 1283.
		//
		// That padding byte is not optional. PKCS#7 always pads, so a payload
		// that comes out a whole number of blocks is padded by a further
		// complete block: at 1284 the plaintext is exactly 1328 and the
		// ciphertext 1344, which puts the datagram 16 bytes over the budget.
		{"cbc-sha1/udp/v2", 1400, cbcSHA1, 1283},

		// A budget smaller than its own overhead yields no usable MSS rather
		// than a negative one.
		{"absurdly small", 40, gcm, 0},
	} {
		if got := MaxMSS(tc.budget, tc.o); got != tc.want {
			t.Errorf("%s: MaxMSS(%d) = %d, want %d", tc.name, tc.budget, got, tc.want)
		}
	}
}

// TestMaxMSSLeavesRoomForCBCPadding is the property the pinned numbers above
// only sample: a full-sized segment, once the packet id is prepended and PKCS#7
// has padded the result to whole blocks, must still fit the budget it was
// derived from. A rounding that forgets padding always adds a complete block
// rather than a byte, so this fails by a whole block when it fails at all.
func TestMaxMSSLeavesRoomForCBCPadding(t *testing.T) {
	for _, budget := range []int{1200, 1300, 1400, 1401, 1402, 1440, 1492, 1500} {
		for _, digest := range []struct {
			name string
			size int
		}{{"SHA1", 20}, {"SHA256", 32}} {
			o := Overhead{
				PeerID:       true,
				IVLen:        16,
				BlockLen:     16,
				DigestLen:    digest.size,
				EncapCounted: true, // the datagram below counts the outer headers
			}
			mss := MaxMSS(budget, o)
			if mss <= 0 {
				continue
			}

			// What the peer will actually put on the wire for that MSS.
			plaintext := packetIDLen + innerIPv4Header + innerTCPHeader + mss
			ciphertext := ((plaintext / o.BlockLen) + 1) * o.BlockLen // PKCS#7 always pads
			datagram := opcodeV2 + o.IVLen + o.DigestLen + ciphertext +
				outerIPv4Header + outerUDPHeader

			if datagram > budget {
				t.Errorf("budget %d, %s: MSS %d yields a %d-byte datagram, %d over",
					budget, digest.name, mss, datagram, datagram-budget)
			}
		}
	}
}
