package mssfix_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/buengese/go-openvpn/internal/mssfix"
)

// buildSYN4 constructs a minimal IPv4 TCP SYN packet with an MSS option.
func buildSYN4(mssVal uint16) []byte {
	// IPv4 header (20) + TCP header (24: 20 fixed + 4 MSS option)
	pkt := make([]byte, 44)
	pkt[0] = 0x45 // version=4, IHL=5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], 44)
	pkt[9] = 6 // TCP
	// src 10.0.0.1, dst 10.0.0.2
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	// TCP: data offset=6 (24 bytes), SYN flag
	tcp := pkt[20:]
	tcp[12] = 0x60 // data offset = 6 (6*4=24)
	tcp[13] = 0x02 // SYN
	// MSS option: kind=2, length=4, value
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mssVal)
	// Compute checksums
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))
	writeTCPChecksum4(pkt, 20)
	return pkt
}

func ipChecksum(hdr []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		s += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func writeTCPChecksum4(pkt []byte, ihl int) {
	tcp := pkt[ihl:]
	tcpLen := len(pkt) - ihl
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], vecChecksum(pseudo, tcp))
}

func vecChecksum(a, b []byte) uint16 {
	var s uint32
	add := func(buf []byte) {
		for i := 0; i+1 < len(buf); i += 2 {
			s += uint32(binary.BigEndian.Uint16(buf[i:]))
		}
		if len(buf)%2 != 0 {
			s += uint32(buf[len(buf)-1]) << 8
		}
	}
	add(a)
	add(b)
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func mssOf(pkt []byte) uint16 {
	ihl := int(pkt[0]&0x0f) * 4
	tcp := pkt[ihl:]
	doff := int(tcp[12]>>4) * 4
	opts := tcp[20:doff]
	for i := 0; i < len(opts); {
		if opts[i] == 0 {
			break
		}
		if opts[i] == 1 {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if opts[i] == 2 && l == 4 {
			return binary.BigEndian.Uint16(opts[i+2:])
		}
		i += l
	}
	return 0
}

// TestClamp covers the four decisions Clamp makes about a packet: lower an
// oversized MSS, leave a smaller one alone, ignore anything that is not a SYN,
// and do nothing at all when no maximum is configured.
func TestClamp(t *testing.T) {
	cases := []struct {
		name string
		pkt  func() []byte
		// maxMSS is the clamp; wantMSS the option value afterwards.
		maxMSS  int
		wantMSS uint16
		// wantUnchanged demands the packet be byte-identical afterwards, not
		// merely to carry the same MSS: a rewrite that lands on the same value
		// still recomputes checksums over a packet nobody asked us to touch.
		wantUnchanged bool
		why           string
	}{
		{
			name: "an oversized MSS is lowered", pkt: func() []byte { return buildSYN4(1460) },
			maxMSS: 1350, wantMSS: 1350,
			why: "1460 is above the configured maximum",
		},
		{
			name: "a smaller MSS is left where it is", pkt: func() []byte { return buildSYN4(1200) },
			maxMSS: 1350, wantMSS: 1200,
			why: "clamping must never raise an MSS",
		},
		{
			name: "a non-SYN packet is untouched",
			pkt: func() []byte {
				pkt := buildSYN4(1460)
				pkt[20+13] = 0x10 // ACK, not SYN
				return pkt
			},
			maxMSS: 1000, wantMSS: 1460, wantUnchanged: true,
			why: "option 2 only means MSS in a SYN",
		},
		{
			name: "a zero maximum is a no-op", pkt: func() []byte { return buildSYN4(1460) },
			maxMSS: 0, wantMSS: 1460, wantUnchanged: true,
			why: "mssfix unset must not rewrite anything",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := tc.pkt()
			before := append([]byte(nil), pkt...)

			mssfix.Clamp(pkt, tc.maxMSS)

			if got := mssOf(pkt); got != tc.wantMSS {
				t.Fatalf("MSS = %d, want %d — %s", got, tc.wantMSS, tc.why)
			}
			if tc.wantUnchanged && !bytes.Equal(pkt, before) {
				t.Errorf("the packet was rewritten — %s", tc.why)
			}
		})
	}
}

// buildSYN6 constructs a minimal IPv6 TCP SYN packet with an MSS option:
// IPv6 header (40) + TCP header (24 with the option).
func buildSYN6(mssVal uint16) []byte {
	pkt := make([]byte, 64)
	pkt[0] = 0x60
	pkt[6] = 6 // TCP next header
	tcp := pkt[40:]
	tcp[12] = 0x60 // data offset = 6 (24 bytes)
	tcp[13] = 0x02 // SYN
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], mssVal)
	return pkt
}

// mss6Of reads the MSS option out of the packet buildSYN6 builds. It is not
// mssOf: that one takes the header length from the IPv4 IHL nibble, which an
// IPv6 packet does not have.
func mss6Of(pkt []byte) uint16 {
	return binary.BigEndian.Uint16(pkt[40+22 : 40+24])
}

// TestClampChargesIPv6ForItsLongerHeader pins the one allowance Clamp applies
// itself. Callers derive a single MSS for an IPv4 payload; an IPv6 header is
// 20 bytes longer, so a v6 SYN must be clamped 20 lower from the same number.
// Passing one value to both families puts 20 bytes back on the wire, which is
// the whole reason this test names both versions.
func TestClampChargesIPv6ForItsLongerHeader(t *testing.T) {
	cases := []struct {
		name    string
		pkt     func() []byte
		mssOf   func([]byte) uint16
		maxMSS  int
		wantMSS uint16
	}{
		{"IPv4", func() []byte { return buildSYN4(1460) }, mssOf, 1400, 1400},
		{"IPv6", func() []byte { return buildSYN6(1460) }, mss6Of, 1400, 1380},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := tc.pkt()
			mssfix.Clamp(pkt, tc.maxMSS)
			if got := tc.mssOf(pkt); got != tc.wantMSS {
				t.Fatalf("MSS after clamping to %d = %d, want %d", tc.maxMSS, got, tc.wantMSS)
			}
		})
	}
}

func TestClampKeepsChecksumsValid(t *testing.T) {
	pkt := buildSYN4(1460)
	mssfix.Clamp(pkt, 1300)
	// IP checksum
	if ipChecksum(pkt[:20]) != 0 {
		t.Fatal("IP checksum invalid after clamp")
	}
	// TCP checksum (verify by recomputing and comparing)
	tcp := pkt[20:]
	savedCsum := binary.BigEndian.Uint16(tcp[16:18])
	writeTCPChecksum4(pkt, 20)
	if binary.BigEndian.Uint16(tcp[16:18]) != savedCsum {
		t.Fatal("TCP checksum invalid after clamp")
	}
}

// TestClampSurvivesShortPackets feeds Clamp buffers too short to hold an IPv4
// header. There is nothing to assert but the absence of a panic: these arrive
// from the tunnel, so a slice expression that assumed a full header would take
// the client down on a malformed packet.
func TestClampSurvivesShortPackets(t *testing.T) {
	for _, l := range []int{0, 1, 10, 19} {
		mssfix.Clamp(make([]byte, l), 1300)
	}
}
