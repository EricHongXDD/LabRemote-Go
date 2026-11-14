// SPDX-License-Identifier: LGPL-2.1-or-later

package keymethod2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/profile"
)

// The key-method-2 exchange: keep what we send, and parse what the peer sends.
//
// SendAuth generates 112 bytes of key material and ConsumeServerAuth reads the
// server's 64. Those 176 bytes are the entire input to the classic key
// derivation.

// TestFramingStringNamesTheFormatItWrites pins each Framing's name to the
// packet that framing actually produces. The shape is read back off the header
// rather than assumed, because the header is the one difference the two
// framings show without parsing any field: stock writes four zero bytes, AWS
// writes the packet's own length little-endian.
func TestFramingStringNamesTheFormatItWrites(t *testing.T) {
	params := TunnelParams{
		Proto:       profile.ProtoUDP,
		TunMTU:      1500,
		CipherName:  "AES-256-GCM",
		KeySizeBits: 256,
	}
	cases := []struct {
		// Named by hand: a subtest named after the method under test cannot
		// report that the method is wrong.
		name    string
		framing Framing
		want    string
	}{
		{"stock", FramingStock, "stock"},
		{"aws large token", FramingAWSLargeToken, "aws-large-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := SendAuth(&buf, params, "user", "pass", tc.framing, IVProtoImplemented); err != nil {
				t.Fatalf("SendAuth: %v", err)
			}
			pkt := buf.Bytes()
			if len(pkt) < authHeaderLen {
				t.Fatalf("packet is %d bytes, too short to carry a header", len(pkt))
			}

			var onTheWire string
			switch hdr := binary.LittleEndian.Uint32(pkt[:authHeaderLen]); hdr {
			case 0:
				onTheWire = "stock"
			case uint32(len(pkt)):
				onTheWire = "aws-large-token"
			default:
				t.Fatalf("header %#08x is neither stock's zero prefix nor this packet's %d-byte length",
					hdr, len(pkt))
			}
			if got := tc.framing.String(); got != onTheWire {
				t.Errorf("Framing(%d).String() = %q, but the packet it wrote is the %q framing",
					int(tc.framing), got, onTheWire)
			}
			if got := tc.framing.String(); got != tc.want {
				t.Errorf("Framing(%d).String() = %q, want %q", int(tc.framing), got, tc.want)
			}
		})
	}
}

// TestSendAuthPacketReturnsTheMaterialItSent checks that the key source handed
// back is the one on the wire, at the offsets OpenVPN defines.
func TestSendAuthPacketReturnsTheMaterialItSent(t *testing.T) {
	for _, framing := range []Framing{FramingStock, FramingAWSLargeToken} {
		t.Run(framing.String(), func(t *testing.T) {
			var buf bytes.Buffer
			// The tunnel parameters are written out rather than resolved
			// from the cipher table: a known-answer test wants the inputs
			// to the options string visible beside the expected bytes.
			params := TunnelParams{
				Proto:       profile.ProtoUDP,
				TunMTU:      1500,
				CipherName:  "AES-256-GCM",
				KeySizeBits: 256,
			}
			ks, err := SendAuth(&buf, params, "user", "pass", framing, IVProtoImplemented)
			if err != nil {
				t.Fatalf("SendAuth: %v", err)
			}

			if len(ks.PreMaster) != 48 {
				t.Errorf("PreMaster is %d bytes, want 48", len(ks.PreMaster))
			}
			if len(ks.Random1) != 32 {
				t.Errorf("Random1 is %d bytes, want 32", len(ks.Random1))
			}
			if len(ks.Random2) != 32 {
				t.Errorf("Random2 is %d bytes, want 32", len(ks.Random2))
			}

			// The 112 bytes sit immediately after the 4-byte header and the
			// key_method byte, in the order pre_master ‖ random1 ‖ random2.
			wire := buf.Bytes()
			const off = 5
			if len(wire) < off+clientKeySourceLen {
				t.Fatalf("packet is %d bytes, too short to hold the key source", len(wire))
			}
			sent := wire[off : off+clientKeySourceLen]
			if !bytes.Equal(ks.PreMaster, sent[0:48]) {
				t.Error("PreMaster is not the pre_master that went on the wire")
			}
			if !bytes.Equal(ks.Random1, sent[48:80]) {
				t.Error("Random1 is not the random1 that went on the wire")
			}
			if !bytes.Equal(ks.Random2, sent[80:112]) {
				t.Error("Random2 is not the random2 that went on the wire")
			}

			// Not aliases of a buffer the function cleared on return.
			if allZero(ks.PreMaster) || allZero(ks.Random1) || allZero(ks.Random2) {
				t.Error("key source is zeroed: it aliases the scratch buffer rather than copying it")
			}
		})
	}
}

// TestSendAuthPacketIsByteExact pins every byte of the packet the client
// writes, in both framings, against a layout built by hand. The two
// advertisement strings come from TunnelOptions and PeerInfo, so what is under
// test is the framing around them.
//
// Reference: openvpn-2.6.22 src/openvpn/ssl.c key_method_2_write(), which emits
// each of the four fields through write_string() — a uint16_be of strlen+1,
// then the string, then its NUL.
func TestSendAuthPacketIsByteExact(t *testing.T) {
	// Written out rather than resolved from the cipher table: a known-answer
	// test wants the inputs to the options string visible beside the bytes.
	params := TunnelParams{
		Proto:       profile.ProtoUDP,
		TunMTU:      1500,
		CipherName:  "AES-256-GCM",
		KeySizeBits: 256,
	}
	const username, password = "user", "pass"

	for _, framing := range []Framing{FramingStock, FramingAWSLargeToken} {
		t.Run(framing.String(), func(t *testing.T) {
			var buf bytes.Buffer
			ks, err := SendAuth(&buf, params, username, password, framing, IVProtoImplemented)
			if err != nil {
				t.Fatalf("SendAuth: %v", err)
			}
			got := buf.Bytes()
			if len(got) < 4+1+clientKeySourceLen {
				t.Fatalf("packet is %d bytes, too short to be an auth packet", len(got))
			}

			// The 112 random bytes are the one part a known-answer test cannot
			// predict, so they come from the key source SendAuth reported.
			keySource := slices.Concat(ks.PreMaster, ks.Random1, ks.Random2)
			want := buildClientAuthPacket(framing, keySource, TunnelOptions(params),
				username, password, PeerInfo(IVProtoImplemented))

			// The header is checked ahead of the whole-packet comparison: a
			// total length short by its own four bytes leaves the server
			// reading the tail of peer_info as the next control message.
			switch framing {
			case FramingStock:
				if hdr := got[:4]; !bytes.Equal(hdr, []byte{0x00, 0x00, 0x00, 0x00}) {
					t.Errorf("stock header = % x, want 00 00 00 00", hdr)
				}
			case FramingAWSLargeToken:
				if declared := binary.LittleEndian.Uint32(got[:4]); int(declared) != len(got) {
					t.Errorf("declared total length %d, but the packet is %d bytes: "+
						"the uint32_le prefix counts itself", declared, len(got))
				}
			}

			if !bytes.Equal(got, want) {
				t.Errorf("auth packet does not match the expected layout: %s",
					describeByteDiff(got, want))
			}
		})
	}
}

// TestSendAuthWritesAbsentCredentialsAsAZeroLengthField covers the cert-only
// profile: u16(0) and u16(1)+NUL are both well-formed and say different things
// — "absent" and "present, and empty" — and key_method_2_write() sends the
// first, through write_empty_string(), when there is no auth-user-pass.
//
// Reference: openvpn-2.6.22 src/openvpn/ssl.c write_empty_string().
func TestSendAuthWritesAbsentCredentialsAsAZeroLengthField(t *testing.T) {
	// A CBC deployment over TCP, so the options string differs from the one
	// above and the offset arithmetic below cannot be accidentally right.
	params := TunnelParams{
		Proto:       profile.ProtoTCP,
		TunMTU:      1500,
		CipherName:  "AES-256-CBC",
		AuthName:    "SHA256",
		KeySizeBits: 256,
	}

	for _, framing := range []Framing{FramingStock, FramingAWSLargeToken} {
		t.Run(framing.String(), func(t *testing.T) {
			var buf bytes.Buffer
			ks, err := SendAuth(&buf, params, "", "", framing, IVProtoImplemented)
			if err != nil {
				t.Fatalf("SendAuth: %v", err)
			}
			got := buf.Bytes()

			opts := TunnelOptions(params)
			width := 2
			if framing == FramingAWSLargeToken {
				width = 4
			}
			// header(4) ‖ key_method(1) ‖ key source(112) ‖ the options field,
			// which is its prefix plus the string plus one NUL.
			off := 4 + 1 + clientKeySourceLen + width + len(opts) + 1
			if len(got) < off+2*width {
				t.Fatalf("packet is %d bytes, too short to hold both credential fields", len(got))
			}
			// Two bare zero-length prefixes, back to back, with no NUL between
			// them and none after: 2*width bytes for two absent strings, where
			// "present, and empty" would need 2*(width+1).
			if creds := got[off : off+2*width]; !bytes.Equal(creds, make([]byte, 2*width)) {
				t.Errorf("username and password fields = % x, want %d zero bytes: "+
					"an absent credential is a bare zero length and no NUL", creds, 2*width)
			}

			keySource := slices.Concat(ks.PreMaster, ks.Random1, ks.Random2)
			want := buildClientAuthPacket(framing, keySource, opts, "", "",
				PeerInfo(IVProtoImplemented))
			if !bytes.Equal(got, want) {
				t.Errorf("auth packet does not match the expected layout: %s",
					describeByteDiff(got, want))
			}
		})
	}
}

// TestConsumeServerAuthPacketReturnsTheServerKeySource is the other half: the
// server's 64 bytes come back, in both framings, alongside the options string.
func TestConsumeServerAuthPacketReturnsTheServerKeySource(t *testing.T) {
	const opts = "V4,dev-type tun,link-mtu 1521,tun-mtu 1500,proto UDPv4," +
		"cipher AES-256-CBC,auth SHA512,keysize 256,key-method 2,tls-server"

	for _, awsFormat := range []bool{false, true} {
		name := "stock"
		if awsFormat {
			name = "aws"
		}
		t.Run(name, func(t *testing.T) {
			randoms := make([]byte, serverKeySourceLen)
			for i := range randoms {
				randoms[i] = byte(i + 1)
			}
			pkt := buildServerAuthPacketWithRandoms(opts, randoms, awsFormat)

			ks, gotOpts, err := ConsumeServerAuth(bytes.NewReader(pkt))
			if err != nil {
				t.Fatalf("ConsumeServerAuth: %v", err)
			}
			if gotOpts != opts {
				t.Errorf("options:\n got %q\nwant %q", gotOpts, opts)
			}
			if !bytes.Equal(ks.Random1, randoms[0:32]) {
				t.Errorf("Random1 = %x, want %x", ks.Random1, randoms[0:32])
			}
			if !bytes.Equal(ks.Random2, randoms[32:64]) {
				t.Errorf("Random2 = %x, want %x", ks.Random2, randoms[32:64])
			}
			// The server never generates a pre-master, and prf.DeriveMasterSecret
			// rejects a server key source that carries one — so this must stay
			// nil rather than becoming a zero-filled 48-byte slice.
			if ks.PreMaster != nil {
				t.Errorf("PreMaster = %x, want nil: only the client generates one", ks.PreMaster)
			}
		})
	}
}

// TestConsumeServerAuthPacketEmptyOptions verifies that a server sending no
// options string is not an error — only a missing fingerprint.
func TestConsumeServerAuthPacketEmptyOptions(t *testing.T) {
	for _, awsFormat := range []bool{false, true} {
		pkt := buildServerAuthPacketWithRandoms("", make([]byte, serverKeySourceLen), awsFormat)
		_, got, err := ConsumeServerAuth(bytes.NewReader(pkt))
		if err != nil {
			t.Fatalf("awsFormat=%t: %v", awsFormat, err)
		}
		if got != "" {
			t.Errorf("awsFormat=%t: got %q, want empty", awsFormat, got)
		}
	}
}

// TestConsumeServerAuthPacketRejectsBadKeyMethod verifies the one thing this
// function is still allowed to fail on for a well-formed packet.
func TestConsumeServerAuthPacketRejectsBadKeyMethod(t *testing.T) {
	pkt := buildServerAuthPacketWithRandoms("V4,proto UDPv4", make([]byte, serverKeySourceLen), false)
	pkt[4] = 0x01 // key_method 1
	if _, _, err := ConsumeServerAuth(bytes.NewReader(pkt)); err == nil {
		t.Fatal("expected an error for key_method 1")
	}
}

// TestConsumeServerAuthPacketTruncation covers a packet cut short at each field
// boundary: it must be an error a caller can classify — both callers map it to
// diag.ClassProtocol at diag.StageAuth — never a panic and never an empty
// options string.
func TestConsumeServerAuthPacketTruncation(t *testing.T) {
	const opts = "V4,proto UDPv4,cipher AES-256-CBC,auth SHA1"

	for _, awsFormat := range []bool{false, true} {
		framing := "stock"
		if awsFormat {
			framing = "aws"
		}
		full := buildServerAuthPacketWithRandoms(opts, make([]byte, serverKeySourceLen), awsFormat)
		prefixLen := 2
		if awsFormat {
			prefixLen = 4
		}

		// Boundaries, in wire order.
		type cut struct {
			name string
			at   int
		}
		cuts := []cut{
			{"mid header", 2},
			{"after header, before key_method", 4},
			{"after key_method, before randoms", 5},
			{"mid randoms", 5 + 20},
			{"after randoms, before the options length prefix", 5 + serverKeySourceLen},
			{"mid options length prefix", 5 + serverKeySourceLen + 1},
			{"after the options length prefix, before its body", 5 + serverKeySourceLen + prefixLen},
			{"mid options body", 5 + serverKeySourceLen + prefixLen + len(opts)/2},
			// Past the options string: the username, password and peer_info
			// blocks must be consumed too, or the stream is left mid-packet
			// and the next control message is read from the wrong offset.
			{"after options, before username", 5 + serverKeySourceLen + prefixLen + len(opts) + 1},
			{"one byte short of the whole packet", len(full) - 1},
		}

		for _, c := range cuts {
			t.Run(framing+"/"+c.name, func(t *testing.T) {
				if c.at >= len(full) || c.at < 0 {
					t.Skipf("cut at %d is not inside a %d-byte packet", c.at, len(full))
				}
				truncated := full[:c.at]

				var ks any
				var gotOpts string
				var err error
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("panicked on a %d-byte packet: %v", len(truncated), r)
						}
					}()
					ks, gotOpts, err = ConsumeServerAuth(bytes.NewReader(truncated))
				}()
				_ = ks

				if err == nil {
					t.Fatalf("a packet truncated to %d bytes was accepted (options=%q); "+
						"a short read must be an error a caller can classify", len(truncated), gotOpts)
				}
				// io.EOF and io.ErrUnexpectedEOF are both fine; what matters is
				// that something came back rather than a nil error.
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) &&
					!bytes.Contains([]byte(err.Error()), []byte("ConsumeServerAuth")) {
					t.Errorf("error does not identify itself: %v", err)
				}
			})
		}
	}
}

// TestConsumeServerAuthPacketConsumesTheWholePacket pins that after a
// successful parse the reader is positioned exactly at the end of the auth
// packet, so the next control message is read from the right offset.
func TestConsumeServerAuthPacketConsumesTheWholePacket(t *testing.T) {
	const opts = "V4,proto UDPv4"
	const trailer = "PUSH_REPLY,ifconfig 10.8.0.2 10.8.0.1"

	for _, awsFormat := range []bool{false, true} {
		name := "stock"
		if awsFormat {
			name = "aws"
		}
		t.Run(name, func(t *testing.T) {
			pkt := buildServerAuthPacketWithRandoms(opts, make([]byte, serverKeySourceLen), awsFormat)
			r := bytes.NewReader(append(pkt, trailer...))

			if _, _, err := ConsumeServerAuth(r); err != nil {
				t.Fatalf("ConsumeServerAuth: %v", err)
			}
			rest, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read the remainder: %v", err)
			}
			if string(rest) != trailer {
				t.Errorf("stream left at the wrong offset:\n got %q\nwant %q", rest, trailer)
			}
		})
	}
}

// TestConsumeServerAuthPacketRejectsAnOverlongString checks the bound on a
// declared string length by name: an `err != nil` assertion cannot tell the
// bound refusing before anything is allocated from the short read afterwards,
// by which point readServerAuthString has allocated what the peer asked for.
func TestConsumeServerAuthPacketRejectsAnOverlongString(t *testing.T) {
	for _, tc := range []struct {
		name     string
		declared uint32
	}{
		{"one byte over the bound", serverAuthMaxStringLen + 1},
		{"the most a uint32_be prefix can declare", math.MaxUint32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// AWS framing: a stock uint16_be prefix cannot declare enough to
			// reach the bound. The packet has to be long enough for the
			// uint32_le header to read as a plausible total length, or the
			// auto-detection takes the stock branch and the 4-byte prefix is
			// never reached.
			body := []byte{0x02}
			body = append(body, make([]byte, serverKeySourceLen)...)
			var prefix [4]byte
			binary.BigEndian.PutUint32(prefix[:], tc.declared)
			body = append(body, prefix[:]...)
			body = append(body, make([]byte, 32)...) // padding, so totalLen clears awsServerAuthMinLen

			var hdr [4]byte
			binary.LittleEndian.PutUint32(hdr[:], uint32(4+len(body)))
			if int(binary.LittleEndian.Uint32(hdr[:])) < awsServerAuthMinLen {
				t.Fatalf("test packet is too short to be read as AWS framing")
			}
			pkt := append(hdr[:], body...)

			_, _, err := ConsumeServerAuth(bytes.NewReader(pkt))
			if err == nil {
				t.Fatal("a string declaring more than the bound was accepted")
			}
			wantMsg := fmt.Sprintf("declared length %d exceeds the %d-byte bound",
				tc.declared, serverAuthMaxStringLen)
			if !strings.Contains(err.Error(), wantMsg) {
				t.Errorf("refused for the wrong reason — the bound was not what stopped it:\n"+
					" got %v\nwant an error containing %q", err, wantMsg)
			}
		})
	}
}

// TestConsumeServerAuthPacketAcceptsTheWidestStockString is the other side of
// that bound: a uint16_be prefix declares at most 65535, sixteen times under
// it, so the bound must stay above everything the stock framing can express or
// it starts refusing legal packets.
func TestConsumeServerAuthPacketAcceptsTheWidestStockString(t *testing.T) {
	// The widest string a uint16_be prefix can carry: 65535 declared, counting
	// the NUL, so 65534 bytes of text.
	opts := strings.Repeat("V", 65534)
	pkt := buildServerAuthPacketWithRandoms(opts, make([]byte, serverKeySourceLen), false)

	_, gotOpts, err := ConsumeServerAuth(bytes.NewReader(pkt))
	if err != nil {
		t.Fatalf("ConsumeServerAuth on a %d-byte options string: %v", len(opts), err)
	}
	if gotOpts != opts {
		t.Errorf("options string came back %d bytes, want %d", len(gotOpts), len(opts))
	}
}

// buildServerAuthPacketWithRandoms mirrors the server side of the key-method-2
// exchange in both framings, with caller-chosen randoms so the parsed key
// source can be checked against known bytes. It matches buildServerAuthPacket
// in testenv/mockserver, which is package main and cannot be imported.
func buildServerAuthPacketWithRandoms(opts string, randoms []byte, awsFormat bool) []byte {
	body := []byte{0x02}
	body = append(body, randoms...)

	str := func(s string) []byte {
		if awsFormat {
			if s == "" {
				return []byte{0, 0, 0, 0}
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(len(s)+1))
			return append(append(b[:], s...), 0x00)
		}
		if s == "" {
			// A bare u16(0): openvpn-2.6.22 src/openvpn/ssl.c:1952-1959.
			return []byte{0x00, 0x00}
		}
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(len(s)+1))
		return append(append(b[:], s...), 0x00)
	}
	body = append(body, str(opts)...)
	body = append(body, str("")...)
	body = append(body, str("")...)
	body = append(body, str("")...)

	if awsFormat {
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(4+len(body)))
		return append(hdr[:], body...)
	}
	return append([]byte{0x00, 0x00, 0x00, 0x00}, body...)
}

// buildClientAuthPacket renders the key-method-2 auth packet a correct client
// sends, in either framing, from key material the caller already knows. It is
// written out by hand on purpose: an expected value produced by the encoder
// under test pins nothing.
func buildClientAuthPacket(framing Framing, keySource []byte, opts, username, password, peerInfo string) []byte {
	width := 2
	if framing == FramingAWSLargeToken {
		width = 4
	}
	// The declared length counts the trailing NUL; an absent field is a bare
	// zero-length prefix with no NUL at all.
	str := func(s string) []byte {
		prefix := make([]byte, width)
		if s == "" {
			return prefix
		}
		if width == 2 {
			binary.BigEndian.PutUint16(prefix, uint16(len(s)+1))
		} else {
			binary.BigEndian.PutUint32(prefix, uint32(len(s)+1))
		}
		return append(append(prefix, s...), 0x00)
	}

	body := []byte{0x02} // key_method
	body = append(body, keySource...)
	body = append(body, str(opts)...)
	body = append(body, str(username)...)
	body = append(body, str(password)...)
	body = append(body, str(peerInfo)...)

	if framing == FramingAWSLargeToken {
		// uint32_le total length, counting the four bytes it occupies.
		var hdr [4]byte
		binary.LittleEndian.PutUint32(hdr[:], uint32(4+len(body)))
		return append(hdr[:], body...)
	}
	return append([]byte{0x00, 0x00, 0x00, 0x00}, body...)
}

// describeByteDiff names the first offset at which two packets differ, with a
// window of context either side. A pair of 400-byte hex dumps is not something
// a reader can compare by eye, and the offset is what identifies the field.
func describeByteDiff(got, want []byte) string {
	for i := range min(len(got), len(want)) {
		if got[i] != want[i] {
			lo := max(i-8, 0)
			return fmt.Sprintf("%d bytes, want %d; first difference at offset %d\n"+
				" got % x\nwant % x", len(got), len(want), i,
				got[lo:min(i+8, len(got))], want[lo:min(i+8, len(want))])
		}
	}
	return fmt.Sprintf("%d bytes, want %d; the shorter is a prefix of the longer",
		len(got), len(want))
}

// allZero reports whether b is entirely zero bytes.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}
