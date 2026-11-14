package datachannel_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/internal/framing"
)

// The two formats differ by three bytes in one place, and by nothing else. A
// round trip cannot tell them apart — a client that had the format backwards in
// both directions at once works too — so these tests assert on the header bytes
// themselves, and the round trips only show that the shorter header did not
// disturb the body.

// v1GCMPair returns two P_DATA_V1 GCM channels wired to each other.
func v1GCMPair(t *testing.T) (a, b *datachannel.Channel) {
	t.Helper()
	keyA := bytes.Repeat([]byte{0xA1}, 32)
	ivA := bytes.Repeat([]byte{0xB1}, 8)
	keyB := bytes.Repeat([]byte{0xC1}, 32)
	ivB := bytes.Repeat([]byte{0xD1}, 8)

	a, err := datachannel.New(datachannel.WireDataV1, 0, 0, keyA, ivA, keyB, ivB)
	if err != nil {
		t.Fatalf("New V1: %v", err)
	}
	b, err = datachannel.New(datachannel.WireDataV1, 0, 0, keyB, ivB, keyA, ivA)
	if err != nil {
		t.Fatalf("New V1: %v", err)
	}
	return a, b
}

// TestDataV1HeaderIsOneByteAndCarriesNoPeerID is the wire-bytes assertion for
// the shorter format. P_DATA_V1 is the opcode and key_id byte and then the
// body: the packet_id begins at offset 1, where a P_DATA_V2 packet is still
// three bytes short of it. Getting this wrong produces a perfectly well-formed
// packet that the peer discards, and no round trip can see it.
func TestDataV1HeaderIsOneByteAndCarriesNoPeerID(t *testing.T) {
	const keyID = 3
	key := bytes.Repeat([]byte{0x07}, 32)
	iv := bytes.Repeat([]byte{0x08}, 8)
	ch, err := datachannel.New(datachannel.WireDataV1, 0, keyID, key, iv, key, iv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := []byte{0x45, 0x00, 0x00, 0x1c}
	pkt, err := ch.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if want := framing.FirstByte(framing.P_DATA_V1, keyID); pkt[0] != want {
		t.Errorf("first byte = %#02x, want %#02x (opcode %d, key_id %d)",
			pkt[0], want, framing.P_DATA_V1, keyID)
	}
	if got := framing.OpcodeFromByte(pkt[0]); got != framing.P_DATA_V1 {
		t.Errorf("opcode = %d, want %d", got, framing.P_DATA_V1)
	}
	if got := framing.KeyIDFromByte(pkt[0]); got != keyID {
		t.Errorf("key_id = %d, want %d — it lives in the same three bits in both formats", got, keyID)
	}

	// The packet_id sits immediately after the opcode byte. If three peer-id
	// bytes had been written, this would read the top of a zero peer-id
	// instead and give 0.
	if got := binary.BigEndian.Uint32(pkt[1:5]); got != 1 {
		t.Errorf("packet_id at offset 1 = %d, want 1: either the packet_id does not "+
			"start there or the first one is not 1", got)
	}

	// The whole packet is header(1) + packet_id(4) + tag(16) + payload.
	if want := 1 + 4 + 16 + len(msg); len(pkt) != want {
		t.Errorf("packet is %d bytes, want %d", len(pkt), want)
	}
}

// TestDataV2StillSendsThePeerID is the other half, and the one that can regress
// silently: making V1 work by shortening the header for everybody would pass
// every P_DATA_V2 round-trip test in this package, because both ends agree.
func TestDataV2StillSendsThePeerID(t *testing.T) {
	const (
		keyID  = 2
		peerID = 0x0A0B0C
	)
	key := bytes.Repeat([]byte{0x07}, 32)
	iv := bytes.Repeat([]byte{0x08}, 8)
	ch, err := datachannel.New(datachannel.WireDataV2, peerID, keyID, key, iv, key, iv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	msg := []byte{0x45, 0x00, 0x00, 0x1c}
	pkt, err := ch.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if want := framing.FirstByte(framing.P_DATA_V2, keyID); pkt[0] != want {
		t.Errorf("first byte = %#02x, want %#02x", pkt[0], want)
	}
	if got := []byte{pkt[1], pkt[2], pkt[3]}; !bytes.Equal(got, []byte{0x0A, 0x0B, 0x0C}) {
		t.Errorf("peer-id bytes = % x, want 0a 0b 0c", got)
	}
	if got := binary.BigEndian.Uint32(pkt[4:8]); got != 1 {
		t.Errorf("packet_id at offset 4 = %d, want 1", got)
	}
	if want := 4 + 4 + 16 + len(msg); len(pkt) != want {
		t.Errorf("packet is %d bytes, want %d", len(pkt), want)
	}
}

// TestDataV1IsThreeBytesShorter pins the difference as a difference, on
// identical inputs. It is the assertion a length-only check on either format
// alone cannot make.
func TestDataV1IsThreeBytesShorter(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 32)
	iv := bytes.Repeat([]byte{0x08}, 8)
	msg := bytes.Repeat([]byte{0x5A}, 60)

	v1, err := datachannel.New(datachannel.WireDataV1, 0, 0, key, iv, key, iv)
	if err != nil {
		t.Fatalf("New V1: %v", err)
	}
	v2, err := datachannel.New(datachannel.WireDataV2, 0, 0, key, iv, key, iv)
	if err != nil {
		t.Fatalf("New V2: %v", err)
	}
	p1, err := v1.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encrypt V1: %v", err)
	}
	p2, err := v2.Encrypt(msg)
	if err != nil {
		t.Fatalf("Encrypt V2: %v", err)
	}
	if len(p2)-len(p1) != 3 {
		t.Errorf("V2 is %d bytes longer than V1, want 3 — the peer-id is the whole difference",
			len(p2)-len(p1))
	}
}

// v1CBCPair returns two P_DATA_V1 AES-256-CBC + HMAC-SHA256 channels wired to
// each other, which is the combination that matters for this format: the
// deployments still speaking P_DATA_V1 are old AES-CBC ones.
func v1CBCPair(t *testing.T) (a, b *datachannel.Channel) {
	t.Helper()
	aesA := bytes.Repeat([]byte{0x11}, 32)
	hmacA := bytes.Repeat([]byte{0x22}, 64)
	aesB := bytes.Repeat([]byte{0x33}, 32)
	hmacB := bytes.Repeat([]byte{0x44}, 64)

	a, err := datachannel.NewCBC(datachannel.WireDataV1, 0, 1, crypto.DigestSHA256, aesA, hmacA, aesB, hmacB)
	if err != nil {
		t.Fatalf("NewCBC: %v", err)
	}
	b, err = datachannel.NewCBC(datachannel.WireDataV1, 0, 1, crypto.DigestSHA256, aesB, hmacB, aesA, hmacA)
	if err != nil {
		t.Fatalf("NewCBC: %v", err)
	}
	return a, b
}

// TestDataV1RoundTrip shows the shorter header left the body alone, on both
// cipher paths. For GCM the AAD shrinks with the header, so a V1 channel that
// authenticated four header bytes would fail here rather than produce wrong
// plaintext; for CBC the header is not authenticated, so the opcode is asserted
// as well as the payload.
func TestDataV1RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		pair func(*testing.T) (a, b *datachannel.Channel)
	}{
		{"GCM", v1GCMPair},
		{"CBC", v1CBCPair},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.pair(t)
			for i := 0; i < 5; i++ {
				msg := []byte{byte(i), 0x45, 0x00, 0x00, 0x28, 0x01}
				pkt, err := a.Encrypt(msg)
				if err != nil {
					t.Fatalf("i=%d encrypt: %v", i, err)
				}
				if got := framing.OpcodeFromByte(pkt[0]); got != framing.P_DATA_V1 {
					t.Fatalf("i=%d opcode = %d, want %d", i, got, framing.P_DATA_V1)
				}
				plain, err := b.Decrypt(pkt)
				if err != nil {
					t.Fatalf("i=%d decrypt: %v", i, err)
				}
				if !bytes.Equal(plain, msg) {
					t.Fatalf("i=%d roundtrip mismatch: got % x want % x", i, plain, msg)
				}
			}
		})
	}
}

// TestDataV1RefusesAPeerID pins the contract's programming-error rule:
// P_DATA_V1 has nowhere to put a peer-id, so a caller holding both took them
// from two different places, and dropping the value would leave that mistake
// invisible for as long as the peer happened to ignore it.
func TestDataV1RefusesAPeerID(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 32)
	iv := bytes.Repeat([]byte{0x08}, 8)

	if _, err := datachannel.New(datachannel.WireDataV1, 1, 0, key, iv, key, iv); err == nil {
		t.Error("New accepted a P_DATA_V1 channel with peer-id 1")
	}
	aes := bytes.Repeat([]byte{0x11}, 32)
	hmac := bytes.Repeat([]byte{0x22}, 64)
	if _, err := datachannel.NewCBC(datachannel.WireDataV1, 1, 0, crypto.DigestSHA256,
		aes, hmac, aes, hmac); err == nil {
		t.Error("NewCBC accepted a P_DATA_V1 channel with peer-id 1")
	}

	// Zero is the only peer-id a V1 channel may be built with, and it is the
	// one the format's own selection rule produces.
	if _, err := datachannel.New(datachannel.WireDataV1, 0, 0, key, iv, key, iv); err != nil {
		t.Errorf("New refused a P_DATA_V1 channel with no peer-id: %v", err)
	}
}

// TestUnknownWireFormatIsRefused guards the int type: WireFormat is not a
// closed enum to the compiler, and a channel built from a stray value would
// otherwise silently behave as P_DATA_V2.
func TestUnknownWireFormatIsRefused(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 32)
	iv := bytes.Repeat([]byte{0x08}, 8)
	if _, err := datachannel.New(datachannel.WireFormat(7), 0, 0, key, iv, key, iv); err == nil {
		t.Error("New accepted wire format 7")
	}
}

// TestWireFormatNames pins the two strings the session report and the sweep
// are read through. They are the opcode names, so a reader of either can match
// them against the protocol document without a translation table.
func TestWireFormatNames(t *testing.T) {
	if got := datachannel.WireDataV2.String(); got != "P_DATA_V2" {
		t.Errorf("WireDataV2 = %q, want %q", got, "P_DATA_V2")
	}
	if got := datachannel.WireDataV1.String(); got != "P_DATA_V1" {
		t.Errorf("WireDataV1 = %q, want %q", got, "P_DATA_V1")
	}
	// The zero value is the format this client prefers, so a parameter set
	// nobody filled in advertises P_DATA_V2 rather than nothing.
	var zero datachannel.WireFormat
	if zero != datachannel.WireDataV2 {
		t.Error("the zero WireFormat is not WireDataV2")
	}
}

// 接收格式可与发送格式不同，但认证和跨格式重放保护必须保持有效。
func TestManagerAcceptsDirectionalFormats(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 32)
	iv := bytes.Repeat([]byte{0x08}, 8)
	for _, cipher := range []string{"AES-256-GCM", "AES-256-CBC", "none"} {
		for _, outgoing := range []datachannel.WireFormat{datachannel.WireDataV1, datachannel.WireDataV2} {
			t.Run(cipher+"/"+outgoing.String(), func(t *testing.T) {
				makeChannel := func(w datachannel.WireFormat) *datachannel.Channel {
					t.Helper()
					params, _, err := datachannel.ResolveParams(cipher, "SHA1")
					if err != nil {
						t.Fatal(err)
					}
					params.Wire = w
					material := make([]byte, 256)
					copy(material[:64], key)
					copy(material[128:192], key)
					copy(material[64:128], iv)
					copy(material[192:], iv)
					ch, err := params.NewChannel(0, 0, material)
					if err != nil {
						t.Fatal(err)
					}
					return ch
				}
				recv := makeChannel(outgoing)
				m := datachannel.NewManager(recv, nil)
				incoming := datachannel.WireDataV1
				if outgoing == incoming {
					incoming = datachannel.WireDataV2
				}
				pkt, err := makeChannel(incoming).Encrypt([]byte{0x45, 0, 1, 2})
				if err != nil {
					t.Fatal(err)
				}
				corrupt := append([]byte(nil), pkt...)
				corrupt[len(corrupt)-1] ^= 1
				if _, err := m.Decrypt(corrupt); err == nil {
					t.Fatal("篡改的数据包必须拒绝")
				}
				plain, err := m.Decrypt(pkt)
				if err != nil || !bytes.Equal(plain, []byte{0x45, 0, 1, 2}) {
					t.Fatalf("合法的反向格式无法解码: %v", err)
				}
				duplicate, _ := makeChannel(outgoing).Encrypt([]byte{0x45, 0, 1, 2})
				if _, err := m.Decrypt(duplicate); err == nil {
					t.Fatal("相同序号不能通过切换格式绕过重放保护")
				}
				wire, err := recv.Encrypt(plain)
				if err != nil {
					t.Fatal(err)
				}
				wantOpcode := uint8(framing.P_DATA_V2)
				if outgoing == datachannel.WireDataV1 {
					wantOpcode = framing.P_DATA_V1
				}
				if framing.OpcodeFromByte(wire[0]) != wantOpcode {
					t.Fatal("接收格式不能改变发送格式")
				}
			})
		}
	}
}
