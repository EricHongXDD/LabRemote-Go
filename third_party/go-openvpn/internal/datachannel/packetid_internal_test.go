// SPDX-License-Identifier: LGPL-2.1-or-later

package datachannel

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/buengese/go-openvpn/internal/crypto"
)

// TestFirstPacketIDIsNotZero pins the wire-format rule that OpenVPN reserves
// packet_id 0, on the bytes rather than on a round trip: a channel that sends 0
// first still works over UDP, whose sliding replay window tolerates it, and
// carries nothing over TCP, where the peer checks sequentially. It is in the
// internal package so it can name firstPacketID — asserting only "not zero"
// from outside would pass if the value drifted to another one the peer rejects.
func TestFirstPacketIDIsNotZero(t *testing.T) {
	ch := mustGCMChannel(t)

	// GCM puts the 4-byte big-endian packet_id straight after the 4-byte
	// header, so it can be read directly off the wire. CBC encrypts it, which
	// is why only the AEAD case is inspected here.
	const seqAt = 4

	pkt, err := ch.Encrypt([]byte("first"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(pkt) < seqAt+4 {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}
	got := binary.BigEndian.Uint32(pkt[seqAt : seqAt+4])
	if got == 0 {
		t.Fatal("first packet carries packet_id 0, which OpenVPN reserves; " +
			"a TCP peer refuses it and kills the session")
	}
	if got != firstPacketID {
		t.Errorf("first packet_id = %d, want %d", got, firstPacketID)
	}

	pkt2, err := ch.Encrypt([]byte("second"))
	if err != nil {
		t.Fatalf("Encrypt second: %v", err)
	}
	if next := binary.BigEndian.Uint32(pkt2[seqAt : seqAt+4]); next != got+1 {
		t.Errorf("second packet_id = %d, want %d", next, got+1)
	}
}

// TestCBCFirstPacketIDIsNotZero covers the same rule for the MAC-then-encrypt
// path, where the packet_id is inside the ciphertext: it reads the channel's
// own send counter instead, which keeps the assertion off the CBC layout.
func TestCBCFirstPacketIDIsNotZero(t *testing.T) {
	ch := newCBCChannel(t)
	if ch.sendSeq != firstPacketID {
		t.Errorf("CBC channel starts at packet_id %d, want %d", ch.sendSeq, firstPacketID)
	}
}

// mustGCMChannel builds an AES-256-GCM channel with throwaway key material.
func mustGCMChannel(t *testing.T) *Channel {
	t.Helper()
	key := make([]byte, 32)
	iv := make([]byte, 12)
	ch, err := New(WireDataV2, 7, 0, key, iv, key, iv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ch
}

// newCBCChannel builds an AES-256-CBC + HMAC-SHA256 channel with throwaway
// keys. The HMAC keys are full 64-byte static-key slots, as the client passes
// them; the constructor takes the digest-sized prefix.
func newCBCChannel(t *testing.T) *Channel {
	t.Helper()
	aesKey := make([]byte, 32)
	hmacSlot := make([]byte, 64)
	ch, err := NewCBC(WireDataV2, 7, 0, crypto.DigestSHA256, aesKey, hmacSlot, aesKey, hmacSlot)
	if err != nil {
		t.Fatalf("NewCBC: %v", err)
	}
	return ch
}

// gcmChannelForWire builds an AES-256-GCM channel for one wire format.
func gcmChannelForWire(t *testing.T, w WireFormat) *Channel {
	t.Helper()
	key := make([]byte, 32)
	iv := make([]byte, 12)
	// V1 carries no peer-id field, and the constructor refuses a non-zero one
	// rather than sending a number the peer will never look at.
	peerID := uint32(7)
	if w == WireDataV1 {
		peerID = 0
	}
	ch, err := New(w, peerID, 0, key, iv, key, iv)
	if err != nil {
		t.Fatalf("New(%v): %v", w, err)
	}
	return ch
}

// TestV1AEADAuthenticatesOnlyThePacketID pins which bytes go into the AAD for
// each wire format, by tampering with the opcode on the wire and asking whether
// the peer still accepts the packet. P_DATA_V2 prepends its header before
// encrypting, deliberately, "so we can authenticate the opcode too"
// (openvpn-2.6.22 src/openvpn/forward.c:665-672); P_DATA_V1 prepends after
// (forward.c:686-689), so its opcode is not authenticated — ssl.c:3608-3620
// sets ad_start past it, and openvpn3 passes a null op32 (crypto_aead.hpp:78-88).
func TestV1AEADAuthenticatesOnlyThePacketID(t *testing.T) {
	for _, tc := range []struct {
		name          string
		wire          WireFormat
		opcodeIsInAAD bool
	}{
		{"P_DATA_V1", WireDataV1, false},
		{"P_DATA_V2", WireDataV2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			send := gcmChannelForWire(t, tc.wire)
			recv := gcmChannelForWire(t, tc.wire)

			pkt, err := send.Encrypt([]byte("payload"))
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if _, err := recv.Decrypt(pkt); err != nil {
				t.Fatalf("an untampered packet did not open: %v", err)
			}

			// Flip a key_id bit in the opcode byte. Whether that breaks the
			// tag is exactly the question.
			tampered := make([]byte, len(pkt))
			copy(tampered, pkt)
			tampered[0] ^= 0x01

			fresh := gcmChannelForWire(t, tc.wire)
			// 此处单独验证密码层 AAD；外层另行检查 opcode 和密钥编号。
			_, err = fresh.decryptGCM(tampered, tc.wire)
			if tc.opcodeIsInAAD && err == nil {
				t.Error("the opcode is not authenticated, but this format authenticates it")
			}
			if !tc.opcodeIsInAAD && err != nil {
				t.Errorf("the opcode is authenticated, but this format must not "+
					"authenticate it — a conforming peer rejects every packet: %v", err)
			}
		})
	}
}

// A key's packet_id space is spent, not wrapped: the reference refuses to send
// rather than reuse an id (openvpn-2.6.22 src/openvpn/packet_id.c:324-343), and
// for GCM the id is the IV counter, so a wrap is a repeated nonce under a live
// key. It is an internal test because reaching the end of the space legitimately
// would take 2^32 packets; the counter is placed instead.
func TestPacketIDSpaceIsSpentNotWrapped(t *testing.T) {
	ch := mustGCMChannel(t)

	ch.mu.Lock()
	ch.sendSeq = maxPacketID
	ch.mu.Unlock()

	last, err := ch.Encrypt([]byte("last one"))
	if err != nil {
		t.Fatalf("Encrypt at maxPacketID: %v", err)
	}
	// The final id is used, not skipped: the reference spends the whole space.
	if got := binary.BigEndian.Uint32(last[4:8]); got != maxPacketID {
		t.Fatalf("last packet carried id %#x, want %#x", got, maxPacketID)
	}

	for i := range 3 {
		if _, err := ch.Encrypt([]byte("one too many")); !errors.Is(err, ErrPacketIDExhausted) {
			t.Fatalf("Encrypt %d past the end = %v, want ErrPacketIDExhausted", i, err)
		}
	}
	// The refusal must not have left the counter somewhere reusable.
	if got := ch.SendCounter(); got != maxPacketID {
		t.Fatalf("counter moved to %#x after exhaustion, want %#x", got, maxPacketID)
	}
}

// The wrap trigger is what keeps the refusal above unreachable: the reference
// asks for a new key at PACKET_ID_WRAP_TRIGGER, 16M packets before the end
// (packet_id.h:53,:316-319, weighed with reneg-sec and reneg-bytes in
// ssl.c:3098-3106). It fires with every configured limit disabled.
func TestRekeyIsAskedForBeforeTheCounterRunsOut(t *testing.T) {
	ch := mustGCMChannel(t)
	m := NewManager(ch, nil) // no reneg-sec, no reneg-bytes

	if m.NeedsRekey() {
		t.Fatal("fresh key already wants a rekey")
	}

	ch.mu.Lock()
	ch.sendSeq = wrapTriggerPacketID - 1
	ch.mu.Unlock()
	if m.NeedsRekey() {
		t.Fatal("rekey asked for one packet before the trigger")
	}

	ch.mu.Lock()
	ch.sendSeq = wrapTriggerPacketID
	ch.mu.Unlock()
	if !m.NeedsRekey() {
		t.Fatal("counter reached the wrap trigger and no rekey was asked for")
	}
}
