package datachannel_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	lzo "github.com/buengese/go-lzo"

	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/internal/datachannel"
)

// makeGCMPair returns a loopback GCM channel pair (a→b, b→a).
func makeGCMPair(t *testing.T, seed byte) (a, b *datachannel.Channel) {
	return makeGCMPairWithKeyID(t, seed, 0)
}

func makeGCMPairWithKeyID(t *testing.T, seed, keyID byte) (a, b *datachannel.Channel) {
	t.Helper()
	keyA := bytes.Repeat([]byte{seed}, 32)
	ivA := bytes.Repeat([]byte{seed + 1}, 8)
	keyB := bytes.Repeat([]byte{seed + 2}, 32)
	ivB := bytes.Repeat([]byte{seed + 3}, 8)
	var err error
	a, err = datachannel.New(datachannel.WireDataV2, 0, keyID, keyA, ivA, keyB, ivB)
	if err != nil {
		t.Fatal(err)
	}
	b, err = datachannel.New(datachannel.WireDataV2, 0, keyID, keyB, ivB, keyA, ivA)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestManagerBasicRoundTrip(t *testing.T) {
	a, b := makeGCMPair(t, 0x10)
	mgrA := datachannel.NewManager(a, nil)
	mgrB := datachannel.NewManager(b, nil)

	msg := []byte{0x45, 0x00, 0x00, 0x3c}
	pkt, err := mgrA.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	plain, err := mgrB.Decrypt(pkt)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("roundtrip mismatch: got %v want %v", plain, msg)
	}
}

// TestManagerDecompressesLZO sends a payload the way a comp-lzo peer that
// compressed it does, and checks the codec's bound applies.
func TestManagerDecompressesLZO(t *testing.T) {
	a, b := makeGCMPair(t, 0x18)
	msg := bytes.Repeat([]byte{0x45, 0x00, 0x04, 0xb0}, 300)
	pkt, err := a.Encrypt(append([]byte{0x66}, lzo.Compress(nil, msg)...))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	codec := compress.NewCodec(compress.ModeLZO, len(msg))
	mgr := datachannel.NewManager(b, &datachannel.ManagerConfig{Compress: codec})
	plain, err := mgr.Decrypt(pkt)
	if err != nil || !bytes.Equal(plain, msg) {
		t.Fatalf("Decrypt = %d bytes, %v; want the %d-byte packet", len(plain), err, len(msg))
	}
	if n := codec.Decompressed(); n != 1 {
		t.Errorf("Decompressed = %d, want 1", n)
	}

	_, b = makeGCMPair(t, 0x18)
	small := datachannel.NewManager(b, &datachannel.ManagerConfig{
		Compress: compress.NewCodec(compress.ModeLZO, len(msg)-1),
	})
	if _, err := small.Decrypt(pkt); err == nil || errors.Is(err, compress.ErrCompressed) {
		t.Errorf("Decrypt past the bound = %v, want a decompression error", err)
	}
}

func TestManagerByteThreshold(t *testing.T) {
	a, _ := makeGCMPair(t, 0x20)
	mgr := datachannel.NewManager(a, &datachannel.ManagerConfig{
		RenegSec:   0,   // disable time limit
		RenegBytes: 100, // trigger after 100 bytes
	})

	if mgr.NeedsRekey() {
		t.Fatal("should not need rekey before threshold")
	}

	// Encrypt packets until we exceed 100 bytes.
	payload := bytes.Repeat([]byte{0xAA}, 60)
	for i := 0; i < 3; i++ {
		if _, err := mgr.Encrypt(payload); err != nil {
			t.Fatalf("encrypt i=%d: %v", i, err)
		}
	}

	if !mgr.NeedsRekey() {
		t.Fatal("should need rekey after byte threshold exceeded")
	}
}

func TestManagerRotate(t *testing.T) {
	a, b := makeGCMPair(t, 0x40)
	mgrA := datachannel.NewManager(a, &datachannel.ManagerConfig{RenegBytes: 50})
	mgrB := datachannel.NewManager(b, nil)

	// Exceed byte threshold.
	payload := bytes.Repeat([]byte{0xBB}, 60)
	if _, err := mgrA.Encrypt(payload); err != nil {
		t.Fatal(err)
	}
	if !mgrA.NeedsRekey() {
		t.Fatal("expected rekey needed before rotate")
	}

	// Rotate to new keys the way the client does it: prepare the epoch, then
	// promote it. Both sides use key_id 1, the next one after the initial 0.
	a2, b2 := makeGCMPairWithKeyID(t, 0x50, 1)
	mgrA.Prepare(a2)
	if !mgrA.Promote(1) {
		t.Fatal("Promote(1) refused the key just prepared")
	}
	if mgrA.NeedsRekey() {
		t.Fatal("should not need rekey immediately after rotate")
	}

	// Verify new channel works.
	mgrB.Prepare(b2) // wire b to the new keys
	if !mgrB.Promote(1) {
		t.Fatal("peer Promote(1) refused the key just prepared")
	}
	msg := []byte{1, 2, 3, 4}
	pkt, err := mgrA.Encrypt(msg)
	if err != nil {
		t.Fatalf("encrypt after rotate: %v", err)
	}
	plain, err := mgrB.Decrypt(pkt)
	if err != nil {
		t.Fatalf("decrypt after rotate: %v", err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatalf("post-rotate roundtrip mismatch")
	}
}

func TestManagerRekeyTransitionAcceptsBothEpochs(t *testing.T) {
	oldClient, oldServer := makeGCMPairWithKeyID(t, 0x51, 0)
	newClient, newServer := makeGCMPairWithKeyID(t, 0x61, 1)
	mgr := datachannel.NewManager(oldClient, nil)

	mgr.Prepare(newClient)
	if mgr.NeedsRekey() {
		t.Fatal("should not start another rekey while a secondary key is pending")
	}

	// Before promotion, outgoing data still uses the old primary key.
	oldPkt, err := mgr.Encrypt([]byte("old-primary"))
	if err != nil {
		t.Fatalf("encrypt with old primary: %v", err)
	}
	if plain, err := oldServer.Decrypt(oldPkt); err != nil || !bytes.Equal(plain, []byte("old-primary")) {
		t.Fatalf("old primary packet = %q, %v", plain, err)
	}

	// The peer may start sending under the new secondary key before promotion.
	newInbound, err := newServer.Encrypt([]byte("new-secondary"))
	if err != nil {
		t.Fatalf("encrypt with new secondary: %v", err)
	}
	if plain, err := mgr.Decrypt(newInbound); err != nil || !bytes.Equal(plain, []byte("new-secondary")) {
		t.Fatalf("new secondary packet = %q, %v", plain, err)
	}

	if !mgr.Promote(1) {
		t.Fatal("promote key 1 returned false")
	}
	newPkt, err := mgr.Encrypt([]byte("new-primary"))
	if err != nil {
		t.Fatalf("encrypt with new primary: %v", err)
	}
	if plain, err := newServer.Decrypt(newPkt); err != nil || !bytes.Equal(plain, []byte("new-primary")) {
		t.Fatalf("new primary packet = %q, %v", plain, err)
	}

	// In-flight packets from the old key remain valid after promotion.
	oldInbound, err := oldServer.Encrypt([]byte("old-in-flight"))
	if err != nil {
		t.Fatalf("encrypt old in-flight packet: %v", err)
	}
	if plain, err := mgr.Decrypt(oldInbound); err != nil || !bytes.Equal(plain, []byte("old-in-flight")) {
		t.Fatalf("old in-flight packet = %q, %v", plain, err)
	}
}

// TestManagerCountsBothDirectionsTowardRenegBytes checks the byte counters
// through the only thing that reads them: the reneg-bytes rekey trigger. Sent
// and received bytes both count, so a mostly-inbound tunnel still rotates its
// keys.
func TestManagerCountsBothDirectionsTowardRenegBytes(t *testing.T) {
	msg := bytes.Repeat([]byte{0xCC}, 40)

	// A threshold of exactly one message: crossing it takes one packet in
	// whichever direction the manager sees it.
	cfg := &datachannel.ManagerConfig{RenegBytes: int64(len(msg))}

	t.Run("outbound", func(t *testing.T) {
		a, _ := makeGCMPair(t, 0x60)
		mgr := datachannel.NewManager(a, cfg)
		if mgr.NeedsRekey() {
			t.Fatal("a fresh manager already wants a rekey")
		}
		if _, err := mgr.Encrypt(msg); err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if !mgr.NeedsRekey() {
			t.Error("sending the threshold did not trigger a rekey")
		}
	})

	t.Run("inbound", func(t *testing.T) {
		a, b := makeGCMPair(t, 0x60)
		sender := datachannel.NewManager(a, nil)
		mgr := datachannel.NewManager(b, cfg)
		pkt, err := sender.Encrypt(msg)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if mgr.NeedsRekey() {
			t.Fatal("a fresh manager already wants a rekey")
		}
		if _, err := mgr.Decrypt(pkt); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !mgr.NeedsRekey() {
			t.Error("receiving the threshold did not trigger a rekey")
		}
	})
}

// TestManagerNeedsRekeyTimeDisabled checks that RenegSec=0 switches the
// time-based trigger off altogether, rather than meaning "renegotiate
// immediately": no amount of elapsed time may make NeedsRekey true once both
// limits are zero.
//
// The opposite case — a manager that has outlived its RenegSec — is not
// asserted here. NeedsRekey compares against time.Now() rather than an
// injected clock, so reaching the limit would mean sleeping for it.
func TestManagerNeedsRekeyTimeDisabled(t *testing.T) {
	a, _ := makeGCMPair(t, 0x70)
	// RenegSec=0 means time-based renegotiation is disabled.
	mgr := datachannel.NewManager(a, &datachannel.ManagerConfig{RenegSec: 0, RenegBytes: 0})
	// Even after some time, should not trigger.
	time.Sleep(time.Millisecond)
	if mgr.NeedsRekey() {
		t.Fatal("NeedsRekey should be false when both limits are 0 (disabled)")
	}
}
