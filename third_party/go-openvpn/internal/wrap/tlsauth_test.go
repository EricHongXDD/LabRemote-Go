package wrap

import (
	"bytes"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/internal/crypto"
)

// Unit tests for the parts of tls-auth no captured vector reaches: the absent
// key direction, the way a direction splits the static key, and the overhead
// the digest moves.

// TestAbsentKeyDirectionUsesSlotZeroBothWays pins that an absent
// --key-direction leaves both directions on slot 0, so the two peers
// authenticate with the same key rather than splitting the material —
// key_direction_state_init's third behaviour, not a default of 0.
func TestAbsentKeyDirectionUsesSlotZeroBothWays(t *testing.T) {
	key := testKey()
	w, err := NewTLSAuth(key, DirectionAbsent, crypto.DigestSHA1)
	if err != nil {
		t.Fatalf("NewTLSAuth: %v", err)
	}
	ta := w.(*tlsAuth)
	want := key[slot0HMACOffset : slot0HMACOffset+crypto.DigestSHA1.Size()]
	if !bytes.Equal(ta.sendKey, want) {
		t.Fatalf("send key = %x, want slot 0's HMAC field %x", ta.sendKey, want)
	}
	if !bytes.Equal(ta.recvKey, want) {
		t.Fatalf("receive key = %x, want slot 0's HMAC field %x", ta.recvKey, want)
	}

	// The consequence: a peer with an absent direction accepts its own
	// outgoing packet, because there is only one key.
	wire, err := w.Wrap(controlPacket(14))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := w.Unwrap(wire); err != nil {
		t.Fatalf("an absent direction shares one key, so this must authenticate: %v", err)
	}
}

// TestKeyDirectionSelectsDifferentHalves is the guard the absent case makes
// necessary: with a direction, the two halves must actually differ, or the
// direction handling has quietly collapsed into the absent behaviour.
func TestKeyDirectionSelectsDifferentHalves(t *testing.T) {
	for _, dir := range []Direction{Direction0, Direction1} {
		w, err := NewTLSAuth(testKey(), dir, crypto.DigestSHA256)
		if err != nil {
			t.Fatalf("NewTLSAuth: %v", err)
		}
		ta := w.(*tlsAuth)
		if bytes.Equal(ta.sendKey, ta.recvKey) {
			t.Fatalf("key-direction %s uses one key for both directions", dir)
		}
	}
	// And the two directions must be mirror images of each other.
	zero, err := NewTLSAuth(testKey(), Direction0, crypto.DigestSHA256)
	if err != nil {
		t.Fatalf("NewTLSAuth: %v", err)
	}
	one, err := NewTLSAuth(testKey(), Direction1, crypto.DigestSHA256)
	if err != nil {
		t.Fatalf("NewTLSAuth: %v", err)
	}
	a, b := zero.(*tlsAuth), one.(*tlsAuth)
	if !bytes.Equal(a.sendKey, b.recvKey) || !bytes.Equal(a.recvKey, b.sendKey) {
		t.Fatal("key-direction 0 and 1 are not each other's complement")
	}
}

// TestTLSAuthOverheadIsNotOneNumber pins that overhead is digest_size + 8. A
// hard-coded 40 is right for tls-crypt and for tls-auth with SHA256, and
// silently wrong for SHA1, the default when a profile carries no --auth.
// SHA512 is here because no vector records it.
func TestTLSAuthOverheadIsNotOneNumber(t *testing.T) {
	want := map[crypto.Digest]int{
		crypto.DigestSHA1:   20 + 8,
		crypto.DigestSHA256: 32 + 8,
		crypto.DigestSHA512: 64 + 8,
	}
	for digest, n := range want {
		w, err := NewTLSAuth(testKey(), Direction1, digest)
		if err != nil {
			t.Fatalf("NewTLSAuth(%s): %v", digest, err)
		}
		if got := w.Overhead(); got != n {
			t.Errorf("%s: Overhead() = %d, want %d", digest, got, n)
		}
	}
}

// TestDirectionStringsAreProfileSpellings pins the strings a report and a
// comment both use, so "absent" cannot quietly become "0".
func TestDirectionStringsAreProfileSpellings(t *testing.T) {
	for d, want := range map[Direction]string{
		DirectionAbsent: "absent",
		Direction0:      "0",
		Direction1:      "1",
	} {
		if got := d.String(); got != want {
			t.Errorf("Direction(%d).String() = %q, want %q", int(d), got, want)
		}
	}
	if got := Direction(9).String(); !strings.Contains(got, "9") {
		t.Errorf("Direction(9).String() = %q, want it to name the value", got)
	}
}
