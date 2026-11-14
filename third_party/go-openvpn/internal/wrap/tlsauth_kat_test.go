// Known-answer tests for the tls-auth wrap, against vectors captured from a
// real OpenVPN 2.4.12 peer: Wrap reproduces the recorded wire, Unwrap recovers
// the recorded plain packet under the receive key, the installed keys match the
// bytes OpenVPN installed, and Overhead is the difference the vectors show.
package wrap_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/wrap"
)

// tlsAuthVectors returns the 24 tls-auth vectors. The tls-crypt ones belong to
// tlscrypt_kat_test.go, and their digest input is in a different order, so
// nothing here may touch them.
func tlsAuthVectors(t *testing.T) []vector {
	t.Helper()
	vf := loadVectors(t)
	var out []vector
	for _, v := range vf.Vectors {
		if v.isTLSAuth() {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		t.Fatal("no tls-auth vectors; the known-answer test would pass vacuously")
	}
	return out
}

// wrapDigest maps a vector's digest name onto the crypto.Digest the wrap takes.
func wrapDigest(t *testing.T, name string) crypto.Digest {
	t.Helper()
	d, err := crypto.ParseDigest(name)
	if err != nil {
		t.Fatalf("digest %q: %v", name, err)
	}
	return d
}

// wrapStaticKey decodes a vector's static key into the wrap's key type.
func wrapStaticKey(t *testing.T, v vector) *wrap.StaticKey {
	t.Helper()
	b := mustHexLen(t, "static_key", v.StaticKey, wrap.StaticKeySize)
	var k wrap.StaticKey
	copy(k[:], b)
	return &k
}

// clientDirection is the key-direction as the vector's .ovpn spells it — the
// client's.
func clientDirection(t *testing.T, v vector) wrap.Direction {
	t.Helper()
	if v.KeyDirection == nil {
		t.Fatalf("%s: tls-auth vector has no key direction", v.Name)
	}
	switch *v.KeyDirection {
	case 0:
		return wrap.Direction0
	case 1:
		return wrap.Direction1
	default:
		t.Fatalf("%s: key direction %d is neither 0 nor 1", v.Name, *v.KeyDirection)
		return wrap.DirectionAbsent
	}
}

// senderDirection is the direction the peer that produced the packet ran. The
// recorded direction is the client's and the server runs the complement, so a
// server-sent vector is reproduced by a wrapper built with the other one.
func senderDirection(t *testing.T, v vector) wrap.Direction {
	t.Helper()
	d := clientDirection(t, v)
	if v.Sender != "server" {
		return d
	}
	if d == wrap.Direction0 {
		return wrap.Direction1
	}
	return wrap.Direction0
}

// newSenderWrap builds the wrapper the vector's sender was running.
func newSenderWrap(t *testing.T, v vector) wrap.Wrapper {
	t.Helper()
	w, err := wrap.NewTLSAuth(wrapStaticKey(t, v), senderDirection(t, v), wrapDigest(t, v.Digest))
	if err != nil {
		t.Fatalf("%s: NewTLSAuth: %v", v.Name, err)
	}
	return w
}

// newClientWrap builds the wrapper a *client* reading this capture would run,
// whichever peer sent the packet.
func newClientWrap(t *testing.T, v vector) wrap.Wrapper {
	t.Helper()
	w, err := wrap.NewTLSAuth(wrapStaticKey(t, v), clientDirection(t, v), wrapDigest(t, v.Digest))
	if err != nil {
		t.Fatalf("%s: NewTLSAuth: %v", v.Name, err)
	}
	return w
}

// TestTLSAuthWrapReproducesEveryVector reproduces every tls-auth vector byte
// for byte. It asserts the whole wire and not just the tag: the output field
// order is not the digest order, and the tag alone would leave it untested.
func TestTLSAuthWrapReproducesEveryVector(t *testing.T) {
	vectors := tlsAuthVectors(t)
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			plain := mustHex(t, "plain", v.Plain)
			want := mustHex(t, "wire", v.Wire)
			packetID := mustHexLen(t, "replay_packet_id", v.ReplayPacketID, 4)
			timestamp := mustHexLen(t, "replay_timestamp", v.ReplayTimestamp, 4)

			w := newSenderWrap(t, v)
			// Wrap stamps a counter and a clock, so the capture's header
			// has to be injected for the recorded answer to be
			// reachable at all.
			wrap.SetReplayHeaderForTest(w, be32(packetID), be32(timestamp))

			got, err := w.Wrap(plain)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("wire mismatch (%s): %s\n got %x\nwant %x",
					v.Digest, describeDiff(got, want), got, want)
			}
		})
	}
	if len(vectors) != 24 {
		t.Errorf("checked %d tls-auth vectors, the capture has 24", len(vectors))
	}
}

// TestTLSAuthWrapCoversBothDirectionsAndDigests pins that the vector set spans
// both directions, both digests and both senders: a key-selection bug is
// invisible if only one direction is exercised.
func TestTLSAuthWrapCoversBothDirectionsAndDigests(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range tlsAuthVectors(t) {
		seen[v.Digest+"/"+clientDirection(t, v).String()+"/"+v.Sender] = true
	}
	for _, want := range []string{
		"SHA1/0/client", "SHA1/0/server", "SHA1/1/client", "SHA1/1/server",
		"SHA256/0/client", "SHA256/0/server", "SHA256/1/client", "SHA256/1/server",
	} {
		if !seen[want] {
			t.Errorf("no vector for digest/direction/sender %q", want)
		}
	}
}

// TestTLSAuthUnwrapsTheServersPackets recovers the recorded plain packet from
// a genuine server packet, which is how the first server reply is validated and
// the only exercise of the receive key half. No clock seam is needed for the
// years-old timestamps: the window judges them against the peer's highest.
func TestTLSAuthUnwrapsTheServersPackets(t *testing.T) {
	n := 0
	for _, v := range tlsAuthVectors(t) {
		if v.Sender != "server" {
			continue
		}
		n++
		t.Run(v.Name, func(t *testing.T) {
			w := newClientWrap(t, v)
			got, err := w.Unwrap(mustHex(t, "wire", v.Wire))
			if err != nil {
				t.Fatalf("Unwrap of a genuine server packet: %v", err)
			}
			want := mustHex(t, "plain", v.Plain)
			if !bytes.Equal(got, want) {
				t.Fatalf("plain mismatch: %s\n got %x\nwant %x",
					describeDiff(got, want), got, want)
			}
		})
	}
	if n != 12 {
		t.Errorf("unwrapped %d server vectors, want 12", n)
	}
}

// TestTLSAuthRejectsItsOwnSendKey pins that the two key halves are not
// confused: a client's own outgoing packet is authenticated under the send key,
// and the receive key is the other half, so a client must refuse to unwrap it.
func TestTLSAuthRejectsItsOwnSendKey(t *testing.T) {
	for _, v := range tlsAuthVectors(t) {
		if v.Sender != "client" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			w := newClientWrap(t, v)
			got, err := w.Unwrap(mustHex(t, "wire", v.Wire))
			if err == nil {
				t.Fatalf("Unwrap accepted the client's own packet: %x", got)
			}
			if !errors.Is(err, wrap.ErrAuth) {
				t.Fatalf("Unwrap error = %v, want one wrapping ErrAuth", err)
			}
		})
	}
}

// TestTLSAuthInstallsTheRecordedKeyHalves asserts the derived keys before the
// tag, so a mismatch is attributable. The recorded bytes come from an
// instrumented init_key_ctx(), not from an assumption about the offsets.
func TestTLSAuthInstallsTheRecordedKeyHalves(t *testing.T) {
	for _, v := range tlsAuthVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			digest := wrapDigest(t, v.Digest)
			wantKey := mustHexLen(t, "hmac_key", v.HMACKey, digest.Size())

			w := newSenderWrap(t, v)
			if got := wrap.SendKeyForTest(w); !bytes.Equal(got, wantKey) {
				t.Fatalf("send key = %x, want the recorded static_key[%d:%d]",
					got, v.HMACKeyOffset, v.HMACKeyOffset+digest.Size())
			}

			// The key is the *leading* digest-sized bytes of a 64-byte
			// field, not the whole field: the recorded tags rule out the
			// whole-field reading on all 24 vectors.
			key := wrapStaticKey(t, v)
			if !bytes.Equal(wantKey, key[v.HMACKeyOffset:v.HMACKeyOffset+digest.Size()]) {
				t.Fatalf("the vector's own hmac_key is not at its recorded offset %d", v.HMACKeyOffset)
			}

			// The peer's receive key is our send key seen from the other
			// side, so a client's receive key is the server's send key.
			client := newClientWrap(t, v)
			if v.Sender == "server" {
				if got := wrap.RecvKeyForTest(client); !bytes.Equal(got, wantKey) {
					t.Fatalf("client receive key = %x, want the server's send key %x", got, wantKey)
				}
			} else if got := wrap.SendKeyForTest(client); !bytes.Equal(got, wantKey) {
				t.Fatalf("client send key = %x, want %x", got, wantKey)
			}
		})
	}
}

// TestTLSAuthOverheadMatchesEveryVector pins the MTU arithmetic against the
// captured packets rather than a constant. Overhead is digest_size + 8: 28 for
// SHA1 and 40 for SHA256, so a hard-coded 40 is silently wrong for the SHA1
// default.
func TestTLSAuthOverheadMatchesEveryVector(t *testing.T) {
	sizes := map[string]int{}
	for _, v := range tlsAuthVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			plain := mustHex(t, "plain", v.Plain)
			wire := mustHex(t, "wire", v.Wire)
			want := len(wire) - len(plain)

			w := newSenderWrap(t, v)
			if got := w.Overhead(); got != want {
				t.Fatalf("Overhead() = %d, want %d (len(wire) - len(plain))", got, want)
			}
			sizes[v.Digest] = want
		})
	}
	if sizes["SHA1"] != 28 {
		t.Errorf("SHA1 overhead = %d, want 28", sizes["SHA1"])
	}
	if sizes["SHA256"] != 40 {
		t.Errorf("SHA256 overhead = %d, want 40", sizes["SHA256"])
	}
	if sizes["SHA1"] == sizes["SHA256"] {
		t.Error("both digests cost the same; a hard-coded Overhead would pass this suite")
	}
}

// TestTLSAuthRejectsATamperedWire mutates one bit of every captured packet, at
// each field the wrap distinguishes, and requires the tag to notice — an Unwrap
// that skipped the comparison reaches every recorded answer too.
func TestTLSAuthRejectsATamperedWire(t *testing.T) {
	for _, v := range tlsAuthVectors(t) {
		if v.Sender != "server" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			wire := mustHex(t, "wire", v.Wire)
			tagLen := wrapDigest(t, v.Digest).Size()
			for _, m := range []struct {
				what   string
				offset int
			}{
				{"opcode/session id", 0},
				{"tag", 9},
				{"packet id", 9 + tagLen},
				{"timestamp", 9 + tagLen + 4},
				{"body", len(wire) - 1},
			} {
				bad := append([]byte(nil), wire...)
				bad[m.offset] ^= 0x01
				w := newClientWrap(t, v)
				if _, err := w.Unwrap(bad); !errors.Is(err, wrap.ErrAuth) {
					t.Errorf("a flipped bit in the %s was accepted (err = %v)", m.what, err)
				}
			}
		})
	}
}

// TestTLSAuthRejectsTruncatedPackets pins that a packet too short to hold the
// header, the tag and the replay id fails under ErrAuth, so the client counts a
// short read with the authentication failures rather than as a protocol error.
func TestTLSAuthRejectsTruncatedPackets(t *testing.T) {
	v := tlsAuthVectors(t)[0]
	wire := mustHex(t, "wire", v.Wire)
	prefix := 9 + wrapDigest(t, v.Digest).Size() + 8
	for n := 0; n < prefix; n++ {
		w := newClientWrap(t, v)
		if _, err := w.Unwrap(wire[:n]); !errors.Is(err, wrap.ErrAuth) {
			t.Fatalf("Unwrap of %d bytes: err = %v, want one wrapping ErrAuth", n, err)
		}
	}
}

// be32 reads a 4-byte big-endian field out of a decoded hex value.
func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
