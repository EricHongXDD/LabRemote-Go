// Known-answer tests for the tls-crypt wrap, against vectors captured from a
// real OpenVPN 2.4.12 peer. tls-auth and tls-crypt hash the same fields in
// opposite orders, which is what these vectors discriminate:
//
//	tls-auth   input = packet_id ‖ timestamp ‖ opcode|key_id ‖ session_id ‖ rest
//	tls-crypt  input = opcode|key_id ‖ session_id ‖ packet_id ‖ timestamp ‖ rest
package wrap_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/buengese/go-openvpn/internal/wrap"
)

// tlsCryptVectors returns the 6 tls-crypt vectors. The tls-auth ones belong to
// tlsauth_kat_test.go, and their digest input is in the other order, so
// nothing here may touch them.
func tlsCryptVectors(t *testing.T) []vector {
	t.Helper()
	vf := loadVectors(t)
	var out []vector
	for _, v := range vf.Vectors {
		if !v.isTLSAuth() {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		t.Fatal("no tls-crypt vectors; the known-answer test would pass vacuously")
	}
	return out
}

// newCryptSenderWrap builds the wrapper the vector's sender was running. There
// is no --key-direction to pass: the peer's role decides the halves, the server
// on slot 0 and the client on slot 1.
func newCryptSenderWrap(t *testing.T, v vector) wrap.Wrapper {
	t.Helper()
	key := wrapStaticKey(t, v)
	var (
		w   wrap.Wrapper
		err error
	)
	if v.Sender == "server" {
		w, err = wrap.NewTLSCryptServerForTest(key)
	} else {
		w, err = wrap.NewTLSCrypt(key)
	}
	if err != nil {
		t.Fatalf("%s: NewTLSCrypt: %v", v.Name, err)
	}
	return w
}

// newCryptClientWrap builds the wrapper a *client* reading this capture would
// run, whichever peer sent the packet.
func newCryptClientWrap(t *testing.T, v vector) wrap.Wrapper {
	t.Helper()
	w, err := wrap.NewTLSCrypt(wrapStaticKey(t, v))
	if err != nil {
		t.Fatalf("%s: NewTLSCrypt: %v", v.Name, err)
	}
	return w
}

// -------------------------------------------------------------------------
// The intermediates, before the cipher
// -------------------------------------------------------------------------

// TestTLSCryptDerivesTheRecordedKeys pins the key slots — Ke and Ka not
// adjacent, the client not on slot 0 — as an instrumented init_key_ctx()
// measured them:
//
//	server:  Ke = static_key[0:32],    Ka = static_key[64:96]
//	client:  Ke = static_key[128:160], Ka = static_key[192:224]
func TestTLSCryptDerivesTheRecordedKeys(t *testing.T) {
	for _, v := range tlsCryptVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			wantKe := mustHexLen(t, "cipher_key", v.CipherKey, 32)
			wantKa := mustHexLen(t, "hmac_key", v.HMACKey, 32)

			// The vector's own claim about where its keys live, checked
			// first: if this fails the testdata is inconsistent and nothing
			// below means anything.
			key := wrapStaticKey(t, v)
			if !bytes.Equal(wantKe, key[v.CipherKeyOffset:v.CipherKeyOffset+32]) {
				t.Fatalf("the vector's own cipher_key is not at its recorded offset %d", v.CipherKeyOffset)
			}
			if !bytes.Equal(wantKa, key[v.HMACKeyOffset:v.HMACKeyOffset+32]) {
				t.Fatalf("the vector's own hmac_key is not at its recorded offset %d", v.HMACKeyOffset)
			}
			if v.CipherKeyOffset+32 == v.HMACKeyOffset {
				t.Fatalf("Ke and Ka are adjacent at %d and %d; the whole point of this test "+
					"is that 32 bytes sit unused between them",
					v.CipherKeyOffset, v.HMACKeyOffset)
			}

			sender := newCryptSenderWrap(t, v)
			if got := wrap.SendCipherKeyForTest(sender); !bytes.Equal(got, wantKe) {
				t.Fatalf("%s Ke = %x, want the recorded static_key[%d:%d]",
					v.Sender, got, v.CipherKeyOffset, v.CipherKeyOffset+32)
			}
			if got := wrap.SendKeyForTest(sender); !bytes.Equal(got, wantKa) {
				t.Fatalf("%s Ka = %x, want the recorded static_key[%d:%d]",
					v.Sender, got, v.HMACKeyOffset, v.HMACKeyOffset+32)
			}

			// The peer's receive keys are our send keys seen from the other
			// side, which is what makes the two roles complements rather than
			// two independent guesses.
			client := newCryptClientWrap(t, v)
			gotKe, gotKa := wrap.SendCipherKeyForTest(client), wrap.SendKeyForTest(client)
			if v.Sender == "server" {
				gotKe, gotKa = wrap.RecvCipherKeyForTest(client), wrap.RecvKeyForTest(client)
			}
			if !bytes.Equal(gotKe, wantKe) {
				t.Fatalf("the client's %s-direction Ke = %x, want %x", v.Sender, gotKe, wantKe)
			}
			if !bytes.Equal(gotKa, wantKa) {
				t.Fatalf("the client's %s-direction Ka = %x, want %x", v.Sender, gotKa, wantKa)
			}
		})
	}
}

// -------------------------------------------------------------------------
// The wire
// -------------------------------------------------------------------------

// TestTLSCryptWrapReproducesEveryVector reproduces every tls-crypt vector byte
// for byte. It asserts the whole wire and not just the tag, because the wire
// order is a third arrangement of the same fields —
//
//	wire = opcode|key_id ‖ session_id ‖ packet_id ‖ timestamp ‖ tag ‖ ciphertext
//
// with the replay header *before* the tag, where tls-auth puts it after.
func TestTLSCryptWrapReproducesEveryVector(t *testing.T) {
	vectors := tlsCryptVectors(t)
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			plain := mustHex(t, "plain", v.Plain)
			want := mustHex(t, "wire", v.Wire)
			packetID := mustHexLen(t, "replay_packet_id", v.ReplayPacketID, 4)
			timestamp := mustHexLen(t, "replay_timestamp", v.ReplayTimestamp, 4)

			w := newCryptSenderWrap(t, v)
			// Wrap stamps a counter and a clock, so the capture's header
			// has to be injected for the recorded answer to be
			// reachable at all.
			wrap.SetReplayHeaderForTest(w, be32(packetID), be32(timestamp))

			got, err := w.Wrap(plain)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("wire mismatch: %s\n got %x\nwant %x",
					describeDiff(got, want), got, want)
			}
		})
	}
	if len(vectors) != 6 {
		t.Errorf("checked %d tls-crypt vectors, the capture has 6", len(vectors))
	}
}

// TestTLSCryptWrapCoversBothPeersAndAllShapes pins that the vector set spans
// both peers and all three packet shapes: a key-slot bug is invisible if only
// one peer is exercised, and an ack carries no message packet id at all.
func TestTLSCryptWrapCoversBothPeersAndAllShapes(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range tlsCryptVectors(t) {
		seen[v.Sender+"/"+v.OpcodeName] = true
	}
	for _, want := range []string{
		"client/P_CONTROL_HARD_RESET_CLIENT_V2", "client/P_ACK_V1", "client/P_CONTROL_V1",
		"server/P_CONTROL_HARD_RESET_SERVER_V2", "server/P_ACK_V1", "server/P_CONTROL_V1",
	} {
		if !seen[want] {
			t.Errorf("no vector for sender/opcode %q", want)
		}
	}
}

// TestTLSCryptUnwrapsTheServersPackets recovers the recorded plain packet from
// a genuine server packet, the only exercise of both receive halves. No clock
// seam is needed for the years-old timestamps: the window judges them against
// the peer's highest.
func TestTLSCryptUnwrapsTheServersPackets(t *testing.T) {
	n := 0
	for _, v := range tlsCryptVectors(t) {
		if v.Sender != "server" {
			continue
		}
		n++
		t.Run(v.Name, func(t *testing.T) {
			w := newCryptClientWrap(t, v)
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
	if n != 3 {
		t.Errorf("unwrapped %d server vectors, want 3", n)
	}
}

// TestTLSCryptRejectsItsOwnSendKey pins that the two slots are not confused: a
// client's own outgoing packet is authenticated under slot 1 and the client
// verifies with slot 0, so it must refuse to unwrap it.
func TestTLSCryptRejectsItsOwnSendKey(t *testing.T) {
	for _, v := range tlsCryptVectors(t) {
		if v.Sender != "client" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			w := newCryptClientWrap(t, v)
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

// -------------------------------------------------------------------------
// The mutation the vectors exist to rule out
// -------------------------------------------------------------------------

// TestTLSCryptWouldFailUnderTLSAuthsOrdering computes what an implementation
// written by analogy with tls-auth would emit — same key, same fields, same
// digest, replay header prepended — and asserts both that it is not the
// recorded tag and that the real Wrap does not produce it.
func TestTLSCryptWouldFailUnderTLSAuthsOrdering(t *testing.T) {
	for _, v := range tlsCryptVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			ka := mustHexLen(t, "hmac_key", v.HMACKey, 32)
			plain := mustHex(t, "plain", v.Plain)
			tag := mustHexLen(t, "tag", v.Tag, tlsCryptTagLen)
			pid := mustHexLen(t, "replay_packet_id", v.ReplayPacketID, 4)
			ts := mustHexLen(t, "replay_timestamp", v.ReplayTimestamp, 4)

			// tls-auth's order: packet_id ‖ timestamp ‖ the whole plain packet.
			m := hmac.New(sha256.New, ka)
			m.Write(concat(pid, ts, plain))
			byAnalogy := m.Sum(nil)

			if bytes.Equal(byAnalogy, tag) {
				t.Fatal("tls-auth's ordering reproduces the recorded tag; this vector " +
					"does not discriminate the two wraps and the capture's premise is wrong")
			}

			// And the real thing does not emit it. The tag sits at a known
			// offset on the wire, after the header and the replay id.
			w := newCryptSenderWrap(t, v)
			wrap.SetReplayHeaderForTest(w, be32(pid), be32(ts))
			wire, err := w.Wrap(plain)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			got := wire[headerLen+replayLen : headerLen+replayLen+tlsCryptTagLen]
			if bytes.Equal(got, byAnalogy) {
				t.Fatal("Wrap emitted tls-auth's tag: the wrap was implemented by analogy " +
					"with tls-auth and hashes packet_id ‖ timestamp ‖ plain instead of the wire order")
			}
			if !bytes.Equal(got, tag) {
				t.Fatalf("tag mismatch: %s", describeDiff(got, tag))
			}
		})
	}
}

// -------------------------------------------------------------------------
// Overhead and hostile input
// -------------------------------------------------------------------------

// TestTLSCryptOverheadIsFortyOnEveryVector pins the MTU arithmetic against the
// captured packets rather than a constant: tls_crypt_kt() fixes the digest at
// SHA256, so it is always the 32-byte tag plus the 8-byte replay header.
func TestTLSCryptOverheadIsFortyOnEveryVector(t *testing.T) {
	for _, v := range tlsCryptVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			plain := mustHex(t, "plain", v.Plain)
			wire := mustHex(t, "wire", v.Wire)
			want := len(wire) - len(plain)
			if want != 40 {
				t.Fatalf("the vector's own overhead is %d, want 40", want)
			}
			if got := newCryptSenderWrap(t, v).Overhead(); got != want {
				t.Fatalf("Overhead() = %d, want %d (len(wire) - len(plain))", got, want)
			}
		})
	}
}

// TestTLSCryptRejectsATamperedWire mutates one bit of every captured packet at
// each field the wrap distinguishes, and requires the tag to notice: CTR
// decryption of a forged packet succeeds unconditionally.
func TestTLSCryptRejectsATamperedWire(t *testing.T) {
	for _, v := range tlsCryptVectors(t) {
		if v.Sender != "server" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			wire := mustHex(t, "wire", v.Wire)
			for _, m := range []struct {
				what   string
				offset int
			}{
				{"opcode/session id", 0},
				{"packet id", headerLen},
				{"timestamp", headerLen + 4},
				{"tag", headerLen + replayLen},
				{"ciphertext", len(wire) - 1},
			} {
				bad := append([]byte(nil), wire...)
				bad[m.offset] ^= 0x01
				w := newCryptClientWrap(t, v)
				if _, err := w.Unwrap(bad); !errors.Is(err, wrap.ErrAuth) {
					t.Errorf("a flipped bit in the %s was accepted (err = %v)", m.what, err)
				}
			}
		})
	}
}

// TestTLSCryptRejectsTruncatedPackets pins that a packet too short to hold the
// header, the replay id and the tag fails under ErrAuth, so the client counts a
// short read with the authentication failures rather than as a protocol error.
func TestTLSCryptRejectsTruncatedPackets(t *testing.T) {
	v := tlsCryptVectors(t)[0]
	wire := mustHex(t, "wire", v.Wire)
	prefix := headerLen + replayLen + tlsCryptTagLen
	for n := 0; n < prefix; n++ {
		w := newCryptClientWrap(t, v)
		if _, err := w.Unwrap(wire[:n]); !errors.Is(err, wrap.ErrAuth) {
			t.Fatalf("Unwrap of %d bytes: err = %v, want one wrapping ErrAuth", n, err)
		}
	}
}
