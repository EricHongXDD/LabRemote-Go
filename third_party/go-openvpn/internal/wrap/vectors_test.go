// Known-answer vectors for the OpenVPN tls-auth and tls-crypt control-channel
// wraps. testdata/vectors.json was captured from a real OpenVPN 2.4.12 peer by
// an instrumented build that dumps every outgoing control packet at each stage
// of write_control_auth() (src/openvpn/ssl.c) and the key bytes each direction
// installed (init_key_ctx(), src/openvpn/crypto.c). See
// docker/TLS-WRAP-VECTORS.md.
//
// They exist because tls-auth's HMAC covers a field order that is easy to read
// wrongly and produces a plausible tag either way: the wire is
//
//	opcode|key_id ‖ session_id ‖ hmac ‖ packet_id ‖ timestamp ‖ rest
//
// while the bytes actually hashed are
//
//	packet_id ‖ timestamp ‖ opcode|key_id ‖ session_id ‖ rest
//
// and tls-crypt hashes them in the wire order instead. Only a captured tag says
// which one is right.
//
// Nothing here implements either wrap: these tests validate the captured
// testdata — that it is well formed, covers the axes the capture set out to
// span, decomposes the way its provenance claims, and that a
// plausible-but-wrong field ordering or key half does not reproduce the
// recorded tags.
package wrap_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA1 is an OpenVPN --auth choice, not a security decision here
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"testing"
)

// vectorsPath is the captured ground truth, relative to this package.
const vectorsPath = "testdata/vectors.json"

// Wire-format constants, all measured rather than assumed — every one of them
// is checked against the recorded bytes by TestVectorsDecomposeAsRecorded.
const (
	// headerLen is opcode|key_id (1) ‖ session_id (8): the part of a control
	// packet that stays at the front of the wire under both wraps.
	headerLen = 9
	// replayLen is the long-form packet id both wraps carry: a 4-byte
	// counter and a 4-byte POSIX timestamp, in that order.
	replayLen = 8
	// tlsCryptTagLen is HMAC-SHA256's output. tls-crypt fixes the digest.
	tlsCryptTagLen = 32
	// tlsCryptIVLen is the AES block size. tls-crypt takes the CTR IV from
	// the leading 16 bytes of the tag.
	tlsCryptIVLen = 16
	// staticKeyLen is an OpenVPN 2048-bit static key.
	staticKeyLen = 256
	// keySlotLen is sizeof(struct key): 64 bytes of cipher material then 64
	// of HMAC material (src/openvpn/crypto.h). A 256-byte static key is two
	// of them.
	keySlotLen = 128
)

// vectorFile is testdata/vectors.json.
type vectorFile struct {
	Provenance struct {
		CapturedAt           string   `json:"captured_at"`
		OpenVPNVersion       string   `json:"openvpn_version"`
		OpenVPNSHA256        string   `json:"openvpn_sha256"`
		Image                string   `json:"image"`
		Patch                string   `json:"patch"`
		InstrumentedFunction string   `json:"instrumented_function"`
		CaptureMethod        string   `json:"capture_method"`
		Layout               []string `json:"layout"`
	} `json:"provenance"`
	Vectors []vector `json:"vectors"`
}

// vector is one control packet as one real OpenVPN peer wrapped it, together
// with every input the wrap consumed.
type vector struct {
	Name string `json:"name"`
	// Wrap is "tls-auth" or "tls-crypt".
	Wrap string `json:"wrap"`
	// Digest is the control-channel HMAC. For tls-auth it is whatever
	// --auth said; tls-crypt fixes SHA256.
	Digest string `json:"digest"`
	// KeyDirection is the *client's* --key-direction, as a .ovpn profile
	// spells it, and nil for tls-crypt, which has no such option. The
	// server ran the complement.
	KeyDirection *int `json:"key_direction"`
	// Sender is the peer that produced this packet, "client" or "server".
	// It decides which half of the static key is in play.
	Sender string `json:"sender"`

	Opcode     int    `json:"opcode"`
	OpcodeName string `json:"opcode_name"`

	// StaticKey is the shared 2048-bit key, fresh per capture run.
	StaticKey string `json:"static_key"`
	// HMACKey and CipherKey are the bytes OpenVPN actually installed for
	// the sender's outgoing direction, and Offset is where the capture
	// found them inside StaticKey. CipherKey is empty for tls-auth, which
	// installs no cipher, and its offset is then -1.
	HMACKey         string `json:"hmac_key"`
	HMACKeyOffset   int    `json:"hmac_key_offset"`
	CipherKey       string `json:"cipher_key"`
	CipherKeyOffset int    `json:"cipher_key_offset"`

	// Plain is the complete unwrapped control packet:
	// opcode|key_id ‖ session_id ‖ ack_array ‖ [message_packet_id ‖ payload].
	Plain string `json:"plain"`
	// AuthInput is the byte string that went into the HMAC, verbatim, taken
	// from the buffer openvpn_encrypt() left behind — a record of what
	// OpenVPN hashed, not a reconstruction of it.
	AuthInput string `json:"auth_input"`
	// Tag is the tls-auth HMAC or the tls-crypt tag.
	Tag string `json:"tag"`
	// ReplayPacketID and ReplayTimestamp are the wrap's own replay header,
	// which is a separate ID space from the reliability layer's sequence
	// numbers carried inside Plain.
	ReplayPacketID  string `json:"replay_packet_id"`
	ReplayTimestamp string `json:"replay_timestamp"`
	// Wire is the answer: the bytes handed to the socket.
	Wire string `json:"wire"`
}

// isTLSAuth reports whether the vector is a tls-auth one.
func (v vector) isTLSAuth() bool { return v.Wrap == "tls-auth" }

// -------------------------------------------------------------------------
// Loading
// -------------------------------------------------------------------------

// loadVectors reads and decodes testdata/vectors.json.
func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("decode %s: %v", vectorsPath, err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("%s contains no vectors", vectorsPath)
	}
	return vf
}

// mustHex decodes a hex field, failing the test with the field's name.
func mustHex(t *testing.T, field, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: not hex: %v", field, err)
	}
	return b
}

// mustHexLen decodes a hex field and asserts its decoded length.
func mustHexLen(t *testing.T, field, s string, want int) []byte {
	t.Helper()
	b := mustHex(t, field, s)
	if len(b) != want {
		t.Fatalf("%s: %d bytes, want %d", field, len(b), want)
	}
	return b
}

// newHash returns the hash constructor a vector's digest names.
func newHash(t *testing.T, digest string) func() hash.Hash {
	t.Helper()
	switch digest {
	case "SHA1":
		return sha1.New
	case "SHA256":
		return sha256.New
	default:
		t.Fatalf("unknown digest %q; the capture only ever configures --auth SHA1 or SHA256", digest)
		return nil
	}
}

// describeDiff summarises how a computed value differs from the recorded one:
// a tag differing in one byte is a different bug from one differing wholesale.
func describeDiff(got, want []byte) string {
	if len(got) != len(want) {
		return fmt.Sprintf("length %d, want %d", len(got), len(want))
	}
	first, differing := -1, 0
	for i := range want {
		if got[i] != want[i] {
			if first < 0 {
				first = i
			}
			differing++
		}
	}
	if first < 0 {
		return "identical"
	}
	return fmt.Sprintf("%d of %d bytes differ, first at offset %d", differing, len(want), first)
}

// -------------------------------------------------------------------------
// Well-formedness and coverage
// -------------------------------------------------------------------------

// TestVectorsAreWellFormed guards the captured testdata: loadable, correctly
// sized, and spanning the axes the capture had to cover — both wraps, both key
// directions, both digests, and for each wrap both a HARD_RESET and a
// P_CONTROL_V1 carrying payload, which are different shapes to wrap.
func TestVectorsAreWellFormed(t *testing.T) {
	vf := loadVectors(t)

	if len(vf.Vectors) < 6 {
		t.Errorf("%d vectors, want at least 6", len(vf.Vectors))
	}
	p := vf.Provenance
	if p.OpenVPNVersion == "" || p.OpenVPNSHA256 == "" || p.Patch == "" ||
		p.Image == "" || p.CapturedAt == "" || p.InstrumentedFunction == "" ||
		p.CaptureMethod == "" {
		t.Error("provenance is incomplete; a vector nobody can regenerate is not ground truth")
	}
	if len(p.Layout) == 0 {
		t.Error("provenance records no wire layout")
	}

	var (
		names     = map[string]string{}
		wires     = map[string]string{}
		wraps     = map[string]bool{}
		authKD    = map[int]bool{}
		authDig   = map[string]bool{}
		shapes    = map[string]bool{} // "<wrap>/<hardreset|payload>"
		staticKey = map[string]bool{}
	)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Name == "" {
				t.Fatal("vector has no name")
			}
			if prev, dup := names[v.Name]; dup {
				t.Fatalf("duplicate vector name (previously %s)", prev)
			}
			names[v.Name] = v.Name

			switch v.Wrap {
			case "tls-auth", "tls-crypt":
			default:
				t.Fatalf("unknown wrap %q", v.Wrap)
			}
			switch v.Sender {
			case "client", "server":
			default:
				t.Fatalf("unknown sender %q", v.Sender)
			}
			if v.OpcodeName == "" {
				t.Error("vector records no opcode name")
			}

			mustHexLen(t, "static_key", v.StaticKey, staticKeyLen)
			hkey := mustHex(t, "hmac_key", v.HMACKey)
			plain := mustHex(t, "plain", v.Plain)
			tag := mustHex(t, "tag", v.Tag)
			mustHex(t, "auth_input", v.AuthInput)
			mustHex(t, "wire", v.Wire)
			mustHexLen(t, "replay_packet_id", v.ReplayPacketID, 4)
			mustHexLen(t, "replay_timestamp", v.ReplayTimestamp, 4)

			if len(plain) < headerLen {
				t.Fatalf("plain is %d bytes, shorter than the %d-byte header", len(plain), headerLen)
			}
			if len(tag) != len(hkey) {
				t.Errorf("tag is %d bytes and the HMAC key is %d; both should be the digest size",
					len(tag), len(hkey))
			}

			if v.isTLSAuth() {
				if v.KeyDirection == nil {
					t.Error("tls-auth vector records no key direction")
				} else if *v.KeyDirection != 0 && *v.KeyDirection != 1 {
					t.Errorf("key_direction %d, want 0 or 1", *v.KeyDirection)
				}
				if v.CipherKey != "" || v.CipherKeyOffset != -1 {
					t.Error("tls-auth installs no cipher; a cipher key here means the capture mislabelled something")
				}
			} else {
				if v.KeyDirection != nil {
					t.Error("tls-crypt has no --key-direction; recording one invites an implementation to honour it")
				}
				if v.Digest != "SHA256" {
					t.Errorf("tls-crypt digest %q, want SHA256 (tls_crypt_kt() fixes it)", v.Digest)
				}
				mustHexLen(t, "cipher_key", v.CipherKey, 32)
				mustHexLen(t, "tag", v.Tag, tlsCryptTagLen)
			}
		})

		wraps[v.Wrap] = true
		staticKey[v.StaticKey] = true
		if prev, dup := wires[v.Wire]; dup {
			t.Errorf("%s and %s recorded the same wire bytes; each vector must be its own packet",
				prev, v.Name)
		}
		wires[v.Wire] = v.Name

		shape := "payload"
		if v.Opcode == 7 || v.Opcode == 8 {
			shape = "hardreset"
		}
		shapes[v.Wrap+"/"+shape] = true

		if v.isTLSAuth() {
			authDig[v.Digest] = true
			if v.KeyDirection != nil {
				authKD[*v.KeyDirection] = true
			}
		}
	}

	if !wraps["tls-auth"] || !wraps["tls-crypt"] {
		t.Errorf("wraps covered: %v, want both tls-auth and tls-crypt", keysOf(wraps))
	}
	if !authKD[0] || !authKD[1] {
		t.Errorf("tls-auth key directions covered: %v, want both 0 and 1", intKeysOf(authKD))
	}
	if !authDig["SHA1"] || !authDig["SHA256"] {
		t.Errorf("tls-auth digests covered: %v, want both SHA1 and SHA256", keysOf(authDig))
	}
	for _, want := range []string{
		"tls-auth/hardreset", "tls-auth/payload",
		"tls-crypt/hardreset", "tls-crypt/payload",
	} {
		if !shapes[want] {
			t.Errorf("no %s vector; the opening packet has no ack array and the general case does, "+
				"and a wrap has to be right for both", want)
		}
	}
	if len(staticKey) < 2 {
		t.Error("every vector shares one static key; the capture is supposed to generate a fresh one per run")
	}
}

// keysOf renders a set of strings for an error message.
func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// intKeysOf renders a set of ints for an error message.
func intKeysOf(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// -------------------------------------------------------------------------
// Structure
// -------------------------------------------------------------------------

// TestVectorsDecomposeAsRecorded checks that each vector's fields fit together
// the way its provenance says they do, so that a hand-edit, a truncated field
// or a re-capture against a different OpenVPN series shows up structurally
// rather than as an inscrutable tag mismatch in the wraps built on top.
func TestVectorsDecomposeAsRecorded(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			static := mustHexLen(t, "static_key", v.StaticKey, staticKeyLen)
			hkey := mustHex(t, "hmac_key", v.HMACKey)
			plain := mustHex(t, "plain", v.Plain)
			tag := mustHex(t, "tag", v.Tag)
			authInput := mustHex(t, "auth_input", v.AuthInput)
			wire := mustHex(t, "wire", v.Wire)
			pid := mustHexLen(t, "replay_packet_id", v.ReplayPacketID, 4)
			ts := mustHexLen(t, "replay_timestamp", v.ReplayTimestamp, 4)

			// The installed key really is a slice of the static key at
			// the recorded offset — the fact tls-auth needs in order to
			// select halves by key-direction.
			if got := sliceAt(static, v.HMACKeyOffset, len(hkey)); !bytes.Equal(got, hkey) {
				t.Errorf("hmac_key is not static_key[%d:%d]", v.HMACKeyOffset, v.HMACKeyOffset+len(hkey))
			}

			header, rest := plain[:headerLen], plain[headerLen:]

			if v.isTLSAuth() {
				// HMAC input: packet_id ‖ timestamp ‖ the whole plain packet.
				want := concat(pid, ts, plain)
				if !bytes.Equal(authInput, want) {
					t.Errorf("auth_input is not packet_id ‖ timestamp ‖ plain: %s",
						describeDiff(authInput, want))
				}
				// Wire: header ‖ hmac ‖ packet_id ‖ timestamp ‖ rest.
				wantWire := concat(header, tag, pid, ts, rest)
				if !bytes.Equal(wire, wantWire) {
					t.Errorf("wire is not header ‖ hmac ‖ packet_id ‖ timestamp ‖ rest: %s",
						describeDiff(wire, wantWire))
				}
				return
			}

			ckey := mustHexLen(t, "cipher_key", v.CipherKey, 32)
			if got := sliceAt(static, v.CipherKeyOffset, len(ckey)); !bytes.Equal(got, ckey) {
				t.Errorf("cipher_key is not static_key[%d:%d]", v.CipherKeyOffset, v.CipherKeyOffset+len(ckey))
			}

			// HMAC input: header ‖ packet_id ‖ timestamp ‖ plaintext — the
			// wire order, which is *not* what tls-auth does.
			want := concat(header, pid, ts, rest)
			if !bytes.Equal(authInput, want) {
				t.Errorf("auth_input is not header ‖ packet_id ‖ timestamp ‖ plaintext: %s",
					describeDiff(authInput, want))
			}
			// Wire: header ‖ packet_id ‖ timestamp ‖ tag ‖ ciphertext.
			prefix := concat(header, pid, ts, tag)
			if len(wire) != len(prefix)+len(rest) {
				t.Fatalf("wire is %d bytes, want %d: AES-256-CTR is a stream mode, so the "+
					"ciphertext must be exactly as long as the %d-byte plaintext",
					len(wire), len(prefix)+len(rest), len(rest))
			}
			if !bytes.Equal(wire[:len(prefix)], prefix) {
				t.Errorf("wire does not open with header ‖ packet_id ‖ timestamp ‖ tag: %s",
					describeDiff(wire[:len(prefix)], prefix))
			}
		})
	}
}

// sliceAt returns static[off:off+n], or nil when that is out of range.
func sliceAt(b []byte, off, n int) []byte {
	if off < 0 || n < 0 || off+n > len(b) {
		return nil
	}
	return b[off : off+n]
}

// concat joins byte slices. Every construction under test is a concatenation
// in some order, so spelling them all this way keeps the orders comparable at
// a glance.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// -------------------------------------------------------------------------
// The answer
// -------------------------------------------------------------------------

// TestVectorsCarryTheAnswerTheyClaim recomputes each recorded tag, and each
// tls-crypt ciphertext, from the recorded inputs. It consumes auth_input
// verbatim rather than assembling it, so what it establishes is only that the
// recorded tag is reachable: these bytes, this key and this digest produce it.
func TestVectorsCarryTheAnswerTheyClaim(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			hkey := mustHex(t, "hmac_key", v.HMACKey)
			authInput := mustHex(t, "auth_input", v.AuthInput)
			tag := mustHex(t, "tag", v.Tag)

			got := mac(newHash(t, v.Digest), hkey, authInput)
			if !bytes.Equal(got, tag) {
				t.Fatalf("recomputed %s tag does not match the captured one: %s\n"+
					"  the vector file is internally inconsistent — recapture it\n"+
					"   got: %x\n  want: %x",
					v.Digest, describeDiff(got, tag), got, tag)
			}

			if v.isTLSAuth() {
				return
			}

			// tls-crypt: AES-256-CTR over the plaintext with the IV taken
			// from the leading 16 bytes of the tag — the MAC is computed
			// first and then supplies the IV.
			ckey := mustHexLen(t, "cipher_key", v.CipherKey, 32)
			plain := mustHex(t, "plain", v.Plain)
			wire := mustHex(t, "wire", v.Wire)
			ctOff := headerLen + replayLen + tlsCryptTagLen
			if len(wire) < ctOff {
				t.Fatalf("wire is %d bytes, shorter than the %d-byte tls-crypt header", len(wire), ctOff)
			}
			gotCT := ctr(t, ckey, tag[:tlsCryptIVLen], plain[headerLen:])
			if !bytes.Equal(gotCT, wire[ctOff:]) {
				t.Fatalf("recomputed ciphertext does not match the captured one: %s\n"+
					"   got: %x\n  want: %x",
					describeDiff(gotCT, wire[ctOff:]), gotCT, wire[ctOff:])
			}
		})
	}
}

// mac computes HMAC(key, msg) with the given hash.
func mac(h func() hash.Hash, key, msg []byte) []byte {
	m := hmac.New(h, key)
	m.Write(msg)
	return m.Sum(nil)
}

// ctr runs AES-CTR over src with the given key and IV.
func ctr(t *testing.T, key, iv, src []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	out := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(out, src)
	return out
}

// -------------------------------------------------------------------------
// Discrimination — the point of the capture
// -------------------------------------------------------------------------

// TestVectorsDiscriminateFieldOrderAndKeySelection pins that the vectors are
// worth having: a vector a wrong implementation also satisfies proves nothing.
// It enumerates the ways a careful reader gets tls-auth and tls-crypt wrong —
// hashing in wire order, borrowing the other wrap's order, dropping the header
// from the digest, taking the key from the wrong half of the static key or from
// the cipher half — and asserts that none reproduces the recorded tag.
func TestVectorsDiscriminateFieldOrderAndKeySelection(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			static := mustHexLen(t, "static_key", v.StaticKey, staticKeyLen)
			hkey := mustHex(t, "hmac_key", v.HMACKey)
			plain := mustHex(t, "plain", v.Plain)
			tag := mustHex(t, "tag", v.Tag)
			pid := mustHexLen(t, "replay_packet_id", v.ReplayPacketID, 4)
			ts := mustHexLen(t, "replay_timestamp", v.ReplayTimestamp, 4)
			h := newHash(t, v.Digest)
			header, rest := plain[:headerLen], plain[headerLen:]

			// Wrong orderings, hashed under the *right* key so that only the
			// ordering is on trial.
			orders := []struct {
				name  string
				input []byte
			}{
				{"wire order (header first, replay header after it)", concat(header, pid, ts, rest)},
				{"replay header appended rather than prepended", concat(plain, pid, ts)},
				{"header omitted from the digest", concat(pid, ts, rest)},
				{"replay header omitted from the digest", plain},
				{"packet id and timestamp swapped", concat(ts, pid, plain)},
				{"session id omitted, opcode kept", concat(pid, ts, plain[:1], rest)},
			}
			if !v.isTLSAuth() {
				// For tls-crypt the first row above is the correct order, so
				// swap in tls-auth's instead: implementing the second wrap by
				// analogy with the first is the live risk here.
				orders[0] = struct {
					name  string
					input []byte
				}{"tls-auth's order (replay header first)", concat(pid, ts, plain)}
			}
			for _, o := range orders {
				got := mac(h, hkey, o.input)
				if bytes.Equal(got, tag) {
					t.Errorf("%s produces the recorded tag — the vector does not discriminate "+
						"this ordering, and an implementation that got it wrong would pass", o.name)
				}
			}

			// Wrong key material, over the right input so that only the
			// key selection is on trial. Every candidate below is a
			// plausible misreading of the two-slot layout.
			authInput := mustHex(t, "auth_input", v.AuthInput)
			n := len(hkey)
			keys := []struct {
				name string
				key  []byte
			}{
				{"the other direction's HMAC material", sliceAt(static, (v.HMACKeyOffset+keySlotLen)%staticKeyLen, n)},
				{"the cipher half of the same slot", sliceAt(static, v.HMACKeyOffset-64, n)},
				{"the first bytes of the static key", sliceAt(static, 0, n)},
				{"the whole 64-byte HMAC field rather than the digest-sized prefix",
					sliceAt(static, v.HMACKeyOffset, 64)},
			}
			for _, k := range keys {
				if k.key == nil || bytes.Equal(k.key, hkey) {
					continue // not a distinct candidate for this vector
				}
				got := mac(h, k.key, authInput)
				if bytes.Equal(got, tag) {
					t.Errorf("%s produces the recorded tag — the vector does not discriminate "+
						"this key selection", k.name)
				}
			}

			if v.isTLSAuth() {
				return
			}

			// tls-crypt's cipher, where the IV is the interesting choice: it
			// comes from the tag, and both "the other half of the tag" and
			// "the replay header, zero-padded" are readings someone will make.
			ckey := mustHexLen(t, "cipher_key", v.CipherKey, 32)
			wire := mustHex(t, "wire", v.Wire)
			wantCT := wire[headerLen+replayLen+tlsCryptTagLen:]
			if len(rest) == 0 {
				t.Skip("no ciphertext in this packet; the IV candidates have nothing to act on")
			}
			ivs := []struct {
				name string
				iv   []byte
			}{
				{"the trailing 16 bytes of the tag", tag[tlsCryptTagLen-tlsCryptIVLen:]},
				{"the replay header, zero-padded", concat(pid, ts, make([]byte, tlsCryptIVLen-replayLen))},
				{"a zero IV", make([]byte, tlsCryptIVLen)},
			}
			for _, iv := range ivs {
				if bytes.Equal(iv.iv, tag[:tlsCryptIVLen]) {
					continue
				}
				if bytes.Equal(ctr(t, ckey, iv.iv, rest), wantCT) {
					t.Errorf("%s produces the recorded ciphertext — the vector does not "+
						"discriminate the IV", iv.name)
				}
			}
			if other := sliceAt(static, (v.CipherKeyOffset+keySlotLen)%staticKeyLen, 32); other != nil &&
				!bytes.Equal(other, ckey) {
				if bytes.Equal(ctr(t, other, tag[:tlsCryptIVLen], rest), wantCT) {
					t.Error("the other direction's cipher material produces the recorded ciphertext")
				}
			}
			if hkeyAsCipher := mustHex(t, "hmac_key", v.HMACKey); len(hkeyAsCipher) == 32 &&
				!bytes.Equal(hkeyAsCipher, ckey) {
				if bytes.Equal(ctr(t, hkeyAsCipher, tag[:tlsCryptIVLen], rest), wantCT) {
					t.Error("Ka used as Ke produces the recorded ciphertext")
				}
			}
		})
	}
}

// -------------------------------------------------------------------------
// The key-direction rule
// -------------------------------------------------------------------------

// TestKeyDirectionSelectsHalvesConsistently states, as a measured rule, which
// bytes of the 256-byte static key each peer sends with:
//
//	tls-auth,  key-direction 0:  outgoing HMAC key = static_key[64:64+n]
//	tls-auth,  key-direction 1:  outgoing HMAC key = static_key[192:192+n]
//	tls-crypt, client:           Ke = static_key[128:160], Ka = static_key[192:224]
//	tls-crypt, server:           Ke = static_key[0:32],    Ka = static_key[64:96]
//
// A static key is two 128-byte slots of 64 cipher bytes followed by 64 HMAC
// bytes (struct key/key2, src/openvpn/crypto.h). key-direction 0 sends with
// slot 0 and receives with slot 1, and 1 is the reverse; the recorded direction
// is the client's, so a server-sent packet uses the complement. tls-crypt has
// no --key-direction: the server is always slot 0 and the client slot 1.
func TestKeyDirectionSelectsHalvesConsistently(t *testing.T) {
	const (
		slot0HMAC = 64
		slot1HMAC = 192
		slot0Ciph = 0
		slot1Ciph = 128
	)
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.isTLSAuth() {
				if v.KeyDirection == nil {
					t.Fatal("tls-auth vector has no key direction")
				}
				// The recorded direction is the client's; the server runs the
				// complement, which is what testenv/matrix_entries.go configures.
				sendersDirection := *v.KeyDirection
				if v.Sender == "server" {
					sendersDirection = 1 - sendersDirection
				}
				want := slot0HMAC
				if sendersDirection == 1 {
					want = slot1HMAC
				}
				if v.HMACKeyOffset != want {
					t.Errorf("%s sends with static_key[%d:], want [%d:] for key-direction %d",
						v.Sender, v.HMACKeyOffset, want, sendersDirection)
				}
				return
			}

			wantCiph, wantHMAC := slot1Ciph, slot1HMAC // client: KEY_DIRECTION_INVERSE
			if v.Sender == "server" {
				wantCiph, wantHMAC = slot0Ciph, slot0HMAC // KEY_DIRECTION_NORMAL
			}
			if v.CipherKeyOffset != wantCiph {
				t.Errorf("tls-crypt %s Ke is static_key[%d:], want [%d:]",
					v.Sender, v.CipherKeyOffset, wantCiph)
			}
			if v.HMACKeyOffset != wantHMAC {
				t.Errorf("tls-crypt %s Ka is static_key[%d:], want [%d:]",
					v.Sender, v.HMACKeyOffset, wantHMAC)
			}
		})
	}
}
