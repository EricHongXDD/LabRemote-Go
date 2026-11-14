package crypto_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // protocol requirement, for the same reason cbc.go imports it
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/datachannel"
)

// TestUnsupportedCipherErrorNamesIt pins that datachannel.ResolveParams names
// the cipher it refuses: the client maps this error to diag.ClassUnsupported
// and puts the name in the report.
func TestUnsupportedCipherErrorNamesIt(t *testing.T) {
	_, _, err := datachannel.ResolveParams("CHACHA20-POLY1305", "SHA256")
	if err == nil {
		t.Fatal("ResolveParams accepted a cipher this client cannot construct")
	}
	if !strings.Contains(err.Error(), "CHACHA20-POLY1305") {
		t.Errorf("error %q does not name the cipher", err)
	}
}

func TestGCMOpenRejectsAChangedContext(t *testing.T) {
	cases := []struct {
		name             string
		sealID, openID   uint32
		sealAAD, openAAD []byte
	}{
		{"packet ID", 1, 2, nil, nil},
		{"AAD", 0, 0, []byte("aad1"), []byte("aad2")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gc, err := crypto.NewGCMCipher(bytes.Repeat([]byte{0xBB}, 32), make([]byte, 8))
			if err != nil {
				t.Fatal(err)
			}
			ct := gc.Seal(tc.sealID, []byte("data"), tc.sealAAD)
			if _, err := gc.Open(tc.openID, ct, tc.openAAD); err == nil {
				t.Fatalf("a changed %s still authenticated", tc.name)
			}
		})
	}
}

func TestNewGCMCipherBadTail(t *testing.T) {
	key := make([]byte, 32)
	_, err := crypto.NewGCMCipher(key, make([]byte, 3)) // too short
	if err == nil {
		t.Fatal("expected error for nonce tail that is too short")
	}
}

// TestIsAEAD pins which mode reports itself as AEAD. The data channel picks a
// whole packet layout from this one bit: true means the header is the AAD and
// the tag is GCM's, false means the header is unauthenticated and the body
// carries an HMAC.
func TestIsAEAD(t *testing.T) {
	gc, err := crypto.NewGCMCipher(make([]byte, 32), make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	if !gc.IsAEAD() {
		t.Error("GCM should report IsAEAD() == true")
	}
	cbc, err := crypto.NewCBCCipher(make([]byte, 32), make([]byte, 32), crypto.DigestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if cbc.IsAEAD() {
		t.Error("CBC should report IsAEAD() == false")
	}
}

func TestCBCBadKeyLen(t *testing.T) {
	// 16 bytes is AES-128 and legal; the invalid lengths are the ones
	// that are not an AES key size at all.
	for _, n := range []int{0, 8, 15, 17, 31, 33, 64} {
		if _, err := crypto.NewCBCCipher(make([]byte, n), make([]byte, 64), crypto.DigestSHA256); err == nil {
			t.Errorf("NewCBCCipher: expected error for %d-byte AES key", n)
		}
	}
	for _, n := range []int{16, 24, 32} {
		if _, err := crypto.NewCBCCipher(make([]byte, n), make([]byte, 64), crypto.DigestSHA256); err != nil {
			t.Errorf("NewCBCCipher: %d-byte AES key rejected: %v", n, err)
		}
	}
}

// ---- The cipher table -------------------------------------------------------

// TestCipherTableIsConstructible builds every cipher the table names. IV_CIPHERS
// is generated from CipherNames(), so a name in the table that cannot be
// constructed is one we advertise and then fail to honour.
func TestCipherTableIsConstructible(t *testing.T) {
	specs := crypto.Ciphers()
	if len(specs) == 0 {
		t.Fatal("Ciphers() is empty")
	}
	for _, spec := range specs {
		t.Run(spec.Name, func(t *testing.T) {
			if spec.Mode == crypto.ModeNone {
				if spec.KeyLen != 0 || !spec.UsesDigest() {
					t.Fatal("none 模式必须使用零长度加密密钥和 HMAC")
				}
				for _, digest := range []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512} {
					if _, err := crypto.NewNullCipher(digest, bytes.Repeat([]byte{0x5B}, 64)); err != nil {
						t.Fatal(err)
					}
				}
				return
			}
			if spec.KeyLen != 16 && spec.KeyLen != 24 && spec.KeyLen != 32 {
				t.Fatalf("KeyLen %d is not an AES key size", spec.KeyLen)
			}
			key := bytes.Repeat([]byte{0x5A}, spec.KeyLen)
			if spec.UsesDigest() {
				if spec.Mode != crypto.ModeCBC {
					t.Fatalf("UsesDigest() true but Mode is %v", spec.Mode)
				}
				slot := bytes.Repeat([]byte{0x5B}, 64)
				for _, d := range []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512} {
					if _, err := crypto.NewCBCCipher(key, slot, d); err != nil {
						t.Fatalf("NewCBCCipher(%s, %s): %v", spec.Name, d, err)
					}
				}
				return
			}
			if spec.Mode != crypto.ModeAEAD {
				t.Fatalf("UsesDigest() false but Mode is %v", spec.Mode)
			}
			if _, err := crypto.NewGCMCipher(key, make([]byte, 8)); err != nil {
				t.Fatalf("NewGCMCipher(%s): %v", spec.Name, err)
			}
		})
	}
}

// TestCipherNamesMatchTable pins the advertisement list itself. The exact set is
// load-bearing: CHACHA20-POLY1305 is out of scope and must not appear in it.
func TestCipherNamesMatchTable(t *testing.T) {
	want := []string{
		"AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
		"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "none",
	}
	got := crypto.CipherNames()
	if len(got) != len(want) {
		t.Fatalf("CipherNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CipherNames()[%d] = %q, want %q (order is the advertisement order)", i, got[i], want[i])
		}
	}
	for _, name := range got {
		if strings.Contains(name, "CHACHA") {
			t.Errorf("CipherNames() advertises %q, which is out of scope", name)
		}
	}
	// The returned slice must be a copy: a caller that sorts or truncates it
	// must not be able to change what the next caller sees.
	got[0] = "MUTATED"
	if crypto.CipherNames()[0] == "MUTATED" {
		t.Error("CipherNames() exposes the table's backing array")
	}
	specs := crypto.Ciphers()
	specs[0].Name = "MUTATED"
	if crypto.Ciphers()[0].Name == "MUTATED" {
		t.Error("Ciphers() exposes the table's backing array")
	}
}

func TestLookupCipher(t *testing.T) {
	cases := []struct {
		name    string
		ok      bool
		keyLen  int
		mode    crypto.Mode
		digestP bool
	}{
		{"AES-128-CBC", true, 16, crypto.ModeCBC, true},
		{"AES-192-CBC", true, 24, crypto.ModeCBC, true},
		{"AES-256-CBC", true, 32, crypto.ModeCBC, true},
		{"AES-128-GCM", true, 16, crypto.ModeAEAD, false},
		{"AES-192-GCM", true, 24, crypto.ModeAEAD, false},
		{"AES-256-GCM", true, 32, crypto.ModeAEAD, false},
		{" aes-256-gcm ", true, 32, crypto.ModeAEAD, false},
		{"CHACHA20-POLY1305", false, 0, 0, false},
		{"BF-CBC", false, 0, 0, false},
		{"", false, 0, 0, false},
	}
	for _, c := range cases {
		spec, ok := crypto.LookupCipher(c.name)
		if ok != c.ok {
			t.Errorf("LookupCipher(%q): ok=%v, want %v", c.name, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if spec.KeyLen != c.keyLen {
			t.Errorf("LookupCipher(%q).KeyLen = %d, want %d", c.name, spec.KeyLen, c.keyLen)
		}
		if spec.Mode != c.mode {
			t.Errorf("LookupCipher(%q).Mode = %v, want %v", c.name, spec.Mode, c.mode)
		}
		if spec.UsesDigest() != c.digestP {
			t.Errorf("LookupCipher(%q).UsesDigest() = %v, want %v", c.name, spec.UsesDigest(), c.digestP)
		}
	}
}

// ---- Digest -----------------------------------------------------------------

func TestDigestSizeAndName(t *testing.T) {
	cases := []struct {
		d    crypto.Digest
		size int
		name string
	}{
		{crypto.DigestSHA1, 20, "SHA1"},
		{crypto.DigestSHA256, 32, "SHA256"},
		{crypto.DigestSHA512, 64, "SHA512"},
	}
	for _, c := range cases {
		if got := c.d.Size(); got != c.size {
			t.Errorf("%v.Size() = %d, want %d", c.d, got, c.size)
		}
		if got := c.d.String(); got != c.name {
			t.Errorf("Digest(%d).String() = %q, want %q", int(c.d), got, c.name)
		}
	}
}

func TestParseDigest(t *testing.T) {
	cases := []struct {
		name string
		want crypto.Digest
		ok   bool
	}{
		{"SHA1", crypto.DigestSHA1, true},
		{"sha1", crypto.DigestSHA1, true},
		{"SHA-1", crypto.DigestSHA1, true},
		{"SHA256", crypto.DigestSHA256, true},
		{"SHA512", crypto.DigestSHA512, true},
		{"MD5", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, err := crypto.ParseDigest(c.name)
		if c.ok {
			if err != nil || got != c.want {
				t.Errorf("ParseDigest(%q) = (%v,%v), want (%v,nil)", c.name, got, err, c.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseDigest(%q): expected error", c.name)
		} else if c.name != "" && !strings.Contains(err.Error(), c.name) {
			t.Errorf("ParseDigest(%q): error %q does not name the digest", c.name, err)
		}
	}
}

// ---- The full CBC matrix ----------------------------------------------------

// cbcMatrix is three AES key lengths crossed with three digests.
func cbcMatrix() []struct {
	keyLen int
	digest crypto.Digest
} {
	var out []struct {
		keyLen int
		digest crypto.Digest
	}
	for _, keyLen := range []int{16, 24, 32} {
		for _, d := range []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512} {
			out = append(out, struct {
				keyLen int
				digest crypto.Digest
			}{keyLen, d})
		}
	}
	return out
}

// TestCBCMatrixSealOpen round-trips every AES key length crossed with every
// digest and checks the wire layout the round trip implies: the body is
// [HMAC(N)][IV(16)][ciphertext], with N taken from the digest.
func TestCBCMatrixSealOpen(t *testing.T) {
	for _, tc := range cbcMatrix() {
		name := fmt.Sprintf("AES-%d-CBC/%s", tc.keyLen*8, tc.digest)
		t.Run(name, func(t *testing.T) {
			aesKey := bytes.Repeat([]byte{0x11}, tc.keyLen)
			slot := bytes.Repeat([]byte{0x22}, 64)
			c, err := crypto.NewCBCCipher(aesKey, slot, tc.digest)
			if err != nil {
				t.Fatalf("NewCBCCipher: %v", err)
			}
			// TagLen is the observable consequence of the digest the cipher
			// was given.
			if got, want := c.TagLen(), tc.digest.Size(); got != want {
				t.Errorf("TagLen() = %d, want %d", got, want)
			}
			// Overhead must track N, not a constant 32.
			if got, want := c.Overhead(), tc.digest.Size()+16+16; got != want {
				t.Errorf("Overhead() = %d, want %d", got, want)
			}

			plain := append([]byte{0, 0, 0, 1}, []byte("hello openvpn cbc matrix")...)
			body := c.Seal(0, plain, nil)

			// The body must be tag + IV + a whole number of blocks.
			n := tc.digest.Size()
			if len(body) < n+16+16 {
				t.Fatalf("body %d bytes, want at least %d", len(body), n+16+16)
			}
			if (len(body)-n-16)%16 != 0 {
				t.Fatalf("ciphertext of %d bytes is not block-aligned", len(body)-n-16)
			}

			got, err := c.Open(0, body, nil)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("roundtrip mismatch: got %q want %q", got, plain)
			}
		})
	}
}

// TestCBCMatrixTamperFails flips one bit in each of the three regions of the
// body — tag, IV, ciphertext — and requires authentication to fail. Flipping the
// IV matters on its own: the HMAC covers IV || ciphertext, so authenticating
// only the ciphertext would still decrypt to attacker-influenced plaintext.
func TestCBCMatrixTamperFails(t *testing.T) {
	for _, tc := range cbcMatrix() {
		name := fmt.Sprintf("AES-%d-CBC/%s", tc.keyLen*8, tc.digest)
		t.Run(name, func(t *testing.T) {
			aesKey := bytes.Repeat([]byte{0x33}, tc.keyLen)
			slot := bytes.Repeat([]byte{0x44}, 64)
			c, err := crypto.NewCBCCipher(aesKey, slot, tc.digest)
			if err != nil {
				t.Fatalf("NewCBCCipher: %v", err)
			}
			plain := append([]byte{0, 0, 0, 7}, []byte("tamper me if you can")...)
			n := tc.digest.Size()

			regions := []struct {
				what string
				off  int
			}{
				{"tag", 0},
				{"tag-last", n - 1},
				{"iv", n},
				{"iv-last", n + 15},
				{"ciphertext", n + 16},
			}
			for _, r := range regions {
				body := c.Seal(0, plain, nil)
				body[r.off] ^= 0x01
				if _, err := c.Open(0, body, nil); err == nil {
					t.Errorf("flipping a bit in the %s at offset %d still authenticated", r.what, r.off)
				}
			}
			// A bit flipped in the last ciphertext byte too.
			body := c.Seal(0, plain, nil)
			body[len(body)-1] ^= 0x80
			if _, err := c.Open(0, body, nil); err == nil {
				t.Error("flipping the last ciphertext bit still authenticated")
			}
		})
	}
}

// TestCBCHMACKeyIsSlotPrefix pins that the HMAC key is a prefix of the 64-byte
// slot: HMAC hashes a key longer than the block size and zero-pads a shorter
// one, so a slot and its 20-byte prefix are different SHA1 keys. Reference:
// OpenVPN init_key_ctx() sizes the HMAC key at md_kt_size(), the digest's
// output length, reading it from the front of the slot.
func TestCBCHMACKeyIsSlotPrefix(t *testing.T) {
	slot := make([]byte, 64)
	for i := range slot {
		slot[i] = byte(i + 1) // distinct bytes, so a prefix is not the whole
	}
	aesKey := bytes.Repeat([]byte{0x77}, 32)

	for _, d := range []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512} {
		t.Run(d.String(), func(t *testing.T) {
			n := d.Size()

			// Built from the whole slot, and built from the prefix the
			// constructor is documented to take: the same cipher.
			fromSlot, err := crypto.NewCBCCipher(aesKey, slot, d)
			if err != nil {
				t.Fatalf("NewCBCCipher(slot): %v", err)
			}
			fromPrefix, err := crypto.NewCBCCipher(aesKey, slot[:n], d)
			if err != nil {
				t.Fatalf("NewCBCCipher(prefix): %v", err)
			}
			plain := append([]byte{0, 0, 0, 3}, []byte("prefix or whole slot?")...)
			if _, err := fromPrefix.Open(0, fromSlot.Seal(0, plain, nil), nil); err != nil {
				t.Fatalf("slot-built cipher not readable by prefix-built cipher: %v", err)
			}
			if _, err := fromSlot.Open(0, fromPrefix.Seal(0, plain, nil), nil); err != nil {
				t.Fatalf("prefix-built cipher not readable by slot-built cipher: %v", err)
			}

			// Recompute the tag independently, both ways, and check which one
			// is on the wire.
			body := fromSlot.Seal(0, plain, nil)
			tag := body[:n]
			ivAndCT := body[n:]

			withPrefix := hmacSum(d, slot[:n], ivAndCT)
			if !bytes.Equal(tag, withPrefix) {
				t.Fatalf("wire tag is not HMAC-%s(slot[:%d]); the key is not the prefix", d, n)
			}
			withWholeSlot := hmacSum(d, slot, ivAndCT)
			if n == 64 {
				// SHA512 consumes the whole slot, so there is no distinction
				// to draw and the two keys are the same 64 bytes.
				if !bytes.Equal(withPrefix, withWholeSlot) {
					t.Fatal("SHA512 prefix is the whole slot; the tags must agree")
				}
				return
			}
			if bytes.Equal(tag, withWholeSlot) {
				t.Fatalf("wire tag matches HMAC-%s(whole 64-byte slot); the prefix is not being taken", d)
			}
		})
	}
}

// hmacSum computes HMAC-digest(key, msg) independently of the cipher under
// test, so the tag assertion above does not check the implementation against
// itself.
func hmacSum(d crypto.Digest, key, msg []byte) []byte {
	var h func() hash.Hash
	switch d {
	case crypto.DigestSHA1:
		h = sha1.New
	case crypto.DigestSHA256:
		h = sha256.New
	case crypto.DigestSHA512:
		h = sha512.New
	default:
		panic("hmacSum: unknown digest")
	}
	mac := hmac.New(h, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// TestCBCShortHMACKey checks that a key shorter than the digest needs is a
// clear error rather than a silently zero-padded key, and that the error says
// how short it was.
func TestCBCShortHMACKey(t *testing.T) {
	aesKey := bytes.Repeat([]byte{0x88}, 32)
	for _, d := range []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512} {
		t.Run(d.String(), func(t *testing.T) {
			short := make([]byte, d.Size()-1)
			_, err := crypto.NewCBCCipher(aesKey, short, d)
			if err == nil {
				t.Fatalf("expected error for a %d-byte HMAC key with %s", len(short), d)
			}
			msg := err.Error()
			for _, want := range []string{d.String(), fmt.Sprint(d.Size()), fmt.Sprint(len(short))} {
				if !strings.Contains(msg, want) {
					t.Errorf("error %q does not mention %q", msg, want)
				}
			}
			// Exactly the digest size is the boundary and must be accepted.
			if _, err := crypto.NewCBCCipher(aesKey, make([]byte, d.Size()), d); err != nil {
				t.Errorf("a %d-byte HMAC key was rejected for %s: %v", d.Size(), d, err)
			}
		})
	}
}

// TestCBCUnknownDigest checks that a Digest value outside the defined set is
// refused rather than producing a cipher with a nil hash constructor.
func TestCBCUnknownDigest(t *testing.T) {
	_, err := crypto.NewCBCCipher(make([]byte, 32), make([]byte, 64), crypto.Digest(99))
	if err == nil {
		t.Fatal("expected error for an undefined digest")
	}
}

// TestCBCShortBodyRejected walks the body length from zero up to one byte short
// of the smallest legal one and requires every length to be refused, for every
// digest — the minimum moves with the digest.
func TestCBCShortBodyRejected(t *testing.T) {
	for _, d := range []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512} {
		t.Run(d.String(), func(t *testing.T) {
			c, err := crypto.NewCBCCipher(make([]byte, 32), make([]byte, 64), d)
			if err != nil {
				t.Fatal(err)
			}
			minLen := d.Size() + 16 + 16
			for n := 0; n < minLen; n++ {
				if _, err := c.Open(0, make([]byte, n), nil); err == nil {
					t.Fatalf("a %d-byte body was accepted; minimum is %d", n, minLen)
				}
			}
			// A body of exactly the minimum length is long enough to reach
			// the HMAC check, which is where it must fail instead.
			_, err = c.Open(0, make([]byte, minLen), nil)
			if err == nil {
				t.Fatal("an all-zero body of minimum length authenticated")
			}
			if !strings.Contains(err.Error(), "authentication failed") {
				t.Errorf("minimum-length body failed with %q, want the HMAC check", err)
			}
		})
	}
}

// ---- GCM key lengths --------------------------------------------------------

// TestGCMKeyLengths round-trips all three AES-GCM key lengths. The key length is
// a property of the negotiated cipher (CipherSpec.KeyLen).
func TestGCMKeyLengths(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("AES-%d-GCM", keyLen*8), func(t *testing.T) {
			key := bytes.Repeat([]byte{0xAA}, keyLen)
			tail := bytes.Repeat([]byte{0x55}, 8)
			g, err := crypto.NewGCMCipher(key, tail)
			if err != nil {
				t.Fatalf("NewGCMCipher: %v", err)
			}
			if got := g.Overhead(); got != 16 {
				t.Errorf("Overhead() = %d, want 16", got)
			}
			plaintext := []byte("hello openvpn data channel")
			aad := []byte{0x09, 0x00, 0x00, 0x01}
			ct := g.Seal(1, plaintext, aad)
			if bytes.Equal(ct, plaintext) {
				t.Fatal("ciphertext equals plaintext")
			}
			pt, err := g.Open(1, ct, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("roundtrip mismatch: got %q want %q", pt, plaintext)
			}

			// A flipped bit in the tag or in the ciphertext must fail.
			for _, off := range []int{0, 15, 16, len(ct) - 1} {
				bad := make([]byte, len(ct))
				copy(bad, ct)
				bad[off] ^= 0x01
				if _, err := g.Open(1, bad, aad); err == nil {
					t.Errorf("flipping a bit at offset %d still authenticated", off)
				}
			}
		})
	}
}

// TestGCMBadKeyLengths checks that an unsupported key length is refused with
// an error that names the constraint, rather than being left to
// aes.NewCipher to describe.
func TestGCMBadKeyLengths(t *testing.T) {
	for _, n := range []int{0, 7, 15, 17, 23, 25, 31, 33, 64} {
		_, err := crypto.NewGCMCipher(make([]byte, n), make([]byte, 8))
		if err == nil {
			t.Errorf("NewGCMCipher: expected error for %d-byte key", n)
			continue
		}
		if !strings.Contains(err.Error(), "16, 24 or 32") {
			t.Errorf("NewGCMCipher(%d bytes): error %q does not name the valid lengths", n, err)
		}
	}
}
