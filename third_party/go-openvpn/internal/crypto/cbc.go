// CBC cipher implementation for the OpenVPN3 data channel.
//
// AES-CBC authenticated by a separate HMAC is the legacy cipher mode used
// when the server does not negotiate an AEAD cipher. The wire layout for the
// body portion of a P_DATA_V2 packet in CBC mode is:
//
//	[HMAC (N B)][random IV (16 B)][AES-CBC ciphertext (padded to 16 B)]
//
// N is the digest's output length — 20 for SHA1, 32 for SHA256, 64 for SHA512
// — and is *not* a constant: every length and offset below comes from the
// digest the cipher was built with. The HMAC covers IV || ciphertext; the
// P_DATA_V2 header is not authenticated here, unlike GCM, where it is the AAD.
// The plaintext carries a 4-byte big-endian packet_id prefix prepended by the
// caller, so replay protection works the same way as for GCM.
//
// On SHA1: OpenVPN's `auth` default is SHA1, so a stock client talks SHA1 to
// any peer whose configuration names no digest. The digest in use is whatever
// that configuration says — a protocol requirement, not a security choice this
// client is free to make.
//
// Reference: openvpn3-core crypto/cipher.hpp, ssl/proto.hpp (P_DATA_V2 CBC
// path); openvpn3-core crypto/static_key.hpp for the 64-byte key slots the
// two keys are sliced from.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // protocol requirement, not a security choice — see the SHA1 note above
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"strings"
)

// Digest names the HMAC hash for the CBC data-channel path. The tag length on
// the wire and the HMAC key length are both the digest's output length, so
// this one value fixes the whole CBC layout.
//
// Reference: OpenVPN's `auth` directive; openvpn3-core crypto/digestapi.hpp.
type Digest int

const (
	// DigestSHA1 is HMAC-SHA1: a 20-byte tag and a 20-byte key. It is
	// OpenVPN's default when a profile carries no `auth` directive.
	DigestSHA1 Digest = iota
	// DigestSHA256 is HMAC-SHA256: a 32-byte tag and a 32-byte key.
	DigestSHA256
	// DigestSHA512 is HMAC-SHA512: a 64-byte tag and a 64-byte key — the
	// whole of the 64-byte static-key slot, with nothing left over.
	DigestSHA512
)

// Size returns the digest's output length in bytes. It is simultaneously the
// HMAC key length, the wire tag length and the amount of the 64-byte
// static-key slot the digest consumes.
func (d Digest) Size() int {
	switch d {
	case DigestSHA1:
		return sha1.Size // 20
	case DigestSHA256:
		return sha256.Size // 32
	case DigestSHA512:
		return sha512.Size // 64
	default:
		return 0
	}
}

// String returns the OpenVPN `auth` name for the digest, or a placeholder
// naming the numeric value when it is outside the defined set.
func (d Digest) String() string {
	switch d {
	case DigestSHA1:
		return "SHA1"
	case DigestSHA256:
		return "SHA256"
	case DigestSHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("Digest(%d)", int(d))
	}
}

// Hash returns the hash constructor for the digest, or nil when the value is
// outside the defined set. It is exported because tls-auth's HMAC is the same
// --auth digest as the CBC data channel's, and internal/wrap must not carry a
// second copy of this switch for the two to drift apart.
func (d Digest) Hash() func() hash.Hash {
	switch d {
	case DigestSHA1:
		return sha1.New
	case DigestSHA256:
		return sha256.New
	case DigestSHA512:
		return sha512.New
	default:
		return nil
	}
}

// DefaultAuthName is the digest OpenVPN uses when a profile names none.
//
// openvpn(8) documents "--auth alg ... The default is SHA1" and openvpn3-core
// inherits it. The three places that need it — the profile parser's default,
// the data-channel resolver and the tls-auth wrap — take it from here, so the
// value cannot disagree with itself.
const DefaultAuthName = "SHA1"

// ParseDigest maps an OpenVPN `auth` name to a Digest. Matching is
// case-insensitive, and both the hyphenated and unhyphenated spellings are
// accepted ("SHA1" and "SHA-1"). An unrecognised name is an error naming the
// digest, so a caller can report it as it reports an unrecognised cipher.
func ParseDigest(name string) (Digest, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SHA1", "SHA-1":
		return DigestSHA1, nil
	case "SHA256", "SHA-256":
		return DigestSHA256, nil
	case "SHA512", "SHA-512":
		return DigestSHA512, nil
	default:
		return 0, fmt.Errorf("crypto: unsupported digest %q", name)
	}
}

// CBCCipher encrypts and decrypts data-channel packets with AES-CBC and an
// HMAC digest.
//
// Wire body layout (excluding the 4-byte P_DATA_V2 header):
//
//	[HMAC (N B)][IV (16 B)][ciphertext (multiple of 16 B)]
//
// N is Digest.Size() for the digest the cipher was built with: 20, 32 or 64.
// The HMAC authenticates IV || ciphertext.
// The plaintext is: [packet_id (4 B BE)][ip_packet...][PKCS#7 padding]
type CBCCipher struct {
	block   cipher.Block
	hmacKey []byte // Digest.Size() bytes — the prefix of the 64-byte slot
	digest  Digest
	newHash func() hash.Hash
	tagLen  int // == digest.Size(), cached because every packet needs it
}

// NewCBCCipher builds an AES-CBC cipher authenticated with HMAC-digest.
//
// aesKey is 16, 24 or 32 bytes, selecting AES-128, AES-192 or AES-256; the
// length is a property of the negotiated cipher — see LookupCipher.
//
// hmacKey is the digest's output length. The key comes from a 64-byte slot, so
// a shorter digest uses a prefix of it: passing the whole slot is the expected
// call and this constructor takes the prefix itself. That matters because HMAC
// hashes any key longer than the hash block size, so a 64-byte slot and its
// 20-byte prefix are *different* SHA1 keys and only the prefix interoperates.
//
// Reference: OpenVPN init_key_ctx() sizes the HMAC key at the digest's output
// length (md_kt_size) and reads it from the front of the 64-byte static-key
// slot; openvpn3-core crypto/static_key.hpp slice().
func NewCBCCipher(aesKey, hmacKey []byte, digest Digest) (*CBCCipher, error) {
	switch len(aesKey) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("crypto: CBC AES key must be 16, 24 or 32 bytes, got %d", len(aesKey))
	}
	newHash := digest.Hash()
	if newHash == nil {
		return nil, fmt.Errorf("crypto: CBC unknown digest %d", int(digest))
	}
	tagLen := digest.Size()
	if len(hmacKey) < tagLen {
		return nil, fmt.Errorf("crypto: CBC HMAC key for %s must be at least %d bytes, got %d",
			digest, tagLen, len(hmacKey))
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: CBC AES key: %w", err)
	}
	hk := make([]byte, tagLen)
	copy(hk, hmacKey[:tagLen])
	return &CBCCipher{
		block:   block,
		hmacKey: hk,
		digest:  digest,
		newHash: newHash,
		tagLen:  tagLen,
	}, nil
}

// Digest returns the HMAC digest this cipher authenticates with.
func (c *CBCCipher) Digest() Digest { return c.digest }

// TagLen returns the length in bytes of the HMAC tag that precedes the IV on
// the wire. It is the digest's output length.
func (c *CBCCipher) TagLen() int { return c.tagLen }

// Seal encrypts plaintext (which must already include a 4-byte packet_id
// prefix) and returns [HMAC(N)][IV(16)][ciphertext], where N is TagLen().
//
// aad is unused for CBC (the P_DATA_V2 header is NOT authenticated in the
// legacy HMAC path). packetID is ignored because the caller embeds it in
// plaintext before calling Seal.
func (c *CBCCipher) Seal(_ uint32, plaintext, _ []byte) []byte {
	bs := c.block.BlockSize() // 16

	// Generate random IV.
	iv := make([]byte, bs)
	if _, err := rand.Read(iv); err != nil {
		panic("crypto: rand.Read failed: " + err.Error())
	}

	// PKCS#7 pad plaintext.
	padded := pkcs7Pad(plaintext, bs)

	// Encrypt with AES-CBC.
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(c.block, iv).CryptBlocks(ct, padded)

	// Compute the HMAC over IV || ciphertext.
	mac := hmac.New(c.newHash, c.hmacKey)
	mac.Write(iv)
	mac.Write(ct)
	tag := mac.Sum(nil) // c.tagLen bytes

	// Wire: HMAC || IV || ciphertext
	out := make([]byte, c.tagLen+bs+len(ct))
	copy(out[:c.tagLen], tag)
	copy(out[c.tagLen:c.tagLen+bs], iv)
	copy(out[c.tagLen+bs:], ct)
	return out
}

// Open decrypts a CBC body: [HMAC(N)][IV(16)][ciphertext], with N = TagLen().
// Returns the plaintext (with the 4-byte packet_id prefix still present) or
// an error if HMAC verification fails or padding is corrupt.
//
// aad is unused. packetID is ignored; the caller validates it from the plaintext.
func (c *CBCCipher) Open(_ uint32, body, _ []byte) ([]byte, error) {
	bs := c.block.BlockSize()
	hmacLen := c.tagLen
	minLen := hmacLen + bs + bs // HMAC + IV + at least one ciphertext block
	if len(body) < minLen {
		return nil, fmt.Errorf("crypto: CBC body too short: %d bytes, want at least %d", len(body), minLen)
	}
	if (len(body)-hmacLen-bs)%bs != 0 {
		return nil, fmt.Errorf("crypto: CBC ciphertext length not block-aligned")
	}

	tag := body[:hmacLen]
	iv := body[hmacLen : hmacLen+bs]
	ct := body[hmacLen+bs:]

	// Verify HMAC.
	mac := hmac.New(c.newHash, c.hmacKey)
	mac.Write(iv)
	mac.Write(ct)
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(tag, expected) != 1 {
		return nil, fmt.Errorf("crypto: CBC HMAC authentication failed")
	}

	// Decrypt.
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(c.block, iv).CryptBlocks(plain, ct)

	// Remove PKCS#7 padding.
	unpadded, err := pkcs7Unpad(plain, bs)
	if err != nil {
		return nil, fmt.Errorf("crypto: CBC: %w", err)
	}
	return unpadded, nil
}

// IsAEAD returns false because CBC uses a separate HMAC for authentication.
func (c *CBCCipher) IsAEAD() bool { return false }

// Overhead returns the maximum overhead: TagLen() (HMAC) + 16 (IV) + up to 16
// (PKCS#7 padding) — 52 bytes for SHA1, 64 for SHA256, 96 for SHA512. It is
// also, numerically, the smallest body this cipher can produce (tag, IV and
// one full block), which is what Open's minimum-length check and the data
// channel's short-packet check are both derived from.
func (c *CBCCipher) Overhead() int { return c.tagLen + 16 + 16 }

// pkcs7Pad pads src to a multiple of blockSize using PKCS#7.
func pkcs7Pad(src []byte, blockSize int) []byte {
	padLen := blockSize - (len(src) % blockSize)
	padded := make([]byte, len(src)+padLen)
	copy(padded, src)
	for i := len(src); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding from src.
func pkcs7Unpad(src []byte, blockSize int) ([]byte, error) {
	if len(src) == 0 || len(src)%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7: invalid padded length %d", len(src))
	}
	padLen := int(src[len(src)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, fmt.Errorf("pkcs7: invalid padding value %d", padLen)
	}
	for i := len(src) - padLen; i < len(src); i++ {
		if src[i] != byte(padLen) {
			return nil, fmt.Errorf("pkcs7: inconsistent padding bytes")
		}
	}
	return src[:len(src)-padLen], nil
}
