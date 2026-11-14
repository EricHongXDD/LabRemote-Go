// Package crypto implements the OpenVPN3 data-channel cipher suite.
//
// Supported ciphers — cipherTable below is the single source of truth, and
// every other statement about our capabilities is generated from it:
//
//   - AES-128-GCM, AES-192-GCM, AES-256-GCM — AEAD, no separate digest
//   - AES-128-CBC, AES-192-CBC, AES-256-CBC — authenticated by HMAC-SHA1,
//     HMAC-SHA256 or HMAC-SHA512, selected by the profile's `auth` directive
//
// CHACHA20-POLY1305 is deliberately absent: this package implements the AES
// suite and nothing else, and because the advertisement is generated from the
// table, leaving it out here is what stops it being advertised.
//
// Reference: openvpn3-core crypto/cipher.hpp, crypto/crypto_aead.hpp
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"strings"
)

// DataCipher is the interface implemented by all supported data-channel ciphers.
//
// Seal encrypts plaintext and returns ciphertext (plus tag for AEAD modes,
// or HMAC prepended for CBC mode).  aad is the AAD header for GCM; ignored
// for CBC.  packetID is the 32-bit counter used in IV derivation.
//
// Open decrypts ciphertext (including the authentication data) and returns
// plaintext, or a non-nil error if authentication fails or the packet is
// malformed.
//
// IsAEAD reports whether the cipher is an AEAD mode (GCM). When false, the
// data channel uses the CBC-with-HMAC path.
//
// Overhead returns the number of bytes added by encryption beyond the
// plaintext length. For GCM this is 16 (tag); for CBC it is the digest's tag
// length + 16 (random IV) + up to 16 (PKCS#7 padding), so it varies with the
// negotiated digest and is not a constant.
type DataCipher interface {
	Seal(packetID uint32, plaintext, aad []byte) []byte
	Open(packetID uint32, ciphertext, aad []byte) ([]byte, error)
	IsAEAD() bool
	Overhead() int
}

// Mode distinguishes the two data-channel constructions. A caller switches on
// it to pick a constructor, so the decision is driven by the cipher table
// rather than by re-parsing the cipher's name.
type Mode int

const (
	// ModeAEAD is AES-GCM: the cipher authenticates its own output and the
	// P_DATA_V2 header is the AAD. No `auth` digest applies — OpenVPN reports
	// it as [null-digest].
	ModeAEAD Mode = iota
	// ModeCBC is AES-CBC authenticated by a separate HMAC. The profile's
	// `auth` digest selects the HMAC and therefore the wire tag length.
	ModeCBC
	// ModeNone 对应学校配置的不加密但保留 HMAC 的数据通道。
	ModeNone
)

// String returns "AEAD" or "CBC", or a placeholder naming the numeric value
// when it is outside the defined set.
func (m Mode) String() string {
	switch m {
	case ModeAEAD:
		return "AEAD"
	case ModeCBC:
		return "CBC"
	case ModeNone:
		return "NONE"
	default:
		return fmt.Sprintf("Mode(%d)", int(m))
	}
}

// CipherSpec describes one data-channel cipher this client can construct: the
// unit of the cipher table, holding everything a caller needs in order to
// slice key material and pick a constructor without re-deriving it from the
// cipher's name. It is a value; callers may keep or copy it freely.
type CipherSpec struct {
	// Name is the canonical OpenVPN spelling, as it appears in a profile's
	// `cipher` / `data-ciphers` directive, in a PUSH_REPLY and in IV_CIPHERS.
	Name string
	// KeyLen is the AES key length in bytes: 16, 24 or 32.
	KeyLen int
	// Mode selects the construction: ModeAEAD (GCM) or ModeCBC.
	Mode Mode
}

// UsesDigest reports whether an `auth` digest applies to this cipher. It is
// false for AEAD ciphers, which authenticate their own output, and true for
// CBC, where the digest chooses the HMAC and the wire tag length.
func (s CipherSpec) UsesDigest() bool { return s.Mode != ModeAEAD }

// cipherTable is the single source of truth for what this client can
// construct. The IV_CIPHERS advertisement, the accept/reject decision for a
// pushed cipher and the key length each path slices are all derived from it,
// so the advertisement cannot drift from the implementation. Order is the
// advertisement order: AEAD first, ascending key length within each mode.
//
// Reference: openvpn3-core ssl/proto.hpp parse_pushed_data_channel_options()
// validates the pushed cipher against the IV_CIPHERS list the client sent, so
// the two must describe the same set.
var cipherTable = []CipherSpec{
	{Name: "AES-128-GCM", KeyLen: 16, Mode: ModeAEAD},
	{Name: "AES-192-GCM", KeyLen: 24, Mode: ModeAEAD},
	{Name: "AES-256-GCM", KeyLen: 32, Mode: ModeAEAD},
	{Name: "AES-128-CBC", KeyLen: 16, Mode: ModeCBC},
	{Name: "AES-192-CBC", KeyLen: 24, Mode: ModeCBC},
	{Name: "AES-256-CBC", KeyLen: 32, Mode: ModeCBC},
	{Name: "none", KeyLen: 0, Mode: ModeNone},
}

// Ciphers returns every cipher this client can construct, in advertisement
// order. The returned slice is a copy; mutating it does not change the table.
func Ciphers() []CipherSpec {
	out := make([]CipherSpec, len(cipherTable))
	copy(out, cipherTable)
	return out
}

// CipherNames returns the canonical names of every cipher this client can
// construct, in advertisement order. It is the IV_CIPHERS list: join the
// result with ":".
func CipherNames() []string {
	out := make([]string, len(cipherTable))
	for i, spec := range cipherTable {
		out[i] = spec.Name
	}
	return out
}

// LookupCipher returns the CipherSpec for a cipher name, and reports whether
// the name is one this client can construct. Matching is case-insensitive and
// tolerates surrounding whitespace, because the name arrives from a profile
// directive or a PUSH_REPLY field. A false result is exactly the set of
// ciphers a caller must report as unsupported.
func LookupCipher(name string) (CipherSpec, bool) {
	want := strings.ToUpper(strings.TrimSpace(name))
	for _, spec := range cipherTable {
		if strings.EqualFold(spec.Name, want) {
			return spec, true
		}
	}
	return CipherSpec{}, false
}

// GCMCipher encrypts and decrypts data-channel packets with AES-GCM.
//
// IV construction is a concatenation, not a XOR:
//
//	iv = packetID (4 bytes, big-endian) ‖ implicit_iv (8 bytes)
//
// That is what openvpn-2.6.22 src/openvpn/crypto.c:88-99 assembles — packet id
// first, implicit part appended after it — and what openvpn3-core
// crypto/crypto_aead.hpp:66-75 lays out through set_tail. The XOR in
// openvpn3-core crypto/data_epoch.cpp:318-324 is the epoch-key data v3 nonce,
// which this cipher does not implement.
//
// The implicit IV is the 8-byte nonce tail handed to NewGCMCipher, taken from
// the HMAC key slot of the key block — a slot an AEAD cipher otherwise leaves
// unused.
type GCMCipher struct {
	aead       cipher.AEAD
	implicitIV []byte // len == aead.NonceSize()
}

// NewGCMCipher creates a GCMCipher from a raw AES key and a nonce tail.
//
//   - key:       16, 24 or 32 bytes for AES-128-GCM, AES-192-GCM or
//     AES-256-GCM. The length is a property of the negotiated cipher — see
//     LookupCipher and CipherSpec.KeyLen. It is validated here so the error
//     names the constraint rather than leaving aes.NewCipher to say "invalid
//     key size" without saying what a valid one would be.
//   - nonceTail: 8 bytes — the last 8 bytes of the 12-byte GCM nonce
//     (set from the first 8 bytes of the HMAC key slice via set_tail in
//     openvpn3-core crypto_aead.hpp).
func NewGCMCipher(key, nonceTail []byte) (*GCMCipher, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("crypto: GCM AES key must be 16, 24 or 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: AES key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM: %w", err)
	}
	const tailLen = 8
	if len(nonceTail) < tailLen {
		return nil, fmt.Errorf("crypto: nonceTail len=%d, want %d", len(nonceTail), tailLen)
	}
	iv := make([]byte, tailLen)
	copy(iv, nonceTail[:tailLen])
	return &GCMCipher{aead: aead, implicitIV: iv}, nil
}

// buildNonce constructs the 12-byte GCM nonce for a given 32-bit packet ID.
//
// openvpn3-core crypto_aead.hpp Nonce layout (data[16]):
//
//	data[0..3]   = op32 (used as AAD, not part of IV)
//	data[4..7]   = packet_id (4 bytes, big-endian) — placed here by pid_send
//	data[8..15]  = nonce tail (first 8 bytes of the HMAC key slice, set by set_tail)
//
// The 12-byte crypto IV is data[4..15]: packet_id(4B) || tail(8B).
// implicitIV here holds the 8-byte tail (no XOR — it's set directly).
func (g *GCMCipher) buildNonce(packetID uint32) []byte {
	nonce := make([]byte, g.aead.NonceSize()) // 12 bytes
	// Bytes [0..3]: packet_id (big-endian).
	binary.BigEndian.PutUint32(nonce[0:4], packetID)
	// Bytes [4..11]: nonce tail from HMAC key (8 bytes).
	copy(nonce[4:], g.implicitIV)
	return nonce
}

// Seal encrypts plaintext and returns tag(16B) || ciphertext.
//
// OpenVPN3 wire format (crypto_aead.hpp encrypt, line ~192):
//
//	auth_tag = e.work.prepend_alloc(AUTH_TAG_LEN)  // tag slot at START of buffer
//	e.impl.encrypt(..., work_data, ..., auth_tag, ...)
//	// result: e.work = [tag(16B)][ciphertext(NB)]
//
// The C++ sample confirms: [OP32][seq#][auth_tag(16B)][ciphertext...]
// Go's aead.Seal returns ciphertext||tag; we reorder to match the wire.
func (g *GCMCipher) Seal(packetID uint32, plaintext, aad []byte) []byte {
	nonce := g.buildNonce(packetID)
	// Go produces ciphertext || tag.
	out := g.aead.Seal(nil, nonce, plaintext, aad)
	const tagLen = 16
	ct := out[:len(out)-tagLen]
	tag := out[len(out)-tagLen:]
	// Reorder to tag || ciphertext for the OpenVPN3 wire.
	result := make([]byte, len(out))
	copy(result[:tagLen], tag)
	copy(result[tagLen:], ct)
	return result
}

// Open decrypts a payload in OpenVPN3 wire order: tag(16B) || ciphertext.
//
// OpenVPN3 wire format (crypto_aead.hpp decrypt, line ~238):
//
//	auth_tag = buf.read_alloc(AUTH_TAG_LEN)  // reads 16-byte tag from FRONT
//	d.impl.decrypt(buf.c_data(), ..., auth_tag, ...)  // remaining bytes = ciphertext
//
// Go's aead.Open expects ciphertext||tag; we reorder from tag||ciphertext.
func (g *GCMCipher) Open(packetID uint32, tagThenCT, aad []byte) ([]byte, error) {
	const tagLen = 16
	if len(tagThenCT) < tagLen {
		return nil, fmt.Errorf("crypto: GCM ciphertext too short (%d bytes)", len(tagThenCT))
	}
	nonce := g.buildNonce(packetID)
	// Reorder tag||ciphertext → ciphertext||tag for Go's aead.Open.
	ctWithTag := make([]byte, len(tagThenCT))
	copy(ctWithTag[:len(tagThenCT)-tagLen], tagThenCT[tagLen:])
	copy(ctWithTag[len(tagThenCT)-tagLen:], tagThenCT[:tagLen])
	plain, err := g.aead.Open(nil, nonce, ctWithTag, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM open: %w", err)
	}
	return plain, nil
}

// IsAEAD returns true because GCM is an authenticated encryption mode.
func (g *GCMCipher) IsAEAD() bool { return true }

// Overhead returns the byte overhead added by GCM encryption beyond the
// plaintext: 16 bytes for the authentication tag. The IV is derived from the
// packet counter (already in the wire header) so it adds 0 overhead here.
func (g *GCMCipher) Overhead() int { return 16 }
