// Package prf implements the classic OpenVPN key-method-2 key derivation: the
// two-stage expansion that turns the key material both peers exchange inside
// the control channel into the 256-byte data-channel key block.
//
// # What OpenVPN computes
//
// Once the control-channel TLS session is up, each peer sends a key_source2
// structure through it: the client's carries a 48-byte pre-master secret and
// two 32-byte randoms, the server's the two randoms alone. Both sides run the
// same two stages over the union of that material, so both arrive at the same
// key block without the block itself ever crossing the wire:
//
//	master    = TLS1PRF(client.PreMaster, "OpenVPN master secret",
//	                    client.Random1 ‖ server.Random1)               ->  48 B
//	key_block = TLS1PRF(master,           "OpenVPN key expansion",
//	                    client.Random2 ‖ server.Random2
//	                    ‖ clientSessionID ‖ serverSessionID)           -> 256 B
//
// Each label is concatenated as its raw ASCII bytes with no terminating NUL,
// and the session IDs are the two peers' 8-byte control-channel session IDs.
// The two stages consume disjoint randoms: Random1 seeds the master secret and
// Random2 seeds the key expansion. Feeding the same pair to both is a wrong
// derivation that still produces plausible-looking bytes.
//
// TLS1PRF is the TLS 1.0 MD5+SHA1 split PRF of RFC 2246 §5 — not HMAC-SHA256,
// and not the TLS 1.2 single-digest PRF. It is the function OpenVPN borrowed,
// run over OpenVPN's own material, and needs nothing from crypto/tls. It hashes
// with MD5 and SHA-1 because the wire format says to: the construction XORs a
// P_MD5 stream with a P_SHA1 stream, neither digest authenticates anything, and
// "modernising" them would simply fail to interoperate.
//
// The evidence that this package is correct is testdata/vectors.json, known
// answers captured from an instrumented OpenVPN 2.4.12 peer and checked at
// both stages by TestKeyMethod2Vectors. Only a known-answer vector
// distinguishes a correct PRF from a convincing wrong one.
//
// References:
//   - openvpn3 openvpn/ssl/tlsprf.hpp — TLSPRF::gen_exp(), both label constants
//   - openvpn3 openvpn/openssl/crypto/tls1prf.hpp — the digest choice,
//     EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1())
//   - openvpn3 openvpn/crypto/static_key.hpp — OpenVPNStaticKey::KEY_SIZE =
//     256 (static_key.hpp:97), sliced as KEY_SIZE/4 (:138) into the four
//     64-byte slots Split returns
//   - OpenVPN 2.4 src/openvpn/ssl.c — generate_key_expansion() and
//     key_source2_randomize_write(), which the vectors were captured from
//   - RFC 2246 §5 — P_hash, the secret split, and the MD5/SHA1 XOR
package prf

import (
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // TLS 1.0 PRF as OpenVPN specifies it (RFC 2246 §5), not a security choice
	"crypto/sha1" //nolint:gosec // TLS 1.0 PRF as OpenVPN specifies it (RFC 2246 §5), not a security choice
	"fmt"
	"hash"
)

// The two labels, byte-for-byte as openvpn3 ssl/tlsprf.hpp spells them. They
// are concatenated with the seed as raw ASCII; there is no terminating NUL,
// and a single character of drift silently produces a different key block.
const (
	labelMasterSecret = "OpenVPN master secret"
	labelKeyExpansion = "OpenVPN key expansion"
)

// Sizes of the fixed-width material the derivation consumes and produces.
const (
	preMasterLen    = 48  // client pre-master secret
	randomLen       = 32  // one random1 or random2 field
	sessionIDLen    = 8   // one control-channel session ID
	masterSecretLen = 48  // stage-one output
	keyBlockLen     = 256 // stage-two output; static_key.hpp KEY_SIZE
	slotLen         = 64  // one key slot; static_key.hpp KEY_SIZE/4
)

// KeySource is one peer's contribution to the key-method-2 exchange.
//
// PreMaster is populated by the client only: the server's key_source carries
// randoms alone (OpenVPN 2.4 src/openvpn/ssl.c, key_source2_randomize_write()).
// All three fields are secrets for the lifetime of the key epoch, and the two
// randoms are not interchangeable.
type KeySource struct {
	PreMaster []byte // 48 bytes, client only
	Random1   []byte // 32 bytes, seeds the master secret
	Random2   []byte // 32 bytes, seeds the key expansion
}

// TLS1PRF is the TLS 1.0 MD5+SHA1 split PRF (RFC 2246 §5) and returns n bytes.
//
// The secret is halved into S1 and S2 of ceil(len/2) bytes each — sharing the
// middle byte when the length is odd — then P_MD5(S1, ·) and P_SHA1(S2, ·) run
// over label‖seed and the two streams are XORed:
//
//	TLS1PRF(secret, label, seed) = P_MD5(S1, label‖seed) XOR P_SHA1(S2, label‖seed)
//
// openvpn3 reaches the same function through OpenSSL by selecting
// EVP_md5_sha1() as the TLS 1.x PRF digest (openvpn/openssl/crypto/tls1prf.hpp);
// OpenVPN 2.x reaches it through tls1_PRF() in src/openvpn/crypto_openssl.c.
//
// n <= 0 returns nil. Every other input is accepted as given: the length checks
// that matter live in DeriveMasterSecret and DeriveKeyBlock, so a caller with
// unusual material can still reach the raw primitive.
func TLS1PRF(secret []byte, label string, seed []byte, n int) []byte {
	if n <= 0 {
		return nil
	}

	// RFC 2246 §5: "S1 and S2 are the two halves of the secret and each is the
	// same length. [...] Their length is created by rounding up the length of
	// the overall secret divided by two; thus, if the original secret is an odd
	// number of bytes long, the last byte of S1 will be the same as the first
	// byte of S2."
	half := (len(secret) + 1) / 2
	s1 := secret[:half]
	s2 := secret[len(secret)-half:]

	// A(0) is label‖seed, not seed alone: the label is part of the seed for
	// every iteration, not a separate HMAC input.
	fullSeed := make([]byte, 0, len(label)+len(seed))
	fullSeed = append(fullSeed, label...)
	fullSeed = append(fullSeed, seed...)

	out := pHash(md5.New, s1, fullSeed, n)
	sha := pHash(sha1.New, s2, fullSeed, n)
	for i := range out {
		out[i] ^= sha[i]
	}
	return out
}

// pHash is RFC 2246 §5's P_hash expansion for one digest:
//
//	A(0) = seed
//	A(i) = HMAC_hash(secret, A(i-1))
//	P_hash(secret, seed) = HMAC_hash(secret, A(1)‖seed) ‖
//	                       HMAC_hash(secret, A(2)‖seed) ‖ ...
//
// truncated to n bytes. Truncation is of the concatenated stream, so a shorter
// request is always a prefix of a longer one.
func pHash(newHash func() hash.Hash, secret, seed []byte, n int) []byte {
	mac := hmac.New(newHash, secret)
	out := make([]byte, 0, n+mac.Size())

	a := seed // A(0)
	for len(out) < n {
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil) // A(i) = HMAC(secret, A(i-1))

		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		out = mac.Sum(out) // append HMAC(secret, A(i)‖seed)
	}
	return out[:n]
}

// DeriveMasterSecret is stage one: 48 bytes from the client's pre-master and
// both peers' random1 values.
//
// It is exported, and testdata/vectors.json records this intermediate, so that
// a mismatch can be localised to a single stage. A non-empty server.PreMaster
// is rejected: the server never generates one, so its presence means the
// arguments were passed the wrong way round — the one mistake that would
// otherwise derive a well-formed key block that no peer agrees with.
func DeriveMasterSecret(client, server KeySource) ([]byte, error) {
	if len(server.PreMaster) != 0 {
		return nil, fmt.Errorf("prf: server key source carries %d pre-master bytes; "+
			"only the client generates one, so the arguments are probably swapped",
			len(server.PreMaster))
	}
	if err := checkLen("client pre-master", client.PreMaster, preMasterLen); err != nil {
		return nil, err
	}
	if err := checkLen("client random1", client.Random1, randomLen); err != nil {
		return nil, err
	}
	if err := checkLen("server random1", server.Random1, randomLen); err != nil {
		return nil, err
	}

	seed := make([]byte, 0, 2*randomLen)
	seed = append(seed, client.Random1...)
	seed = append(seed, server.Random1...)
	return TLS1PRF(client.PreMaster, labelMasterSecret, seed, masterSecretLen), nil
}

// DeriveKeyBlock runs both stages and returns the 256-byte key block.
//
// clientSessionID and serverSessionID are the 8-byte control-channel session
// IDs of the two peers, which seed stage two alongside both random2 values.
// Their order is fixed — client first — and swapping them yields a key block
// wrong in a way no length or determinism check can see. Pass the block to
// Split to reach the four key slots.
func DeriveKeyBlock(client, server KeySource, clientSessionID, serverSessionID []byte) ([]byte, error) {
	master, err := DeriveMasterSecret(client, server)
	if err != nil {
		return nil, err
	}
	if err := checkLen("client random2", client.Random2, randomLen); err != nil {
		return nil, err
	}
	if err := checkLen("server random2", server.Random2, randomLen); err != nil {
		return nil, err
	}
	if err := checkLen("client session ID", clientSessionID, sessionIDLen); err != nil {
		return nil, err
	}
	if err := checkLen("server session ID", serverSessionID, sessionIDLen); err != nil {
		return nil, err
	}

	seed := make([]byte, 0, 2*randomLen+2*sessionIDLen)
	seed = append(seed, client.Random2...)
	seed = append(seed, server.Random2...)
	seed = append(seed, clientSessionID...)
	seed = append(seed, serverSessionID...)
	return TLS1PRF(master, labelKeyExpansion, seed, keyBlockLen), nil
}

// Slots is a 256-byte key block split into its four 64-byte slots, named for
// the client's NORMAL direction.
//
// openvpn3 (crypto/static_key.hpp) indexes the same block by a (CIPHER|HMAC,
// ENCRYPT|DECRYPT, NORMAL|INVERSE) specifier, and the server reads it INVERSE:
// slice()'s key table is {0,1,2,3,2,3,0,1}, so the server's slots 0 and 1 are
// the client's 2 and 3. That swap is what makes one peer's transmit key the
// other's receive key, and why the names below are unambiguous only here.
//
// A slot is 64 bytes whatever consumes it: AES-256 takes the first 32, AES-128
// the first 16, an HMAC-SHA1 tag key the first 20, a GCM nonce tail the first
// 12 minus the packet-ID width. The trailing bytes are unused.
type Slots struct {
	CipherEncrypt []byte // slot 0 — our transmit cipher key
	HMACEncrypt   []byte // slot 1 — our transmit HMAC key or GCM nonce tail
	CipherDecrypt []byte // slot 2 — our receive cipher key
	HMACDecrypt   []byte // slot 3 — our receive HMAC key or GCM nonce tail
}

// Split maps a 256-byte key block onto the four slots at offsets 0, 64, 128
// and 192.
//
// It is the only place that mapping exists, so the AEAD and CBC paths cannot
// disagree about it. Each slot is a copy: the caller stays free to wipe the key
// block, and no slot can be grown into its neighbour by an accidental append.
func Split(keyBlock []byte) (Slots, error) {
	if len(keyBlock) != keyBlockLen {
		return Slots{}, fmt.Errorf("prf: key block must be %d bytes, got %d", keyBlockLen, len(keyBlock))
	}
	slot := func(i int) []byte {
		s := make([]byte, slotLen)
		copy(s, keyBlock[i*slotLen:(i+1)*slotLen])
		return s
	}
	return Slots{
		CipherEncrypt: slot(0),
		HMACEncrypt:   slot(1),
		CipherDecrypt: slot(2),
		HMACDecrypt:   slot(3),
	}, nil
}

// checkLen reports a wrong-sized input as an error rather than letting it reach
// a slice expression. Every field the derivation consumes is fixed-width, so a
// wrong length is a caller bug, never something to pad or truncate around.
func checkLen(what string, b []byte, want int) error {
	if len(b) != want {
		return fmt.Errorf("prf: %s must be %d bytes, got %d", what, want, len(b))
	}
	return nil
}
