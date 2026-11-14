// SPDX-License-Identifier: LGPL-2.1-or-later
//
// params.go: which Channel constructor, with which slices of the key block.

package datachannel

import (
	"fmt"

	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/prf"
)

// Params is the negotiated data-channel configuration for a
// connection: the cipher, and for CBC the digest. It does not change between
// key epochs, so a rekey reuses it rather than renegotiating.
type Params struct {
	// Spec is the negotiated cipher, from the table in internal/crypto that
	// is also what IV_CIPHERS is generated from.
	Spec crypto.CipherSpec
	// Digest is the CBC HMAC digest. Meaningless when Spec.Mode is ModeAEAD,
	// where the cipher authenticates its own output.
	Digest crypto.Digest
	// Wire is the data-channel packet format, from the connection's push. It
	// rides here because it is settled at the same moment as the cipher and
	// outlives key epochs the same way, so the first channel and every rekey
	// get one answer. Its zero value, WireDataV2, is what a parameter set
	// resolved before any push exists should name.
	Wire WireFormat
}

// ResolveParams maps a cipher name and a digest name onto the parameters the
// data channel is built from. Either name may be empty, in which case
// OpenVPN's defaults apply: AES-256-GCM for the cipher, SHA1 for the digest.
// The second return value names the feature that could not be provided, for
// the report, and is empty on success.
func ResolveParams(cipherName, digestName string) (Params, string, error) {
	if cipherName == "" {
		cipherName = "AES-256-GCM"
	}
	spec, ok := crypto.LookupCipher(cipherName)
	if !ok {
		return Params{}, "cipher " + cipherName,
			fmt.Errorf("unsupported cipher: %s", cipherName)
	}
	p := Params{Spec: spec}
	if !spec.UsesDigest() {
		// An AEAD cipher authenticates its own output; OpenVPN reports its
		// digest as [null-digest] and no digest is resolved.
		return p, "", nil
	}
	if digestName == "" {
		digestName = crypto.DefaultAuthName
	}
	digest, err := crypto.ParseDigest(digestName)
	if err != nil {
		return Params{}, "auth " + digestName, err
	}
	p.Digest = digest
	return p, "", nil
}

// NewChannel builds the data channel for one key epoch from a 256-byte key
// block.
//
// This is the only place the key block is mapped onto cipher and HMAC keys, for
// either cipher and for both the initial handshake and every rekey. Transmit is
// slots 0 and 1, receive is slots 2 and 3, for both ciphers. Both constructors
// are handed the whole 64-byte HMAC slot rather than a slice of it — GCM takes
// the first 8 bytes as its nonce tail, CBC the digest-sized prefix as its HMAC
// key — because slicing at the call site is what lets two mappings drift apart.
//
// Reference: openvpn3-core crypto/static_key.hpp OpenVPNStaticKey::slice(),
// 4 x 64-byte slots in the client's NORMAL direction.
func (p Params) NewChannel(peerID uint32, keyID uint8, keyMat256 []byte) (*Channel, error) {
	slots, err := prf.Split(keyMat256)
	if err != nil {
		return nil, err
	}
	switch p.Spec.Mode {
	case crypto.ModeAEAD:
		return New(p.Wire, peerID, keyID,
			slots.CipherEncrypt[:p.Spec.KeyLen], slots.HMACEncrypt,
			slots.CipherDecrypt[:p.Spec.KeyLen], slots.HMACDecrypt)
	case crypto.ModeNone:
		enc, err := crypto.NewNullCipher(p.Digest, slots.HMACEncrypt)
		if err != nil {
			return nil, err
		}
		dec, err := crypto.NewNullCipher(p.Digest, slots.HMACDecrypt)
		if err != nil {
			return nil, err
		}
		return &Channel{wire: p.Wire, peerID: peerID, keyID: keyID, encryptor: enc, decryptor: dec, sendSeq: firstPacketID}, nil
	case crypto.ModeCBC:
		return NewCBC(p.Wire, peerID, keyID, p.Digest,
			slots.CipherEncrypt[:p.Spec.KeyLen], slots.HMACEncrypt,
			slots.CipherDecrypt[:p.Spec.KeyLen], slots.HMACDecrypt)
	default:
		return nil, fmt.Errorf("crypto: unknown cipher mode %s", p.Spec.Mode)
	}
}
