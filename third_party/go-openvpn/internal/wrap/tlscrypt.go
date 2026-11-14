package wrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// tls-crypt: the control channel authenticated *and* encrypted.
//
// Everything about it that looks like tls-auth is a trap. The two carry the
// same fields in three different arrangements:
//
//	tls-auth   wire  = opcode|key_id ‖ session_id ‖ tag ‖ packet_id ‖ timestamp ‖ rest
//	tls-auth   input = packet_id ‖ timestamp ‖ opcode|key_id ‖ session_id ‖ rest
//	tls-crypt  wire  = opcode|key_id ‖ session_id ‖ packet_id ‖ timestamp ‖ tag ‖ ciphertext
//	tls-crypt  input = opcode|key_id ‖ session_id ‖ packet_id ‖ timestamp ‖ plaintext
//
// tls-auth *prepends* the replay header to its digest input; tls-crypt hashes
// in wire order, the replay header between the 9-byte control header and the
// payload. Applying tls-auth's ordering reproduces none of the captured tags,
// differing from each in about half its bits (docker/TLS-WRAP-VECTORS.md §6):
// right length, right key, right bytes, wrong. So this file is written against
// testdata/vectors.json, and tlscrypt_kat_test.go is its specification.
//
// The keys are the second trap. Ke and Ka are **not adjacent**, and the client
// is **not on slot 0** even though tls-crypt has no --key-direction directive
// at all. See tlsCryptKeys below. The outbound counter and the replay window
// are tls-auth's, unchanged — see replay.go.
//
// Reference, for provenance rather than authority, all from the pinned OpenVPN
// 2.4.12 tarball the capture used (docs/openvpn3-reference-policy.md §3.3):
//   - src/openvpn/tls_crypt.c, tls_crypt_wrap() — the wire order, the digest
//     input order, and the IV taken from the tag
//   - src/openvpn/tls_crypt.h, TLS_CRYPT_OFF_PID / _OFF_TAG / _OFF_CT — the
//     offsets
//   - src/openvpn/tls_crypt.c, tls_crypt_kt() — AES-256-CTR and HMAC-SHA256,
//     fixed
//   - src/openvpn/tls_crypt.c, tls_crypt_init_key() — the server is always
//     KEY_DIRECTION_NORMAL and the client always KEY_DIRECTION_INVERSE

const (
	// NameTLSCrypt is what Name reports for a tls-crypt control channel, and
	// what the session report records.
	NameTLSCrypt = "tls-crypt"

	// tlsCryptTagLen is HMAC-SHA256's output. tls_crypt_kt() fixes the
	// digest, so unlike tls-auth there is nothing to configure and nothing
	// for a profile's --auth to change.
	tlsCryptTagLen = 32
	// tlsCryptKeyLen is AES-256's key length, also fixed by tls_crypt_kt().
	tlsCryptKeyLen = 32
	// tlsCryptIVLen is the AES block size, and therefore the width of the
	// CTR IV. The IV is the *leading* 16 bytes of the tag; §6 rules out the
	// trailing 16, the zero-padded replay header and a zero IV.
	tlsCryptIVLen = 16

	// slot0CipherOffset and slot1CipherOffset are where each slot's cipher
	// field begins. They pair with slot0HMACOffset and slot1HMACOffset in
	// tlsauth.go — 64 bytes apart, not 32.
	slot0CipherOffset = 0
	slot1CipherOffset = keySlotSize // 128
)

// tlsCryptKeys is one direction's key pair, cut from the static key at
// measured offsets — the most misreadable fact in this package:
//
//	server:  Ke = static_key[0:32],    Ka = static_key[64:96]
//	client:  Ke = static_key[128:160], Ka = static_key[192:224]
//
// **Ke and Ka are not adjacent.** The obvious reading — 32 bytes for the
// cipher, the next 32 for the HMAC — is wrong: the split follows the 64-byte
// fields of struct key, so 32 bytes sit unused between each pair. Only the
// leading key-length bytes of a field are installed (init_key_ctx()).
//
// **The client is on slot 1, with no --key-direction to say so.** tls-crypt
// has no direction option; tls_crypt_init_key() hard-codes the server to
// KEY_DIRECTION_NORMAL and the client to KEY_DIRECTION_INVERSE. Reusing
// tls-auth's Direction here would be correct for exactly one of the two peers,
// which fails as "the server never answers".
type tlsCryptKeys struct {
	// ke is the AES-256-CTR key: 32 bytes from the head of a slot's cipher
	// field.
	ke []byte
	// ka is the HMAC-SHA256 key: 32 bytes from the head of the same slot's
	// HMAC field, 64 bytes further on.
	ka []byte
}

// peerRole is which end of the connection a wrapper speaks for, and therefore
// which slot of the static key it sends with. It is *not* a key-direction:
// tls-crypt has no such directive, and the role is decided by which program is
// running. This library is only ever a client, so NewTLSCrypt takes no
// argument and roleServer is reachable from tests alone.
type peerRole int

const (
	// roleClient sends with slot 1 and receives with slot 0.
	roleClient peerRole = iota
	// roleServer is the complement. It exists so a known-answer test can
	// reproduce the captured server packets on the wire, not only through
	// Unwrap; see export_test.go.
	roleServer
)

// keys returns the send and receive key pairs this role cuts from a static key.
func (r peerRole) keys(key *StaticKey) (send, recv tlsCryptKeys, err error) {
	slot := func(cipherOff, hmacOff int) tlsCryptKeys {
		return tlsCryptKeys{
			ke: append([]byte(nil), key[cipherOff:cipherOff+tlsCryptKeyLen]...),
			ka: append([]byte(nil), key[hmacOff:hmacOff+tlsCryptTagLen]...),
		}
	}
	var (
		slot0 = slot(slot0CipherOffset, slot0HMACOffset)
		slot1 = slot(slot1CipherOffset, slot1HMACOffset)
	)
	switch r {
	case roleClient:
		return slot1, slot0, nil
	case roleServer:
		return slot0, slot1, nil
	default:
		return tlsCryptKeys{}, tlsCryptKeys{}, fmt.Errorf("wrap: tls-crypt: unknown peer role %d", int(r))
	}
}

// tlsCrypt is the tls-crypt Wrapper. It is safe for concurrent use, as Wrapper
// requires: the send counter and the receive window are the mutable state and
// each has its own lock, so an inbound packet never waits on an outbound one.
// The keys are read-only after construction.
type tlsCrypt struct {
	// send and recv are the two directions' Ke/Ka pairs. The 256-byte static
	// key is not retained: 128 of its bytes are never used by either peer.
	send tlsCryptKeys
	recv tlsCryptKeys

	// sendCtr stamps the outbound replay header. It is the counter tls-auth
	// stamps, unchanged — see replay.go.
	sendCtr sendCounter

	// recvWin is the inbound replay window, tls-auth's verbatim: tls-crypt's
	// replay header is the same long-form packet id, and the window judges a
	// timestamp against the *peer's* own highest rather than the local clock,
	// so nothing about encryption reaches it.
	//
	// It is consulted only after the tag verifies, for the same reason as in
	// tls-auth: checked first, anyone able to send us a datagram could
	// advance the window past the peer's real packet ids with a forged header
	// and stall the session without holding the key.
	recvWin replayWindow
}

// NewTLSCrypt builds a tls-crypt wrapper from a 2048-bit static key. There is
// nothing else to pass: tls_crypt_kt() fixes AES-256-CTR and HMAC-SHA256, there
// is no --key-direction, and the halves of the key are chosen by which peer you
// are. The wrapper returned is the client's.
//
// It is fixed for the life of one connection and must be chosen before the
// socket opens, because tls-crypt encrypts and authenticates the opening
// HARD_RESET. A new one per attempt: the replay window and the send counter are
// per connection, and a peer restarting its ids at 1 would look like 64 replays.
func NewTLSCrypt(key *StaticKey) (Wrapper, error) {
	return newTLSCrypt(key, roleClient)
}

// newTLSCrypt is NewTLSCrypt with the peer role spelled out, for the
// known-answer test's server half.
func newTLSCrypt(key *StaticKey, role peerRole) (*tlsCrypt, error) {
	if key == nil {
		return nil, fmt.Errorf("wrap: tls-crypt: no static key")
	}
	send, recv, err := role.keys(key)
	if err != nil {
		return nil, err
	}
	return &tlsCrypt{send: send, recv: recv}, nil
}

// Name reports "tls-crypt".
func (w *tlsCrypt) Name() string { return NameTLSCrypt }

// Overhead is 40 bytes: the 8-byte replay header and the 32-byte tag. It is
// one number here, where tls-auth's is not — the digest is fixed at SHA256,
// and AES-256-CTR is a stream mode whose ciphertext is exactly as long as the
// plaintext.
func (w *tlsCrypt) Overhead() int { return replayHeaderLen + tlsCryptTagLen }

// String describes the wrap without describing its keys.
func (w *tlsCrypt) String() string { return "tls-crypt(AES-256-CTR, HMAC-SHA256)" }

// Wrap returns the on-wire form of one outbound control packet:
//
//	opcode|key_id ‖ session_id ‖ packet_id ‖ timestamp ‖ tag ‖ ciphertext
//
// where the tag is HMAC-SHA256(Ka) over
//
//	opcode|key_id ‖ session_id ‖ packet_id ‖ timestamp ‖ plaintext
//
// and the ciphertext is AES-256-CTR(Ke) over the plaintext with the leading 16
// bytes of the tag as the IV.
//
// "Encrypt-then-MAC" does not describe this: the tag is taken over the
// *plaintext* and then supplies the IV for encrypting it, so the MAC must run
// first. It is a synthetic-IV construction, and Unwrap is the mirror image.
func (w *tlsCrypt) Wrap(pkt []byte) ([]byte, error) {
	if len(pkt) < controlHeaderLen {
		return nil, fmt.Errorf("wrap: tls-crypt: control packet of %d bytes is shorter than its %d-byte header",
			len(pkt), controlHeaderLen)
	}

	packetID, timestamp := w.sendCtr.header()
	var replay [replayHeaderLen]byte
	binary.BigEndian.PutUint32(replay[0:4], packetID)
	binary.BigEndian.PutUint32(replay[4:8], timestamp)

	header, plaintext := pkt[:controlHeaderLen], pkt[controlHeaderLen:]

	// Wire order, not tls-auth's. The replay header sits *between* the
	// control header and the payload in the digest, exactly where it sits on
	// the wire.
	mac := hmac.New(sha256.New, w.send.ka)
	mac.Write(header)
	mac.Write(replay[:])
	mac.Write(plaintext)
	tag := mac.Sum(nil)

	out := make([]byte, 0, len(pkt)+w.Overhead())
	out = append(out, header...)
	out = append(out, replay[:]...)
	out = append(out, tag...)

	ct, err := w.ctr(w.send.ke, tag[:tlsCryptIVLen], plaintext)
	if err != nil {
		return nil, err
	}
	return append(out, ct...), nil
}

// Unwrap authenticates and decrypts one inbound control packet and returns its
// plain form, or ErrAuth, ErrReplay or ErrStaleTimestamp.
//
// The tag covers the plaintext, so the packet is decrypted *before* it can be
// authenticated — forced by the construction, not chosen. Nothing may act on
// the recovered bytes until the comparison below succeeds, which is why they
// are held in a local: CTR decryption of a forged packet always "succeeds" and
// yields plausible-looking garbage.
//
// A caller must treat every error here as "drop this packet and read the next",
// never as a reason to end the connection, as OpenVPN does: on UDP it is the
// difference between a session and one anyone who guesses the four-tuple kills
// with a single datagram.
func (w *tlsCrypt) Unwrap(pkt []byte) ([]byte, error) {
	prefix := controlHeaderLen + replayHeaderLen + tlsCryptTagLen
	if len(pkt) < prefix {
		return nil, fmt.Errorf("%w: %d bytes, need at least %d for the header, replay id and tag",
			ErrAuth, len(pkt), prefix)
	}
	header := pkt[:controlHeaderLen]
	replay := pkt[controlHeaderLen : controlHeaderLen+replayHeaderLen]
	tag := pkt[controlHeaderLen+replayHeaderLen : prefix]

	plaintext, err := w.ctr(w.recv.ke, tag[:tlsCryptIVLen], pkt[prefix:])
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, w.recv.ka)
	mac.Write(header)
	mac.Write(replay)
	mac.Write(plaintext)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, ErrAuth
	}

	if err := w.recvWin.accept(
		binary.BigEndian.Uint32(replay[0:4]),
		binary.BigEndian.Uint32(replay[4:8]),
	); err != nil {
		return nil, err
	}

	plain := make([]byte, 0, controlHeaderLen+len(plaintext))
	plain = append(plain, header...)
	return append(plain, plaintext...), nil
}

// ctr runs AES-256-CTR over src; CTR is its own inverse, so Wrap and Unwrap
// share it. The error is unreachable with key lengths fixed at construction
// and a SHA256 slice for an IV, but returning it keeps a mis-sized key a
// configuration failure rather than a crash mid-handshake.
func (w *tlsCrypt) ctr(key, iv, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("wrap: tls-crypt: cipher: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("wrap: tls-crypt: IV is %d bytes, want %d", len(iv), block.BlockSize())
	}
	out := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(out, src)
	return out, nil
}
