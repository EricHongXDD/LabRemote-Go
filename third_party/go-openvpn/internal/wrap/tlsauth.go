package wrap

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"strconv"

	"github.com/buengese/go-openvpn/internal/crypto"
)

// tls-auth: an HMAC and a replay header on every control packet. The wire
// layout and the digest input carry the same fields in *different orders*, and
// neither order looks wrong from the packet:
//
//	wire  = opcode|key_id ‖ session_id ‖ hmac ‖ packet_id ‖ timestamp ‖ rest
//	input = packet_id ‖ timestamp ‖ opcode|key_id ‖ session_id ‖ rest
//
// The replay header is *prepended* to the digest input, not hashed where it
// sits on the wire; tls-crypt, which looks like the same shape, hashes in wire
// order instead. Either choice yields a tag of the right length from the right
// key, and a wrong one is indistinguishable from a dead server, so this file is
// written against testdata/vectors.json rather than a reading of the source
// (docs/openvpn3-reference-policy.md §3.4). tlsauth_kat_test.go is the
// specification; docker/TLS-WRAP-VECTORS.md §6 is the evidence that every wrong
// ordering and wrong key half differs from the recorded tag in half its bits.
//
// Reference, for provenance rather than authority, all from the pinned 2.4.12
// tarball the capture used (docs/openvpn3-reference-policy.md §3.3):
//   - src/openvpn/ssl.c, write_control_auth() and swap_hmac() — the wire order
//   - src/openvpn/crypto.c, openvpn_encrypt_v1() — the digest input order
//   - src/openvpn/packet_id.c, packet_id_write() — the long-form replay header
//   - src/openvpn/crypto.c, key_direction_state_init() and init_key_ctx() —
//     which half of the static key each direction installs

const (
	// StaticKeySize is the length of an OpenVPN 2048-bit static key.
	StaticKeySize = 256

	// keySlotSize is sizeof(struct key): a 256-byte static key is two of
	// them (struct key2), each 64 bytes of cipher material then 64 of HMAC.
	keySlotSize = 128
	// keyFieldSize is the width of one field inside a slot. Only the
	// leading digest_size bytes of the HMAC field are installed, which is
	// why SHA1 and SHA256 read from the same offset.
	keyFieldSize = 64
	// slot0HMACOffset and slot1HMACOffset are where each slot's HMAC field
	// begins. Both are measured rather than assumed; see
	// TestKeyDirectionSelectsHalvesConsistently.
	slot0HMACOffset = keyFieldSize               // 64
	slot1HMACOffset = keySlotSize + keyFieldSize // 192

	// controlHeaderLen is opcode|key_id (1) ‖ session_id (8). This much of
	// a control packet stays at the front of the wire under the wrap; the
	// HMAC and the replay header are inserted after it.
	controlHeaderLen = 9
	// replayHeaderLen is the long-form packet id: a 4-byte counter then a
	// 4-byte POSIX timestamp, both big-endian, in that order.
	replayHeaderLen = 8

	// NameTLSAuth is what Name reports for a tls-auth control channel, and
	// what the session report records.
	NameTLSAuth = "tls-auth"
)

// redactedStaticKey stands in for the bytes in every rendering of a StaticKey.
const redactedStaticKey = "[OpenVPN static key: 256 bytes, redacted]"

// StaticKey is an OpenVPN 2048-bit static key as a wrap consumes it: 256
// bytes, two 128-byte slots of 64 cipher bytes then 64 HMAC bytes. It is
// layout-identical to profile.StaticKey, so a caller converts with
// (*wrap.StaticKey)(prof.TLSAuth) and copies no key material; it is declared
// here rather than imported so that this package — the wire format — does not
// depend on the profile parser.
//
// A StaticKey is a secret, and the type is where that is enforced. String,
// GoString and MarshalJSON all yield a fixed placeholder, so a key cannot
// reach a log line, an error or a session report by being swept up in a %v, a
// %#v or a json.Marshal of whatever holds it. The three methods duplicate
// profile.StaticKey's on purpose: sharing them is what the declaration above
// avoids.
type StaticKey [StaticKeySize]byte

// String returns a fixed placeholder rather than the key.
func (k StaticKey) String() string { return redactedStaticKey }

// GoString returns the same placeholder as String, because %#v bypasses
// fmt.Stringer and %#v is what someone debugging a wrap reaches for.
func (k StaticKey) GoString() string { return redactedStaticKey }

// MarshalJSON encodes the key as the placeholder string. The result is
// deliberately not decodable back into a key.
func (k StaticKey) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(redactedStaticKey)), nil
}

// Direction is the --key-direction a profile carries, selecting the halves of
// the static key used to send and to receive. Absent is a third behaviour and
// not a default of 0: key_direction_state_init leaves both directions on slot
// 0, so the two peers share one key rather than splitting the material.
type Direction int

const (
	// DirectionAbsent is a profile with no key-direction directive: both
	// directions use slot 0.
	DirectionAbsent Direction = iota
	// Direction0 is "key-direction 0": send with slot 0, receive with slot 1.
	Direction0
	// Direction1 is "key-direction 1": send with slot 1, receive with slot 0.
	Direction1
)

// String returns the direction as a profile spells it.
func (d Direction) String() string {
	switch d {
	case DirectionAbsent:
		return "absent"
	case Direction0:
		return "0"
	case Direction1:
		return "1"
	default:
		return "Direction(" + strconv.Itoa(int(d)) + ")"
	}
}

// hmacOffsets returns the offsets of the send and receive HMAC fields inside a
// static key for this direction. key-direction 0 sends with slot 0 and
// receives with slot 1; 1 is the reverse, and both are measured over vectors
// covering either direction on both peers.
//
// Absent is *not* measured — no vector covers it. It is implemented from
// key_direction_state_init() read from the pinned source, where both
// directions stay on slot 0 so the two peers authenticate with the same key,
// and it is untested against a real peer. If a profile ever needs it, that is
// the first thing to doubt.
func (d Direction) hmacOffsets() (send, recv int, err error) {
	switch d {
	case DirectionAbsent:
		return slot0HMACOffset, slot0HMACOffset, nil
	case Direction0:
		return slot0HMACOffset, slot1HMACOffset, nil
	case Direction1:
		return slot1HMACOffset, slot0HMACOffset, nil
	default:
		return 0, 0, fmt.Errorf("wrap: tls-auth: unknown key direction %d", int(d))
	}
}

// tlsAuth is the tls-auth Wrapper. It is safe for concurrent use, as Wrapper
// requires: the send counter and the receive window are the mutable state and
// each has its own lock, so an inbound packet never waits on an outbound one.
// The keys are read-only after construction.
type tlsAuth struct {
	digest  crypto.Digest
	newHash func() hash.Hash
	// sendKey and recvKey are the leading digest_size bytes of one HMAC
	// field each. They are the only key material this type holds; the
	// 256-byte static key is not retained.
	sendKey []byte
	recvKey []byte
	tagLen  int
	// direction is kept for String only.
	direction Direction

	// send stamps the outbound replay header. It starts at 1, not 0, as
	// OpenVPN's counter does; it lives in replay.go because tls-crypt needs
	// the same counter on the same terms.
	send sendCounter

	// recv is the inbound replay window. It is a distinct ID space from the
	// reliable layer's message sequencing — see replay.go.
	recv replayWindow
}

// NewTLSAuth builds a tls-auth wrapper from a 2048-bit static key and the
// profile's key-direction. digest is the control-channel HMAC, the profile's
// auth digest, defaulting to SHA1.
//
// The Wrapper is fixed for the life of one connection and must be chosen
// before the socket opens, because tls-auth authenticates the opening
// HARD_RESET. A new one is built for every attempt: the replay window and the
// send counter are per connection, and a peer restarting its packet ids at 1
// against a carried-over window would look like 64 replays.
func NewTLSAuth(key *StaticKey, direction Direction, digest crypto.Digest) (Wrapper, error) {
	if key == nil {
		return nil, fmt.Errorf("wrap: tls-auth: no static key")
	}
	newHash := digest.Hash()
	if newHash == nil {
		return nil, fmt.Errorf("wrap: tls-auth: unsupported digest %s", digest)
	}
	size := digest.Size()
	if size <= 0 || size > keyFieldSize {
		// SHA512 fills the 64-byte field exactly and nothing OpenVPN
		// offers is wider, so this guards an unknown digest rather than
		// a reachable branch.
		return nil, fmt.Errorf("wrap: tls-auth: digest %s needs %d key bytes, the static key field holds %d",
			digest, size, keyFieldSize)
	}
	sendOff, recvOff, err := direction.hmacOffsets()
	if err != nil {
		return nil, err
	}

	w := &tlsAuth{
		digest:    digest,
		newHash:   newHash,
		sendKey:   append([]byte(nil), key[sendOff:sendOff+size]...),
		recvKey:   append([]byte(nil), key[recvOff:recvOff+size]...),
		tagLen:    size,
		direction: direction,
	}
	return w, nil
}

// Name reports "tls-auth".
func (w *tlsAuth) Name() string { return NameTLSAuth }

// Overhead is the digest size plus the 8-byte replay header. It is *not* one
// number: SHA1 costs 28 bytes and SHA256 costs 40, so a hard-coded 40 is
// silently wrong for the other digest — which shows up as control packets one
// fragment too large, long after the handshake.
func (w *tlsAuth) Overhead() int { return w.tagLen + replayHeaderLen }

// String describes the wrap without describing its keys.
func (w *tlsAuth) String() string {
	return fmt.Sprintf("tls-auth(%s, key-direction %s)", w.digest, w.direction)
}

// Wrap returns the on-wire form of one outbound control packet:
//
//	opcode|key_id ‖ session_id ‖ hmac ‖ packet_id ‖ timestamp ‖ rest
//
// where the hmac covers packet_id ‖ timestamp ‖ the whole plain packet. The
// header moves *behind* the replay header in the digest and stays in front of
// it on the wire; that asymmetry is the thing the vectors pin.
func (w *tlsAuth) Wrap(pkt []byte) ([]byte, error) {
	if len(pkt) < controlHeaderLen {
		return nil, fmt.Errorf("wrap: tls-auth: control packet of %d bytes is shorter than its %d-byte header",
			len(pkt), controlHeaderLen)
	}

	packetID, timestamp := w.send.header()

	var replay [replayHeaderLen]byte
	binary.BigEndian.PutUint32(replay[0:4], packetID)
	binary.BigEndian.PutUint32(replay[4:8], timestamp)

	mac := hmac.New(w.newHash, w.sendKey)
	mac.Write(replay[:])
	mac.Write(pkt)
	tag := mac.Sum(nil)

	out := make([]byte, 0, len(pkt)+w.Overhead())
	out = append(out, pkt[:controlHeaderLen]...)
	out = append(out, tag...)
	out = append(out, replay[:]...)
	out = append(out, pkt[controlHeaderLen:]...)
	return out, nil
}

// Unwrap authenticates one inbound control packet and returns its plain form,
// or ErrAuth, ErrReplay or ErrStaleTimestamp.
//
// A caller must treat every one of those as "drop this packet and read the
// next", never as a reason to end the connection, as OpenVPN does: on UDP it is
// the difference between a session and one anyone who guesses the four-tuple
// kills with a single datagram.
func (w *tlsAuth) Unwrap(pkt []byte) ([]byte, error) {
	prefix := controlHeaderLen + w.tagLen + replayHeaderLen
	if len(pkt) < prefix {
		return nil, fmt.Errorf("%w: %d bytes, need at least %d for the header, tag and replay id",
			ErrAuth, len(pkt), prefix)
	}
	tag := pkt[controlHeaderLen : controlHeaderLen+w.tagLen]
	replay := pkt[controlHeaderLen+w.tagLen : prefix]

	plain := make([]byte, 0, controlHeaderLen+len(pkt)-prefix)
	plain = append(plain, pkt[:controlHeaderLen]...)
	plain = append(plain, pkt[prefix:]...)

	mac := hmac.New(w.newHash, w.recvKey)
	mac.Write(replay)
	mac.Write(plain)
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, ErrAuth
	}

	// The replay window is consulted only after the packet authenticates:
	// checked first, anyone able to send us a datagram could advance it past
	// the peer's real packet ids with a forged header and stall the session
	// without holding the key.
	if err := w.recv.accept(
		binary.BigEndian.Uint32(replay[0:4]),
		binary.BigEndian.Uint32(replay[4:8]),
	); err != nil {
		return nil, err
	}
	return plain, nil
}
