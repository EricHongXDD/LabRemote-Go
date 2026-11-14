// Package datachannel implements the OpenVPN3 data channel: the P_DATA_V2 and
// P_DATA_V1 packet framings, the encrypt/decrypt pipeline, and the
// replay-protection sliding window.
//
// P_DATA_V2 wire layout — GCM mode (openvpn3-core ssl/proto.hpp):
//
//	[opcode|keyid (1B)][peer_id (3B)][packet_id (4B)][GCM-tag (16B)][ciphertext]
//
// For AES-256-GCM the AAD is the 4-byte header (opcode+peer_id) and the 4-byte
// packet_id that follows it.
//
// P_DATA_V2 wire layout — CBC mode:
//
//	[opcode|keyid (1B)][peer_id (3B)][HMAC (N B)][IV (16B)][ciphertext]
//
// N is the negotiated digest's output length — 20 for SHA1, 32 for SHA256, 64
// for SHA512 — not a constant, and reached through DataCipher.Overhead(),
// which for CBC is tag + IV + one block.
//
// The packet_id is embedded in the first 4 bytes of the AES-CBC plaintext
// for replay protection; the P_DATA_V2 header (4B) is NOT authenticated.
//
// P_DATA_V1 wire layout — the same two bodies behind a shorter header:
//
//	[opcode|keyid (1B)][packet_id (4B)][GCM-tag (16B)][ciphertext]   GCM
//	[opcode|keyid (1B)][HMAC (N B)][IV (16B)][ciphertext]            CBC
//
// It carries no peer-id, and its opcode byte is not authenticated either, so
// for GCM the AAD is the 4-byte packet_id alone — see aeadHeaderLen. Nothing
// else differs: the key_id, the packet_id rule, the replay window and the CBC
// body layout are the same.
// 发送格式在构造时固定；接收格式由每包 opcode 决定，见 WireFormat。
//
// Replay protection uses a 64-bit sliding window — see replayWindowSize.
//
// Reference: openvpn3-core crypto/cipher.hpp, data_epoch.cpp, ssl/proto.hpp
package datachannel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/framing"
)

// replayWindowSize is the number of bits in the replay-protection window.
//
// 64 is stock OpenVPN's --replay-window default: DEFAULT_SEQ_BACKTRACK in
// openvpn-2.6.22 src/openvpn/packet_id.h:100, installed at options.c:870. It
// is not openvpn3-core's, whose standard PacketIDDataReceive is order 8, a
// 2048-bit window (crypto/packet_id_data.hpp:288-289, :494-496).
const replayWindowSize = 64

// WireFormat is the data-channel packet format.
//
// 发送格式由服务端推送的 peer-id 决定；接收格式则按每包 opcode 解析。
// 两个方向可能不同，接收 V1 不改变发送格式、密钥或重放窗口。
type WireFormat int

const (
	// WireDataV2 carries a 3-byte peer-id after the opcode.
	WireDataV2 WireFormat = iota
	// WireDataV1 carries no peer-id: opcode byte, then the payload.
	WireDataV1
)

// Header lengths, which are the whole of the difference between the two
// formats: the opcode and key_id byte, and for P_DATA_V2 the 3-byte peer-id
// after it.
const (
	dataV1HeaderLen = 1
	dataV2HeaderLen = 4
)

// String names the format by its opcode. It is what the session report
// records, so the two can be counted apart.
func (f WireFormat) String() string {
	switch f {
	case WireDataV2:
		return "P_DATA_V2"
	case WireDataV1:
		return "P_DATA_V1"
	default:
		return fmt.Sprintf("WireFormat(%d)", int(f))
	}
}

// opcode is the packet opcode this format puts in the top 5 bits of the first
// byte.
func (f WireFormat) opcode() uint8 {
	if f == WireDataV1 {
		return framing.P_DATA_V1
	}
	return framing.P_DATA_V2
}

// aeadHeaderLen is how much of the header the AEAD authenticates.
//
// P_DATA_V2 authenticates its whole 4-byte header — opcode and peer-id —
// because the reference prepends it *before* encrypting, "so we can
// authenticate the opcode too" (openvpn-2.6.22 src/openvpn/forward.c:665-672).
// P_DATA_V1's opcode is prepended *after* encrypting (forward.c:686-689), so it
// authenticates nothing but the packet id; ssl.c:3608-3620 sets ad_start past
// the V1 byte and at the start of the buffer for V2, and openvpn3 passes a null
// op32 for V1 (crypto_aead.hpp:77-91). Getting this wrong is invisible on the
// sending side: the packet leaves well formed and the peer discards every one.
func (f WireFormat) aeadHeaderLen() int {
	if f == WireDataV1 {
		return 0
	}
	return f.headerLen()
}

// headerLen is how many bytes precede the packet body.
func (f WireFormat) headerLen() int {
	if f == WireDataV1 {
		return dataV1HeaderLen
	}
	return dataV2HeaderLen
}

// Channel encrypts and decrypts data-channel packets for one key epoch.
//
// A Channel is safe for concurrent use by multiple goroutines.
type Channel struct {
	// wire 固定发送方向的格式；接收方向按每包 opcode 解析。
	// 密钥轮换继承发送格式，不改变服务端分配的 peer-id。
	wire      WireFormat
	peerID    uint32 // 3-byte peer_id assigned by the server; 0 for WireDataV1
	keyID     uint8
	encryptor crypto.DataCipher
	decryptor crypto.DataCipher

	mu sync.Mutex
	// sendSeq is the packet_id of the next outbound data packet. It starts
	// at firstPacketID, never 0 — see that constant.
	sendSeq uint32
	// sendExhausted records that maxPacketID has been handed out, so the next
	// Encrypt refuses instead of wrapping to an id already used under this
	// key. A separate flag, not a sendSeq sentinel: every uint32 is a valid id.
	sendExhausted bool
	// replayBits is the sliding window ending at replayTop: bit i is set when
	// packet_id replayTop-i has been seen, so bit 0 is replayTop itself. A
	// window is a shift register; this is one.
	replayBits uint64
	replayTop  uint32
	replaySet  bool // true once any packet has been received
}

// New creates a Channel using AES-256-GCM for both directions.
//
//   - wire:    packet format, from what the peer pushed (see WireFormat)
//   - peerID:  3-byte peer identifier from the server; meaningful only for
//     WireDataV2, and must be 0 for WireDataV1
//   - keyID:   key slot index (0–7)
//   - txKey:   cipher key for the send direction (32 bytes for AES-256-GCM)
//   - txIV:    implicit IV for the send direction (12 bytes)
//   - rxKey:   cipher key for the receive direction
//   - rxIV:    implicit IV for the receive direction
func New(wire WireFormat, peerID uint32, keyID uint8, txKey, txIV, rxKey, rxIV []byte) (*Channel, error) {
	enc, err := crypto.NewGCMCipher(txKey, txIV)
	if err != nil {
		return nil, fmt.Errorf("datachannel: tx cipher: %w", err)
	}
	dec, err := crypto.NewGCMCipher(rxKey, rxIV)
	if err != nil {
		return nil, fmt.Errorf("datachannel: rx cipher: %w", err)
	}
	return newWithCiphers(wire, peerID, keyID, enc, dec)
}

// NewCBC creates a Channel using AES-CBC authenticated by an HMAC digest for
// both directions.
//
//   - wire:      packet format, from what the peer pushed (see WireFormat)
//   - peerID:    3-byte peer identifier, meaningful only for WireDataV2
//   - keyID:     key slot index (0–7)
//   - digest:    HMAC digest for both directions — SHA1, SHA256 or SHA512. It
//     fixes the wire tag length and the HMAC key length, so it precedes the
//     key material rather than trailing it.
//   - txAESKey:  16-, 24- or 32-byte AES key, send direction
//   - txHMACKey: HMAC key, send direction — the whole 64-byte static-key slot;
//     crypto.NewCBCCipher takes the digest-sized prefix
//   - rxAESKey:  16-, 24- or 32-byte AES key, receive direction
//   - rxHMACKey: HMAC key, receive direction — likewise the whole slot
//
// One digest serves both: OpenVPN negotiates a single `auth` value for the
// connection, and there is no per-direction digest on the wire.
func NewCBC(wire WireFormat, peerID uint32, keyID uint8, digest crypto.Digest, txAESKey, txHMACKey, rxAESKey, rxHMACKey []byte) (*Channel, error) {
	enc, err := crypto.NewCBCCipher(txAESKey, txHMACKey, digest)
	if err != nil {
		return nil, fmt.Errorf("datachannel: tx CBC cipher: %w", err)
	}
	dec, err := crypto.NewCBCCipher(rxAESKey, rxHMACKey, digest)
	if err != nil {
		return nil, fmt.Errorf("datachannel: rx CBC cipher: %w", err)
	}
	return newWithCiphers(wire, peerID, keyID, enc, dec)
}

// firstPacketID is the packet_id of the first data packet a channel sends.
//
// It is 1 rather than 0 because OpenVPN reserves 0: a peer's replay state
// starts out meaning "nothing received yet" and 0 is the value that represents
// it, so packet_id_test refuses 0 before it consults the window at all
// (openvpn-2.6.22 src/openvpn/packet_id.c:209-212).
//
// Over UDP a packet carrying 0 costs one datagram and the tunnel works from id
// 1 onward. Over TCP a failed decrypt is fatal by design — forward.c:1124-1128
// raises SIGUSR1 whenever decryption fails on a connection-oriented link — so
// the session is torn down and no data crosses at all. The replay window is
// not the difference: --replay-window defaults to 64 on both
// (options.c:870-871).
//
// Reference: openvpn3 crypto/packet_id_data.hpp — PacketIDDataSend::next()
// returns an id beginning at 1, and PacketIDDataReceive refuses id 0 outright.
const firstPacketID uint32 = 1

// maxPacketID is the last id a short-form packet_id can carry, and the point at
// which the reference stops sending rather than reusing one (openvpn-2.6.22
// src/openvpn/packet_id.h:47, packet_id.c:324-343). Reuse under one key is not
// a dropped packet, it is a repeated nonce: for GCM the id *is* the IV counter,
// so a second packet at the same id hands an observer the xor of two plaintexts
// and forfeits the authentication key.
const maxPacketID uint32 = 0xFFFFFFFF

// ErrPacketIDExhausted is returned by Encrypt once this key's packet_id space
// is spent. It is terminal for the key epoch, not for the packet: the caller's
// answer is a renegotiation, which wrapTriggerPacketID should already have
// asked for 16M packets earlier.
var ErrPacketIDExhausted = errors.New("datachannel: packet_id space exhausted for this key")

// wrapTriggerPacketID is where the reference asks for a new key rather than
// waiting for the counter to run out — openvpn-2.6.22 src/openvpn/packet_id.h:53
// (PACKET_ID_WRAP_TRIGGER), consulted alongside reneg-sec and reneg-bytes in
// ssl.c:3098-3106. The 16M-packet margin is what makes ErrPacketIDExhausted
// unreachable in practice: a rekey has that long to complete.
const wrapTriggerPacketID uint32 = 0xFF000000

// newWithCiphers is the internal constructor used by New and NewCBC.
//
// A WireDataV1 channel carrying a peer-id is refused rather than corrected:
// P_DATA_V1 has no field to put one in, and the format is chosen from the
// *absence* of a pushed peer-id, so the two cannot legitimately disagree.
func newWithCiphers(wire WireFormat, peerID uint32, keyID uint8, enc, dec crypto.DataCipher) (*Channel, error) {
	switch wire {
	case WireDataV2:
	case WireDataV1:
		if peerID != 0 {
			return nil, fmt.Errorf(
				"datachannel: P_DATA_V1 channel built with peer-id %d: the format carries no "+
					"peer-id field, so the peer would never see it", peerID)
		}
	default:
		return nil, fmt.Errorf("datachannel: unknown wire format %d", int(wire))
	}
	return &Channel{
		wire:      wire,
		peerID:    peerID & 0x00FFFFFF,
		keyID:     keyID & 0x07,
		encryptor: enc,
		decryptor: dec,
		sendSeq:   firstPacketID,
	}, nil
}

// Encrypt encapsulates a plaintext IP packet into a data-channel wire packet
// in this channel's format.
//
// For GCM the packet_id appears explicitly after the header, and the tag and
// ciphertext follow. For CBC it is embedded as the first 4 bytes of the
// plaintext before encryption, and the HMAC and IV appear in the body.
func (c *Channel) Encrypt(plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	if c.sendExhausted {
		c.mu.Unlock()
		return nil, ErrPacketIDExhausted
	}
	seq := c.sendSeq
	if seq == maxPacketID {
		c.sendExhausted = true
	} else {
		c.sendSeq++
	}
	c.mu.Unlock()

	header := c.buildHeader()

	if c.encryptor.IsAEAD() {
		return c.encryptGCM(header, seq, plaintext)
	}
	return c.encryptCBC(header, seq, plaintext)
}

// SendCounter returns the packet_id the next outbound packet will carry, or
// maxPacketID once the space is spent. It exists for the rekey trigger, which
// is the reference's reason for looking at it too
// (packet_id_close_to_wrapping, packet_id.h:316-319).
func (c *Channel) SendCounter() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendSeq
}

// encryptGCM builds an AEAD data packet.
//
// Wire: header + packet_id(4B) + tag(16B) + ciphertext
// AAD = the authenticated part of the header + packet_id(4B), which follows
// the format rather than a constant — see aeadHeaderLen.
//
// Reference: openvpn3-core crypto/crypto_aead.hpp encrypt() sample comment:
//
//	48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
//	[ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
func (c *Channel) encryptGCM(header []byte, seq uint32, plaintext []byte) ([]byte, error) {
	// AAD = the authenticated part of the header || packet_id. For V1 that
	// header part is empty; see aeadHeaderLen.
	var seqBuf [4]byte
	binary.BigEndian.PutUint32(seqBuf[:], seq)
	aad := make([]byte, 0, len(header)+4)
	aad = append(aad, header[:c.wire.aeadHeaderLen()]...)
	aad = append(aad, seqBuf[:]...)

	ct := c.encryptor.Seal(seq, plaintext, aad)

	h := len(header)
	pkt := make([]byte, h+4+len(ct))
	copy(pkt[:h], header)
	binary.BigEndian.PutUint32(pkt[h:h+4], seq)
	copy(pkt[h+4:], ct)
	return pkt, nil
}

// encryptCBC builds a CBC+HMAC data packet.
// Wire: header + body  where body = [HMAC(N)][IV(16)][ciphertext], N the
// negotiated digest's tag length, and the plaintext passed to CBCCipher.Seal
// carries a 4-byte packet_id prefix. The body is byte-identical in both
// formats: the CBC header is not authenticated, so a shorter one only moves
// where the body starts.
func (c *Channel) encryptCBC(header []byte, seq uint32, plaintext []byte) ([]byte, error) {
	// Prepend packet_id to plaintext so it is encrypted and authenticated.
	inner := make([]byte, 4+len(plaintext))
	binary.BigEndian.PutUint32(inner[:4], seq)
	copy(inner[4:], plaintext)

	body := c.encryptor.Seal(seq, inner, nil)

	h := len(header)
	pkt := make([]byte, h+len(body))
	copy(pkt[:h], header)
	copy(pkt[h:], body)
	return pkt, nil
}

// Decrypt 按接收包的格式解码为明文 IP 包，并验证认证标签和重放保护。
func (c *Channel) Decrypt(pkt []byte) ([]byte, error) {
	if len(pkt) == 0 || framing.KeyIDFromByte(pkt[0]) != c.keyID {
		return nil, fmt.Errorf("datachannel: missing or mismatched key_id")
	}
	var incoming WireFormat
	switch framing.OpcodeFromByte(pkt[0]) {
	case framing.P_DATA_V1:
		incoming = WireDataV1
	case framing.P_DATA_V2:
		incoming = WireDataV2
	default:
		return nil, fmt.Errorf("datachannel: not a data packet")
	}
	// OpenVPN ssl.c handle_data_channel_packet 按接收 opcode 选择头长度和 AAD。
	// 服务端可发送 V1，同时要求客户端发送带 peer-id 的 V2；仍完整校验认证标签。
	if c.decryptor.IsAEAD() {
		return c.decryptGCM(pkt, incoming)
	}
	return c.decryptCBC(pkt, incoming)
}

// decryptGCM handles GCM-mode data packets.
//
// Wire: header + packet_id(4B) + tag(16B) + ciphertext
// (tag precedes ciphertext — see GCMCipher.Open for reorder logic)
func (c *Channel) decryptGCM(pkt []byte, incoming WireFormat) ([]byte, error) {
	h := incoming.headerLen()
	minLen := h + 4 + 16 // header + packetID + min GCM tag
	if len(pkt) < minLen {
		return nil, fmt.Errorf("datachannel: GCM packet too short: %d bytes", len(pkt))
	}

	seq := binary.BigEndian.Uint32(pkt[h : h+4])
	ct := pkt[h+4:]

	aad := pkt[h-incoming.aeadHeaderLen() : h+4] // authenticated header part + packet_id
	plain, err := c.decryptor.Open(seq, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("datachannel: decrypt GCM seq=%d: %w", seq, err)
	}
	// The window is consulted only once the tag has verified, which is where
	// the reference puts it: crypto_check_replay runs after
	// cipher_ctx_final_check_tag in openvpn_decrypt_aead (openvpn-2.6.22
	// src/openvpn/crypto.c). A replayed packet is decrypted before it is
	// refused; in exchange a packet that never authenticated cannot move or
	// probe the window at all, and CBC — whose packet_id is inside the
	// plaintext — has no other order available.
	if err := c.acceptReplay(seq); err != nil {
		return nil, err
	}
	return plain, nil
}

// decryptCBC handles CBC+HMAC data packets.
// Wire: header + [HMAC(N)][IV(16)][ciphertext]
// After decryption the first 4 bytes of plaintext are the packet_id.
func (c *Channel) decryptCBC(pkt []byte, incoming WireFormat) ([]byte, error) {
	// The smallest body is HMAC + IV + one ciphertext block, and the tag length
	// varies with the digest, so take it from the cipher: CBCCipher.Overhead()
	// is exactly that sum.
	h := incoming.headerLen()
	minBodyLen := c.decryptor.Overhead()
	if len(pkt) < h+minBodyLen {
		return nil, fmt.Errorf("datachannel: CBC packet too short: %d bytes", len(pkt))
	}

	body := pkt[h:] // strip the data-channel header

	inner, err := c.decryptor.Open(0, body, nil)
	if err != nil {
		return nil, fmt.Errorf("datachannel: decrypt CBC: %w", err)
	}
	if len(inner) < 4 {
		return nil, fmt.Errorf("datachannel: CBC plaintext too short after decrypt")
	}

	seq := binary.BigEndian.Uint32(inner[:4])
	if err := c.acceptReplay(seq); err != nil {
		return nil, err
	}
	return inner[4:], nil // strip the embedded packet_id
}

// buildHeader constructs this channel's packet header: the opcode and key_id
// byte, followed for P_DATA_V2 by the 3-byte peer-id.
func (c *Channel) buildHeader() []byte {
	h := make([]byte, c.wire.headerLen())
	h[0] = framing.FirstByte(c.wire.opcode(), c.keyID)
	if c.wire == WireDataV1 {
		return h
	}
	h[1] = byte(c.peerID >> 16)
	h[2] = byte(c.peerID >> 8)
	h[3] = byte(c.peerID)
	return h
}

// acceptReplay records seq in the replay window and reports whether the packet
// may be delivered. A non-nil error means the packet is a replay, or has fallen
// out of the back of the window, and the caller must drop it.
//
// Testing the window and recording the id are one operation under one lock: two
// goroutines that both passed a separate check before either recorded would
// deliver one captured packet twice, which is what a replay window exists to
// refuse. internal/wrap's replayWindow.accept is the same shape, and so is the
// reference — packet_id_test and packet_id_add run together inside
// crypto_check_replay (openvpn-2.6.22 src/openvpn/crypto.c).
func (c *Channel) acceptReplay(seq uint32) error {
	// packet_id 0 is reserved and never valid on the wire, in either direction
	// — the same rule the send side starts at 1 for; see firstPacketID.
	if seq == 0 {
		return fmt.Errorf("datachannel: replay: packet_id 0 is reserved")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	switch {
	case !c.replaySet:
		// First packet ever: it establishes the window rather than being
		// judged against it.
		c.replayTop, c.replayBits, c.replaySet = seq, 1, true
		return nil

	case seq > c.replayTop:
		// A new high-water mark. The window slides up by advance, so every
		// recorded id moves that many bits further from the top; an advance
		// of a whole window or more leaves nothing in range.
		if advance := seq - c.replayTop; advance >= replayWindowSize {
			c.replayBits = 0
		} else {
			c.replayBits <<= advance
		}
		c.replayTop = seq
		c.replayBits |= 1
		return nil

	case c.replayTop-seq >= replayWindowSize:
		return fmt.Errorf("datachannel: replay: seq %d too old (top=%d)", seq, c.replayTop)
	}

	bit := uint64(1) << (c.replayTop - seq)
	if c.replayBits&bit != 0 {
		return fmt.Errorf("datachannel: replay: seq %d already seen", seq)
	}
	c.replayBits |= bit
	return nil
}
