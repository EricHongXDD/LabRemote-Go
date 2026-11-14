// Key rotation manager for the OpenVPN3 data channel.
//
// OpenVPN renegotiates data-channel keys either after a time interval
// (reneg-sec) or after a byte threshold (reneg-bytes), whichever comes first.
// The server advertises these limits in the PUSH_REPLY options; the client is
// responsible for initiating renegotiation.
//
// Renegotiation lifecycle (openvpn3-core client/ovpncli.cpp):
//
//  1. Caller detects the limit via NeedsRekey.
//  2. Caller sends P_CONTROL_SOFT_RESET_V1 over the control channel.
//  3. A new TLS session completes and a new key block is derived.
//  4. Caller calls Prepare with a new *Channel built from the new keys.
//     Both key epochs remain valid during the promotion window.
//  5. Caller promotes the new key once the peer has had time to activate it.
//
// This package only tracks the *when* of renegotiation; the actual TLS
// renegotiation is handled by the caller (the ctls / reliable layer).
//
// Reference: openvpn3-core ssl/proto.hpp ProtoConfig and KeyContext
package datachannel

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/internal/framing"
)

// DefaultRenegSec is the default key renegotiation interval (3600 s = 1 hour).
// Matches openvpn3-core ssl/proto.hpp ProtoConfig::renegotiate.
const DefaultRenegSec = 3600

// DefaultRenegBytes is the default byte threshold for key renegotiation.
// 0 means no byte-limit renegotiation (openvpn3-core default).
const DefaultRenegBytes = 0

// Manager wraps a Channel and tracks the byte and time limits that trigger
// key renegotiation.  It is safe for concurrent use.
type Manager struct {
	mu        sync.RWMutex
	current   *Channel // primary: used for outgoing packets
	secondary *Channel // newly negotiated key, accepted before promotion
	previous  *Channel // prior primary, accepted after promotion

	renegSec   int          // renegotiation interval in seconds (0 = disabled)
	renegBytes int64        // byte threshold (0 = disabled)
	startedAt  time.Time    // time the current key epoch started
	bytesSent  atomic.Int64 // bytes encrypted since last rotation
	bytesRecv  atomic.Int64 // bytes decrypted since last rotation

	// codec is the session's compression, fixed at construction.
	// Reference: openvpn3-core ssl/proto.hpp parse_pushed_compression() line ~875.
	codec *compress.Codec
}

// ManagerConfig holds the renegotiation parameters parsed from PUSH_REPLY.
type ManagerConfig struct {
	// RenegSec is the key renegotiation interval in seconds.
	// 0 disables time-based renegotiation.
	RenegSec int

	// RenegBytes is the byte threshold for renegotiation.
	// 0 disables byte-based renegotiation.
	RenegBytes int64

	// Compress is the session's compression codec, built from the *effective*
	// mode: what compress.EffectiveMode made of the profile's directive, the
	// server's pushed one and allow-compression. nil adds and strips nothing.
	Compress *compress.Codec
}

// NewManager creates a Manager wrapping ch with the given renegotiation config.
// If cfg is nil, defaults are used (3600 s, no byte limit).
func NewManager(ch *Channel, cfg *ManagerConfig) *Manager {
	m := &Manager{
		current:   ch,
		startedAt: time.Now(),
		codec:     compress.NewCodec(compress.ModeNone, 0),
	}
	if cfg != nil {
		m.renegSec = cfg.RenegSec
		m.renegBytes = cfg.RenegBytes
		if cfg.Compress != nil {
			m.codec = cfg.Compress
		}
	} else {
		m.renegSec = DefaultRenegSec
		m.renegBytes = DefaultRenegBytes
	}
	return m
}

// Encrypt encrypts a plaintext IP packet, updates the byte counter, and
// returns the wire packet in the current epoch's format.
//
// If a compression mode is active the plaintext is framed before encryption
// (Wrap), always with the uncompressed marker.
//
// Reference: openvpn3-core ssl/proto.hpp KeyContext::do_encrypt().
func (m *Manager) Encrypt(plaintext []byte) ([]byte, error) {
	m.mu.RLock()
	ch := m.current
	m.mu.RUnlock()

	inner, err := m.codec.Wrap(plaintext)
	if err != nil {
		return nil, err
	}
	pkt, err := ch.Encrypt(inner)
	if err != nil {
		return nil, err
	}
	m.bytesSent.Add(int64(len(plaintext)))
	return pkt, nil
}

// Decrypt decrypts a data-channel wire packet, updates the byte counter, and
// returns the plaintext IP packet.
//
// If a compression mode is active the framing is stripped after decryption
// (Unwrap). A payload compressed with an algorithm this client cannot
// decompress comes back as compress.ErrCompressed.
//
// Reference: openvpn3-core ssl/proto.hpp KeyContext::decrypt().
func (m *Manager) Decrypt(pkt []byte) ([]byte, error) {
	m.mu.RLock()
	ch, err := m.decryptChannel(pkt)
	m.mu.RUnlock()
	if err != nil {
		return nil, err
	}

	inner, err := ch.Decrypt(pkt)
	if err != nil {
		return nil, err
	}
	plain, err := m.codec.Unwrap(inner)
	if err != nil {
		return nil, err
	}
	m.bytesRecv.Add(int64(len(plain)))
	return plain, nil
}

// decryptChannel selects the data-channel key epoch from the packet's key ID.
// During a rekey, OpenVPN keeps the old and newly negotiated keys valid at the
// same time, so packets can arrive under either ID.
//
// 密钥按 key_id 选择，包头格式交给 Channel.Decrypt 逐包解析。
// 接收包仍使用同一密钥与重放窗口，不修改已协商的发送格式。
//
// m.mu must be held by the caller.
func (m *Manager) decryptChannel(pkt []byte) (*Channel, error) {
	if len(pkt) == 0 {
		return nil, fmt.Errorf("datachannel: empty packet")
	}
	op := framing.OpcodeFromByte(pkt[0])
	if op != framing.P_DATA_V1 && op != framing.P_DATA_V2 {
		return nil, fmt.Errorf("datachannel: not a data packet: opcode %d", op)
	}

	keyID := framing.KeyIDFromByte(pkt[0])
	for _, ch := range []*Channel{m.current, m.secondary, m.previous} {
		if ch == nil || ch.keyID != keyID {
			continue
		}
		return ch, nil
	}
	return nil, fmt.Errorf("datachannel: unknown key_id %d", keyID)
}

// NeedsRekey reports whether the current key epoch has exceeded its time or
// byte limits, or is running out of packet ids, and a renegotiation should be
// initiated. The reference weighs the same conditions in one expression
// (openvpn-2.6.22 src/openvpn/ssl.c:3098-3106). The send counter approaching
// its wrap is the one trigger that still fires with every configured limit
// disabled — a key whose packet_id space runs out can send nothing more (see
// ErrPacketIDExhausted).
func (m *Manager) NeedsRekey() bool {
	m.mu.RLock()
	pending := m.secondary != nil
	startedAt := m.startedAt
	renegSec := m.renegSec
	renegBytes := m.renegBytes
	current := m.current
	m.mu.RUnlock()

	// A secondary key is already being negotiated or is awaiting promotion.
	// Starting another rekey would replace it before the peer can switch.
	if pending {
		return false
	}
	if renegSec > 0 {
		if time.Since(startedAt) >= time.Duration(renegSec)*time.Second {
			return true
		}
	}
	if renegBytes > 0 {
		total := m.bytesSent.Load() + m.bytesRecv.Load()
		if total >= renegBytes {
			return true
		}
	}
	if current != nil && current.SendCounter() >= wrapTriggerPacketID {
		return true
	}
	return false
}

// Prepare installs next as a secondary key while retaining current as the
// primary send key. Both key IDs are accepted for decryption until Promote.
// It also starts the next renegotiation interval and clears its byte counters.
func (m *Manager) Prepare(next *Channel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secondary = next
	// OpenVPN maintains only a primary and one secondary context. A stale key
	// from the prior transition must not survive into a new transition.
	m.previous = nil
	m.startedAt = time.Now()
	m.bytesSent.Store(0)
	m.bytesRecv.Store(0)
}

// Promote makes the prepared keyID the primary send key, retaining the old
// primary for decryption because the peer may still have in-flight packets from
// the old epoch. It returns false unless the requested key is still the
// prepared secondary.
func (m *Manager) Promote(keyID uint8) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.secondary == nil || m.secondary.keyID != keyID&0x07 {
		return false
	}
	m.previous = m.current
	m.current = m.secondary
	m.secondary = nil
	return true
}
