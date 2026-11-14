package wrap

import (
	"errors"
	"sync"
	"time"
)

// The control-channel replay window.
//
// This is a *different ID space* from the reliability layer's message packet
// ids, and the distinction is what this file is careful about. Every wrapped
// control packet carries two counters:
//
//	plain = opcode|key_id ‖ session_id ‖ ack_array ‖ [message_packet_id ‖ payload]
//	wire  = opcode|key_id ‖ session_id ‖ hmac ‖ packet_id ‖ timestamp ‖ …
//
// The inner message_packet_id belongs to the reliable layer: it numbers
// control *messages*, it is acknowledged, and a retransmission reuses it. The
// outer packet_id belongs to the wrap: it numbers *packets*, nothing
// acknowledges it, and a retransmission of the same message gets a fresh one
// (docker/TLS-WRAP-VECTORS.md §2). Conflating them produces a client that
// works until the first retransmit, so this window is built where it cannot
// see the reliable layer at all: it takes two integers off the wrap's own
// header and answers accept or reject.
//
// Reference: OpenVPN 2.4.12 src/openvpn/packet_id.c, packet_id_test() and the
// --replay-window option, read from the pinned tarball the vector capture uses
// (docs/openvpn3-reference-policy.md §3.3) and asserted directly rather than
// trusted (§3.4) — see replay_test.go.

// Errors a Wrapper returns for a packet it will not accept. They are sentinels
// because the caller has to tally them apart: an authentication failure means
// the key is wrong and the session cannot work, while a replay means the key is
// right and something on the path duplicated a packet.
var (
	// ErrAuth means the packet did not authenticate under the receive key:
	// an HMAC mismatch, or a packet too short for the fields the wrap
	// requires. Both are diag.ClassCrypto.
	ErrAuth = errors.New("wrap: control packet failed authentication")

	// ErrReplay means the packet authenticated but its packet id has been
	// seen before, or has fallen out of the back of the window.
	ErrReplay = errors.New("wrap: control packet id replayed")

	// ErrStaleTimestamp means the packet authenticated but its timestamp is
	// older than one already accepted from this peer, which retires every
	// packet id below it.
	ErrStaleTimestamp = errors.New("wrap: control packet timestamp went backwards")
)

// replayWindowSize is how far behind the highest accepted packet id a
// reordered packet may still arrive: OpenVPN's --replay-window default of 64,
// which is also the width of the bitmap below, so it is not a knob.
const replayWindowSize = 64

// replayWindow accepts each (packet id, timestamp) pair at most once.
//
// The state is per connection and per direction, shared with nothing: a
// reconnect builds a new wrap, so the peer restarting its packet ids at 1 is a
// new window and not 64 replays. It is safe for concurrent use, because
// Wrapper's contract promises that whatever the client does today.
type replayWindow struct {
	mu sync.Mutex
	// started is false until the first packet is accepted. That packet
	// establishes the epoch rather than being judged against it.
	started bool
	// epoch is the highest timestamp accepted so far, and top the highest
	// packet id accepted within that timestamp.
	epoch uint32
	top   uint32
	// seen is a bitmap of the replayWindowSize ids at and below top. Bit k
	// stands for id top-k, so bit 0 is top itself, always set once started.
	seen uint64
}

// accept records a packet's replay header and reports whether it may be
// delivered. A non-nil result is ErrReplay or ErrStaleTimestamp, and the
// packet must be dropped and counted.
//
// The comparison is against the *peer's* own highest timestamp, never the
// local clock, as OpenVPN's packet_id_test does: the timestamp is written by
// the sender, so a window judged against our clock rejects every packet from a
// peer whose clock differs by more than the tolerance.
//
// The cost is that this window does not, on its own, stop a packet from an
// *earlier session* being replayed into a new one — a fresh window accepts
// whatever arrives first, and neither does OpenVPN's. The session id in the
// header and the TLS handshake above it are what make an old packet useless.
func (w *replayWindow) accept(packetID, timestamp uint32) error {
	// Packet id 0 is never legitimate: OpenVPN's counter starts at 1 in both
	// directions and packet_id_test rejects a zero id outright.
	if packetID == 0 {
		return ErrReplay
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	switch {
	case !w.started:
		w.started = true
		w.epoch, w.top, w.seen = timestamp, packetID, 1
		return nil

	case timestamp > w.epoch:
		// The peer moved into a new second. Its counter continues, but
		// every id below is retired: OpenVPN starts a fresh sequence list
		// when the time value increases.
		w.epoch, w.top, w.seen = timestamp, packetID, 1
		return nil

	case timestamp < w.epoch:
		// A timestamp that goes backwards is stale, as it is for OpenVPN.
		// A reordering across a one-second boundary is dropped and the
		// reliable layer retransmits with a fresh packet id and timestamp,
		// so the retransmit is not itself a replay.
		return ErrStaleTimestamp
	}

	// Same second: an ordinary sliding window on the id.
	switch {
	case packetID > w.top:
		if shift := packetID - w.top; shift >= replayWindowSize {
			w.seen = 1
		} else {
			w.seen = w.seen<<shift | 1
		}
		w.top = packetID
		return nil

	case w.top-packetID >= replayWindowSize:
		// Older than the window can remember. Refusing it is the safe
		// answer: we cannot tell it apart from a packet already delivered.
		return ErrReplay

	default:
		bit := uint64(1) << (w.top - packetID)
		if w.seen&bit != 0 {
			return ErrReplay
		}
		w.seen |= bit
		return nil
	}
}

// -------------------------------------------------------------------------
// The send side of the same ID space
// -------------------------------------------------------------------------

// sendCounter stamps the replay header on outgoing packets: the wrap's own
// packet id, and the clock. It lives here, beside the window that judges the
// header coming the other way, because both wraps produce it identically —
// tls-auth prepends it to its digest and tls-crypt hashes it where it sits. The
// counter starts at 1, not 0, which every captured vector shows and which the
// peer's packet_id_test rejects.
//
// It is safe for concurrent use, as Wrapper's contract requires: the client's
// control, ack, retransmit and rekey paths all send from goroutines of their own.
type sendCounter struct {
	mu sync.Mutex
	// next is the packet id the next header will carry. The zero value is
	// treated as 1 rather than being an error, so a wrap does not have to
	// remember to initialise it.
	next uint32
	// stub, when set, replaces the counter and the clock, so a known-answer
	// test can reproduce the header a capture stamped. Nothing in production
	// sets it; see export_test.go.
	stub func() (uint32, uint32)
}

// header returns the packet id and timestamp for one outgoing packet.
func (c *sendCounter) header() (uint32, uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stub != nil {
		return c.stub()
	}
	// Packet id 0 is not a legal control-channel id; this skips it in both
	// the cases that produce one, a counter never used and one that has just
	// wrapped past 0xFFFFFFFF.
	if c.next == 0 {
		c.next = 1
	}
	id := c.next
	c.next++
	return id, uint32(time.Now().Unix())
}

// setForTest fixes the header every subsequent call to header returns.
func (c *sendCounter) setForTest(packetID, timestamp uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stub = func() (uint32, uint32) { return packetID, timestamp }
}
