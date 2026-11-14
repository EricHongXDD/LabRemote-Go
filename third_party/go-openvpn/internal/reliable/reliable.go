// Package reliable implements the OpenVPN3 reliable control-channel transport:
// sequence numbers, ACK handling, retransmit queue, and a sliding receive window.
//
// Reference: openvpn3-core reliable/relsend.hpp and relrecv.hpp, driven from
// ssl/protostack.hpp.
package reliable

import (
	"sync"
	"time"
)

// WindowSize is the maximum number of unacknowledged in-flight packets: the
// receive window openvpn3-core takes from ReliableAck::maximum_acks_ack_v1
// (reliable/relack.hpp:31), applied here in both directions.
const WindowSize = 8

// RetransmitTimeout is the initial retransmit interval, OpenVPN 2.x's
// --tls-timeout default. openvpn3-core resets a flat tls_timeout on every send
// (reliable/relsend.hpp:50-53); the back-off below is ours.
const RetransmitTimeout = 2 * time.Second

// maxRetransmitBackoff caps the exponential back-off between retransmits.
const maxRetransmitBackoff = 30 * time.Second

// maxBackoffShift is the retry count past which the back-off is the cap
// regardless, so the shift is never taken. RetransmitTimeout * (1 << 4) is
// already over the cap, so this is generous.
const maxBackoffShift = 16

// Entry is a single outgoing packet held in the retransmit queue. The schedule
// is NextRetry, which DueForRetransmit compares against and retransmitBackoff
// advances; there is no send timestamp because no decision consults one.
type Entry struct {
	PacketID  uint32
	Payload   []byte
	Retries   int
	NextRetry time.Time
}

// SendQueue manages the sliding window of unacknowledged outgoing packets.
type SendQueue struct {
	mu      sync.Mutex
	entries []*Entry
	nextID  uint32
}

// Enqueue adds payload to the send queue and returns the assigned packet ID.
// It never drops: the queue is unbounded so large TLS records (which fragment
// into many P_CONTROL_V1 segments) can all be tracked for retransmit.
func (q *SendQueue) Enqueue(payload []byte) (uint32, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	id := q.nextID
	q.nextID++
	now := time.Now()
	e := &Entry{
		PacketID:  id,
		Payload:   payload,
		NextRetry: now.Add(RetransmitTimeout),
	}
	q.entries = append(q.entries, e)
	return id, nil
}

// Ack removes the entry with the given packet ID from the queue.
// It is safe to call with an ID that is not in the queue (idempotent).
func (q *SendQueue) Ack(packetID uint32) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i, e := range q.entries {
		if e.PacketID == packetID {
			q.entries = append(q.entries[:i], q.entries[i+1:]...)
			return
		}
	}
}

// AckMany removes all entries whose packet IDs appear in ids.
func (q *SendQueue) AckMany(ids []uint32) {
	for _, id := range ids {
		q.Ack(id)
	}
}

// DueForRetransmit returns entries whose NextRetry deadline has passed.
// It updates each returned entry's NextRetry and Retries counter.
func (q *SendQueue) DueForRetransmit() []*Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	var due []*Entry
	for _, e := range q.entries {
		if now.After(e.NextRetry) {
			e.Retries++
			e.NextRetry = now.Add(retransmitBackoff(e.Retries))
			due = append(due, e)
		}
	}
	return due
}

// retransmitBackoff is the exponential back-off for a packet that has been
// retransmitted retries times, capped at maxRetransmitBackoff.
//
// Bounding the shift separately is the point of this function.
// RetransmitTimeout * (1 << retries) overflows int64 nanoseconds at retries 33,
// and the negative duration that comes back is not caught by a "larger than the
// cap" test: NextRetry lands in the past and every tick retransmits every
// entry.
func retransmitBackoff(retries int) time.Duration {
	if retries >= maxBackoffShift {
		return maxRetransmitBackoff
	}
	if backoff := RetransmitTimeout * (1 << retries); backoff < maxRetransmitBackoff {
		return backoff
	}
	return maxRetransmitBackoff
}

// Len returns the current number of unacknowledged entries.
func (q *SendQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries)
}

// NextID returns the packet ID that will be assigned to the next Enqueue call.
// Use this to build the wire packet before calling Enqueue.
func (q *SendQueue) NextID() uint32 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.nextID
}

// RecvWindow is a sliding receive window that delivers packets in order
// and discards duplicates / out-of-range packets.
type RecvWindow struct {
	mu       sync.Mutex
	expected uint32
	// pending holds out-of-order packets keyed by packet_id.
	pending map[uint32][]byte
}

// NewRecvWindow creates a RecvWindow expecting the first packet ID to be 0.
func NewRecvWindow() *RecvWindow {
	return &RecvWindow{pending: make(map[uint32][]byte)}
}

// NewRecvWindowFrom creates a RecvWindow expecting the first packet ID to be firstExpected.
func NewRecvWindowFrom(firstExpected uint32) *RecvWindow {
	return &RecvWindow{expected: firstExpected, pending: make(map[uint32][]byte)}
}

// NewSendQueue creates a SendQueue that assigns packet IDs starting from firstPacketID.
func NewSendQueue(firstPacketID uint32) *SendQueue {
	return &SendQueue{nextID: firstPacketID}
}

// ShouldAck reports whether a received packet id may be acknowledged.
//
// The rule is the reference's, and it is not "everything we admitted": a packet
// already delivered is acknowledged again, deliberately (openvpn-2.6.22
// src/openvpn/ssl.c:4046-4047, "Process outgoing acknowledgment for packet just
// received, even if it's a replay"), which is how a peer whose ACK was lost
// learns its retransmit arrived.
//
// What is refused is a packet beyond the window, which
// reliable_wont_break_sequentiality (ssl.c:4031) rejects before any ack is
// considered: acknowledging one claims receipt of something that was dropped,
// and the peer stops retransmitting it.
func (w *RecvWindow) ShouldAck(packetID uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return packetID < w.expected+WindowSize
}

// Receive delivers a packet to the window. payloads holds the in-order packets
// now ready for the upper layer, and ackIDs the packet ids to acknowledge.
//
// A packet already delivered, or beyond the window, is dropped and yields no
// ackID; re-acknowledging a delivered packet is ShouldAck's job, not this
// one's.
func (w *RecvWindow) Receive(packetID uint32, payload []byte) (payloads [][]byte, ackIDs []uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Drop if too far behind (already delivered).
	if packetID < w.expected {
		return nil, nil
	}

	// Drop if too far ahead (outside window).
	if packetID >= w.expected+WindowSize {
		return nil, nil
	}

	// Store in pending (idempotent — overwriting is safe for immutable payloads).
	w.pending[packetID] = payload
	ackIDs = append(ackIDs, packetID)

	// Deliver all consecutive packets starting from expected.
	for {
		p, ok := w.pending[w.expected]
		if !ok {
			break
		}
		payloads = append(payloads, p)
		delete(w.pending, w.expected)
		w.expected++
	}
	return payloads, ackIDs
}
