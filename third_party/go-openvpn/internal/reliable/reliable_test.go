package reliable_test

import (
	"testing"

	"github.com/buengese/go-openvpn/internal/framing"
	"github.com/buengese/go-openvpn/internal/reliable"
)

// --- SendQueue tests ---

func TestSendQueueEnqueueAck(t *testing.T) {
	q := &reliable.SendQueue{}

	id0, err := q.Enqueue([]byte("pkt0"))
	if err != nil || id0 != 0 {
		t.Fatalf("Enqueue 0: id=%d err=%v", id0, err)
	}
	id1, err := q.Enqueue([]byte("pkt1"))
	if err != nil || id1 != 1 {
		t.Fatalf("Enqueue 1: id=%d err=%v", id1, err)
	}
	if q.Len() != 2 {
		t.Fatalf("Len = %d, want 2", q.Len())
	}

	q.Ack(0)
	if q.Len() != 1 {
		t.Fatalf("Len after Ack(0) = %d, want 1", q.Len())
	}

	// Double-ack is idempotent
	q.Ack(0)
	if q.Len() != 1 {
		t.Fatal("double-ack changed queue length")
	}
}

func TestSendQueueUnbounded(t *testing.T) {
	// SendQueue is unbounded — large TLS records fragment into many segments.
	q := &reliable.SendQueue{}
	for i := 0; i < reliable.WindowSize*4; i++ {
		if _, err := q.Enqueue([]byte("x")); err != nil {
			t.Fatalf("unexpected error at i=%d: %v", i, err)
		}
	}
	if q.Len() != reliable.WindowSize*4 {
		t.Fatalf("Len = %d, want %d", q.Len(), reliable.WindowSize*4)
	}
}

func TestSendQueueAckMany(t *testing.T) {
	q := &reliable.SendQueue{}
	for i := 0; i < 4; i++ {
		q.Enqueue([]byte("x")) //nolint:errcheck
	}
	q.AckMany([]uint32{0, 2})
	if q.Len() != 2 {
		t.Fatalf("Len = %d, want 2", q.Len())
	}
}

// TestControlPacketAcknowledgesReliableQueue closes the loop between the wire
// and the queue: the IDs a P_CONTROL_V1 piggybacks are handed to AckMany, so
// the two numberings have to be one numbering. The queue starts at ID 1, as
// Client.tlsHandshake's does, because the HARD_RESET already spent ID 0.
func TestControlPacketAcknowledgesReliableQueue(t *testing.T) {
	var sender, remote [8]byte
	q := reliable.NewSendQueue(1)
	if _, err := q.Enqueue([]byte("first")); err != nil {
		t.Fatalf("enqueue first: %v", err)
	}
	if _, err := q.Enqueue([]byte("second")); err != nil {
		t.Fatalf("enqueue second: %v", err)
	}

	// P_CONTROL_V1 carries a packet ID of its own and can piggyback ACKs for
	// outbound client control packets.  The outbound queue starts at ID 1.
	pkt := framing.BuildControlV1(sender, remote, 1, 12, []uint32{1, 2}, []byte("server TLS"))
	q.AckMany(framing.ParseControlV1AckIDs(pkt))
	if got := q.Len(); got != 0 {
		t.Fatalf("unacknowledged control packets = %d, want 0", got)
	}
}

// TestSendQueueNothingDueImmediatelyAfterEnqueue covers the near edge of the
// retransmit timer: a packet enqueued a moment ago has not timed out, so
// resending it would double every control packet on the wire.
func TestSendQueueNothingDueImmediatelyAfterEnqueue(t *testing.T) {
	q := &reliable.SendQueue{}
	q.Enqueue([]byte("retrans")) //nolint:errcheck

	if due := q.DueForRetransmit(); len(due) != 0 {
		t.Fatalf("expected no retransmit immediately, got %d", len(due))
	}
}

// --- RecvWindow tests ---

func TestRecvWindowInOrder(t *testing.T) {
	w := reliable.NewRecvWindow()
	payloads, acks := w.Receive(0, []byte("a"))
	if len(payloads) != 1 || string(payloads[0]) != "a" {
		t.Fatalf("expected [a], got %v", payloads)
	}
	if len(acks) != 1 || acks[0] != 0 {
		t.Fatalf("acks = %v, want [0]", acks)
	}
	// The window advanced: the next id in sequence delivers straight away
	// rather than being held back as out of order.
	if next, _ := w.Receive(1, []byte("b")); len(next) != 1 || string(next[0]) != "b" {
		t.Fatalf("packet 1 was not delivered in order, got %v", next)
	}
}

func TestRecvWindowOutOfOrder(t *testing.T) {
	w := reliable.NewRecvWindow()

	// Deliver packet 1 before packet 0.
	payloads, acks := w.Receive(1, []byte("b"))
	if len(payloads) != 0 {
		t.Fatal("expected no delivered packets for out-of-order pkt 1")
	}
	if len(acks) != 1 {
		t.Fatalf("expected ack for pkt 1, got %v", acks)
	}

	// Now deliver packet 0; both should flush.
	payloads, acks = w.Receive(0, []byte("a"))
	if len(payloads) != 2 {
		t.Fatalf("expected 2 delivered packets, got %d", len(payloads))
	}
	if string(payloads[0]) != "a" || string(payloads[1]) != "b" {
		t.Fatalf("unexpected order: %v", payloads)
	}
	// Both were consumed, so the window now sits at 2 and the next id in
	// sequence delivers on arrival.
	if next, _ := w.Receive(2, []byte("c")); len(next) != 1 || string(next[0]) != "c" {
		t.Fatalf("packet 2 was not delivered in order, got %v", next)
	}
	_ = acks
}

func TestRecvWindowDuplicate(t *testing.T) {
	w := reliable.NewRecvWindow()
	w.Receive(0, []byte("a")) //nolint:errcheck
	// Duplicate — should be dropped, no second delivery.
	payloads, _ := w.Receive(0, []byte("a"))
	if len(payloads) != 0 {
		t.Fatalf("duplicate packet should not be re-delivered, got %v", payloads)
	}
}

func TestRecvWindowOutsideWindow(t *testing.T) {
	w := reliable.NewRecvWindow()
	// Packet beyond window size should be dropped.
	payloads, acks := w.Receive(uint32(reliable.WindowSize), []byte("far"))
	if len(payloads) != 0 || len(acks) != 0 {
		t.Fatalf("out-of-window packet should be dropped: payloads=%v acks=%v", payloads, acks)
	}
}

// TestShouldAckFollowsTheReferenceRule pins both halves of the reference's
// acknowledgement decision. A packet already delivered is acknowledged again
// (openvpn-2.6.22 src/openvpn/ssl.c:4046-4047), which is how a peer whose ACK
// was lost learns its retransmit arrived; a packet beyond the window is not,
// because reliable_wont_break_sequentiality (ssl.c:4031) rejects it first.
func TestShouldAckFollowsTheReferenceRule(t *testing.T) {
	w := reliable.NewRecvWindowFrom(10)

	if !w.ShouldAck(10) {
		t.Error("the expected packet is not acknowledged")
	}
	if !w.ShouldAck(10 + reliable.WindowSize - 1) {
		t.Error("the last packet inside the window is not acknowledged")
	}
	if w.ShouldAck(10 + reliable.WindowSize) {
		t.Error("a packet beyond the window is acknowledged; the peer would stop retransmitting it")
	}

	// Deliver 10, then replay it: still acknowledged.
	w.Receive(10, []byte("x"))
	if !w.ShouldAck(10) {
		t.Error("a replay is not acknowledged; a peer whose ACK was lost would retransmit forever")
	}
}
