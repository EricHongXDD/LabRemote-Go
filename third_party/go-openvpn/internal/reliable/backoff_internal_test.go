package reliable

import (
	"testing"
	"time"
)

// TestRetransmitBackoffStaysPositiveAndCapped walks the retry counter past the
// point where RetransmitTimeout * (1 << retries) overflows int64 nanoseconds.
// The product goes negative there, and a negative duration passes a "larger
// than the cap" test unchanged, which hands back a deadline in the past.
func TestRetransmitBackoffStaysPositiveAndCapped(t *testing.T) {
	for retries := 0; retries <= 70; retries++ {
		got := retransmitBackoff(retries)
		if got <= 0 {
			t.Errorf("retries=%d: back-off %v is not positive", retries, got)
		}
		if got > maxRetransmitBackoff {
			t.Errorf("retries=%d: back-off %v exceeds the %v cap", retries, got, maxRetransmitBackoff)
		}
	}
}

// TestDueForRetransmitAlwaysDefersTheNextTry is the same property one level up:
// however long an entry has gone unacknowledged, being handed back for
// retransmission must push its next attempt into the future. When it did not,
// every tick retransmitted every entry — a storm rather than a back-off.
func TestDueForRetransmitAlwaysDefersTheNextTry(t *testing.T) {
	q := &SendQueue{}
	if _, err := q.Enqueue([]byte("control")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	for round := 0; round <= 70; round++ {
		q.mu.Lock()
		for _, e := range q.entries {
			e.NextRetry = time.Now().Add(-time.Second)
		}
		q.mu.Unlock()

		due := q.DueForRetransmit()
		if len(due) != 1 {
			t.Fatalf("round %d: got %d entries due, want 1", round, len(due))
		}
		if !due[0].NextRetry.After(time.Now()) {
			t.Fatalf("round %d (retries=%d): next retry %v is not in the future",
				round, due[0].Retries, due[0].NextRetry)
		}
	}
}
