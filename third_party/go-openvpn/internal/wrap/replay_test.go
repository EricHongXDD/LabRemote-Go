package wrap

import (
	"errors"
	"sync"
	"testing"
)

// The control replay window: which packet ids and timestamps it accepts, and
// which it refuses.

// TestReplayWindowAcceptsAFreshSequence is the case every handshake takes: a
// counter starting at 1 inside one second.
func TestReplayWindowAcceptsAFreshSequence(t *testing.T) {
	var w replayWindow
	for id := uint32(1); id <= 200; id++ {
		if err := w.accept(id, 1000); err != nil {
			t.Fatalf("packet id %d rejected: %v", id, err)
		}
	}
}

// TestReplayWindowRejectsARepeatedID is the property the window exists for: a
// packet with a replayed control packet id is rejected.
func TestReplayWindowRejectsARepeatedID(t *testing.T) {
	var w replayWindow
	for _, id := range []uint32{1, 2, 3} {
		if err := w.accept(id, 1000); err != nil {
			t.Fatalf("packet id %d rejected on first sight: %v", id, err)
		}
	}
	for _, id := range []uint32{1, 2, 3} {
		if err := w.accept(id, 1000); !errors.Is(err, ErrReplay) {
			t.Fatalf("replay of packet id %d: err = %v, want ErrReplay", id, err)
		}
	}
}

// TestReplayWindowAcceptsReorderingInsideTheWindow keeps the window from being
// a plain high-water mark. UDP reorders, and rejecting every out-of-order
// packet would make the wrap the thing that breaks the link.
func TestReplayWindowAcceptsReorderingInsideTheWindow(t *testing.T) {
	var w replayWindow
	// 10 arrives first; 1..9 are still legitimate arrivals behind it.
	if err := w.accept(10, 1000); err != nil {
		t.Fatalf("packet id 10: %v", err)
	}
	for id := uint32(1); id < 10; id++ {
		if err := w.accept(id, 1000); err != nil {
			t.Fatalf("out-of-order packet id %d rejected: %v", id, err)
		}
	}
	// ...and each of them exactly once.
	for id := uint32(1); id <= 10; id++ {
		if err := w.accept(id, 1000); !errors.Is(err, ErrReplay) {
			t.Fatalf("second delivery of packet id %d: err = %v, want ErrReplay", id, err)
		}
	}
}

// TestReplayWindowRejectsPacketsOlderThanTheWindow pins the back edge at
// OpenVPN's --replay-window default of 64. A packet further back cannot be
// told apart from one already delivered, so it is refused.
func TestReplayWindowRejectsPacketsOlderThanTheWindow(t *testing.T) {
	var w replayWindow
	const top = 1000
	if err := w.accept(top, 1); err != nil {
		t.Fatalf("packet id %d: %v", top, err)
	}
	if err := w.accept(top-replayWindowSize+1, 1); err != nil {
		t.Fatalf("packet id %d is the oldest the window holds and was rejected: %v",
			top-replayWindowSize+1, err)
	}
	if err := w.accept(top-replayWindowSize, 1); !errors.Is(err, ErrReplay) {
		t.Fatalf("packet id %d is past the back edge: err = %v, want ErrReplay",
			top-replayWindowSize, err)
	}
}

// TestReplayWindowSlidesWithoutFalseReplays covers the shift arithmetic: a
// jump of more than the window width must clear the bitmap rather than shift
// bits off the end and leave stale ones behind.
func TestReplayWindowSlidesWithoutFalseReplays(t *testing.T) {
	var w replayWindow
	if err := w.accept(1, 1); err != nil {
		t.Fatalf("packet id 1: %v", err)
	}
	// A jump far past the window width. Nothing below it may be accepted
	// afterwards, and the new id itself must not read as already seen.
	if err := w.accept(1000, 1); err != nil {
		t.Fatalf("packet id 1000 after a gap: %v", err)
	}
	if err := w.accept(1000, 1); !errors.Is(err, ErrReplay) {
		t.Fatalf("packet id 1000 twice: err = %v, want ErrReplay", err)
	}
	if err := w.accept(1001, 1); err != nil {
		t.Fatalf("packet id 1001: %v", err)
	}
	// A shift of exactly the window width is the off-by-one worth pinning.
	var v replayWindow
	if err := v.accept(1, 1); err != nil {
		t.Fatalf("packet id 1: %v", err)
	}
	if err := v.accept(1+replayWindowSize, 1); err != nil {
		t.Fatalf("packet id %d: %v", 1+replayWindowSize, err)
	}
	if err := v.accept(1, 1); !errors.Is(err, ErrReplay) {
		t.Fatalf("packet id 1 after the window slid past it: err = %v, want ErrReplay", err)
	}
}

// TestReplayWindowRejectsAStaleTimestamp pins that a timestamp going backwards
// is refused, and refused under its own error: a stale timestamp says something
// about the path, where a repeated id says something about duplication.
func TestReplayWindowRejectsAStaleTimestamp(t *testing.T) {
	var w replayWindow
	if err := w.accept(5, 2000); err != nil {
		t.Fatalf("first packet: %v", err)
	}
	if err := w.accept(6, 1999); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("older timestamp with a fresh id: err = %v, want ErrStaleTimestamp", err)
	}
	if err := w.accept(1, 0); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("zero timestamp: err = %v, want ErrStaleTimestamp", err)
	}
}

// TestReplayWindowStartsAFreshEpoch checks that a peer moving into a new
// second may reuse ids the previous second retired — which OpenVPN's counter
// never does, but the window must not depend on that to stay correct.
func TestReplayWindowStartsAFreshEpoch(t *testing.T) {
	var w replayWindow
	if err := w.accept(9, 1000); err != nil {
		t.Fatalf("first packet: %v", err)
	}
	if err := w.accept(9, 1001); err != nil {
		t.Fatalf("same id in a later second: %v", err)
	}
	if err := w.accept(9, 1001); !errors.Is(err, ErrReplay) {
		t.Fatalf("repeat inside the new second: err = %v, want ErrReplay", err)
	}
	// The old second is now stale, even for an id it never saw.
	if err := w.accept(1000, 1000); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("packet from the retired second: err = %v, want ErrStaleTimestamp", err)
	}
}

// TestReplayWindowRejectsPacketIDZero pins the one id that is never
// legitimate. OpenVPN's counter starts at 1 in both directions — every
// captured vector shows it — and packet_id_test refuses a zero id outright.
func TestReplayWindowRejectsPacketIDZero(t *testing.T) {
	var w replayWindow
	if err := w.accept(0, 1000); !errors.Is(err, ErrReplay) {
		t.Fatalf("packet id 0: err = %v, want ErrReplay", err)
	}
	// And it must not have initialised the window on the way through.
	if err := w.accept(1, 1000); err != nil {
		t.Fatalf("packet id 1 after a rejected zero: %v", err)
	}
}

// TestReplayWindowIgnoresTheLocalClock pins that a timestamp is compared
// against the peer's own highest, never against ours: a window judged by the
// local clock rejects every packet from a peer whose clock differs.
func TestReplayWindowIgnoresTheLocalClock(t *testing.T) {
	var w replayWindow
	// A timestamp from 1970 and one from far in the future are both fine;
	// only their order relative to each other matters.
	if err := w.accept(1, 1); err != nil {
		t.Fatalf("timestamp 1: %v", err)
	}
	if err := w.accept(2, 1<<31); err != nil {
		t.Fatalf("timestamp far in the future: %v", err)
	}
	if err := w.accept(3, ^uint32(0)); err != nil {
		t.Fatalf("maximum timestamp: %v", err)
	}
}

// TestReplayWindowIsConcurrencySafe runs the window from many goroutines and
// requires that exactly one caller be told "accepted" for each id, which is
// what Wrapper's contract promises. Run with -race.
func TestReplayWindowIsConcurrencySafe(t *testing.T) {
	const (
		goroutines = 8
		ids        = 500
	)
	var w replayWindow
	var mu sync.Mutex
	accepted := make(map[uint32]int, ids)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := uint32(1); id <= ids; id++ {
				if err := w.accept(id, 7); err == nil {
					mu.Lock()
					accepted[id]++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	for id := uint32(1); id <= ids; id++ {
		if got := accepted[id]; got != 1 {
			t.Fatalf("packet id %d accepted %d times, want exactly 1", id, got)
		}
	}
}
