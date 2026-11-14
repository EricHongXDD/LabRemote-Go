// SPDX-License-Identifier: LGPL-2.1-or-later

package ctls

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentReadsDeliverEveryByteOnce pins the invariant Read owes net.Conn:
// two goroutines calling it at once must between them see the stream exactly
// once, no byte lost and no byte twice. readBuf — the remainder of a chunk too
// large for the caller's buffer — is the shared state; run under -race.
func TestConcurrentReadsDeliverEveryByteOnce(t *testing.T) {
	const (
		chunks    = 64
		chunkLen  = 8
		readers   = 2
		perRead   = 3 // smaller than chunkLen, so every chunk leaves a remainder
		totalWant = chunks * chunkLen
	)

	tr := NewControlTransport(nil, nil, chunks)
	// Every chunk is a run of one distinct byte value, so the bytes read can be
	// tallied per value whichever reader got them. All of it is queued before
	// any reader starts, so a reader that blocks has run out of stream.
	for i := range chunks {
		chunk := make([]byte, chunkLen)
		for j := range chunk {
			chunk[j] = byte(i)
		}
		if err := tr.InjectInbound(chunk); err != nil {
			t.Fatalf("inject %d: %v", i, err)
		}
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		count [chunks]int
		total atomic.Int64
		done  = make(chan struct{})
		once  sync.Once
	)
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, perRead)
			for total.Load() < totalWant {
				n, err := tr.Read(buf)
				if err != nil {
					return
				}
				mu.Lock()
				for _, b := range buf[:n] {
					count[b]++
				}
				mu.Unlock()
				if total.Add(int64(n)) >= totalWant {
					once.Do(func() { close(done) })
				}
			}
		}()
	}
	// Whichever reader loses the last chunk to the other would block for
	// ever, so the stream is closed under it once the tally is complete —
	// or once it is clear it never will be, which is the failing case.
	go func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		_ = tr.Close()
	}()
	wg.Wait()

	if got := total.Load(); got != totalWant {
		t.Errorf("read %d bytes, want %d", got, totalWant)
	}
	for i, got := range count {
		if got != chunkLen {
			t.Errorf("byte value %d seen %d times, want %d", i, got, chunkLen)
		}
	}
}
