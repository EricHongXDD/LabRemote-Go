// SPDX-License-Identifier: LGPL-2.1-or-later

package ctls

import (
	"sync"
	"testing"
)

// TestCloseDoesNotPanicASender pins the reason nothing closes inbound or
// outbound.
//
// A sender that reads a closed flag under the mutex, releases it and then
// sends races a Close that closes the channel it sends on: a connection
// dropping mid-write — an ordinary teardown, and every failover — lands
// between the two and panics with "send on closed channel". Closing only
// closedCh and selecting on it removes the window rather than narrowing it.
//
// Without the fix this panics within a few dozen iterations.
func TestCloseDoesNotPanicASender(t *testing.T) {
	for range 2000 {
		tr := NewControlTransport(nil, nil, 1)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); _ = tr.InjectInbound([]byte("x")) }()
		go func() { defer wg.Done(); _, _ = tr.Write([]byte("y")) }()
		go func() { defer wg.Done(); _ = tr.Close() }()
		go func() { _, _ = tr.DrainOutbound() }()
		go func() { b := make([]byte, 8); _, _ = tr.Read(b) }()
		wg.Wait()
	}
}
