// SPDX-License-Identifier: LGPL-2.1-or-later

package datachannel

import "testing"

// TestReplayWindowRejectsEveryPacketInRange replays every id inside the window,
// not just the newest.
//
// A [64]bool indexed relatively when testing and marking but absolutely when
// advancing sets only bit 0 on in-order traffic, so every packet but the newest
// replays exactly once. Replaying only the top, or ids more than a window away,
// are the two cases such a window gets right.
//
// Reference: openvpn-2.6.22 src/openvpn/packet_id.c:200-260.
func TestReplayWindowRejectsEveryPacketInRange(t *testing.T) {
	c := &Channel{}
	const top = 200
	for seq := uint32(1); seq <= top; seq++ {
		if err := c.acceptReplay(seq); err != nil {
			t.Fatalf("seq %d rejected on first sight: %v", seq, err)
		}
	}
	// Everything still in the window must be refused. A refusal records
	// nothing, so these probes leave the window as they found it.
	for seq := uint32(top - replayWindowSize + 1); seq <= top; seq++ {
		if err := c.acceptReplay(seq); err == nil {
			t.Errorf("replay of seq %d accepted (top=%d)", seq, top)
		}
	}
	// Anything older than the window is refused as too old, not as unseen.
	if err := c.acceptReplay(top - replayWindowSize); err == nil {
		t.Error("a packet older than the window was accepted")
	}
	// A gap admits the ids inside it exactly once.
	if err := c.acceptReplay(top + 10); err != nil {
		t.Fatalf("seq %d rejected on first sight: %v", top+10, err)
	}
	for _, seq := range []uint32{top + 1, top + 5, top + 9} {
		if err := c.acceptReplay(seq); err != nil {
			t.Errorf("seq %d inside the gap was refused: %v", seq, err)
		}
		if err := c.acceptReplay(seq); err == nil {
			t.Errorf("seq %d was accepted twice", seq)
		}
	}
}

// TestReplayWindowSlidesClear covers the jump the shift has to get right: an
// advance of a whole window or more leaves nothing behind it in range.
func TestReplayWindowSlidesClear(t *testing.T) {
	c := &Channel{}
	for seq := uint32(1); seq <= 64; seq++ {
		if err := c.acceptReplay(seq); err != nil {
			t.Fatalf("seq %d rejected on first sight: %v", seq, err)
		}
	}
	if err := c.acceptReplay(64 + replayWindowSize); err != nil {
		t.Fatalf("the packet that slides the window was refused: %v", err)
	}
	for seq := uint32(1); seq <= 64; seq++ {
		if err := c.acceptReplay(seq); err == nil {
			t.Fatalf("seq %d accepted after the window slid past it", seq)
		}
	}
}

// TestPacketIDZeroIsRefused mirrors the send side's rule on receive.
//
// The reference refuses packet_id 0 before any window logic
// (openvpn-2.6.22 src/openvpn/packet_id.c:208-211). This client already
// refuses to *send* it — firstPacketID, and the TCP teardown that taught us
// why — but accepted it as the first packet of a session, where replaySet is
// still false and the window has nothing to say.
func TestPacketIDZeroIsRefused(t *testing.T) {
	if err := (&Channel{}).acceptReplay(0); err == nil {
		t.Error("packet_id 0 accepted as the first packet of a session")
	}
	c := &Channel{}
	if err := c.acceptReplay(5); err != nil {
		t.Fatalf("seq 5 rejected on first sight: %v", err)
	}
	if err := c.acceptReplay(0); err == nil {
		t.Error("packet_id 0 accepted mid-session")
	}
}
