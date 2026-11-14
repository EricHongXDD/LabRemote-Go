// SPDX-License-Identifier: LGPL-2.1-or-later

// The advertisement itself, as opposed to the packet it rides in: the IV_PROTO
// sum this client claims.

package keymethod2

import "testing"

// TestIVProtoImplementedIsStillTheFourNamedBits pins the sum at 30, in the
// package that declares it: adding an unimplemented bit has to fail here and
// not only where the rendered peer-info block is read back.
func TestIVProtoImplementedIsStillTheFourNamedBits(t *testing.T) {
	if IVProtoImplemented != 30 {
		t.Errorf("IVProtoImplemented = %d, want 30", IVProtoImplemented)
	}
}
