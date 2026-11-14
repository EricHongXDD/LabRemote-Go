// SPDX-License-Identifier: LGPL-2.1-or-later

package device_test

import (
	"testing"

	"github.com/buengese/go-openvpn/device"
)

// TestKindValues pins the strings that land in session reports. Renaming one
// silently reclassifies every historical measurement.
//
// This is all the package itself has to test. The Device and Backend contracts
// — a read that ends with its context, a close that unblocks it, a write that
// does not retain its buffer, parameters that arrive unchanged — are checked
// against a real device in device/fd and netstack, which is where a violation
// would live. Exercising them here against fakes defined in this file could
// only fail if the fake were edited.
func TestKindValues(t *testing.T) {
	cases := map[device.Kind]string{
		device.KindKernel:   "kernel",
		device.KindFD:       "fd",
		device.KindNetstack: "netstack",
	}
	for k, want := range cases {
		if string(k) != want || k.String() != want {
			t.Errorf("Kind = %q / %q, want %q", string(k), k.String(), want)
		}
	}
}
