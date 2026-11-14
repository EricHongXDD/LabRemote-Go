// SPDX-License-Identifier: LGPL-2.1-or-later

package control

import (
	"testing"
	"time"
)

// TestAuthTempIsNotACredentialRejection pins the distinction the reference
// draws: openvpn-2.6.22 src/openvpn/push.c:72-76 raises SIGUSR1 — a soft
// restart — for AUTH_FAILED,TEMP and SIGTERM for a plain AUTH_FAILED.
func TestAuthTempIsNotACredentialRejection(t *testing.T) {
	for _, tc := range []struct {
		msg  string
		want MsgKind
	}{
		{"AUTH_FAILED", MsgKindAuthFailed},
		{"AUTH_FAILED,TEMP", MsgKindAuthFailedTemp},
		{"AUTH_FAILED,TEMP[backoff 30]:server busy", MsgKindAuthFailedTemp},
		{"AUTH_FAILED,CRV1:R,E:state:base64", MsgKindAuthFailedCRV1},
	} {
		if got := ClassifyMsg(tc.msg); got != tc.want {
			t.Errorf("ClassifyMsg(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// TestParseAuthTempFlags covers the wire form in
// openvpn-2.6.22 src/openvpn/options_util.c:34-95.
func TestParseAuthTempFlags(t *testing.T) {
	for _, tc := range []struct {
		body        string
		wantBackoff time.Duration
		wantAdvance AuthTempAdvance
		wantReason  string
	}{
		{"", 0, AdvanceAddr, ""},
		{":just a reason", 0, AdvanceAddr, "just a reason"},
		{"[backoff 30]", 30 * time.Second, AdvanceAddr, ""},
		{"[backoff 30,advance no]:come back later", 30 * time.Second, AdvanceNo, "come back later"},
		{"[advance remote]", 0, AdvanceRemote, ""},
		{"[advance addr]", 0, AdvanceAddr, ""},
		// An unparseable flag is skipped, not fatal: a temporary rejection
		// nobody can parse is still a temporary rejection, and calling it
		// permanent is the worse error (options_util.c:81).
		{"[backoff abc,nonsense,advance no]:x", 0, AdvanceNo, "x"},
	} {
		got := ParseAuthTemp(tc.body)
		if got.Backoff != tc.wantBackoff || got.Advance != tc.wantAdvance || got.Reason != tc.wantReason {
			t.Errorf("ParseAuthTemp(%q) = %+v, want backoff=%s advance=%s reason=%q",
				tc.body, got, tc.wantBackoff, tc.wantAdvance, tc.wantReason)
		}
	}
}
