// SPDX-License-Identifier: LGPL-2.1-or-later

package control_test

import (
	"errors"
	"testing"

	"github.com/buengese/go-openvpn/internal/control"
)

// A server that pushes RESTART or HALT is ending a session that was working.
// Dropping either into the monitor's default arm leaves the tunnel sitting
// until the dead-link timer fires and blames the link.
//
// Reference for the shape, including the bracketed flags: openvpn-2.6.22
// src/openvpn/push.c:131-186.
func TestParsePushedSignal(t *testing.T) {
	for _, tt := range []struct {
		msg  string
		want control.ServerPushedSignal
	}{
		{"HALT", control.ServerPushedSignal{}},
		{"RESTART", control.ServerPushedSignal{Restart: true}},
		{"HALT,server going down for maintenance", control.ServerPushedSignal{Reason: "server going down for maintenance"}},
		{"RESTART,[P]", control.ServerPushedSignal{Restart: true, PreserveCreds: true}},
		{"RESTART,[N]try elsewhere", control.ServerPushedSignal{Restart: true, NextServer: true, Reason: "try elsewhere"}},
		{"RESTART,[PN]both flags", control.ServerPushedSignal{Restart: true, PreserveCreds: true, NextServer: true, Reason: "both flags"}},
		// The reference reads flag letters one at a time and ignores what it
		// does not know, so an unknown one must not cost us the message.
		{"HALT,[PX]unknown letter", control.ServerPushedSignal{PreserveCreds: true, Reason: "unknown letter"}},
		// OpenVPN terminates control messages with a NUL.
		{"HALT,done\x00", control.ServerPushedSignal{Reason: "done"}},
	} {
		t.Run(tt.msg, func(t *testing.T) {
			got, ok := control.ParsePushedSignal(tt.msg)
			if !ok {
				t.Fatalf("ParsePushedSignal(%q) did not recognise it", tt.msg)
			}
			if *got != tt.want {
				t.Fatalf("ParsePushedSignal(%q) = %+v, want %+v", tt.msg, *got, tt.want)
			}
			if !errors.Is(got, control.ErrServerPushedSignal) {
				t.Errorf("%q does not match ErrServerPushedSignal", tt.msg)
			}
		})
	}

	// A message that merely starts with the letters is not one of these.
	for _, msg := range []string{"RESTARTED,no", "HALTING", "PUSH_REPLY,route 10.0.0.0 255.0.0.0", ""} {
		if _, ok := control.ParsePushedSignal(msg); ok {
			t.Errorf("ParsePushedSignal(%q) claimed a pushed signal", msg)
		}
	}
}

// Classification has to agree with the parser, because the monitor switches on
// the kind and only then parses.
func TestClassifyPushedSignals(t *testing.T) {
	for msg, want := range map[string]control.MsgKind{
		"HALT":                  control.MsgKindHalt,
		"HALT,bye":              control.MsgKindHalt,
		"RESTART":               control.MsgKindRestart,
		"RESTART,[P]soon":       control.MsgKindRestart,
		"HALTING":               control.MsgKindUnknown,
		"AUTH_FAILED":           control.MsgKindAuthFailed,
		"PUSH_REPLY,route 10/8": control.MsgKindPushReply,
	} {
		if got := control.ClassifyMsg(msg); got != want {
			t.Errorf("ClassifyMsg(%q) = %v, want %v", msg, got, want)
		}
	}
}
