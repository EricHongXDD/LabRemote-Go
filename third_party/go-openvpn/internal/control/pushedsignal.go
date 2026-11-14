// SPDX-License-Identifier: LGPL-2.1-or-later

package control

import (
	"errors"
	"strings"
)

// ErrServerPushedSignal marks a session the server ended on purpose, by
// pushing RESTART or HALT down the control channel of a tunnel that was
// working.
//
// It is not a failure of ours and not a network fault, which is what it used
// to be recorded as: the message hit the monitor's default arm, was logged and
// dropped, and the session then sat there until the dead-link timer fired
// tens of seconds later and blamed the link.
//
// Reference: openvpn-2.6.22 src/openvpn/push.c:131-186 (server_pushed_signal),
// which raises SIGUSR1 for RESTART — a reconnect — and SIGTERM for HALT.
var ErrServerPushedSignal = errors.New("control: server ended the session")

// ServerPushedSignal is a parsed RESTART or HALT push.
//
// This client records it and ends the session; it does not reconnect on the
// client's behalf, so Restart and NextServer are what a caller reads to decide
// that for itself.
type ServerPushedSignal struct {
	// Restart distinguishes RESTART (the server wants us back) from HALT
	// (it does not).
	Restart bool
	// PreserveCreds is the "[P]" flag: keep the cached credentials rather
	// than purging them, so a reconnect need not re-authenticate. The
	// reference purges unless it is present (push.c:160-166).
	PreserveCreds bool
	// NextServer is the "[N]" flag, which asks that the reconnect go to the
	// next remote rather than this one (push.c:154-158).
	NextServer bool
	// Reason is the free text the server appended after the flags. It is
	// peer-authored and goes in the report, never in a credential path.
	Reason string
}

// Directive is the message the server sent, "RESTART" or "HALT". It never
// includes the flags or the reason, so it is safe to put in a report.
func (s *ServerPushedSignal) Directive() string {
	if s.Restart {
		return "RESTART"
	}
	return "HALT"
}

// Error implements error so a ServerPushedSignal can travel as one.
func (s *ServerPushedSignal) Error() string {
	return "control: server pushed " + s.Directive()
}

// Is makes errors.Is(err, ErrServerPushedSignal) true for any pushed signal.
func (s *ServerPushedSignal) Is(target error) bool { return target == ErrServerPushedSignal }

// ParsePushedSignal parses a RESTART or HALT control message.
//
// The shape is the directive, then an optional comma and a message which may
// itself begin with a bracketed flag word — "RESTART,[P]session expired". The
// reference reads the flags one character at a time and ignores any it does
// not know (push.c:148-166), so an unrecognised letter is not an error here
// either; a server is free to add one and we still end the session.
func ParsePushedSignal(msg string) (*ServerPushedSignal, bool) {
	msg = strings.TrimRight(msg, "\x00")

	var sig ServerPushedSignal
	var rest string
	switch {
	case msg == "RESTART" || strings.HasPrefix(msg, "RESTART,"):
		sig.Restart = true
		rest = strings.TrimPrefix(msg, "RESTART")
	case msg == "HALT" || strings.HasPrefix(msg, "HALT,"):
		rest = strings.TrimPrefix(msg, "HALT")
	default:
		return nil, false
	}
	rest = strings.TrimPrefix(rest, ",")

	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end > 0 {
			for _, f := range rest[1:end] {
				switch f {
				case 'P':
					sig.PreserveCreds = true
				case 'N':
					sig.NextServer = true
				}
			}
			rest = rest[end+1:]
		}
	}
	sig.Reason = rest
	return &sig, true
}
