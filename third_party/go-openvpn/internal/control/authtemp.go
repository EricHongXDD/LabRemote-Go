// SPDX-License-Identifier: LGPL-2.1-or-later

package control

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrAuthTemp marks a rejection the server said was temporary. It is not a
// statement about credentials, and a caller that retries on it is doing what
// the reference does: openvpn-2.6.22 src/openvpn/push.c:75 raises SIGUSR1 —
// a soft restart — where a plain AUTH_FAILED raises SIGTERM.
var ErrAuthTemp = errors.New("control: server rejected this attempt temporarily")

// AuthTempAdvance says which remote a temporary rejection wants tried next.
//
// Reference: openvpn-2.6.22 src/openvpn/options_util.c:59-79, which sets
// no_advance, advance_next_remote or neither from the "advance" flag.
type AuthTempAdvance int

const (
	// AdvanceAddr is the default: move on to the next address.
	AdvanceAddr AuthTempAdvance = iota
	// AdvanceNo retries the same remote.
	AdvanceNo
	// AdvanceRemote moves on to the next remote entry.
	AdvanceRemote
)

// String returns a stable lowercase token.
func (a AuthTempAdvance) String() string {
	switch a {
	case AdvanceNo:
		return "no"
	case AdvanceRemote:
		return "remote"
	default:
		return "addr"
	}
}

// AuthTemp is a server's temporary rejection: it declined this attempt and
// said to come back, optionally saying when and where. It is emphatically not
// a credential rejection — a server under load emits it, and a client that
// treats it as permanent records a working account as a failing one.
//
// Wire form, from openvpn-2.6.22 src/openvpn/push.c:64-76 and
// options_util.c:34-95:
//
//	AUTH_FAILED,TEMP[backoff 30,advance no]:human readable reason
//
// The bracketed flag list and the reason are both optional.
type AuthTemp struct {
	// Backoff is how long the server asked us to wait. Zero when unstated.
	Backoff time.Duration
	// Advance says which remote to try next.
	Advance AuthTempAdvance
	// Reason is the server's human-readable text, or empty. It is server-
	// supplied and must be treated as untrusted when displayed.
	Reason string
}

// ParseAuthTemp parses the body of an "AUTH_FAILED,TEMP..." message, that is,
// everything after the "TEMP" token. An unparseable flag is skipped rather
// than failing the whole message, which is what the reference does
// (options_util.c:81, a warning and carry on): a temporary rejection nobody
// can parse is still a temporary rejection, and treating it as permanent is
// the worse error.
func ParseAuthTemp(body string) AuthTemp {
	t := AuthTemp{Advance: AdvanceAddr}
	if end := strings.Index(body, "]"); strings.HasPrefix(body, "[") && end > 0 {
		for _, tok := range strings.Split(body[1:end], ",") {
			switch tok := strings.TrimSpace(tok); {
			case strings.HasPrefix(tok, "backoff "):
				if n, err := strconv.Atoi(strings.TrimSpace(tok[len("backoff "):])); err == nil && n > 0 {
					t.Backoff = time.Duration(n) * time.Second
				}
			case strings.HasPrefix(tok, "advance "):
				switch strings.TrimSpace(tok[len("advance "):]) {
				case "no":
					t.Advance = AdvanceNo
				case "remote":
					t.Advance = AdvanceRemote
				case "addr":
					t.Advance = AdvanceAddr
				}
			}
		}
		body = body[end+1:]
	}
	if reason, ok := strings.CutPrefix(body, ":"); ok {
		t.Reason = reason
	}
	return t
}

// AuthTemp returns the temporary-rejection detail carried by an
// "AUTH_FAILED,TEMP..." message, and the zero AuthTemp for any other kind. It
// exists so a caller holding the Message need not know that the flags live
// after the "AUTH_FAILED,TEMP" prefix; that string surgery is this package's
// business, not its callers'.
func (m *Message) AuthTemp() AuthTemp {
	if m == nil || m.Kind != MsgKindAuthFailedTemp {
		return AuthTemp{}
	}
	return ParseAuthTemp(strings.TrimPrefix(m.Raw, "AUTH_FAILED,TEMP"))
}
