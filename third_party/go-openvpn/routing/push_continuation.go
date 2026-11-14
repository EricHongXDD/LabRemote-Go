// PUSH_REPLY reassembly.
//
// A server whose reply does not fit one control message splits it. Every
// fragment is a complete PUSH_REPLY message in its own right; every one but
// the last ends in ",push-continuation 2" and the last in
// ",push-continuation 1". A client that reads only the first brings the tunnel
// up with whatever part of the configuration happened to fit.
//
// Reference: openvpn-2.6.22 src/openvpn/push.c:718-735 (send_push_options
// flushes a full bundle with "push-continuation 2"), push.c:795-806
// (send_push_reply closes a split reply with "push-continuation 1"),
// push.c:1041-1066 (process_incoming_push_reply: 2 means PUSH_MSG_CONTINUATION,
// 0 and 1 complete the reply) and options.c:7929-7933 (the directive itself).
// The bundle size is PUSH_BUNDLE_SIZE = 1024 in src/openvpn/common.h:88.
package routing

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// pushReplyCmd is the keyword every PUSH_REPLY fragment opens with
// (openvpn-2.6.22 src/openvpn/push.c, push_reply_cmd).
const pushReplyCmd = "PUSH_REPLY"

// MaxPushFragments bounds how many control messages one PUSH_REPLY may be
// reassembled from. The reference has no limit: it keeps applying options for
// as long as the server keeps saying "push-continuation 2", which is a
// peer-controlled loop with a peer-controlled buffer behind it. The cap is
// MaxPushFragments × PUSH_BUNDLE_SIZE — 64 KiB, well over a thousand routes.
const MaxPushFragments = 64

// PushAccumulator reassembles a PUSH_REPLY the server split across several
// control messages. The zero value is ready to take the first fragment.
//
// Feed each PUSH_REPLY message to AddFragment in arrival order until it
// reports the reply complete, then hand Reply to ParsePushReply. A reply that
// arrived whole goes through unchanged: AddFragment returns complete on the
// first call and Reply returns exactly the message it was given.
type PushAccumulator struct {
	// bodies holds each fragment's option list — everything after the
	// PUSH_REPLY keyword, with the push-continuation directive removed and
	// nothing else touched, so a single-fragment reply survives verbatim.
	bodies []string
	frags  int
	done   bool
}

// ErrPushComplete is returned by AddFragment when the reply was already
// complete: a server that sends a fragment after the one it marked last would
// otherwise append to a configuration the client has already acted on.
var ErrPushComplete = errors.New("routing: push-continuation: reply is already complete")

// AddFragment takes one PUSH_REPLY control message and reports whether the
// reply is now complete.
//
// A trailing NUL is tolerated, as it is on the wire. The message must open
// with the PUSH_REPLY keyword; anything else is a protocol error rather than a
// fragment. Absence of a push-continuation directive completes the reply, which
// the reference reads as its case 0 (push.c:1053-1062).
func (a *PushAccumulator) AddFragment(msg string) (complete bool, err error) {
	if a.done {
		return true, ErrPushComplete
	}
	if a.frags >= MaxPushFragments {
		return false, fmt.Errorf(
			"routing: push-continuation: reply exceeds %d fragments", MaxPushFragments)
	}

	rest, ok := strings.CutPrefix(strings.TrimRight(msg, "\x00"), pushReplyCmd)
	if !ok || (rest != "" && !strings.HasPrefix(rest, ",")) {
		return false, fmt.Errorf(
			"routing: push-continuation: fragment %d is not a PUSH_REPLY message", a.frags+1)
	}

	// Split and rejoin on "," is the identity on a fragment that carries no
	// continuation directive, so an unsplit reply is stored byte for byte.
	fields := strings.Split(rest, ",")
	kept := make([]string, 0, len(fields))
	cont := 0
	for _, f := range fields {
		tok := strings.Fields(f)
		if len(tok) == 0 || !strings.EqualFold(tok[0], "push-continuation") {
			kept = append(kept, f)
			continue
		}
		if len(tok) != 2 {
			return false, fmt.Errorf(
				"routing: push-continuation: expected one argument, got %q", strings.TrimSpace(f))
		}
		v, convErr := strconv.Atoi(tok[1])
		if convErr != nil {
			return false, fmt.Errorf(
				"routing: push-continuation: unparseable value %q", tok[1])
		}
		cont = v
	}

	a.frags++
	a.bodies = append(a.bodies, strings.Join(kept, ","))

	switch cont {
	case 0, 1:
		a.done = true
		return true, nil
	case 2:
		return false, nil
	default:
		return false, fmt.Errorf("routing: push-continuation: unknown value %d", cont)
	}
}

// Reply returns the single PUSH_REPLY message the fragments amount to, suitable
// for ParsePushReply and for every other consumer of a raw reply. The option
// lists are concatenated in arrival order, which is the order the reference
// applies them in, so a directive a later fragment repeats still wins and routes
// still accumulate.
func (a *PushAccumulator) Reply() string {
	return pushReplyCmd + strings.Join(a.bodies, "")
}

// Fragments reports how many control messages the reply arrived in. One means
// the server did not split it.
func (a *PushAccumulator) Fragments() int { return a.frags }
