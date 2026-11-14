// SPDX-License-Identifier: LGPL-2.1-or-later

package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// SessionMonitor watches an active VPN control channel for server-side
// AUTH_FAILED messages that indicate session expiry.
//
// After PUSH_REPLY and with the tunnel up, the server may send AUTH_FAILED at
// any time to signal that the session has expired and must be re-authenticated.
// SessionMonitor reads control messages from an io.Reader in a goroutine and
// delivers a *SessionExpiredError, or any other read error, via Done.
//
// Usage:
//
//	mon := control.NewSessionMonitor(tlsConn)
//	mon.Start(ctx)
//	// ... use VPN tunnel ...
//	select {
//	case err := <-mon.Done():
//	    if se, ok := err.(*control.SessionExpiredError); ok {
//	        // re-authenticate
//	    }
//	}
type SessionMonitor struct {
	r    io.Reader
	done chan error
}

// NewSessionMonitor creates a SessionMonitor that reads from r, typically the
// TLS connection to the VPN server, read after PUSH_REPLY.
//
// A reader that carries SetReadDeadline — every net.Conn, so every *tls.Conn —
// lets a cancelled monitor unblock its own read and shut down on the spot. A
// plain io.Reader cannot be interrupted from outside, so its reader goroutine
// stays parked until the reader returns; Done reports the cancellation either
// way.
func NewSessionMonitor(r io.Reader) *SessionMonitor {
	return &SessionMonitor{
		r:    r,
		done: make(chan error, 1),
	}
}

// Start begins monitoring in a background goroutine.
// The goroutine stops when ctx is cancelled or when a message is received.
// Errors (including *SessionExpiredError) are delivered via Done().
func (m *SessionMonitor) Start(ctx context.Context) {
	go m.run(ctx)
}

// Done returns a channel that receives exactly one value when monitoring ends.
// A *SessionExpiredError indicates the server sent AUTH_FAILED mid-session.
// io.EOF or context errors indicate normal connection close / cancellation.
func (m *SessionMonitor) Done() <-chan error {
	return m.done
}

// readResult is one pass of the reader goroutine: a classified message, or the
// error that ended the stream.
type readResult struct {
	cm  *Message
	err error
}

// deadlineReader is the part of net.Conn that makes a blocked read
// interruptible. Every net.Conn has it, so the *tls.Conn the real monitor
// reads does; a plain io.Reader does not, and nothing outside it can unblock
// one of those.
type deadlineReader interface {
	SetReadDeadline(time.Time) error
}

// interruptRead unblocks a read parked on m.r, when m.r is the kind of reader
// that can be unblocked.
//
// A deadline in the past interrupts the read in flight and fails every read
// after it, which is why this runs only once the monitor has finished with the
// reader for good: its context was cancelled, or it has already delivered the
// message that ends the session.
func (m *SessionMonitor) interruptRead() {
	if dr, ok := m.r.(deadlineReader); ok {
		// Not the zero Time — that clears a deadline rather than setting one.
		_ = dr.SetReadDeadline(time.Unix(1, 0))
	}
}

func (m *SessionMonitor) run(ctx context.Context) {
	// Read control messages in a loop until ctx is cancelled or the connection
	// closes. openvpn3-core cliproto.hpp dispatches an unlimited stream of
	// mid-session control messages (AUTH_FAILED, keepalive, etc.), so reading
	// only one message drops every later AUTH_FAILED silently.
	//
	// One reader goroutine covers the whole loop, and cancelling runCtx on the
	// way out interrupts the read it is sitting in, so the reader ends with the
	// monitor instead of outliving it parked on a read nobody will answer.
	//
	// Reference: openvpn3-core client/cliproto.hpp — each incoming message is
	// dispatched in turn through ClientProto::Session::control_recv() (:936).
	runCtx, stopReader := context.WithCancel(ctx)
	defer stopReader()
	context.AfterFunc(runCtx, m.interruptRead)

	ch := make(chan readResult)
	go m.readLoop(runCtx, ch)

	for {
		select {
		case <-ctx.Done():
			m.done <- ctx.Err()
			return
		case res := <-ch:
			if res.err != nil {
				if errors.Is(res.err, io.EOF) {
					m.done <- io.EOF
				} else {
					m.done <- fmt.Errorf("control: session monitor read: %w", res.err)
				}
				return
			}
			switch res.cm.Kind {
			case MsgKindAuthFailed, MsgKindAuthFailedCRV1:
				// The classification, not the raw line: Msg is documented as
				// non-sensitive, and a CRV1 re-challenge carries the state id
				// and the IdP URL.
				m.done <- &SessionExpiredError{Msg: res.cm.Kind.String()}
				return
			case MsgKindRestart, MsgKindHalt:
				// The server is ending a session that was working. Waiting
				// for the dead-link timer to notice takes tens of seconds
				// and then blames the link, which is the wrong answer to
				// write down about a peer that told us plainly.
				if sig, ok := ParsePushedSignal(res.cm.Raw); ok {
					m.done <- sig
					return
				}
				m.done <- ErrServerPushedSignal
				return
			default:
				// Unknown mid-session message (e.g. a server-pushed PUSH_REPLY
				// update, INFO_PRE, a restart notice): keep reading. Do not
				// close the tunnel for messages we don't recognise, and do not
				// log them — Raw is the one field in this package documented
				// as unsafe to log.
			}
		}
	}
}

// readLoop is the monitor's single reader. It hands every message it frames to
// run and stops on the first error, or when runCtx ends — which is also what
// unblocks the read it is sitting in.
func (m *SessionMonitor) readLoop(runCtx context.Context, ch chan<- readResult) {
	for {
		cm, err := ReadControlMsg(m.r, 0)
		select {
		case ch <- readResult{cm: cm, err: err}:
		case <-runCtx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}
