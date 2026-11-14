// Package ctls implements TLS-over-control-channel for OpenVPN3.
//
// OpenVPN embeds TLS inside its own reliable control channel rather than
// running TLS directly over TCP. This package bridges the gap by exposing
// a net.Conn view of the control-channel byte stream so that crypto/tls can
// run over it unchanged.
//
// Architecture:
//
//	Application
//	    │
//	    ▼
//	crypto/tls.Conn  (run directly over the transport below)
//	    │
//	    ▼
//	ControlTransport  (net.Conn; goroutine pairs raw TLS bytes with OpenVPN framing)
//	    │
//	    ▼
//	Reliable control channel  (framing + reliable.SendQueue/RecvWindow)
//
// Reference: openvpn3-core ssl/sslctx.hpp, ssl/proto.hpp
package ctls

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ControlTransport is a net.Conn whose Read/Write methods exchange raw TLS
// bytes with the caller while the underlying transport carries those bytes
// inside OpenVPN control-channel packets.
//
// Use NewControlTransport to create one, then pass it to tls.Client or
// tls.Server. The caller runs the packet I/O loop on the underlying OpenVPN
// connection, feeding InjectInbound and draining DrainOutbound.
type ControlTransport struct {
	// inbound delivers reassembled TLS payload bytes to Read callers.
	inbound chan []byte
	// outbound receives bytes from Write callers for framing/sending.
	outbound chan []byte
	// closedCh is closed when Close is called.
	closedCh chan struct{}

	mu         sync.Mutex
	closeOnce  sync.Once
	localAddr  net.Addr
	remoteAddr net.Addr

	// readMu serialises Read, and is the only thing that may touch readBuf.
	//
	// It is separate from mu because Read blocks — on a chunk, on the deadline,
	// on Close — and mu is taken by SetReadDeadline, which a caller is entitled
	// to invoke *while* a Read is outstanding. One mutex covering both would
	// deadlock the first time a deadline was set on a blocked reader.
	readMu sync.Mutex
	// readBuf holds a partial read from the current inbound chunk. Guarded by
	// readMu.
	readBuf []byte

	readDeadline  time.Time
	writeDeadline time.Time
}

// NewControlTransport creates a ControlTransport with buffered channels.
// bufSize controls how many chunks can be queued in each direction.
func NewControlTransport(local, remote net.Addr, bufSize int) *ControlTransport {
	if bufSize <= 0 {
		bufSize = 64
	}
	return &ControlTransport{
		inbound:    make(chan []byte, bufSize),
		outbound:   make(chan []byte, bufSize),
		closedCh:   make(chan struct{}),
		localAddr:  local,
		remoteAddr: remote,
	}
}

// InjectInbound delivers a reassembled TLS payload chunk to waiting Read calls.
// Called by the OpenVPN framing layer when a complete control packet arrives.
func (t *ControlTransport) InjectInbound(data []byte) error {
	chunk := make([]byte, len(data))
	copy(chunk, data)
	// Selecting on closedCh rather than checking a flag first is the whole
	// point: a flag read under the mutex is stale the instant it is released.
	// A lost race delivers one more chunk to a transport that is going away.
	select {
	case t.inbound <- chunk:
		return nil
	case <-t.closedCh:
		return fmt.Errorf("ctls: transport closed")
	}
}

// DrainOutbound returns the next chunk written by TLS to send over the wire, and
// (nil, io.EOF) once the transport is closed. It is the only way to consume
// them: the channel is never closed, so ranging over it raw would never finish.
func (t *ControlTransport) DrainOutbound() ([]byte, error) {
	select {
	case chunk := <-t.outbound:
		return chunk, nil
	case <-t.closedCh:
		return nil, io.EOF
	}
}

// ClosedChan returns a channel that is closed when Close is called.
// The returned channel is safe to use in select statements.
func (t *ControlTransport) ClosedChan() <-chan struct{} {
	return t.closedCh
}

// Read implements net.Conn. It blocks until TLS bytes arrive via InjectInbound.
//
// Concurrent Reads are serialised rather than merely tolerated: net.Conn
// promises a Conn's methods may be called from several goroutines at once, and
// the remainder of an oversized chunk lives in readBuf between calls, so two
// unsynchronised readers would hand TLS a record stream with bytes duplicated
// or missing. tls.Conn serialises its own reads, so nothing here exercises it.
func (t *ControlTransport) Read(b []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	for {
		// Serve from leftover buffer first.
		if len(t.readBuf) > 0 {
			n := copy(b, t.readBuf)
			t.readBuf = t.readBuf[n:]
			return n, nil
		}

		// Wait for next chunk with optional deadline.
		var deadline <-chan time.Time
		t.mu.Lock()
		rd := t.readDeadline
		t.mu.Unlock()
		if !rd.IsZero() {
			d := time.Until(rd)
			if d <= 0 {
				return 0, &timeoutError{}
			}
			deadline = time.After(d)
		}

		select {
		case <-t.closedCh:
			return 0, io.EOF
		case chunk := <-t.inbound:
			n := copy(b, chunk)
			if n < len(chunk) {
				t.readBuf = chunk[n:]
			}
			return n, nil
		case <-deadline:
			return 0, &timeoutError{}
		}
	}
}

// Write implements net.Conn. It queues TLS bytes for pickup by DrainOutbound.
func (t *ControlTransport) Write(b []byte) (int, error) {
	t.mu.Lock()
	wd := t.writeDeadline
	t.mu.Unlock()

	chunk := make([]byte, len(b))
	copy(chunk, b)

	if !wd.IsZero() {
		d := time.Until(wd)
		if d <= 0 {
			return 0, &timeoutError{}
		}
		select {
		case t.outbound <- chunk:
			return len(b), nil
		case <-t.closedCh:
			return 0, fmt.Errorf("ctls: transport closed")
		case <-time.After(d):
			return 0, &timeoutError{}
		}
	}

	select {
	case t.outbound <- chunk:
		return len(b), nil
	case <-t.closedCh:
		return 0, fmt.Errorf("ctls: transport closed")
	}
}

// Close implements net.Conn.
func (t *ControlTransport) Close() error {
	t.closeOnce.Do(func() {
		// Only closedCh is closed. Closing inbound or outbound would race
		// every sender that had already passed its own closed check.
		close(t.closedCh)
	})
	return nil
}

// LocalAddr implements net.Conn.
func (t *ControlTransport) LocalAddr() net.Addr { return t.localAddr }

// RemoteAddr implements net.Conn.
func (t *ControlTransport) RemoteAddr() net.Addr { return t.remoteAddr }

// SetDeadline implements net.Conn.
func (t *ControlTransport) SetDeadline(tm time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.readDeadline = tm
	t.writeDeadline = tm
	return nil
}

// SetReadDeadline implements net.Conn.
func (t *ControlTransport) SetReadDeadline(tm time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.readDeadline = tm
	return nil
}

// SetWriteDeadline implements net.Conn.
func (t *ControlTransport) SetWriteDeadline(tm time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.writeDeadline = tm
	return nil
}

// timeoutError is a net.Error indicating a deadline exceeded.
type timeoutError struct{}

// Error implements the error interface.
func (e *timeoutError) Error() string { return "ctls: deadline exceeded" }

// Timeout reports that this error is a timeout, satisfying net.Error.
func (e *timeoutError) Timeout() bool { return true }

// Temporary reports that this error is transient, satisfying net.Error.
func (e *timeoutError) Temporary() bool { return true }
