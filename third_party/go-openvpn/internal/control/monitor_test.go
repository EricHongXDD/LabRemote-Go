// SPDX-License-Identifier: LGPL-2.1-or-later

package control_test

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/internal/control"
)

// TestSessionMonitorReportsWhyTheSessionEnded covers what the monitor puts on
// Done() for each way an established session can stop: AUTH_FAILED, with or
// without a CRV1 re-challenge behind it, is a *SessionExpiredError the caller
// can recover from by re-authenticating, and a closed connection is io.EOF.
func TestSessionMonitorReportsWhyTheSessionEnded(t *testing.T) {
	tests := []struct {
		name string
		// input is what the server sends on the control channel.
		input string
		// wantExpired asserts a *SessionExpiredError; otherwise wantErr is
		// compared with errors.Is.
		wantExpired bool
		wantMsg     string
		wantErr     error
	}{
		{
			name:        "auth failed",
			input:       "AUTH_FAILED\x00",
			wantExpired: true,
			wantMsg:     "AUTH_FAILED",
		},
		{
			// A CRV1 re-challenge mid-session is still an expiry: the server
			// is asking for a fresh assertion, not reporting a fault.
			name:        "crv1 re-challenge",
			input:       "AUTH_FAILED,CRV1:R:state::https://idp.example.com\x00",
			wantExpired: true,
			// The classification, not the raw line, which names the IdP and
			// carries the state id.
			wantMsg: "AUTH_FAILED_CRV1",
		},
		{
			name:    "server closed the connection",
			input:   "",
			wantErr: io.EOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mon := control.NewSessionMonitor(strings.NewReader(tt.input))
			mon.Start(context.Background())

			select {
			case err := <-mon.Done():
				if !tt.wantExpired {
					if !errors.Is(err, tt.wantErr) {
						t.Fatalf("expected %v, got %v", tt.wantErr, err)
					}
					return
				}
				var se *control.SessionExpiredError
				if !errors.As(err, &se) {
					t.Fatalf("expected *SessionExpiredError, got %T: %v", err, err)
				}
				if tt.wantMsg != "" && se.Msg != tt.wantMsg {
					t.Errorf("Msg = %q, want %q", se.Msg, tt.wantMsg)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for the monitor to report")
			}
		})
	}
}

// TestSessionMonitorContextCancel pins that a monitor blocked on a reader that
// will never produce a byte still ends when its context does.
func TestSessionMonitorContextCancel(t *testing.T) {
	pr, _ := io.Pipe()
	defer pr.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	mon := control.NewSessionMonitor(pr)
	mon.Start(ctx)
	cancel()

	select {
	case err := <-mon.Done():
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout after context cancel")
	}
}

// TestSessionMonitorLeavesNoGoroutineBehind counts goroutines rather than
// waiting on a timeout: a cancelled monitor reports context.Canceled promptly
// whether or not the goroutine blocked on the read ever ends. The reader is a
// net.Pipe conn — something with a read deadline, parked on a silent peer.
func TestSessionMonitorLeavesNoGoroutineBehind(t *testing.T) {
	const monitors = 50

	settle := func(t *testing.T) int {
		t.Helper()
		// Goroutines from an earlier subtest may still be unwinding; take the
		// lowest count seen over a short window rather than an instant sample.
		low := runtime.NumGoroutine()
		for range 20 {
			time.Sleep(10 * time.Millisecond)
			if n := runtime.NumGoroutine(); n < low {
				low = n
			}
		}
		return low
	}

	base := settle(t)

	cancels := make([]context.CancelFunc, 0, monitors)
	dones := make([]<-chan error, 0, monitors)
	for range monitors {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() { clientConn.Close(); serverConn.Close() }) //nolint:errcheck

		ctx, cancel := context.WithCancel(context.Background())
		mon := control.NewSessionMonitor(clientConn)
		mon.Start(ctx)
		cancels = append(cancels, cancel)
		dones = append(dones, mon.Done())
	}

	// Let every monitor reach the blocking read before any of them is
	// cancelled: a monitor cancelled before it reads never parks, and would
	// pass the count without exercising anything.
	time.Sleep(100 * time.Millisecond)
	for _, cancel := range cancels {
		cancel()
	}
	for _, done := range dones {
		<-done
	}

	// Poll rather than sample once: the goroutines are being torn down
	// concurrently and the assertion is about where they settle.
	deadline := time.Now().Add(3 * time.Second)
	var leaked int
	for time.Now().Before(deadline) {
		leaked = runtime.NumGoroutine() - base
		if leaked <= 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%d monitors started and cancelled left %d goroutines parked", monitors, leaked)
}

// TestSessionMonitorSurfacesAPushedSignal pins that a pushed RESTART or HALT
// comes out of the monitor rather than being swallowed by its default arm, and
// that a message merely beginning with the same letters still takes the default
// arm.
func TestSessionMonitorSurfacesAPushedSignal(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    *control.ServerPushedSignal
		wantEOF bool
	}{
		{
			name:  "halt with a reason",
			input: "HALT,maintenance\x00",
			want:  &control.ServerPushedSignal{Reason: "maintenance"},
		},
		{
			name:  "restart preserving credentials",
			input: "RESTART,[P]rebalancing\x00",
			want:  &control.ServerPushedSignal{Restart: true, PreserveCreds: true, Reason: "rebalancing"},
		},
		{
			// Not a signal: read past it and hit the end of the stream.
			name:    "a message that only looks like one",
			input:   "RESTARTING,no\x00",
			wantEOF: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mon := control.NewSessionMonitor(strings.NewReader(tt.input))
			mon.Start(context.Background())

			select {
			case err := <-mon.Done():
				if tt.wantEOF {
					if !errors.Is(err, io.EOF) {
						t.Fatalf("got %v, want io.EOF for a message that is not a pushed signal", err)
					}
					return
				}
				var got *control.ServerPushedSignal
				if !errors.As(err, &got) {
					t.Fatalf("got %T (%v), want *ServerPushedSignal", err, err)
				}
				if *got != *tt.want {
					t.Fatalf("signal = %+v, want %+v", *got, *tt.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for the monitor to report")
			}
		})
	}
}

// TestSessionExpiredErrorDisclosesNothing pins that neither the message nor the
// structured field carries what the server said: the error is built straight
// from a control-channel line, and a CRV1 line names the IdP and the state id.
func TestSessionExpiredErrorDisclosesNothing(t *testing.T) {
	const canary = "CANARY_AUTH_MATERIAL_MUST_NOT_BE_LOGGED"

	mon := control.NewSessionMonitor(strings.NewReader("AUTH_FAILED,CRV1:R:" + canary + "::https://idp.example.com\x00"))
	mon.Start(context.Background())

	select {
	case err := <-mon.Done():
		var se *control.SessionExpiredError
		if !errors.As(err, &se) {
			t.Fatalf("expected *SessionExpiredError, got %T: %v", err, err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("error text disclosed server authentication material: %v", err)
		}
		if strings.Contains(se.Msg, canary) {
			t.Errorf("Msg retained server authentication material: %q", se.Msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for the monitor to report")
	}
}

// TestSessionExpiredDeliveredAsynchronously covers an expiry that arrives while
// the monitor is already blocked on a live reader, rather than one waiting in a
// buffer when it starts.
func TestSessionExpiredDeliveredAsynchronously(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close() //nolint:errcheck
	defer serverConn.Close() //nolint:errcheck

	mon := control.NewSessionMonitor(clientConn)
	mon.Start(t.Context())

	// The server ends the session after the monitor is already reading.
	go func() {
		time.Sleep(50 * time.Millisecond)
		serverConn.Write([]byte("AUTH_FAILED\x00")) //nolint:errcheck
	}()

	select {
	case err := <-mon.Done():
		var se *control.SessionExpiredError
		if !errors.As(err, &se) {
			t.Fatalf("expected *SessionExpiredError, got %T: %v", err, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for session expiry")
	}
}
