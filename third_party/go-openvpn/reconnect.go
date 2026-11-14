// SPDX-License-Identifier: LGPL-2.1-or-later
//
// reconnect.go: attempts, resumption, retry policy and reconnect.

package vpn

import (
	"context"
	"fmt"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/control"
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/internal/prf"
)

// ---- Attempts ------------------------------------------------------------
//
// A reconnect is a sequence of attempts, each keeping its own report.

// Attempt is one connection attempt within a reconnect sequence.
type Attempt struct {
	// N is the 1-based attempt number.
	N int
	// StartedAt is when the dial began.
	StartedAt time.Time
	// Report is the attempt's own session report, complete and independent
	// of every other attempt's.
	Report *diag.SessionReport
}

// attemptSlot is the client's side of one Attempt: the recorder a running
// attempt writes into, or the frozen report of one that has ended. reset zeroes
// the counters, so a report has to be taken before the next attempt starts.
type attemptSlot struct {
	n         int
	startedAt time.Time
	// rec is the recorder this attempt writes into, and stays readable after
	// the freeze because nothing owns it but this slot.
	rec *sessionRecorder
	// frozen is the report as it stood when the attempt ended, or nil while
	// this is still the current attempt. Both fields are read under mu.
	frozen *diag.SessionReport
}

// Attempts returns every attempt made by the current or most recent Reconnect,
// in order; a single Connect yields exactly one. Every Report is a snapshot and
// safe to retain, so this is safe to call from another goroutine while a
// Reconnect runs, and like Report the reports carry unredacted credential
// material: marshal SessionReport.Redacted. MaxReconnects bounds the slice and
// defaults to unlimited.
func (c *Client) Attempts() []Attempt {
	// The live counters belong to whichever attempt is still running. A
	// frozen slot was snapshotted with its own, before reset zeroed them.
	counters := c.counters()
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Attempt, 0, len(c.attempts))
	for _, s := range c.attempts {
		rep := s.frozen
		if rep == nil {
			rep = s.rec.snapshot(counters)
		}
		out = append(out, Attempt{N: s.n, StartedAt: s.startedAt, Report: rep})
	}
	return out
}

// registerAttempt opens the Attempt slot for the recorder beginAttempt has
// just started an attempt in. Outside a Reconnect the sequence is replaced
// rather than extended: a Connect is a sequence of one attempt.
func (c *Client) registerAttempt(rec *sessionRecorder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.reconnecting {
		c.attempts = nil
	}
	c.attempts = append(c.attempts, &attemptSlot{
		n:         len(c.attempts) + 1,
		startedAt: time.Now(),
		rec:       rec,
	})
}

// freezeAttemptLocked takes the current attempt's report while the counters it
// reads are still that attempt's own. c.mu must be held.
func (c *Client) freezeAttemptLocked(counters diag.Counters) {
	n := len(c.attempts)
	if n == 0 || c.attempts[n-1].frozen != nil {
		return
	}
	c.attempts[n-1].frozen = c.attempts[n-1].rec.snapshot(counters)
}

// ---- Resumption ----------------------------------------------------------
//
// What a method needs in order to attempt a session again without asking the
// user for anything: an assertion with the CRV1 state id and address it is bound
// to, or credentials already held — a certificate, or a cached password.

// resumption is one method's resumption state, and everything the reconnect
// loop does with it. The loop asks; it decides nothing about a method itself.
//
// The state is captured once rather than read per attempt because a failing
// attempt erases it: every connection-setup failure funnels through
// setDisconnected, which calls clearCredentialsLocked.
type resumption interface {
	// usable reports what stops an attempt being made from this state at all,
	// or nil when one can be. A non-nil answer is what Reconnect returns,
	// having made no attempt and recorded none.
	usable() error

	// seedLocked puts the state back into the client that reset, and the
	// failed attempt before it, have just emptied. c.mu is held.
	seedLocked(c *Client)

	// attemptMessage describes the attempt about to be made, in the terms the
	// method makes it in.
	attemptMessage(attempt int) string

	// reattempt makes one attempt.
	reattempt(ctx context.Context, c *Client) error

	// rejected says what a server refusing this method's credentials means:
	// whether another attempt is worth making, and what Reconnect returns when
	// it is not. Answering yes may spend state, hence the pointer receiver.
	rejected(c *Client, err error) (retry bool, out error)
}

// redialResumption is how a method that authenticates from what it already
// holds resumes: the whole handshake again from the top, including remote
// failover across each remote the profile names. Nothing about it expires.
type redialResumption struct{}

func (redialResumption) usable() error { return nil }

func (redialResumption) seedLocked(*Client) {
	// The certificate is in the profile and the profile is the caller's, so
	// there is nothing to carry and nothing to seed.
}

func (redialResumption) attemptMessage(attempt int) string {
	return fmt.Sprintf("vpn: reconnect attempt %d — redialing", attempt)
}

func (redialResumption) reattempt(ctx context.Context, c *Client) error {
	// Connect is the whole handshake and emits its own StateConnecting.
	return c.Connect(ctx)
}

// rejected ends the loop. A certificate the server has refused will be refused
// again, and the client is left as the failed attempt left it so that Report
// still explains what happened.
func (redialResumption) rejected(_ *Client, err error) (bool, error) {
	return false, err
}

// userPassResumption is a redial that carries the password the callback has
// already been asked for, so that a dropped link does not put a second prompt
// in front of the user.
type userPassResumption struct {
	redialResumption
	creds  Credentials
	cached bool
	// mayAsk records that CredentialsFn was set when the loop started, which
	// is the only condition under which a rejected credential is worth
	// presenting a second time.
	mayAsk bool
}

func (r *userPassResumption) seedLocked(c *Client) {
	c.creds, c.credsCached = r.creds, r.cached
}

// rejected drops the cached password and asks the callback again, once. Not a
// loop: the second rejection is the callback confirming the credential, and a
// third presentation of it is the account lockout this policy avoids.
func (r *userPassResumption) rejected(_ *Client, err error) (bool, error) {
	if !r.mayAsk {
		return false, err
	}
	r.mayAsk = false
	r.creds, r.cached = Credentials{}, false
	return true, nil
}

// samlExpiryMargin is how much of a cached assertion's life must be left for a
// resumed second exchange to be worth starting. One that expires mid-handshake
// costs an attempt and, more expensively, the CRV1 session it was spent on.
const samlExpiryMargin = 30 * time.Second

// samlResumption is the AWS Client VPN session a reconnect resumes into: the
// assertion, the CRV1 state id and backend instance it is bound to, and when it
// stops being accepted. The second exchange runs from these, with no browser.
type samlResumption struct {
	assertion string
	stateID   string
	serverIP  string
	expiry    time.Time
}

// usable answers the question no other method has to. An assertion is bound to
// the AuthnRequest of the exchange that obtained it, so an expired one needs
// another browser round-trip, which is the caller's to run and not the loop's.
func (r samlResumption) usable() error {
	if r.assertion == "" || r.stateID == "" || r.serverIP == "" ||
		r.expiry.IsZero() || !time.Now().Add(samlExpiryMargin).Before(r.expiry) {
		return ErrReauthRequired
	}
	return nil
}

func (r samlResumption) seedLocked(c *Client) {
	// The second exchange needs a first exchange's worth of state and takes it
	// from here instead of from another browser round-trip.
	c.seedSecondExchangeLocked(r.stateID, r.serverIP)
}

func (r samlResumption) attemptMessage(attempt int) string {
	return fmt.Sprintf("vpn: reconnect attempt %d — reusing token (TTL %s) ip=%s",
		attempt, time.Until(r.expiry).Round(time.Second), r.serverIP)
}

func (r samlResumption) reattempt(ctx context.Context, c *Client) error {
	// The first exchange is skipped, so no browser opens and the dial goes
	// straight to the backend instance the CRV1 state id is bound to.
	c.emit(Event{Type: EventStateChanged, State: StateConnecting})
	return c.bringUpTunnel(ctx, r.assertion)
}

// rejected ends the loop with the one error a caller can act on: the CRV1
// session is gone and the caller's next move is the browser flow, which Connect
// runs from stateNew and nowhere else, so the client is left there.
func (r samlResumption) rejected(c *Client, _ error) (bool, error) {
	c.disconnect(false)   //nolint:errcheck
	c.WaitForDisconnect() //nolint:errcheck
	c.reset()
	return false, ErrReauthRequired
}

// ---- The retry policy ----------------------------------------------------

// The backoff bounds between attempts: the first retry waits a second, each one
// after it doubles, to a half-minute ceiling.
const (
	reconnectBackoffBase = 1 * time.Second
	reconnectBackoffMax  = 30 * time.Second
)

// requestedBackoff returns the wait a peer asked for, or zero when it asked for
// nothing. Only an AUTH_FAILED,TEMP carrying a backoff flag sets it.
func requestedBackoff(err error) time.Duration {
	if derr := diag.AsError(err); derr != nil {
		return derr.RetryAfter
	}
	return 0
}

// retryClass reports whether a second attempt could go differently, from the
// class of the failure that ended the first — does dialing again change
// anything:
//
//	Network, TLS         yes: the endpoint was down, filtered, or halfway
//	                     through a restart
//	ServerBusy           yes, and the one class where the server said so
//	                     itself: an AUTH_FAILED,TEMP is a request to come back
//	Config, Unsupported  no: the profile says so, and will say so again
//	Auth                 not decided here — Reconnect decides, because the
//	                     answer depends on where the credential came from
//	Protocol, Crypto,    no: the next action each of these implies is that
//	Local                somebody changes something, and a loop is not
//	                     somebody
func retryClass(class diag.Class) bool {
	switch class {
	case diag.ClassNetwork, diag.ClassTLS, diag.ClassServerBusy:
		return true
	default:
		return false
	}
}

// Reconnect tears down the current connection and re-establishes the tunnel.
// It is not safe for concurrent use.
//
// Every method reconnects from its own resumption state, and this loop asks the
// method rather than deciding for it. A certificate or a cached password redials
// and runs the whole handshake again, including remote failover; a SAML session
// still inside its NotOnOrAfter skips the first exchange and runs the second
// against the backend that issued it. ErrReauthRequired is that method's answer
// and no other's, from either of the two ways its state runs out, and it leaves
// the client in stateNew because Connect's browser flow starts nowhere else.
//
// What is retried follows the class of the failure, not how many there have
// been: see retryClass. A rejected credential ends the loop unless the method
// has something else to present — a password from CredentialsFn, once, because
// retrying a rejected password locks an account. Backoff is 1 s, 2 s, 4 s, …
// capped at 30 s; MaxReconnects limits total attempts (0 = unlimited).
func (c *Client) Reconnect(ctx context.Context) error {
	res := c.method().captureResumption()

	c.mu.Lock()
	// The sequence starts empty, so Attempts describes this reconnect rather
	// than everything the client has ever tried.
	c.attempts = nil
	c.reconnecting = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.reconnecting = false
		c.mu.Unlock()
	}()

	backoff := reconnectBackoffBase
	var lastErr error

	for attempt := 1; ; attempt++ {
		if c.MaxReconnects > 0 && attempt > c.MaxReconnects {
			if lastErr != nil {
				return fmt.Errorf("vpn: reconnect: exceeded %d attempts: %w", c.MaxReconnects, lastErr)
			}
			return fmt.Errorf("vpn: reconnect: exceeded %d attempts", c.MaxReconnects)
		}

		if attempt > 1 {
			// A server that answered AUTH_FAILED,TEMP with a backoff named a
			// wait, and its number beats the doubling in both directions. The
			// ceiling still applies, so a server cannot park a client forever.
			wait := backoff
			if asked := requestedBackoff(lastErr); asked > wait {
				wait = min(asked, reconnectBackoffMax)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			backoff *= 2
			if backoff > reconnectBackoffMax {
				backoff = reconnectBackoffMax
			}
		}

		// The teardown runs before the usability check as well as between
		// attempts, and that ordering is load-bearing: a caller handed
		// ErrReauthRequired goes on to Connect, which runs only from stateNew.
		c.disconnect(true)    //nolint:errcheck
		c.WaitForDisconnect() //nolint:errcheck
		c.reset()

		if err := res.usable(); err != nil {
			// Nothing is left to attempt with, so none is made and none is
			// recorded. Only the SAML method can answer this way.
			return err
		}

		c.mu.Lock()
		res.seedLocked(c)
		c.mu.Unlock()

		c.emit(Event{Type: EventLog, Message: res.attemptMessage(attempt)})

		err := res.reattempt(ctx, c)
		if err == nil {
			c.mu.Lock()
			c.reconnectCount++
			c.mu.Unlock()
			return nil
		}
		lastErr = err
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
			"vpn: reconnect attempt %d failed: %v", attempt, err)})

		// Every way a server can reject credentials — including a federated
		// second exchange refusing the assertion — arrives here as ClassAuth,
		// so the class is the whole question.
		derr := diag.AsError(err)
		if derr != nil && derr.Class == diag.ClassAuth {
			retry, out := res.rejected(c, err)
			if !retry {
				return out
			}
			continue
		}
		if derr != nil && !retryClass(derr.Class) {
			return err
		}
		// An error with no class did not come from a stage boundary, and
		// every one of ours does. Retry rather than decide a policy from
		// nothing; MaxReconnects and ctx still bound the loop.
	}
}

// isCredentialsRejected reports whether the server answered PUSH_REQUEST by
// rejecting the credentials, in any flow: a plain AUTH_FAILED rejects what was
// offered, and a CRV1 challenge answering cached CRV1 credentials says the same.
func isCredentialsRejected(cm *control.Message) bool {
	// MsgKindAuthFailedTemp is deliberately not here. The server declined this
	// attempt and asked us back; treating that as a credential rejection
	// records a working account as a failing one.
	return cm != nil && (cm.Kind == control.MsgKindAuthFailed || cm.Kind == control.MsgKindAuthFailedCRV1)
}

// rewindConnectionLocked zeroes everything one connection attempt leaves
// behind on the client, so that the next one starts from the state the first
// one did. c.mu must be held.
//
// It is shared by reset, which starts the next attempt of a reconnect, and by
// rewindForNextRemote, which starts the next remote of a failover inside one
// attempt. reset is a strict superset, and that is the trap: a field added to
// the connection and zeroed only in reset leaves failover carrying one server's
// session id, key material or control-channel tallies into the next one, which
// shows up as a dropped HARD_RESET or a misattributed failure class and names
// no field at all.
//
// Both key sources are secrets: an old epoch's material would derive keys from
// bytes the peer never saw. The control-channel tallies are what
// resetFailureClass reads to tell a silent server from a static key that does
// not match.
func (c *Client) rewindConnectionLocked() {
	c.rawConn = nil
	c.tlsConn = nil
	c.tlsRW = nil
	c.reply = replyNone
	c.samlSession = nil
	c.clientSID = [8]byte{}
	c.serverSID = [8]byte{}
	c.sendSeq = 0
	c.recvExp = 0
	c.backendIP = ""
	c.keySource = prf.KeySource{}
	c.serverKeySource = prf.KeySource{}
	ctl := &c.stats().ctl
	ctl.authFailures.Store(0)
	ctl.replays.Store(0)
	ctl.staleTimestamps.Store(0)
	ctl.foreignSession.Store(0)
}

// reset returns the Client to a stateNew state so Connect can be called
// again.  It must only be called after Disconnect+Wait have completed.
func (c *Client) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	// First, before anything below can take it away: the attempt that is
	// ending keeps its report, counters and all. The fresh recorder and the
	// zeroed counters further down are what would otherwise destroy it.
	c.freezeAttemptLocked(c.counters())
	c.rewindConnectionLocked()
	c.state = stateNew
	c.manager = nil
	c.codec.Store(nil)
	c.peerID = 0
	c.wire = datachannel.WireDataV2
	c.dev = nil
	c.dataCh = nil
	c.pushOpts = nil
	c.connectedAt = time.Time{}
	c.lastTransientErr = nil
	// Cached credentials intentionally survive this internal reset while
	// Reconnect is in progress. Explicit Disconnect and terminal setup failure
	// clear them before returning control to the caller.
	c.cancelFn = nil
	c.doneErr = nil
	c.doneCh = make(chan struct{})
	c.rekeySessionCh = make(chan *controlSession, 1)
	c.peerRekeyCh = make(chan *controlSession, 1)
	c.rekeyActive.Store(false)
	c.nextKeyID = 1
	c.counts.Store(new(attemptStats))
	// Each attempt gets its own report. Report therefore describes the most
	// recent attempt, which is what a Reconnect loop needs to explain itself.
	c.rec.Store(newSessionRecorder())
	c.clearCredentialsOnCleanup = false
}

// Phase1ForTest runs dialAndAuthenticate and returns the SAML challenge (or nil).
// Only for integration tests — do not use in production code.
func (c *Client) Phase1ForTest(ctx context.Context) (*SAMLChallenge, error) {
	return c.dialAndAuthenticate(ctx)
}

// SetRelayPhase2 pre-seeds the Phase 1 state obtained by the mobile/desktop app
// so that ConnectPhase2 can skip Phase 1 and dial the sticky backend IP with the
// SAML credentials the relay delivered. It must be called before ConnectPhase2
// and only in relay mode: remoteIP is the backend server IP from the CRV1
// challenge, stateID the opaque CRV1 state token.
func (c *Client) SetRelayPhase2(remoteIP, stateID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The relay delivered what a first exchange would have produced, so this
	// client picks the flow up at the second one.
	c.seedSecondExchangeLocked(stateID, remoteIP)
	// The method is written down too, though nothing depends on its being set
	// here: it is asked for at the point of sending, and a client that arrives
	// without one gets what its profile implies.
	c.auth = c.authMethodFor(c.prof)
}

// seedSecondExchangeLocked puts the client where a first exchange would have
// left it: holding a CRV1 state id, pointed at the backend instance that issued
// it, and in the state bringUpTunnel starts from. c.mu must be held.
//
// All four assignments are load-bearing: without the state id AWS has no session
// to match the assertion to, without the backend address the dial can land on a
// different instance of a load-balanced endpoint, without replySecondExchange
// bringUpTunnel reads a PUSH_REPLY that was never sent, and without
// stateConnecting it refuses to start. It does not set the method — the relay
// entry point says which one to use, and a reconnect resumes the client's own.
func (c *Client) seedSecondExchangeLocked(stateID, backendIP string) {
	c.state = stateConnecting
	c.backendIP = backendIP
	c.samlSession = &SAMLChallenge{StateID: stateID}
	c.reply = replySecondExchange
}

// ConnectPhase2 completes the connection with a SAML assertion the caller
// already holds: it runs the CRV1 second exchange and brings the tunnel up.
// samlToken is the base64-encoded SAMLResponse, and where it came from is not
// this method's business. What is required is the first exchange's state — a
// state id, a backend address and a client in stateConnecting — put there by
// SetRelayPhase2 or by the client's own first exchange.
func (c *Client) ConnectPhase2(ctx context.Context, samlToken string) error {
	return c.bringUpTunnel(ctx, samlToken)
}
