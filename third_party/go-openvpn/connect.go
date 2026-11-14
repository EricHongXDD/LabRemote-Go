// SPDX-License-Identifier: LGPL-2.1-or-later
//
// connect.go: the connect flow, including the AWS Client VPN CRV1
// two-phase path, and the data-channel bring-up it ends in.

package vpn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/buengese/go-openvpn/auth/saml"
	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/dns"
	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/internal/control"
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/internal/framing"
	"github.com/buengese/go-openvpn/internal/keymethod2"
	"github.com/buengese/go-openvpn/internal/prf"
	"github.com/buengese/go-openvpn/profile"
	"github.com/buengese/go-openvpn/routing"
)

// Connect dials, authenticates, and brings up the VPN tunnel.
//
// The authentication method is taken from the profile: a client certificate, a
// username and password from CredentialsFn, or — for an AWS Client VPN
// endpoint — a federated SAML assertion from SAMLTokenFn. All three take the
// same route through this function; only the method knows how many exchanges
// it needs.
//
// Connect is not safe for concurrent use. However it ends, Report describes
// the attempt: the stages it reached and the class of the failure.
func (c *Client) Connect(ctx context.Context) error {
	c.auth = c.authMethodFor(c.prof)

	c.emit(Event{Type: EventStateChanged, State: StateConnecting})

	if err := c.beginAttempt(); err != nil {
		c.emit(Event{Type: EventStateChanged, State: StateError, Message: err.Error()})
		return err
	}
	// Before a socket is opened: a method Connect cannot drive on its own has
	// nothing to present, and no answer the server could give would change
	// that. In practice this refuses a federated profile with no SAMLTokenFn —
	// an assertion has a second way in and a password does not — since
	// beginAttempt has already refused what the two questions agree on.
	if missing := c.method().missing(missingForConnect); missing != "" {
		return c.failStage(diag.ClassConfig, diag.StageParse, nil, missing)
	}

	challenge, err := c.dialAndAuthenticate(ctx)
	if err != nil {
		c.emit(Event{Type: EventStateChanged, State: StateError, Message: err.Error()})
		return err
	}

	// A challenge means the method has a second exchange to make and needs a
	// SAML assertion from outside the protocol first. The check above has
	// already refused the attempt if SAMLTokenFn were nil.
	var token string
	if challenge != nil {
		// The callback carries the SAML URL through a typed value. Do not also
		// place it in the generic state message, which consumers commonly log.
		c.emit(Event{Type: EventStateChanged, State: StateWaitingSAML})
		// Collecting the assertion is part of authentication, so it gets its
		// own StageAuth span. The first exchange's StageAuth has already
		// closed; this one measures the browser round-trip.
		c.enterStage(diag.StageAuth)
		token, err = c.SAMLTokenFn(ctx, *challenge)
		if err != nil {
			derr := c.failStage(diag.ClassAuth, diag.StageAuth, err, "collect SAML token")
			// The first exchange's connection is still open: dialRemote leaves
			// it for a second exchange that is not going to happen. Every
			// other way out of Connect closes its socket or goes through
			// setDisconnected; without this the socket and its goroutines run
			// on, Done stays open and the client parks in stateConnecting.
			c.abandonAttempt(derr)
			c.emit(Event{Type: EventStateChanged, State: StateError, Message: derr.Error()})
			return derr
		}
		c.recorder().edit(func(r *diag.SessionReport) { r.AddSecret(token) })
		c.completeStage(diag.StageAuth)
		c.emit(Event{Type: EventStateChanged, State: StateConnecting})
	}

	if err := c.bringUpTunnel(ctx, token); err != nil {
		c.emit(Event{Type: EventStateChanged, State: StateError, Message: err.Error()})
		return err
	}
	return nil
}

// dialAndAuthenticate dials the VPN server, performs the OpenVPN HARD_RESET +
// TLS handshake, and waits for the server's first control message.
//
// A non-nil *SAMLChallenge means the method has a second exchange to make and
// needs a SAML assertion from outside the protocol first. Both values nil
// means the PUSH_REPLY is buffered — bringUpTunnel must still be called, with
// an empty samlToken.
func (c *Client) dialAndAuthenticate(ctx context.Context) (*SAMLChallenge, error) {
	// Phase1ForTest and the mobile wrappers reach the handshake without going
	// through Connect, so the StageParse boundary is run here too. It is
	// idempotent.
	if err := c.beginAttempt(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	if c.state != stateNew {
		st := c.state
		c.mu.Unlock()
		return nil, c.failStage(diag.ClassLocal, diag.StageParse, nil,
			fmt.Sprintf("dialAndAuthenticate called in state %v", st))
	}
	c.state = stateConnecting
	// Connect sets a method, and so do the relay entry points. Anything else
	// that reaches here — Phase1ForTest, the mobile wrappers — gets the one its
	// profile implies, so bypassing Connect cannot mean the wrong wire format.
	if c.auth == nil {
		c.auth = c.authMethodFor(c.prof)
	}
	_, federated := c.auth.(samlMethod)
	c.mu.Unlock()
	if federated {
		c.emit(Event{Type: EventLog, Message: "vpn: notice: " + AWSSAMLUnsupportedNotice})
	}

	// Every remote in turn, until one completes the handshake. The failure
	// that stops the loop is the one the attempt ends with; every remote
	// tried, and what became of each, is in the session report.
	order := c.dialOrder()
	var last *diag.Error
	for i, target := range order {
		if i > 0 {
			if err := c.rewindForNextRemote(); err != nil {
				last = c.failStage(diag.ClassConfig, diag.StageDial, err,
					"control-channel wrap for the next remote")
				break
			}
		}
		c.setActiveRemote(target.Remote)
		c.beginRemoteAttempt(target.Index, target.Remote)

		ch, derr := c.dialRemote(ctx, target.Remote)
		if derr == nil {
			c.endRemoteAttempt(nil)
			return ch, nil
		}
		c.endRemoteAttempt(derr)
		last = derr
		if !failoverContinues(derr.Class) {
			break
		}
		if i < len(order)-1 {
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
				"vpn: remote %d of %d failed (%s at %s); trying the next one",
				i+1, len(order), derr.Class, derr.Stage)})
		}
	}
	if last == nil {
		// Unreachable: dialOrder never returns an empty list. Guarded anyway,
		// because a nil *diag.Error here would travel out as a non-nil error
		// interface wrapping a nil pointer.
		last = c.failStage(diag.ClassConfig, diag.StageDial, nil, "profile names no remote to dial")
	}
	// The attempt is over only now. Each remote's own failure closed its
	// socket; marking the client disconnected is the loop's to do, and once,
	// because doing it per remote closes doneCh with endpoints left to try.
	c.setDisconnected(last)
	return nil, last
}

// failPushReply classifies a server's refusal of PUSH_REQUEST.
//
// Three different things arrive here and each implies a different next action:
//
//	AUTH_FAILED, AUTH_FAILED,CRV1   the credentials were rejected. Final.
//	AUTH_FAILED,TEMP                the server declined this attempt and asked
//	                                us back, sometimes saying when. Retry.
//	anything else                   the peer sent something we could not
//	                                follow, which is a quirk or our bug.
//
// Folding the middle case into the last records "busy, come back in five
// seconds" as a protocol fault — the one class that accuses this client of a
// parser bug — and retryClass then declines to retry it.
func (c *Client) failPushReply(p exchangeParams, cm *control.Message, cause error) *diag.Error {
	switch {
	case isCredentialsRejected(cm):
		return c.failExchange(p, diag.ClassAuth, diag.StagePush, cause, "authentication rejected")

	case cm != nil && cm.Kind == control.MsgKindAuthFailedTemp:
		// Built and stamped before it is recorded, because the recorder is
		// handed the finished error. The server's own reason text stays in the
		// wrapped cause rather than Detail: it is untrusted, and reports print
		// Detail.
		derr := diag.Wrap(diag.ClassServerBusy, diag.StagePush, cause,
			p.label+"server declined this attempt and asked us back")
		derr.RetryAfter = cm.AuthTemp().Backoff
		c.recorder().fail(derr)
		if p.endsSession {
			c.setDisconnected(derr)
		}
		return derr

	default:
		return c.failExchange(p, diag.ClassProtocol, diag.StagePush, cause, "read PUSH_REPLY")
	}
}

// abandonAttempt drops the connection an attempt was holding and marks the
// client disconnected with the reason it stopped. It is for a failure between
// the two exchanges of a federated connection, where the socket is deliberately
// still open; failures inside a single exchange close their own on the way past.
//
// Closing the socket is what ends the goroutines tlsHandshake started: the raw
// reader wakes with an error and the inbound relay follows it out, closing the
// control transports the send goroutines are parked on. They are not in c.wg,
// so nothing else would collect them.
func (c *Client) abandonAttempt(err error) {
	c.mu.Lock()
	conn := c.rawConn
	c.rawConn = nil
	c.tlsConn = nil
	c.tlsRW = nil
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	c.setDisconnected(err)
}

// rewindForNextRemote clears what one failed remote left behind, so that the
// next one is dialed from the state the first one was.
//
// The control-channel wrap is rebuilt rather than reused. It owns
// connection-scoped state — a replay window and a packet-id counter — and the
// next remote has never sent us a control packet, so a window carried across
// would drop its HARD_RESET as a replay and make failover impossible on every
// wrapped profile. See selectWrapper.
//
// The session report is not cleared: the stage timeline keeps every stage of
// every remote, in order, and only the outcome the failed remote wrote is
// rewound, so the next remote can write its own.
func (c *Client) rewindForNextRemote() error {
	c.mu.Lock()
	c.rewindConnectionLocked()
	c.mu.Unlock()

	c.recorder().rewind()
	return c.selectWrapper()
}

// ---- One exchange --------------------------------------------------------
//
// A federated connection runs the control-channel handshake twice: once to be
// handed the SAML challenge, and once more with the assertion. Everything
// between the dial and the server's answer to PUSH_REQUEST is the same both
// times, and runExchange is the one copy of it.

// exchangeParams is everything that differs between the two exchanges.
type exchangeParams struct {
	// addr is the resolved "host:port" to dial, and proto how to dial it.
	addr  string
	proto profile.Proto
	// creds names which key-method-2 credentials to present.
	creds authExchange
	// label prefixes every failure detail, so a report says which exchange
	// stopped. Empty for the first.
	label string
	// endsSession says a failure here ends the client's session rather than
	// being handed back to be judged. Only the first exchange has a dial loop
	// above it that might try another remote.
	endsSession bool
}

// failExchange records a failure of this exchange, labelled, and ends the
// session when this exchange is the one that owns that decision.
func (c *Client) failExchange(p exchangeParams, class diag.Class, stage diag.Stage, cause error, detail string) *diag.Error {
	derr := c.failStage(class, stage, cause, p.label+detail)
	if p.endsSession {
		// The typed error rather than the bare cause: it is what
		// WaitForDisconnect hands back, and it carries the class and stage.
		c.setDisconnected(derr)
	}
	return derr
}

// runExchange dials and drives the control channel as far as the server's
// answer to PUSH_REQUEST: HARD_RESET, TLS, the key-method-2 exchange, then the
// reply. It returns either a live TLS connection and that reply, or a typed
// failure having already closed everything it opened. What the reply means is
// the caller's business.
func (c *Client) runExchange(ctx context.Context, p exchangeParams) (*tls.Conn, *control.Message, *diag.Error) {
	c.enterStage(diag.StageDial)
	dialStart := time.Now()
	rawConn, err := c.dialWithContext(ctx, p.proto, p.addr)
	if err != nil {
		return nil, nil, c.failExchange(p, diag.ClassNetwork, diag.StageDial, err, "dial "+p.addr)
	}
	// The resolved address, so a second exchange reaches the same backend:
	// AWS Client VPN binds the CRV1 state id to one server instance, and
	// re-resolving the hostname may land on a different one.
	resolved := ""
	if ra := rawConn.RemoteAddr(); ra != nil {
		if h, _, _ := net.SplitHostPort(ra.String()); h != "" {
			resolved = h
		}
	}
	// Under the lock, because Phase1IP reads backendIP from whatever goroutine
	// the caller is on: the daemon's Status does it on the bus thread while a
	// Connect is in flight, which is what the GTK app does every time it polls.
	c.mu.Lock()
	c.rawConn = rawConn
	changed := resolved != "" && resolved != c.backendIP
	if changed {
		c.backendIP = resolved
	}
	c.mu.Unlock()

	// Outside it: emit hands the event to EventFn, which is the caller's own
	// code and free to call back in — Stats and Phase1IP both take this mutex,
	// so emitting under it is a deadlock waiting for a caller who logs.
	if changed {
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: remote resolved to %s", resolved)})
	}
	c.recordDial(rawConn, time.Since(dialStart))
	c.completeStage(diag.StageDial)

	fail := func(class diag.Class, stage diag.Stage, cause error, detail string) *diag.Error {
		rawConn.Close()
		return c.failExchange(p, class, stage, cause, detail)
	}

	if _, err := rand.Read(c.clientSID[:]); err != nil {
		return nil, nil, fail(diag.ClassLocal, diag.StageReset, err, "rand session id")
	}

	// HARD_RESET, retransmitted: UDP is unreliable, so every 2s for up to 16s,
	// which is openvpn3-core's default.
	c.enterStage(diag.StageReset)
	srvReset, err := c.sendWithRetry(rawConn, framing.BuildHardReset(c.clientSID),
		framing.P_CONTROL_HARD_RESET_SERVER_V2, 2*time.Second, 8)
	if err != nil {
		class, detail := c.resetFailureClass()
		return nil, nil, fail(class, diag.StageReset, err, "HARD_RESET exchange"+detail)
	}
	// No opcode check: sendWithRetry returns only a packet whose opcode is the
	// one asked for, and keeps reading until the deadline otherwise.
	if len(srvReset) < 9 {
		return nil, nil, fail(diag.ClassProtocol, diag.StageReset, nil,
			fmt.Sprintf("HARD_RESET_SERVER is %d bytes, too short to carry a session id", len(srvReset)))
	}
	copy(c.serverSID[:], srvReset[1:9])

	// HARD_RESET and P_CONTROL_V1 share one reliable sequence counter in
	// openvpn3-core. Ours went out as packet_id 0, so the first outbound
	// P_CONTROL_V1 is 1; the server must be ACKed before it takes ClientHello.
	_, srvPacketID := framing.ParseControlV1Payload(srvReset)
	// A hard reset opens a session, so its packet id is 0 by definition and any
	// other value is a peer we cannot follow. The reference drops the packet
	// rather than adopting the number (openvpn-2.6.22 src/openvpn/ssl.c:4022-4029,
	// "0 was expected, ignoring packet"): taking it on trust lets a peer set
	// our receive sequence anywhere it likes.
	if srvPacketID != 0 {
		return nil, nil, fail(diag.ClassProtocol, diag.StageReset, nil,
			fmt.Sprintf("HARD_RESET_SERVER carried packet id %d, not 0", srvPacketID))
	}
	ack := framing.BuildAck(c.clientSID, c.serverSID, 0, []uint32{srvPacketID})
	if err := c.writePacket(rawConn, ack); err != nil {
		return nil, nil, fail(diag.ClassNetwork, diag.StageReset, err, "send ACK for HARD_RESET_SERVER")
	}
	c.recvExp = srvPacketID + 1
	c.sendSeq = 1
	c.completeStage(diag.StageReset)

	c.enterStage(diag.StageTLS)
	tlsConn, err := c.tlsHandshake(ctx, rawConn)
	if err != nil {
		return nil, nil, fail(diag.ClassTLS, diag.StageTLS, err, "TLS handshake")
	}
	c.tlsConn = tlsConn
	c.tlsRW = tlsConn
	c.recordTLS(tlsConn.ConnectionState())
	c.completeStage(diag.StageTLS)

	// openvpn3-core cliproto.hpp: client auth, then server auth, then the ACKs
	// that make the session ACTIVE, and only then PUSH_REQUEST.
	c.enterStage(diag.StageAuth)
	// Collecting credentials can block — a username/password profile may put a
	// prompt in front of the user — so it happens inside StageAuth, which is
	// where the time it takes belongs.
	creds, err := c.authCredentials(ctx, p.creds)
	if err != nil {
		return nil, nil, fail(diag.ClassAuth, diag.StageAuth, err, "collect credentials")
	}
	c.recordAdvertised(creds.Username, creds.Password)
	keySource, err := keymethod2.SendAuth(tlsConn,
		tunnelParams(c.activeProto(), c.prof.TunMTU, c.advertisedDataChannel()),
		creds.Username, creds.Password, c.method().framing(), ivProtoFor(c.DataV2))
	if err != nil {
		return nil, nil, fail(diag.ClassNetwork, diag.StageAuth, err, "send auth packet")
	}
	// A second exchange opens a fresh TLS session and runs a fresh
	// key-method-2 exchange, so this material supersedes the first's entirely.
	c.keySource = keySource

	tlsConn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
	serverKeySource, serverOpts, err := keymethod2.ConsumeServerAuth(tlsConn)
	c.recordServerOpts(serverOpts)
	if err != nil {
		return nil, nil, fail(diag.ClassProtocol, diag.StageAuth, err, "read server auth packet")
	}
	c.serverKeySource = serverKeySource
	c.completeStage(diag.StageAuth)

	c.enterStage(diag.StagePush)
	if _, err := tlsConn.Write([]byte("PUSH_REQUEST\x00")); err != nil {
		return nil, nil, fail(diag.ClassNetwork, diag.StagePush, err, "send PUSH_REQUEST")
	}
	cm, err := control.ReadServerReply(tlsConn)
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		rawConn.Close()
		return nil, nil, c.failPushReply(p, cm, err)
	}
	return tlsConn, cm, nil
}

// readPushBody collects the rest of a PUSH_REPLY the server split across
// several control messages. They have to be taken while the connection is
// readable: bringUpTunnel has nothing else to read them from.
func (c *Client) readPushBody(tlsConn *tls.Conn, first string, p exchangeParams) (string, *diag.Error) {
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
	pushRaw, err := c.joinPushContinuation(tlsConn, first)
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		c.rawConn.Close()
		return "", c.failExchange(p, diag.ClassProtocol, diag.StagePush, err, "read PUSH_REPLY continuation")
	}
	return pushRaw, nil
}

// dialRemote runs one remote's first exchange: dial, HARD_RESET, TLS, the
// key-method-2 exchange and PUSH_REQUEST, ending either in a SAML challenge, a
// buffered PUSH_REPLY, or a typed failure.
//
// It returns the failure rather than ending the session with it: whether a
// failure is terminal depends on the class and on whether the profile named
// another remote — see failoverContinues.
func (c *Client) dialRemote(ctx context.Context, rem profile.Remote) (*SAMLChallenge, *diag.Error) {
	host := rem.Host
	if c.prof.RandomHostname {
		host = randomSubdomain(host)
	}
	p := exchangeParams{
		addr:  net.JoinHostPort(host, strconv.Itoa(rem.Port)),
		proto: rem.Proto,
		creds: authInitial,
	}
	tlsConn, cm, derr := c.runExchange(ctx, p)
	if derr != nil {
		return nil, derr
	}

	// What the server's answer means is the method's to say, including whether
	// it is an answer at all: a CRV1 challenge completes the exchange for a
	// federated profile and ends it for everyone else.
	reply, derr := c.method().handleReply(cm)
	if derr != nil {
		c.rawConn.Close()
		return nil, derr
	}

	if reply == replySecondExchange {
		// The challenge is the intended answer to this exchange, so the push
		// stage is finished for it. The second exchange opens its own.
		c.completeStage(diag.StagePush)
		c.mu.Lock()
		c.reply = reply
		challenge := c.samlSession
		c.mu.Unlock()
		return challenge, nil
	}

	pushRaw, derr := c.readPushBody(tlsConn, cm.Raw, p)
	if derr != nil {
		return nil, derr
	}
	c.completeStage(diag.StagePush)
	c.mu.Lock()
	c.reply = reply
	c.mu.Unlock()
	// Preload the PUSH_REPLY so bringUpTunnel can read it back, in front of the
	// connection it came off: this exchange consumed the reply, and what
	// follows the replay is the live channel sessionMonitor watches.
	c.tlsRW = newPrereadRW([]byte(pushRaw+"\x00"), tlsConn)
	return nil, nil
}

// bringUpTunnel completes the VPN connection.
//
// samlToken is the base64-encoded SAMLResponse when the method asked for one,
// and empty otherwise. A method that finished in one exchange already has its
// PUSH_REPLY buffered in c.tlsRW and reuses that connection; one that asked for
// a second exchange opens a fresh connection here. On success, the TUN
// interface is up and data channel goroutines are running.
func (c *Client) bringUpTunnel(ctx context.Context, samlToken string) error {
	if err := c.beginBringUp(samlToken); err != nil {
		return err
	}

	pushRaw, err := c.readPushReply(ctx)
	if err != nil {
		return err
	}

	pushOpts, dnsOpts, err := c.applyPushReply(pushRaw)
	if err != nil {
		return err
	}

	keyMat256, err := c.deriveDataKeys(pushOpts)
	if err != nil {
		return err
	}

	tunMTU := effectiveTunMTU(pushOpts.TunMTU, c.prof.TunMTU)
	if err := c.startDataChannel(pushOpts, keyMat256, tunMTU); err != nil {
		return err
	}

	c.enterDataStage(pushOpts, tunMTU)

	if err := c.bringUpDevice(ctx, pushOpts, dnsOpts, tunMTU); err != nil {
		return err
	}

	c.startDataPath(pushOpts)
	return nil
}

// beginBringUp opens the attempt, checks that the first exchange left the
// client somewhere the second can start from, and caches the credentials a
// reconnect will reuse.
func (c *Client) beginBringUp(samlToken string) error {
	// ConnectPhase2 enters here without a first exchange of its own, so the
	// StageParse boundary runs here too. It is idempotent.
	if err := c.beginAttempt(); err != nil {
		return err
	}

	c.mu.Lock()
	st := c.state
	reply := c.reply
	session := c.samlSession
	c.mu.Unlock()

	if st != stateConnecting {
		return c.failStage(diag.ClassLocal, diag.StageParse, nil,
			fmt.Sprintf("bringUpTunnel called in state %v", st))
	}
	if reply == replyNone {
		return c.failStage(diag.ClassLocal, diag.StageParse, nil,
			"dialAndAuthenticate must be called before bringUpTunnel")
	}

	// Cache the SAML session for future reconnects. A method that carries no
	// session leaves every one of these empty, and TokenExpiry of the empty
	// token is the zero time.
	expiry := saml.TokenExpiry(samlToken)
	c.recorder().edit(func(r *diag.SessionReport) {
		r.AddSecret(samlToken)
		if session != nil {
			r.AddSecret(session.StateID)
		}
	})
	c.mu.Lock()
	c.cachedSAMLToken = samlToken
	c.cachedSAMLExpiry = expiry
	if session != nil {
		c.cachedStateID = session.StateID
	}
	c.cachedBackendIP = c.backendIP
	c.mu.Unlock()
	if samlToken != "" {
		if !expiry.IsZero() {
			ttl := time.Until(expiry).Round(time.Second)
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
				"vpn: SAML token expires at %s (TTL %s)", expiry.UTC().Format(time.RFC3339), ttl)})
		} else {
			c.emit(Event{Type: EventLog, Message: "vpn: SAML token expiry unknown (no NotOnOrAfter in assertion)"})
		}
	}

	return nil
}

// readPushReply obtains the server's PUSH_REPLY, by whichever of the two routes
// the method took: a method that authenticated in one exchange already has the
// reply buffered, and one that asked for a second exchange has yet to send it.
func (c *Client) readPushReply(ctx context.Context) (string, error) {
	c.mu.Lock()
	reply := c.reply
	c.mu.Unlock()
	if reply == replyPushed {
		return c.readPushBuffered()
	}
	return c.readPushSecondExchange(ctx)
}

// readPushBuffered reads the PUSH_REPLY the first exchange already received.
// The whole authentication happened there for these methods, so the reply is
// sitting in c.tlsRW and no new connection is needed.
func (c *Client) readPushBuffered() (string, error) {
	var pushRaw string

	// Under the lock: the inbound relay is already running and asks for this
	// field, and a Reconnect swaps it from another goroutine.
	c.mu.Lock()
	c.dataCh = make(chan []byte, 256)
	c.mu.Unlock()

	// No exchange of its own — this reads back what the first one received —
	// but a failure here ends the session all the same, which is what
	// endsSession says. There is no label because there is no second exchange
	// to tell it apart from, and classifying goes to failPushReply, as the
	// second exchange's does.
	p := exchangeParams{endsSession: true}

	c.enterStage(diag.StagePush)
	pushCM, err := control.ReadServerReply(c.tlsRW)
	if err != nil {
		c.rawConn.Close()
		return "", c.failPushReply(p, pushCM, err)
	}
	if pushCM.Kind != control.MsgKindPushReply {
		c.rawConn.Close()
		return "", c.failPushReply(p, pushCM, errors.New(notPushReply(pushCM)))
	}

	// No continuation join here: readPushBody already did it, on the live
	// connection, while the first exchange owned the read. The replay holds the
	// reassembled reply, so there is nothing left on the wire to collect.
	pushRaw = pushCM.Raw

	return pushRaw, nil
}

// joinPushContinuation completes a PUSH_REPLY the server split across several
// control messages, given the first fragment and the reader the rest arrive on.
//
// A reply that does not fit PUSH_BUNDLE_SIZE (1024 bytes,
// openvpn-2.6.22 src/openvpn/common.h:88 — roughly twenty routes) is sent in
// fragments: every one but the last ends in ",push-continuation 2"
// (push.c:718-735) and the last in ",push-continuation 1" (push.c:795-806).
// Reading only the first is not a partial failure that announces itself: the
// tunnel comes up on whatever part of the configuration fit, and the remaining
// messages turn up as unexpected control traffic in the data stage.
//
// Reference: openvpn-2.6.22 src/openvpn/push.c:1041-1066
// (process_incoming_push_reply returns PUSH_MSG_CONTINUATION for 2 and
// PUSH_MSG_REPLY for 0 or 1) and options.c:7929-7933.
func (c *Client) joinPushContinuation(r io.Reader, first string) (string, error) {
	var acc routing.PushAccumulator
	complete, err := acc.AddFragment(first)
	if err != nil {
		return "", err
	}
	for !complete {
		cm, readErr := control.ReadControlMsg(r, 0)
		if readErr != nil {
			return "", fmt.Errorf("PUSH_REPLY fragment %d: %w", acc.Fragments()+1, readErr)
		}
		if cm.Kind != control.MsgKindPushReply {
			return "", fmt.Errorf(
				"expected a PUSH_REPLY continuation, got message kind %s", cm.Kind)
		}
		if complete, err = acc.AddFragment(cm.Raw); err != nil {
			return "", err
		}
	}
	if n := acc.Fragments(); n > 1 {
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
			"vpn: PUSH_REPLY reassembled from %d push-continuation fragments", n)})
	}
	return acc.Reply(), nil
}

// readPushSecondExchange runs the second exchange of a federated connection.
//
// The first exchange's connection existed only to obtain the SAML challenge,
// so this opens a fresh one and runs the handshake again with the CRV1
// credential built from the assertion. It dials the address the first exchange
// reached verbatim, because AWS binds the state id to one backend instance.
func (c *Client) readPushSecondExchange(ctx context.Context) (string, error) {
	// The first exchange's connection has served its purpose.
	if c.rawConn != nil {
		c.rawConn.Close()
		c.rawConn = nil
	}
	c.tlsConn = nil
	c.tlsRW = nil
	c.sendSeq = 0
	c.recvExp = 0
	// Under the lock: the inbound relay is already running and asks for this
	// field, and a Reconnect swaps it from another goroutine.
	c.mu.Lock()
	c.dataCh = make(chan []byte, 256)
	c.mu.Unlock()

	host := c.backendIP
	if host == "" {
		host = c.activeRemote().Host
		if c.prof.RandomHostname {
			host = randomSubdomain(host)
		}
	}
	p := exchangeParams{
		addr:        net.JoinHostPort(host, strconv.Itoa(c.activeRemote().Port)),
		proto:       c.activeProto(),
		creds:       authCRV1Phase2,
		label:       "second exchange: ",
		endsSession: true,
	}
	tlsConn, cm, derr := c.runExchange(ctx, p)
	if derr != nil {
		return "", derr
	}
	// Unlike the first exchange there is nothing left to negotiate: the
	// assertion has been presented and a PUSH_REPLY is the only answer that
	// means anything. failPushReply classifies the rest — a rejected assertion
	// is ClassAuth, which Reconnect reads to decide on a fresh browser flow.
	if cm.Kind != control.MsgKindPushReply {
		c.rawConn.Close()
		return "", c.failPushReply(p, cm, errors.New(notPushReply(cm)))
	}

	pushRaw, derr := c.readPushBody(tlsConn, cm.Raw, p)
	if derr != nil {
		return "", derr
	}
	return pushRaw, nil
}

// applyPushReply parses the PUSH_REPLY into routing and DNS options, merges the
// profile's own DNS settings over the pushed ones, and records the result.
func (c *Client) applyPushReply(pushRaw string) (*routing.PushOptions, *dns.Config, error) {
	// The peer-id, and with it the data-channel wire format, come off the raw
	// reply before the routes are parsed: they do not depend on that parse
	// succeeding, and a report claiming P_DATA_V2 for a server that pushed no
	// peer-id is the wrong answer to give. They are stored on the Client so
	// that startDataChannel and every later rekey build from the same pair —
	// openvpn3-core treats remote_peer_id as connection-scoped.
	peerID, peerIDPushed := parsePeerID(pushRaw)
	c.peerID = peerID
	c.wire = pushedWireFormat(peerIDPushed)

	// Parse PUSH_REPLY options.
	pushOpts, err := routing.ParsePushReply(pushRaw)
	if err != nil {
		c.recordPush(pushRaw, nil, 0)
		c.rawConn.Close()
		c.setDisconnected(err)
		return nil, nil, c.failStage(diag.ClassProtocol, diag.StagePush, err, "parse PUSH_REPLY routes")
	}
	dnsOpts, err := dns.ParsePushReply(pushRaw)
	if err != nil {
		c.recordPush(pushRaw, pushOpts, 0)
		c.rawConn.Close()
		c.setDisconnected(err)
		return nil, nil, c.failStage(diag.ClassProtocol, diag.StagePush, err, "parse PUSH_REPLY DNS")
	}
	dnsOpts = dns.Merge(dnsOpts, &c.prof.DNS)
	// Only the routing options are stored. The merged DNS configuration is
	// returned instead: it reaches the device as a parameter of bringUpDevice,
	// and the backend owns unwinding it.
	c.pushOpts = pushOpts

	c.recordPush(pushRaw, pushOpts, peerID)
	c.completeStage(diag.StagePush)

	return pushOpts, dnsOpts, nil
}

// deriveKeyBlock produces the 256-byte key block a data-channel epoch is
// sliced from, by whichever derivation the server selected. It serves the
// initial session and every renegotiation, and is one copy on purpose: two
// derivations that disagree do not fail, they produce a tunnel whose packets
// the peer silently discards.
//
// Reference: openvpn3-core ssl/proto.hpp
// KeyContext::generate_datachannel_keys() line ~2170:
//
//	if (key_derivation == TLS_EKM)
//	  export_key_material(dck->key, "EXPORTER-OpenVPN-datakeys");  // 256 bytes
//	else
//	  tlsprf->generate_key_expansion(...)
//
// The two branches are not two spellings of one thing. EKM is RFC 5705 over
// the TLS session; the classic path is the TLS 1.0 PRF over material the peers
// exchanged inside the control channel and that neither TLS stack ever sees.
// Only servers from 2.6 onward offer the first.
//
// It returns a bare error and classifies nothing: the initial session ends the
// attempt at StageKeys, while a renegotiation leaves the session running on the
// previous key and reports a transient.
//
// conn and capture are the epoch's own TLS session, and clientKS and serverKS
// its own key sources. The session IDs are not parameters: they are
// connection-scoped, so a rekey seeds stage two with the pair the first
// handshake did.
func (c *Client) deriveKeyBlock(deriv routing.KeyDerivation, conn *tls.Conn, capture *prf.Capture,
	clientKS, serverKS prf.KeySource) ([]byte, error) {
	switch deriv {
	case routing.KeyDerivationTLSEKM:
		// RFC 5705 — symmetric, same 256 bytes on both sides. A profile can
		// ask for it from a TLS session that cannot safely support it, which
		// is what exportDataChannelKeys is for.
		ekm, err := c.exportDataChannelKeys(conn.ConnectionState(), capture)
		if err != nil {
			return nil, fmt.Errorf("ExportKeyingMaterial: %w", err)
		}
		return ekm, nil
	case routing.KeyDerivationOpenVPNPRF:
		// The classic two-stage derivation, over the key sources the two peers
		// exchanged during the auth stage and the two control-channel session
		// IDs.
		block, err := prf.DeriveKeyBlock(clientKS, serverKS, c.clientSID[:], c.serverSID[:])
		if err != nil {
			return nil, fmt.Errorf("PRF key derivation: %w", err)
		}
		return block, nil
	default:
		// Unreachable: routing parses the pushed flags into exactly the two
		// above. Named rather than left to fall through, which returns a nil
		// key block and shows the caller a cipher refusing a short key.
		return nil, fmt.Errorf("unknown key derivation %d", deriv)
	}
}

// deriveDataKeys derives the initial session's data-channel key block and ends
// the attempt if it cannot.
func (c *Client) deriveDataKeys(pushOpts *routing.PushOptions) ([]byte, error) {
	c.enterStage(diag.StageKeys)
	// The key block exists after this function and the TLS secrets have no
	// second use, so this is where the capture's life ends, on every path
	// through here. Taken from the client rather than read in place, so a
	// concurrent teardown cannot zero the material the export derives from.
	secrets := c.takeTLSSecrets()
	defer secrets.Wipe()

	keyMat256, err := c.deriveKeyBlock(
		pushOpts.KeyDerivation, c.tlsConn, secrets, c.keySource, c.serverKeySource)
	if err != nil {
		c.rawConn.Close()
		c.setDisconnected(err)
		return nil, c.failStage(diag.ClassCrypto, diag.StageKeys, err, "derive the data-channel key block")
	}
	return keyMat256, nil
}

// negotiateDataChannel resolves the cipher and digest for this connection. A
// value pushed in PUSH_REPLY outranks the profile's, which is what NCP
// negotiation means; the profile's own directive applies when the server
// pushes none.
//
// The wire format is settled here with them, from what the same PUSH_REPLY did
// or did not carry (see pushedWireFormat). By the time a data packet is in the
// wrong format the session is broken and the peer has said nothing about it, so
// there is no later point at which this could be a fallback.
func (c *Client) negotiateDataChannel(pushOpts *routing.PushOptions) (datachannel.Params, string, error) {
	cipherName := pushOpts.Cipher
	if cipherName == "" {
		cipherName = c.prof.Cipher
	}
	digestName := pushOpts.Auth
	if digestName == "" {
		digestName = c.prof.Auth
	}
	params, feature, err := datachannel.ResolveParams(cipherName, digestName)
	// Set unconditionally, including on the error path: an unsupported cipher
	// does not make the peer's choice of format unknown, and the report reads
	// these parameters even when the connection ends at StageKeys.
	params.Wire = c.wire
	return params, feature, err
}

// advertisedDataChannel is what the client tells the server it intends to use,
// in the options string of its key-method-2 packet. It comes from the profile
// alone, because the advertisement is sent during the auth stage and the
// options string is one of the inputs the server negotiates *from*.
//
// A profile naming a cipher this client cannot construct still gets a
// well-formed string, built from the defaults: the attempt goes on to fail at
// StageKeys with ClassUnsupported naming the real cipher, which is a better
// answer than a malformed advertisement failing at StageAuth.
func (c *Client) advertisedDataChannel() datachannel.Params {
	params, _, err := datachannel.ResolveParams(c.prof.Cipher, c.prof.Auth)
	if err != nil {
		params, _, _ = datachannel.ResolveParams("", "") //nolint:errcheck // the defaults are in the table by construction
	}
	return params
}

// startDataChannel builds the cipher the server negotiated and installs the
// manager that owns rekeys. tunMTU bounds a decompressed payload.
func (c *Client) startDataChannel(pushOpts *routing.PushOptions, keyMat256 []byte, tunMTU int) error {
	params, feature, err := c.negotiateDataChannel(pushOpts)
	if err != nil {
		c.rawConn.Close()
		c.setDisconnected(err)
		return c.failUnsupported(diag.StageKeys, feature,
			"the negotiated data-channel cipher or digest is not implemented")
	}
	c.mu.Lock()
	c.dataParams = params
	c.mu.Unlock()

	// The framing comes from two sources that can disagree: an OpenVPN server
	// does not push its compression setting, so a comp-lzo profile against a
	// comp-lzo server settles it in silence and a PUSH_REPLY says nothing.
	mode, err := c.effectiveCompression(pushOpts)
	if err != nil {
		c.rawConn.Close()
		c.setDisconnected(err)
		return c.failUnsupported(diag.StageKeys, "allow-compression", err.Error())
	}
	codec := compress.NewCodec(mode, tunMTU)
	c.codec.Store(codec)

	// peerID and the wire format params carries were both parsed out of the
	// PUSH_REPLY by applyPushReply and are connection-scoped, so they
	// outlive every key epoch.
	ch2, err := params.NewChannel(c.peerID, 0, keyMat256)
	if err != nil {
		c.rawConn.Close()
		c.setDisconnected(err)
		return c.failStage(diag.ClassCrypto, diag.StageKeys, err, "data channel init")
	}

	c.manager = datachannel.NewManager(ch2, &datachannel.ManagerConfig{
		// An explicit reneg-sec 0 is meaningful: AWS-issued profiles use it to
		// disable client-initiated rekeys. Do not silently replace it with the
		// OpenVPN default, or an unsupported rekey starts an hour in.
		RenegSec:   c.prof.RenegSec,
		RenegBytes: c.prof.RenegBytes,
		Compress:   codec,
	})
	c.completeStage(diag.StageKeys)

	return nil
}

// effectiveCompression resolves the framing this session must use from the two
// sources that can name one: the profile's own directive and the server's
// pushed one, under the profile's allow-compression policy.
//
// It is a method rather than an inline call because the report needs the same
// answer as the data channel, and computing it twice is how they disagree.
func (c *Client) effectiveCompression(pushOpts *routing.PushOptions) (compress.Mode, error) {
	pushed := compress.ModeNone
	if pushOpts != nil {
		pushed = pushOpts.Compression
	}

	// The profile says which framing; the peer decides whether there is one.
	// Letting a profile-declared mode apply whenever the server pushed nothing
	// is right against a server configured for compression — none of 2.4, 2.5
	// or 2.6 pushes its setting — and wrong against a server configured for
	// none, where framing puts a leading byte on every data packet that the
	// peer discards and the tunnel carries nothing.
	//
	// The peer's own options string is the signal, and the only one: it carries
	// a compression token whenever the peer has a framework enabled. See
	// compress.PeerDeclaresFraming.
	profileMode := c.prof.Compression
	if pushed == compress.ModeNone && !compress.PeerDeclaresFraming(c.serverOptsSeen()) {
		profileMode = compress.ModeNone
	}
	return compress.EffectiveMode(profileMode, pushed, c.prof.AllowCompression)
}

// serverOptsSeen returns the peer's OCC options string under the lock.
func (c *Client) serverOptsSeen() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverOpts
}

// enterDataStage opens the data stage and settles the MSS clamp the data path
// frames against.
func (c *Client) enterDataStage(pushOpts *routing.PushOptions, tunMTU int) {
	// Bringing up the tunnel is the data stage. It stays open until plaintext
	// has crossed in both directions — see markDataFlow — so a report whose
	// StageData record has no duration reached the tunnel but never proved it.
	c.enterStage(diag.StageData)

	// The codec's mode, not pushOpts.Compression: the framing byte comes off
	// the link budget whichever of the two sources asked for it, and for a
	// profile-declared mode the push says nothing at all.
	c.mssFix = c.effectiveMSSFix(
		pushOpts.Mssfix, tunMTU, c.dataParams, c.codec.Load().Mode(),
		c.rawConn.RemoteAddr(),
	)
}

// tunnelBackend 只接受宿主显式提供的进程内设备，禁止退回内核网卡。
func (c *Client) tunnelBackend() device.Backend {
	if c.Device != nil {
		return c.Device
	}
	return isolatedBackendRequired{}
}

type isolatedBackendRequired struct{}

func (isolatedBackendRequired) Open(context.Context, device.Params) (device.Device, error) {
	return nil, errors.New("必须显式提供进程内网络设备")
}

// bringUpDevice opens the tunnel device and records which backend served it.
// A PUSH_REPLY with no ifconfig is a protocol error, not a no-op: skipping the
// device reports a connected tunnel with no data path.
func (c *Client) bringUpDevice(ctx context.Context, pushOpts *routing.PushOptions, dnsOpts *dns.Config, tunMTU int) error {
	if pushOpts.Ifconfig == nil {
		err := errors.New("PUSH_REPLY carried no ifconfig, so the tunnel has no address")
		c.rawConn.Close()
		c.setDisconnected(err)
		return c.failStage(diag.ClassProtocol, diag.StageData, err, "no ifconfig pushed")
	}

	backend := c.tunnelBackend()
	dev, err := backend.Open(ctx, device.Params{
		Push:     pushOpts,
		DNS:      dnsOpts,
		MTU:      tunMTU,
		ServerIP: net.ParseIP(c.backendIP),
	})
	if err != nil {
		c.rawConn.Close()
		c.setDisconnected(err)
		return c.failStage(diag.ClassLocal, diag.StageData, err, "open tunnel device")
	}
	c.mu.Lock()
	c.dev = dev
	c.mu.Unlock()
	c.recordDevice(backend, dev, pushOpts)

	c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
		"vpn: TUN interface %s up, local=%s mtu=%d", dev.Name(), pushOpts.Ifconfig.Local, tunMTU)})
	return nil
}

// startDataPath marks the tunnel up and starts every goroutine that runs for
// the life of the session.
func (c *Client) startDataPath(pushOpts *routing.PushOptions) {
	loops := []func(context.Context){
		c.tunToWire,
		c.wireToTun,
		// Keepalive: send probes and detect dead links. The loop always runs,
		// as openvpn3's does; what the server pushed goes in raw, and
		// keepaliveFor decides what a zero means — the profile's ping
		// directives, then defaults.
		func(ctx context.Context) { c.keepaliveLoop(ctx, pushOpts.PingInterval, pushOpts.PingRestart) },
		// Key renegotiation loop — initiates SOFT_RESET when keys are due for rotation.
		// Reference: openvpn3-core ssl/proto.hpp ProtoContext::renegotiate() line ~4108.
		c.rekeyLoop,
		c.sessionMonitor,
	}
	// Inactive session timeout: disconnect if traffic falls below the server's threshold.
	if pushOpts.InactiveTimeout > 0 {
		loops = append(loops, func(ctx context.Context) {
			c.inactiveLoop(ctx, pushOpts.InactiveTimeout, pushOpts.InactiveBytes)
		})
	}
	cctx, cancel := context.WithCancel(context.Background())

	// One step under the lock: a teardown that sees stateTunnelUp must also
	// find cancelFn and the goroutines in wg, or it cancels nothing and waits
	// for nothing while they run on.
	c.mu.Lock()
	c.state = stateTunnelUp
	c.connectedAt = time.Now()
	c.cancelFn = cancel
	c.wg.Add(len(loops))
	serverIP := c.backendIP
	assignedIP := ""
	if pushOpts.Ifconfig != nil {
		assignedIP = pushOpts.Ifconfig.Local.String()
	}
	c.mu.Unlock()
	c.recorder().succeed()
	c.emit(Event{
		Type:     EventStateChanged,
		State:    StateConnected,
		ServerIP: serverIP,
		Message:  assignedIP,
	})

	for _, loop := range loops {
		go loop(cctx)
	}
}

// exportDataChannelKeys derives the pushed tls-ekm key block, recording the
// one case where it did not come from crypto/tls. The choice itself is
// prf.ExportDataChannelKeys; what stays here is a report field and a log line.
func (c *Client) exportDataChannelKeys(cs tls.ConnectionState, capture *prf.Capture) ([]byte, error) {
	keys, usedFallback, err := prf.ExportDataChannelKeys(cs, capture)
	if err != nil {
		return nil, err
	}
	if usedFallback {
		c.recordEMSExportFallback()
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
			"vpn: keys: crypto/tls refuses RFC 5705 export from this %s session for want of "+
				"extended master secret; derived the key block from the captured session "+
				"material, as openvpn does", tls.VersionName(cs.Version))})
	}
	return keys, nil
}
