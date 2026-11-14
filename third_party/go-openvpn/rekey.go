// SPDX-License-Identifier: LGPL-2.1-or-later
//
// rekey.go: the rekey engine.

package vpn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/ctls"
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/internal/framing"
	"github.com/buengese/go-openvpn/internal/keymethod2"
	"github.com/buengese/go-openvpn/internal/prf"
	"github.com/buengese/go-openvpn/internal/reliable"
	"github.com/buengese/go-openvpn/internal/tlsverify"
	"github.com/buengese/go-openvpn/routing"
)

// rekeyLoop monitors the data-channel key epoch and initiates renegotiation
// when manager.NeedsRekey() returns true.
//
// Renegotiation protocol (client-initiated):
//  1. Allocate the next key_id (cycles 1-7, skipping 0 which is the initial key).
//  2. Register a new control session with the relay so inbound packets for the
//     new key_id are accepted before the reset is sent.
//  3. Exchange and ACK P_CONTROL_SOFT_RESET_V1 packets with the server.
//  4. Perform a new TLS handshake through the registered transport.
//  5. Exchange auth packets using the active authentication credentials.
//  6. Export new keying material (same EKM label) and build a new Channel.
//  7. Keep the old and new channels active during the promotion window, then
//     promote the new channel for outgoing packets.
//
// Reference: openvpn3-core ssl/proto.hpp ProtoContext::renegotiate() line ~4108:
//
//	new_secondary_key(true);  // initiator=true
//	secondary->start();       // sends SOFT_RESET, starts new TLS session
//
// KeyContext::init_data_channel() (ssl/proto.hpp:2755) then derives the keys.
func (c *Client) rekeyLoop(ctx context.Context) {
	defer c.wg.Done()

	// Poll every 30 seconds — frequent enough to catch a 3600s limit without
	// burning CPU.  openvpn3-core checks in housekeeping() which runs ~1/s.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case sess := <-c.peerRekeyCh:
			// A renegotiation the server started. The relay has already built
			// the session, registered it, claimed rekeyActive and satisfied
			// the peer's half of the reset exchange; ours is what is left.
			c.runRekey(func() error { return c.answerRekey(ctx, sess) })

		case <-ticker.C:
			if !c.manager.NeedsRekey() {
				continue
			}
			if !c.rekeyActive.CompareAndSwap(false, true) {
				// A server-initiated renegotiation is in flight. It rotates
				// this epoch's keys exactly as ours would, so a second exchange
				// would only contend for the key_id.
				continue
			}
			c.runRekey(func() error { return c.doRekey(ctx) })
		}
	}
}

// runRekey runs one renegotiation, in either direction, and owns what the two
// have in common: the stage boundary, the counter, and what a failure is
// reported as. A renegotiation is not allowed to end the session — openvpn3-core
// schedules a retry and so do we, by leaving the old key installed for the next
// tick, and the report notes the failure without failing the attempt.
//
// The caller must already hold the rekeyActive claim; releasing it here gives
// rekeyLoop's ticker and newPeerRekeySession one release between them.
func (c *Client) runRekey(run func() error) {
	defer c.rekeyActive.Store(false)

	c.enterStage(diag.StageRekey)
	if err := run(); err != nil {
		c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: rekey failed: %v", err)})
		c.recorder().note(diag.StageRekey, diag.Wrap(diag.ClassCrypto, diag.StageRekey, err, "rekey"))
		// The session survived it, so nothing else will ever mention it.
		c.noteTransient(err)
		return
	}
	c.stats().rekeys.Add(1)
	c.completeStage(diag.StageRekey)
}

// newPeerRekeySession builds the control session for a renegotiation the server
// started, or returns nil when this client will not take one on. It runs on the
// inbound relay goroutine, which is holding the peer's SOFT_RESET and has to
// know whether a session will exist to receive it. On success it claims
// rekeyActive; runRekey releases the claim, or the relay does.
func (c *Client) newPeerRekeySession(keyID uint8) *controlSession {
	// A renegotiation before there is a key epoch to rotate is not one. The
	// state is read under the lock rather than by testing c.manager, which is
	// published without one.
	c.mu.Lock()
	up := c.state == stateTunnelUp
	c.mu.Unlock()
	if !up {
		return nil
	}

	if !c.rekeyActive.CompareAndSwap(false, true) {
		// Our own renegotiation is in flight under a key_id we chose and the
		// server has chosen a different one — the collision this flag exists to
		// survive. This reset goes unanswered rather than racing for the slot.
		return nil
	}

	// Adopt the server's choice. next_key_id is ours to allocate from, so
	// leaving it behind would let the next client-initiated renegotiation pick
	// the key_id this epoch is about to occupy.
	c.mu.Lock()
	c.advanceKeyIDLocked(keyID)
	c.mu.Unlock()

	c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
		"vpn: server initiated key renegotiation (key_id=%d)", keyID)})

	return newControlSession(keyID)
}

// advanceKeyIDLocked moves next_key_id past keyID, cycling 1-7 and skipping 0,
// which belongs to the initial session for the life of the connection. c.mu
// must be held.
//
// Both directions allocate from the same counter, which is why this is written
// in terms of the id consumed rather than of who consumed it.
//
// Reference: openvpn3-core ssl/proto.hpp ProtoContext::next_key_id() line ~4740:
//
//	if ((upcoming_key_id = (upcoming_key_id+1) & KEY_ID_MASK) == 0) upcoming_key_id = 1;
func (c *Client) advanceKeyIDLocked(keyID uint8) {
	next := (keyID + 1) & 0x07
	if next == 0 {
		next = 1
	}
	c.nextKeyID = next
}

// newControlSession builds the control session one key epoch runs on: its own
// send queue and receive window, its own TLS transport, and the three one-shot
// channels the reset handshake and the relay signal each other over. Sequence
// numbers restart at 0 per epoch, so a session cannot be reused.
func newControlSession(keyID uint8) *controlSession {
	return &controlSession{
		keyID:      keyID,
		transport:  ctls.NewControlTransport(nil, nil, 64),
		sendQueue:  reliable.NewSendQueue(0),
		recvWindow: reliable.NewRecvWindow(),
		registered: make(chan struct{}),
		peerReset:  make(chan struct{}),
		resetAcked: make(chan struct{}),
	}
}

// answerRekey completes a renegotiation the server started: doRekey's cycle
// without choosing a key_id or registering the session, both of which the relay
// did. It still sends this end's own SOFT_RESET, and that is not a courtesy —
// the reliable send queue starts at packet ID 0 and the peer expects the epoch's
// first packet to be the reset, so our first TLS record would otherwise be read
// as one (src/openvpn/ssl.c sends KEY_STATE_SEND_RESET from S_INITIAL at either
// end).
func (c *Client) answerRekey(ctx context.Context, rekey *controlSession) error {
	c.mu.Lock()
	rawConn := c.rawConn
	c.mu.Unlock()
	if rawConn == nil {
		rekey.transport.Close()
		return fmt.Errorf("no active connection")
	}

	return c.openRekeyEpoch(ctx, rawConn, rekey)
}

// openRekeyEpoch sends this end's SOFT_RESET — the first packet of the new key
// epoch, through the reliable queue — and carries the renegotiation on. Both
// directions send one, and the peer's ACK must arrive before either side starts
// TLS, which is what finishRekey waits for.
//
// The reset is both enqueued and written, and both halves are load-bearing.
// Enqueued but not written, it waits for the retransmit ticker and arrives one
// full RetransmitTimeout late; written but not enqueued, finishRekey has no
// ACK to wait for. Either way the renegotiation times out at the hand-window
// with nothing in the log to say which half was missing.
//
// Reference: openvpn3-core ssl/proto.hpp KeyContext::send_reset() (:3485),
// which sends initial_op() — CONTROL_SOFT_RESET_V1 when key_id_ != 0.
func (c *Client) openRekeyEpoch(ctx context.Context, rawConn net.Conn, rekey *controlSession) error {
	softReset := framing.BuildSoftReset(c.clientSID, rekey.keyID)
	if _, err := rekey.sendQueue.Enqueue(softReset); err != nil {
		rekey.transport.Close()
		return fmt.Errorf("queue SOFT_RESET: %w", err)
	}
	if err := c.writePacket(rawConn, softReset); err != nil {
		rekey.transport.Close()
		return fmt.Errorf("send SOFT_RESET: %w", err)
	}

	return c.finishRekey(ctx, rekey, c.keyExchangeDeadline(ctx))
}

// keyExchangeDeadline bounds one key exchange's control-channel work: the
// initial handshake and every renegotiation alike, which is what hand-window
// means. A caller's own deadline still wins when it is the tighter of the two.
func (c *Client) keyExchangeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(c.handWindow())
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
}

// handWindow is how long a key exchange is given to finish: the profile's
// hand-window, or the reference's 60 seconds. ssl.c:2590 sets must_negotiate
// from it; ssl.c:2916-2920 reports "TLS key negotiation failed to occur".
func (c *Client) handWindow() time.Duration {
	handWindow := c.prof.HandWindowSec
	if handWindow <= 0 {
		handWindow = defaultHandWindowSec
	}
	return time.Duration(handWindow) * time.Second
}

// doRekey performs a single client-initiated key renegotiation cycle, called
// from rekeyLoop when manager.NeedsRekey() is true. answerRekey is the same
// cycle in the other direction; only the key_id choice and the registration
// differ, and everything from the reset onwards is openRekeyEpoch.
func (c *Client) doRekey(ctx context.Context) error {
	c.mu.Lock()
	keyID := c.nextKeyID
	c.advanceKeyIDLocked(keyID)
	rawConn := c.rawConn
	c.mu.Unlock()

	if rawConn == nil {
		return fmt.Errorf("no active connection")
	}

	c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: initiating key renegotiation (key_id=%d)", keyID)})

	rekey := newControlSession(keyID)

	// Hand the new session to the inbound relay and wait for it to confirm
	// registration before sending SOFT_RESET. Without this barrier the relay may
	// still be blocked in readPacket when the server's reply arrives, and the
	// reply is dropped for an unknown key_id.
	select {
	case c.rekeySessionCh <- rekey:
	case <-ctx.Done():
		rekey.transport.Close()
		return ctx.Err()
	}
	select {
	case <-rekey.registered:
	case <-ctx.Done():
		rekey.transport.Close()
		return ctx.Err()
	}

	return c.openRekeyEpoch(ctx, rawConn, rekey)
}

// finishRekey carries a renegotiation from the reset exchange through to a
// prepared data-channel key, for both directions. keyID comes from the session,
// which is the one place that knows which direction chose it.
func (c *Client) finishRekey(ctx context.Context, rekey *controlSession, deadline time.Time) error {
	keyID := rekey.keyID
	// However this ends, the session has had its renegotiation. The relay
	// reads this to decide whether a later SOFT_RESET for the same key_id can
	// be answered by it or needs a session of its own.
	defer rekey.finished.Store(true)

	// The control channel is a reliable state machine: neither side starts TLS
	// before the reset exchange completes, or both wait out the deadline. For a
	// server-initiated renegotiation the relay closed peerReset as it handed the
	// session over, so only our own reset's ACK is outstanding.
	if err := waitForRekeyReset(ctx, rekey, deadline); err != nil {
		rekey.transport.Close()
		return err
	}

	tlsCfg, _, err := tlsverify.BuildConfig(c.prof)
	if err != nil {
		rekey.transport.Close()
		return fmt.Errorf("build TLS config: %w", err)
	}

	// A server that refused the RFC 5705 export once refuses it again — the same
	// server negotiating the same TLS 1.2 without EMS — so this epoch needs its
	// own capture, or the tunnel dies at its first key rotation.
	rekeyCapture := prf.NewCapture(tlsCfg)
	defer rekeyCapture.Wipe()

	rekeyTLS := tls.Client(rekeyCapture.Wrap(rekey.transport), tlsCfg)
	rekeyTLS.SetDeadline(deadline) //nolint:errcheck
	if err := rekeyTLS.Handshake(); err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey TLS handshake: %w", err)
	}

	// Auth packet exchange: the server expects the same key-method-2 format, and
	// a renegotiation is a fresh authentication event, so reuse the active
	// credential (or the server-issued auth-token) rather than empty fields —
	// openvpn3 ssl/proto.hpp KeyContext::send_auth does so for every rekey.
	creds, err := c.authCredentials(ctx, authRekey)
	if err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey credentials: %w", err)
	}
	// A rekey re-sends the options string, and the cipher suite is settled for
	// the connection by then, so it advertises what is actually in use rather
	// than what the profile asked for.
	c.mu.Lock()
	rekeyParams := c.dataParams
	c.mu.Unlock()
	// A rekey runs a fresh key-method-2 exchange, so this epoch derives from this
	// epoch's randoms. They stay local: c.keySource is the initial epoch's
	// contribution, already consumed by deriveDataKeys, and no rekey reads it.
	rekeyKeySource, err := keymethod2.SendAuth(rekeyTLS, tunnelParams(c.activeProto(), c.prof.TunMTU, rekeyParams), creds.Username, creds.Password, c.method().framing(), ivProtoFor(c.DataV2))
	if err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey send auth: %w", err)
	}
	rekeyServerKeySource, serverOpts, err := keymethod2.ConsumeServerAuth(rekeyTLS)
	c.recordServerOpts(serverOpts)
	if err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey read server auth: %w", err)
	}
	// Receiving the server's auth message is only half of activation: the peer
	// must also ACK the control packets that carried ours, which is why
	// openvpn3-core reaches ACTIVE only on an empty send queue. Otherwise a
	// server can install its secondary key while treating this client as unready.
	if err := waitForControlAcks(ctx, rekey, deadline); err != nil {
		rekeyTLS.Close()
		return err
	}
	rekeyTLS.SetDeadline(time.Time{}) //nolint:errcheck

	// Derive new data-channel keys by the same method and code as the initial
	// session: deriveKeyBlock is the one copy of the switch, and this epoch's TLS
	// session, capture and key sources make the result this epoch's. Reference:
	// openvpn3-core ssl/proto.hpp generate_datachannel_keys() (:2638).
	c.mu.Lock()
	keyDeriv := routing.KeyDerivationTLSEKM
	if c.pushOpts != nil {
		keyDeriv = c.pushOpts.KeyDerivation
	}
	c.mu.Unlock()
	params := rekeyParams
	rekeyMat, err := c.deriveKeyBlock(
		keyDeriv, rekeyTLS, rekeyCapture, rekeyKeySource, rekeyServerKeySource)
	if err != nil {
		rekeyTLS.Close()
		// A renegotiation that cannot derive is not a failed session: runRekey
		// records it against this rekey and the old key stays installed.
		return fmt.Errorf("rekey: %w", err)
	}

	// Re-use the peer-id from the original PUSH_REPLY: openvpn3-core scopes
	// remote_peer_id to the connection, not the key epoch. The cipher suite is
	// connection-scoped too, so this epoch uses the first's params.
	newCh, err := params.NewChannel(c.peerID, keyID, rekeyMat)
	if err != nil {
		rekeyTLS.Close()
		return fmt.Errorf("rekey new channel: %w", err)
	}

	// OpenVPN keeps the original key primary while the new one is secondary, so
	// the peer can go on sending old-key packets. Reference: openvpn3-core
	// ssl/proto.hpp process_secondary_event() and promote_secondary_to_primary().
	manager := c.manager
	promotionDelay := c.rekeyPromotionDelay()
	manager.Prepare(newCh)
	c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: rekey ready (key_id=%d, promotion in %s)", keyID, promotionDelay)})
	c.scheduleRekeyPromotion(ctx, manager, keyID, promotionDelay)

	// Update the stored TLS connection for future EKM exports (if needed).
	c.mu.Lock()
	c.tlsConn = rekeyTLS
	c.mu.Unlock()

	return nil
}

// defaultHandWindowSec is the reference's hand-window when a profile does not
// set one — openvpn-2.6.22 src/openvpn/options.c:880, and openvpn3
// ssl/proto.hpp:505, which agree on it.
const defaultHandWindowSec = 60

// rekeyPromotionDelay is openvpn3's become-primary calculation:
// min(hand-window, reneg-sec / 2), from ssl/proto.hpp:1268-1270. An explicit
// become-primary directive overrides it.
func (c *Client) rekeyPromotionDelay() time.Duration {
	if c.prof.BecomePrimarySec > 0 {
		return time.Duration(c.prof.BecomePrimarySec) * time.Second
	}
	// reneg-sec 0 disables the client's own renegotiation timer, which is how the
	// key manager reads it. It leaves no interval to halve, so the default stands
	// in; the cap below reduces that to the hand-window either way.
	renegSec := c.prof.RenegSec
	if renegSec == 0 {
		renegSec = datachannel.DefaultRenegSec
	}
	delay := time.Duration(renegSec/2) * time.Second
	if handWindow := c.handWindow(); delay > handWindow {
		delay = handWindow
	}
	return delay
}

// scheduleRekeyPromotion promotes the prepared data-channel key after its
// configured transition interval. The connection context cancels this timer
// on teardown.
func (c *Client) scheduleRekeyPromotion(ctx context.Context, manager *datachannel.Manager, keyID uint8, delay time.Duration) {
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if manager.Promote(keyID) {
				c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: rekey complete (key_id=%d)", keyID)})
			}
		}
	}()
}

// waitForRekeyReset waits for the reliable SOFT_RESET exchange to complete.
// Both notifications are required: peerReset means we have acknowledged the
// server's reset, and resetAcked means the server acknowledged ours.
func waitForRekeyReset(ctx context.Context, sess *controlSession, deadline time.Time) error {
	peerReset := sess.peerReset
	resetAcked := sess.resetAcked
	gotPeerReset := false
	gotResetAck := false
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	for peerReset != nil || resetAcked != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("rekey reset exchange: deadline exceeded (peer reset received=%t, local reset acknowledged=%t)", gotPeerReset, gotResetAck)
		case <-peerReset:
			peerReset = nil
			gotPeerReset = true
		case <-resetAcked:
			resetAcked = nil
			gotResetAck = true
		}
	}
	return nil
}

// waitForControlAcks waits until the peer has ACKed every reliably sent control
// packet in sess, the key-method-2 auth packet after a rekey TLS handshake
// included. ACKs are standalone P_ACK_V1 or piggybacked on P_CONTROL_V1.
func waitForControlAcks(ctx context.Context, sess *controlSession, deadline time.Time) error {
	if sess.sendQueue.Len() == 0 {
		return nil
	}

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return fmt.Errorf("rekey auth acknowledgement: deadline exceeded (%d control packets unacknowledged)", sess.sendQueue.Len())
		case <-ticker.C:
			if sess.sendQueue.Len() == 0 {
				return nil
			}
		}
	}
}
