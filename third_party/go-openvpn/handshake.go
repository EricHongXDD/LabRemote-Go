// SPDX-License-Identifier: LGPL-2.1-or-later
//
// handshake.go: the TLS handshake, the control-channel relay and certificates.

package vpn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buengese/go-openvpn/internal/ctls"
	"github.com/buengese/go-openvpn/internal/framing"
	"github.com/buengese/go-openvpn/internal/prf"
	"github.com/buengese/go-openvpn/internal/reliable"
	"github.com/buengese/go-openvpn/internal/tlsverify"
)

// controlSession bundles the reliable-transport state for one TLS key epoch:
// the primary (key_id=0) is created inside tlsHandshake, each rekey epoch gets
// its own over rekeySessionCh. openvpn3-core ssl/proto.hpp calls it a KeyContext.
type controlSession struct {
	keyID      uint8
	transport  *ctls.ControlTransport
	sendQueue  *reliable.SendQueue
	recvWindow *reliable.RecvWindow
	// registered is closed by the inbound relay once this session is in the
	// sessions map and ready to receive inbound P_CONTROL_V1 packets. doRekey
	// waits on it before sending SOFT_RESET, so no race can drop the reply.
	registered chan struct{}
	// peerReset and resetAcked are closed by the inbound relay during a rekey.
	// OpenVPN starts TLS only after the peer's SOFT_RESET and the ACK for our
	// own SOFT_RESET have both arrived.
	peerReset  chan struct{}
	resetAcked chan struct{}
	// finished is set when the renegotiation this session was created for has
	// ended, either way. The session stays in the relay's map afterwards so a
	// retransmitted control packet still has somewhere to go, but it cannot
	// answer a new SOFT_RESET: peerReset is closed and nothing waits on it.
	// Without it the relay cannot tell a live epoch from a spent one, and key_id
	// has only seven usable values before every slot holds a spent session.
	finished atomic.Bool
}

// receiveControl records a reliable control packet and delivers every newly
// in-order payload to the TLS transport. Reset packets carry no TLS payload but
// are still recorded: they consume packet ID 0, so the peer's ID 1 can land.
func (s *controlSession) receiveControl(packetID uint32, payload []byte) {
	payloads, _ := s.recvWindow.Receive(packetID, payload)
	for _, p := range payloads {
		if len(p) > 0 {
			_ = s.transport.InjectInbound(p)
		}
	}
}

// rekeyChans returns the two channels the inbound relay exchanges control
// sessions over: the one new sessions arrive on for a renegotiation this end
// started, and the one the relay hands sessions out on for one the peer started.
//
// reset replaces both between attempts while the previous attempt's relay may
// still be selecting on them — tlsHandshake leaves a raw reader and a relay
// behind and WaitForDisconnect does not join them — so a plain field read is a
// data race the moment a cert-only profile reconnects. A capture under the lock
// is enough: rekeyLoop and doRekey are in the wait group, which leaves one
// unsynchronised reader.
func (c *Client) rekeyChans() (sessions, peer chan *controlSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rekeySessionCh, c.peerRekeyCh
}

// dueRetransmits collects the control packets to resend on this tick, from every
// session that still has a renegotiation to finish. The caller must hold the
// sessions lock.
//
// A spent epoch is skipped. It keeps its map entry so a late inbound packet
// still has somewhere to go — that is what finished means — but its own
// unacknowledged packets are dead, and resending them is a permanent stream of
// SOFT_RESET and TLS packets the server can only log as unroutable.
func dueRetransmits(sessions map[uint8]*controlSession) []*reliable.Entry {
	var due []*reliable.Entry
	for _, sess := range sessions {
		if sess.finished.Load() {
			continue
		}
		due = append(due, sess.sendQueue.DueForRetransmit()...)
	}
	return due
}

// retireSession drops a spent control session for keyID and closes its
// transport, which ends the send goroutine started for it. Both halves matter:
// the map entry makes a spent epoch indistinguishable from a live one, and the
// transport is a goroutine otherwise held for the connection's life. key_id 0 is
// never retired — it is the connection's own control channel, never marked
// finished, and closing it would end the connection.
//
// The caller must hold the sessions lock, and is the inbound relay, which is
// also the only caller of InjectInbound.
func retireSession(sessions map[uint8]*controlSession, keyID uint8) {
	if keyID == 0 {
		return
	}
	old, ok := sessions[keyID]
	if !ok {
		return
	}
	delete(sessions, keyID)
	old.transport.Close()
}

// tlsHandshake performs the TLS client handshake over the OpenVPN control
// channel using reliable.SendQueue/RecvWindow and ctls.ControlTransport. The
// three goroutines it leaves behind — inbound relay, outbound relay, retransmit
// ticker — run for the connection's life and serve every key epoch.
func (c *Client) tlsHandshake(ctx context.Context, rawConn net.Conn) (*tls.Conn, error) {
	tlsCfg, verifier, err := tlsverify.BuildConfig(c.prof)
	if err != nil {
		return nil, err
	}
	// The capture has to be in place before the handshake it captures, and
	// whether it is needed is not known until the PUSH_REPLY several stages
	// later; deriveDataKeys empties it either way. A previous one is emptied
	// rather than dropped: the AWS flow reaches this a second time.
	capture := prf.NewCapture(tlsCfg)
	c.installTLSSecrets(capture)

	// Primary controlSession for key_id=0.
	// recvExp is already set by the caller (HARD_RESET exchange).
	// sendSeq=1 because the HARD_RESET used packet_id=0.
	primSess := &controlSession{
		keyID:      0,
		transport:  ctls.NewControlTransport(nil, nil, 64),
		sendQueue:  reliable.NewSendQueue(c.sendSeq),
		recvWindow: reliable.NewRecvWindowFrom(c.recvExp),
	}

	// sessions maps key_id → active controlSession; protected by sessionsMu.
	var sessionsMu sync.Mutex
	sessions := map[uint8]*controlSession{0: primSess}

	// Resolve the control-channel MTU budget once, before any session starts:
	// the wrap is fixed for the connection, so the budget is too.
	maxSeg := c.controlSegmentSize()

	// startSendGoroutine spawns a goroutine that drains one session's outbound
	// TLS bytes, fragments into segments of at most maxSeg bytes and writes to
	// rawConn. Each session gets its own, so rekey sessions are independent.
	startSendGoroutine := func(sess *controlSession) {
		go func() {
			for {
				chunk, err := sess.transport.DrainOutbound()
				if err != nil {
					return
				}
				for len(chunk) > 0 {
					seg := chunk
					if len(seg) > maxSeg {
						seg = chunk[:maxSeg]
					}
					chunk = chunk[len(seg):]
					nextID := sess.sendQueue.NextID()
					wire := framing.BuildControlV1(c.clientSID, c.serverSID, sess.keyID, nextID, nil, seg)
					sess.sendQueue.Enqueue(wire) //nolint:errcheck
					c.writePacket(rawConn, wire) //nolint:errcheck
				}
			}
		}()
	}
	startSendGoroutine(primSess)

	// Keep reads in their own goroutine so the dispatcher can register a rekey
	// session immediately: a dispatcher blocked on network input cannot see a
	// rekeySessionCh notification, and a peer's SOFT_RESET is dropped.
	type inboundPacket struct {
		pkt []byte
		err error
	}
	packets := make(chan inboundPacket, 1)
	relayDone := make(chan struct{})
	go func() {
		defer close(packets)
		for {
			pkt, err := c.readPacket(rawConn)
			select {
			case packets <- inboundPacket{pkt: pkt, err: err}:
			case <-relayDone:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	// Captured once, here, rather than read from the fields on every loop of
	// the relay below: see rekeyChans. A Reconnect replaces them while this
	// connection's relay is still draining.
	rekeyCh, peerRekeyCh := c.rekeyChans()

	// The session ids, for the same reason: both were fixed before this handshake
	// was called, but the next attempt zeroes them under the lock while this
	// relay may still be draining.
	relayClientSID, relayServerSID := c.sessionIDs()

	// inbound relay dispatches packets from the raw-reader and registers every
	// new control session before its SOFT_RESET is sent.
	go func() {
		defer close(relayDone)
		defer primSess.transport.Close()
		// Same reason as rekeyCh above, one step later: the connect path
		// installs dataCh after this goroutine is already running, so it is
		// claimed on the first data packet instead of here.
		var dataCh chan []byte
		for {
			select {
			case sess := <-rekeyCh:
				if sess == nil {
					continue
				}
				sessionsMu.Lock()
				retireSession(sessions, sess.keyID)
				sessions[sess.keyID] = sess
				sessionsMu.Unlock()
				startSendGoroutine(sess)
				close(sess.registered) // unblock doRekey; SOFT_RESET is sent after this

			case inbound, ok := <-packets:
				if !ok || inbound.err != nil {
					// Close secondary transports so their TLS handshakes unblock.
					sessionsMu.Lock()
					for kid, sess := range sessions {
						if kid != 0 {
							sess.transport.Close()
						}
					}
					sessionsMu.Unlock()
					return
				}
				pkt := inbound.pkt
				if len(pkt) < 1 {
					continue
				}
				op := pkt[0] >> 3
				keyID := pkt[0] & 0x07

				// A control packet has to name the session it belongs to.
				// The reference matches every inbound control packet's
				// source session id against the peer id it recorded and
				// drops what matches nothing as an "Unroutable control
				// packet" (openvpn-2.6.22 src/openvpn/ssl.c:3777,:3860-3868);
				// where the packet echoes ours back, that has to be ours
				// too (reliable.c:159-168). On a bare control channel this
				// is the only thing between us and a forged packet from
				// anyone who can guess the four-tuple.
				if isControlOpcode(op) && !controlPacketIsOurs(pkt, relayClientSID, relayServerSID) {
					c.countControlDrop(errForeignSession)
					continue
				}

				switch op {
				case framing.P_DATA_V1, framing.P_DATA_V2:
					// Both data opcodes, because the format is the peer's
					// choice and this switch runs before the manager can
					// object. Which one is expected is checked where the key
					// epoch is selected; dropping the other here would look
					// exactly like a network fault.
					//
					// dataCh is installed after this goroutine starts, so it
					// is asked for until there is one and then kept; nothing
					// closes it, so it stays safe to send on. pkt is ours:
					// the reader allocates each packet.
					if dataCh == nil {
						dataCh = c.dataChannel()
					}
					if dataCh != nil {
						select {
						case dataCh <- pkt:
						default:
						}
					}

				case framing.P_CONTROL_V1:
					payload, packetID := framing.ParseControlV1Payload(pkt)

					sessionsMu.Lock()
					sess, ok := sessions[keyID]
					sessionsMu.Unlock()
					if !ok {
						break
					}
					// Acknowledge only what the window can hold: beyond it
					// an ACK claims receipt of what we dropped. Re-acking a
					// delivered packet is deliberate — see ShouldAck.
					if sess.recvWindow.ShouldAck(packetID) {
						ack := framing.BuildAck(c.clientSID, c.serverSID, keyID, []uint32{packetID})
						c.writePacket(rawConn, ack) //nolint:errcheck
					}
					// A P_CONTROL_V1 packet can carry ACKs as well as TLS
					// payload, and they are not advisory: OpenVPN makes a
					// rekeyed key context ACTIVE only once our auth packet is
					// acknowledged.
					sess.sendQueue.AckMany(framing.ParseControlV1AckIDs(pkt))
					sess.receiveControl(packetID, payload)

				case framing.P_CONTROL_SOFT_RESET_V1:
					// A rekey is a reset exchange, not TLS data. Acknowledge the
					// peer's reset and record it so doRekey starts TLS only once
					// both sides have completed the reliable reset handshake.
					_, packetID := framing.ParseControlV1Payload(pkt)
					ack := framing.BuildAck(c.clientSID, c.serverSID, keyID, []uint32{packetID})
					c.writePacket(rawConn, ack) //nolint:errcheck

					sessionsMu.Lock()
					sess, known := sessions[keyID]
					if known && sess.finished.Load() {
						// Its renegotiation is over: peerReset is closed and
						// nothing waits on it, so handing this reset here would
						// drop the server's renegotiation. Reaching it means all
						// seven usable key_id values have come round.
						retireSession(sessions, keyID)
						sess, known = nil, false
					}
					adopted := false
					if !known {
						// The server started this renegotiation; nothing on
						// this side chose its key_id. The session is built here
						// because the peer's reset is in hand: anywhere else it
						// would need a second channel to reach this packet.
						if sess = c.newPeerRekeySession(keyID); sess != nil {
							sessions[keyID] = sess
							startSendGoroutine(sess)
							close(sess.registered)
							adopted = true
						}
					}
					sessionsMu.Unlock()
					if sess == nil || sess.peerReset == nil {
						break
					}
					// The reset is packet ID 0 in this key epoch. Advance the
					// receive window before TLS starts, or the server's first TLS
					// control packet (ID 1) stays buffered forever.
					sess.receiveControl(packetID, nil)
					for _, id := range framing.ParseControlV1AckIDs(pkt) {
						sess.sendQueue.Ack(id)
						if id == 0 && sess.resetAcked != nil {
							select {
							case <-sess.resetAcked:
							default:
								close(sess.resetAcked)
							}
						}
					}
					select {
					case <-sess.peerReset:
					default:
						close(sess.peerReset)
					}
					if adopted {
						// Hand it over only now: rekeyLoop starts by waiting
						// for the reset exchange, satisfied just above. Never
						// block — this goroutine is the socket's only reader,
						// and must not stall the data channel.
						select {
						case peerRekeyCh <- sess:
						default:
							c.rekeyActive.Store(false)
							c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
								"vpn: dropped a server-initiated rekey (key_id=%d): one is already in flight", keyID)})
						}
					}

				case framing.P_ACK_V1:
					if len(pkt) < 11 {
						break
					}
					nAcks := int(pkt[9])
					off := 10
					sessionsMu.Lock()
					sess, ok := sessions[keyID]
					sessionsMu.Unlock()
					if !ok {
						break
					}
					for i := 0; i < nAcks && off+4 <= len(pkt); i++ {
						id := binary.BigEndian.Uint32(pkt[off:])
						off += 4
						sess.sendQueue.Ack(id)
						if id == 0 && sess.resetAcked != nil {
							select {
							case <-sess.resetAcked:
							default:
								close(sess.resetAcked)
							}
						}
					}
				}
			}
		}
	}()

	// retransmit goroutine: polls all sessions once per second for unACKed packets
	// past their NextRetry deadline. Runs for the connection lifetime.
	primClosed := primSess.transport.ClosedChan()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-primClosed:
				return
			case <-ticker.C:
				sessionsMu.Lock()
				allDue := dueRetransmits(sessions)
				sessionsMu.Unlock()
				c.stats().retransmits.Add(uint64(len(allDue)))
				for _, e := range allDue {
					c.writePacket(rawConn, e.Payload) //nolint:errcheck
				}
			}
		}
	}()

	tlsConn := tls.Client(capture.Wrap(primSess.transport), tlsCfg)
	// hand-window bounds the key exchange here as it does for a renegotiation,
	// and through the same keyExchangeDeadline.
	tlsConn.SetDeadline(c.keyExchangeDeadline(ctx)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		primSess.transport.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck
	c.logRemoteCertificate(tlsConn.ConnectionState(), tlsCfg.ServerName, verifier.OK())

	return tlsConn, nil
}

// ---- Certificate verification --------------------------------------------
//
// logRemoteCertificate's only caller is a few lines above.

// The sentinel is exported API — consumers compare against it with errors.Is and
// gomobile binds it — so the name lives in the root package while the check that
// returns it lives in internal/tlsverify. Aliasing keeps it one value.

// ErrNoUsableCA is returned for a profile that carries no certificate authority
// the server can be verified against. It is a configuration fault, not a TLS
// fault: knowable before a socket opens, and refused at the StageParse boundary
// so that no unverified tunnel is ever built.
var ErrNoUsableCA = tlsverify.ErrNoUsableCA

// logRemoteCertificate emits certificate details only at OpenVPN's debug
// verbosity (verb 4 or greater), and only after the handshake, so the shown
// certificate is the control channel's. verified comes from tlsverify.Verifier
// rather than state.VerifiedChains, which crypto/tls leaves empty under
// InsecureSkipVerify.
func (c *Client) logRemoteCertificate(state tls.ConnectionState, serverName string, verified bool) {
	if c.prof.Verb < 4 || len(state.PeerCertificates) == 0 {
		return
	}

	cert := state.PeerCertificates[0]
	verification := "not verified"
	if verified {
		verification = "verified"
	}
	c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
		"vpn: TLS server certificate (%s for %q):\nsubject=%s\nissuer=%s\nserial=%s\nnotBefore=%s\nnotAfter=%s\nX509v3 Subject Alternative Name:\n    %s\nsha256 Fingerprint=%s",
		verification, serverName, tlsverify.SubjectDN(cert), tlsverify.IssuerDN(cert),
		tlsverify.SerialNumber(cert), tlsverify.FormatTime(cert.NotBefore), tlsverify.FormatTime(cert.NotAfter),
		tlsverify.FormatSANs(cert), tlsverify.Fingerprint(cert.Raw),
	)})
}
