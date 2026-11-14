// SPDX-License-Identifier: LGPL-2.1-or-later
//
// datapath.go: the data path and the monitors that watch it.

package vpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/internal/control"
	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/internal/mssfix"
	"github.com/buengese/go-openvpn/internal/occ"
	"github.com/buengese/go-openvpn/profile"
)

// endSession records why an established session ended and starts the teardown
// — unless the context says a teardown is already under way, in which case it
// records nothing and does nothing. It is the only way a running session ends.
//
// A goroutine that notices its context is cancelled has observed a deliberate
// teardown, not a failure: Disconnect cancels the context and closes the
// socket underneath every loop that holds it. The rule is keyed on the context
// and never on the error, because the transport sites fail with "use of closed
// network connection" on a clean close and a genuine mid-session transport
// failure produces that same text with the context still alive.
//
// err is what WaitForDisconnect hands back and what the outcome is classified
// from; noteSessionFailure leaves an outcome already recorded standing.
func (c *Client) endSession(ctx context.Context, err error) {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return
	}
	c.noteSessionFailure(err)
	c.mu.Lock()
	if c.doneErr == nil {
		c.doneErr = err
	}
	c.mu.Unlock()
	c.disconnect(true) //nolint:errcheck
}

// tunToWire reads plaintext IP packets from the TUN device, encrypts them, and
// writes data packets — P_DATA_V2, or P_DATA_V1 against a server that pushed no
// peer-id — to the raw connection.
func (c *Client) tunToWire(ctx context.Context) {
	defer c.wg.Done()
	// Taken once: the device is published before these goroutines start and
	// cleared only after wg.Wait sees them exit, so it cannot change underneath
	// the loop and does not need the lock on every packet.
	dev := c.TunnelDevice()
	if dev == nil {
		return
	}
	st, sent := c.stats(), false
	buf := make([]byte, 65535)
	for {
		// ReadPacket ends with ctx; a backend that needs a read deadline of its
		// own keeps one.
		n, err := dev.ReadPacket(ctx, buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: tunToWire: TUN read error: %v", err)})
			return
		}
		plain := buf[:n]
		c.clampMSS(plain)
		wire, err := c.manager.Encrypt(plain)
		if err != nil {
			if errors.Is(err, datachannel.ErrPacketIDExhausted) {
				// Every later packet fails the same way, so continuing leaves
				// a tunnel that reports itself up and carries nothing.
				// NeedsRekey asks for a key 16M packets earlier.
				c.endSession(ctx, c.failStage(diag.ClassCrypto, diag.StageData, err,
					"data key ran out of packet ids and was not renegotiated"))
				return
			}
			continue
		}
		if werr := c.writePacket(c.rawConn, wire); werr != nil {
			// The socket is gone: either it died under a live session, or a
			// deliberate Disconnect closed it while this write was in flight.
			// endSession is where those two are told apart.
			c.endSession(ctx, fmt.Errorf("vpn: tunToWire: write error: %w", werr))
			return
		}
		st.tx.bytes.Add(uint64(n))
		st.tx.packets.Add(1)
		if !sent {
			sent = true
			c.markDataFlow(st, true)
		}
	}
}

// clampMSS applies the MSS allowance this connection settled on, which is one
// number however it was derived: Clamp takes the IPv6 difference off itself.
func (c *Client) clampMSS(pkt []byte) {
	mssfix.Clamp(pkt, c.mssFix)
}

// exitNotifyCopies returns how many exit notifications this teardown should
// put on the wire. Zero means send nothing, and three things have to hold for
// it to be anything else.
//
//   - The teardown is deliberate. A session that ended because the transport
//     died has nothing left to send down, and attempting the write is how a
//     clean teardown acquires an error that never happened.
//   - The transport is UDP. A TCP session ends when the socket closes, which
//     the peer sees without being told, and stock openvpn refuses to start
//     with the combination at all (2.4.12 options.c line 2181).
//   - The profile asked for it. The count is the directive's optional
//     argument, and 0 covers both the absent directive and an explicit
//     "explicit-exit-notify 0", which openvpn also treats as "send none"
//     (sig.c line 355).
func (c *Client) exitNotifyCopies(deliberate bool) int {
	if !deliberate || c.prof == nil || c.activeProto() != profile.ProtoUDP {
		return 0
	}
	if c.prof.ExplicitExitNotify <= 0 {
		return 0
	}
	return c.prof.ExplicitExitNotify
}

// sendExitNotify tells the peer this client is leaving, so the server frees
// the session now rather than holding it until its own keepalive timeout
// expires; an endpoint left holding a dead session per attempt starts
// rate-limiting the next one.
//
// The message goes out on the data channel, encrypted under the current key
// like any other data packet: the control-channel form needs
// IV_PROTO_CC_EXIT_NOTIFY (1<<7), which this client does not advertise because
// it does not implement it (see peerInfo). Copies are encrypted separately
// rather than encrypted once and written twice — identical wire bytes are a
// replay, and the peer's replay window drops every copy after the first.
//
// Wire format, from OpenVPN 2.4.12 src/openvpn/occ.c
// check_send_occ_msg_dowork() — buf_write of occ_magic at line 227,
// buf_write_u8(OCC_EXIT) at line 333, encrypt_sign() at line 348. That is 17
// plaintext bytes:
//
//	occ_magic (16 bytes) || OCC_EXIT (0x06)
//
// encrypt_sign is the ordinary outgoing data path, so the compression framing
// applies exactly as Manager.Encrypt applies it here. The copies leave back to
// back; 2.4's one-second spacing is the granularity of the coarse timer it
// hangs the retry off (sig.c line 340, drained at line 348). There is no write
// deadline, unlike keepaliveLoop, because this path only ever runs on UDP, and
// errors are dropped: nothing acknowledges the message and the session is
// going away whatever happens to it.
func (c *Client) sendExitNotify(copies int) {
	mgr, conn := c.manager, c.rawConn
	if mgr == nil || conn == nil {
		return
	}

	msg := occ.ExitMessage()

	sent := 0
	for range copies {
		wire, err := mgr.Encrypt(msg)
		if err != nil {
			break
		}
		if err := c.writePacket(conn, wire); err != nil {
			break
		}
		sent++
	}

	c.emit(Event{Type: EventLog, Message: fmt.Sprintf(
		"vpn: explicit-exit-notify: sent %d of %d exit notification(s)", sent, copies)})
}

// failCompressedPayload ends the session because the peer compressed a payload
// with an algorithm this client cannot decompress. It is ClassUnsupported at
// StageData, and Feature names the directive that selected the algorithm.
func (c *Client) failCompressedPayload(ctx context.Context, cause *compress.CompressedPayloadError) {
	feature := cause.Mode.String() + " (" + cause.Algorithm + ")"
	// Recorded rather than returned — the only caller is a data-path goroutine
	// with nowhere to hand an error — and recorded before the teardown, because
	// the first failure recorded wins the outcome.
	c.failUnsupported(diag.StageData, feature, //nolint:errcheck
		"the peer compressed a data-channel payload with a codec this client lacks: "+cause.Error())
	c.emit(Event{Type: EventLog, Message: "vpn: " + cause.Error()})
	c.endSession(ctx, fmt.Errorf("vpn: wireToTun: %w", cause))
}

// wireToTun reads data packets — P_DATA_V2 or P_DATA_V1, whichever the session
// settled on — from dataCh (fed by the relay goroutine inside tlsHandshake,
// which is the sole reader of rawConn), decrypts them, and writes the plaintext
// IP packets to the TUN device.
//
// Keepalive magic packets are recognised and discarded (not forwarded to TUN).
// Each successfully decrypted packet, keepalives included, counts as received
// for the ping-restart dead-link timer.
func (c *Client) wireToTun(ctx context.Context) {
	defer c.wg.Done()
	// See tunToWire: taken once, for the same reason.
	dev := c.TunnelDevice()
	if dev == nil {
		return
	}
	// Captured once: this starts after the connect path installed the channel,
	// and a Reconnect replaces the field while this goroutine is still draining
	// the old attempt. Nothing closes it — ctx is what ends the loop.
	dataCh := c.dataChannel()
	if dataCh == nil {
		return
	}
	st, received := c.stats(), false
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-dataCh:
			plain, err := c.manager.Decrypt(pkt)
			if err != nil {
				// A peer compressing with a codec we lack will keep doing so:
				// end the session, naming the algorithm.
				var cpe *compress.CompressedPayloadError
				if errors.As(err, &cpe) {
					c.failCompressedPayload(ctx, cpe)
					return
				}
				// Replay drops and LZO payloads that fail to decode reach us
				// as ordinary errors, so diag.Counters.Replays stays zero and
				// this tally covers all three.
				st.rx.decryptFailures.Add(1)
				// 仅输出错误类别、序列号或帧标记，不输出数据包内容或密钥。
				c.emit(Event{Type: EventLog, Message: "vpn: data packet dropped: " + err.Error()})
				continue
			}
			st.rx.packets.Add(1)
			// Drop keepalive magic — it is not a real IP packet.
			if occ.IsKeepalive(plain) {
				continue
			}
			c.clampMSS(plain)
			st.rx.bytes.Add(uint64(len(plain)))
			if !received {
				received = true
				c.markDataFlow(st, false)
			}
			dev.WritePacket(plain) //nolint:errcheck
		}
	}
}

// Keepalive defaults, in seconds, for a session where neither the PUSH_REPLY
// nor the profile names a value.
//
// They are openvpn3's: ssl/proto.hpp lines 508-509 initialise keepalive_ping
// to 8 seconds and keepalive_timeout to 40, and nothing writes over them
// unless a config file or a pushed option says so (lines 1278-1294). 2.4 and
// 2.6 are not the model, because they send no probe unless ping or keepalive
// is configured or pushed and set only a pre-pull dead-link timeout of 120
// seconds on a pulling UDP client (src/openvpn/ping.h line 33
// PRE_PULL_INITIAL_PING_RESTART, src/openvpn/init.c lines 200-205).
// keepaliveLoop is unconditional, like openvpn3's.
const (
	defaultPingInterval = 8
	defaultPingRestart  = 40
)

// keepaliveFor resolves the probe interval and dead-link timeout for one
// session, in seconds, from what the server pushed, what the profile asked for
// and the defaults above — in that order of precedence.
//
// The precedence is per value rather than per source, which is openvpn3's:
// ssl/proto.hpp line 752 runs load_common over the pushed option list after
// the config file, and load_duration_parm writes only when the option it names
// is present, so a PUSH_REPLY carrying ping and no ping-restart leaves the
// profile's ping-restart standing. A pushed zero means "pushed nothing". A
// profile's explicit "ping-restart 0" disables the dead-link timer, as
// openvpn3's set_duration_parm turns a zero into its 7-day maximum
// (time/durhelper.hpp:34).
func (c *Client) keepaliveFor(pushedInterval, pushedRestart int) (interval, restart int) {
	interval, restart = defaultPingInterval, defaultPingRestart
	if c.prof != nil {
		if c.prof.PingInterval > 0 {
			interval = c.prof.PingInterval
		}
		if c.prof.PingTimeout > 0 || c.prof.PingTimeoutSet {
			restart = c.prof.PingTimeout
		}
	}
	if pushedInterval > 0 {
		interval = pushedInterval
	}
	if pushedRestart > 0 {
		restart = pushedRestart
	}
	return interval, restart
}

// keepaliveLoop sends a keepalive P_DATA_V2 packet every pingInterval seconds
// and triggers a disconnect if no data arrives within pingRestart seconds. The
// two arguments are what the server pushed; a zero means it pushed nothing,
// and keepaliveFor fills the gap from the profile or the defaults.
//
// The dead-link check polls the received-packet count on a 1-second ticker
// rather than arming a one-shot timer, so packets arriving between ticks are
// noticed without a timestamp per packet.
//
// Reference: openvpn3-core ssl/proto.hpp
//   - ProtoContext::housekeeping() line ~4580: calls primary->send_keepalive()
//     when now >= keepalive_xmit.
//   - keepalive_xmit is rescheduled by send_keepalive() line ~4280.
//   - ProtoContext::housekeeping() line ~4503: keepalive_expire reset on any recv.
//   - is_keepalive_enabled() line ~4345 guards both send and recv paths.
func (c *Client) keepaliveLoop(ctx context.Context, pingInterval, pingRestart int) {
	defer c.wg.Done()

	pingInterval, pingRestart = c.keepaliveFor(pingInterval, pingRestart)

	pollInterval := time.Second
	if pingInterval > 0 && time.Duration(pingInterval)*time.Second < pollInterval {
		pollInterval = time.Duration(pingInterval) * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var nextSend time.Time
	if pingInterval > 0 {
		nextSend = time.Now().Add(time.Duration(pingInterval) * time.Second)
	}
	st := c.stats()
	lastPackets, lastRecv := st.rx.packets.Load(), time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// Send keepalive if interval elapsed.
			// Use a short write deadline so a stalled TCP socket does not block
			// this goroutine — if the write times out the dead-link check below
			// will fire on the next tick anyway.
			if !now.Before(nextSend) {
				wire, err := c.manager.Encrypt(occ.KeepaliveMagic)
				if err == nil {
					c.rawConn.SetWriteDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
					c.writePacket(c.rawConn, wire)                              //nolint:errcheck
					c.rawConn.SetWriteDeadline(time.Time{})                     //nolint:errcheck
				}
				nextSend = now.Add(time.Duration(pingInterval) * time.Second)
			}
			// Dead-link detection: disconnect if nothing received for pingRestart seconds.
			if n := st.rx.packets.Load(); n != lastPackets {
				lastPackets, lastRecv = n, now
			}
			if pingRestart > 0 && now.Sub(lastRecv) >= time.Duration(pingRestart)*time.Second {
				c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: keepalive: no data for %d seconds, disconnecting", pingRestart)})
				c.endSession(ctx, fmt.Errorf("vpn: keepalive timeout: no data for %d seconds", pingRestart))
				return
			}
		}
	}
}

// inactiveLoop disconnects the session when traffic falls below the threshold
// pushed by the server via "inactive <timeout> [bytes]".
//
// Traffic is counted in both directions, which is what makes an upload-only
// tunnel survive: openvpn3 client/cliproto.hpp arms reset_inactive_timer()
// (line 1512) on TUN_BYTES_OUT and TUN_BYTES_IN alike from process_inactive()
// (line 1474), and OpenVPN 2.6.22 src/openvpn/forward.c
// check_inactivity_timeout() (line 483) measures tun_read_bytes +
// tun_write_bytes. Only bytes carried by the tunnel count: keepalive probes
// are dropped before wireToTun reaches its counter.
func (c *Client) inactiveLoop(ctx context.Context, timeout, minBytes int) {
	defer c.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Snapshot traffic at start of window.
	st := c.stats()
	windowStart := time.Now()
	startSent := st.tx.bytes.Load()
	startRecv := st.rx.bytes.Load()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(windowStart) < time.Duration(timeout)*time.Second {
				continue
			}
			sent := st.tx.bytes.Load()
			recv := st.rx.bytes.Load()
			totalFlow := (sent - startSent) + (recv - startRecv)

			// With no byte argument, any byte in either direction keeps the
			// session alive. Both references reset on either direction;
			// neither has a receive-only rule.
			expired := totalFlow == 0
			if minBytes > 0 {
				expired = totalFlow < uint64(minBytes)
			}

			if expired {
				c.emit(Event{Type: EventLog, Message: fmt.Sprintf("vpn: inactive: no traffic for %d seconds, disconnecting", timeout)})
				c.endSession(ctx, fmt.Errorf(
					"vpn: inactive timeout: no traffic for %d seconds", timeout))
				return
			}

			// Reset window for next period.
			windowStart = time.Now()
			startSent = sent
			startRecv = recv
		}
	}
}

// sessionMonitor watches for mid-session AUTH_FAILED messages from the server.
func (c *Client) sessionMonitor(ctx context.Context) {
	defer c.wg.Done()
	if c.tlsRW == nil {
		return
	}
	mon := control.NewSessionMonitor(c.tlsRW)
	mon.Start(ctx)
	select {
	case <-ctx.Done():
	case err := <-mon.Done():
		if errors.Is(err, io.EOF) {
			return
		}
		// A deliberate Disconnect tears the control transport down underneath
		// the monitor at the same instant ctx.Done becomes ready, and select
		// picks between two ready cases at random. endSession tells them apart.
		c.endSession(ctx, err)
	}
}

// effectiveTunMTU picks the tunnel MTU from what the profile asked for and
// what the server pushed. An explicit profileMTU is an upper bound: a server
// may only reduce it, so a larger push cannot undo a profile MTU chosen to
// avoid path fragmentation. Returns profileMTU, or OpenVPN 2's default when
// neither side said.
func effectiveTunMTU(pushedMTU, profileMTU int) int {
	if profileMTU > 0 {
		if pushedMTU > 0 && pushedMTU < profileMTU {
			return pushedMTU
		}
		return profileMTU
	}
	if pushedMTU > 0 {
		return pushedMTU
	}
	return openVPN2DefaultTunMTU
}

const (
	openVPN2DefaultTunMTU = 1500
	// OpenVPN 2's default mssfix, applied when the profile uses the default
	// 1500-byte TUN MTU and sets no mssfix of its own. It is a link budget — the
	// whole encapsulated packet — which is what mssfix.MaxMSS takes.
	openVPN2DefaultMSSFixBudget = 1492

	// innerIPv4AndTCP is what a fixed budget gives up to the payload's own
	// headers, the only subtraction the reference makes in that mode.
	innerIPv4AndTCP = 40
)

// effectiveMSSFix returns the maximum MSS an inner IPv4 TCP SYN may advertise.
// Clamp derives the IPv6 figure from it, so one number covers both families —
// the shape the reference keeps (a single frame->mss_fix).
//
// mssfix is a *link budget*, not an MSS: the reference subtracts the whole
// encapsulation — transport, opcode, packet id, crypto and the inner IP and
// TCP headers — before clamping (openvpn-2.6.22 src/openvpn/mss.c:286-332),
// deriving 1336 from `mssfix 1400` rather than 1400. The overhead here is
// computed from the negotiated cipher, digest and wire format.
func (c *Client) effectiveMSSFix(pushedMSS, tunMTU int, dcp datachannel.Params, comp compress.Mode, remoteAddr net.Addr) int {
	o := mssfix.Overhead{
		TCPTransport:       c.activeProto() == profile.ProtoTCP,
		PeerID:             dcp.Wire == datachannel.WireDataV2,
		AEAD:               dcp.Spec.Mode == crypto.ModeAEAD,
		CompressionFraming: comp.Overhead() > 0,
		// Only the derived defaults below measure the outer headers: an
		// explicit "mssfix N" measures the tunnel packet alone unless it says
		// "mtu" (options.c:7318-7335, openvpn3 ssl/proto.hpp:2713).
		EncapCounted: c.prof.MSSFixMode == profile.MSSFixEncap,
	}
	if o.AEAD {
		o.TagLen = aeadTagLen
	} else {
		o.IVLen = cbcBlockLen
		o.BlockLen = cbcBlockLen
		o.DigestLen = dcp.Digest.Size()
	}
	if ip := addrIP(remoteAddr); ip != nil && ip.To4() == nil {
		o.OuterIPv6 = true
	}

	if pushedMSS > 0 {
		return mssfix.MaxMSS(pushedMSS, o)
	}
	if c.prof.MSSFixSet {
		if c.prof.MSSFixMode == profile.MSSFixFixed {
			// "fixed" says the number is already the payload budget: give up
			// only the inner headers (mss.c:289-294).
			if c.prof.MSSFix <= innerIPv4AndTCP {
				return 0
			}
			return c.prof.MSSFix - innerIPv4AndTCP
		}
		return mssfix.MaxMSS(c.prof.MSSFix, o)
	}
	// A non-default TUN MTU is itself the budget: the reference sets mssfix to
	// the tun MTU and marks it fixed, subtracting only the inner IPv4 and TCP
	// headers (openvpn-2.6.22 src/openvpn/options.c:3234-3239, mss.c:289-294).
	if tunMTU != openVPN2DefaultTunMTU {
		return tunMTU - innerIPv4AndTCP
	}
	o.EncapCounted = true // options.c:3227-3229 sets mssfix_encap with the default budget
	return mssfix.MaxMSS(openVPN2DefaultMSSFixBudget, o)
}

// AES block and GCM tag lengths, named here because the overhead sum reads
// better with them than with bare 16s.
const (
	aeadTagLen  = 16
	cbcBlockLen = 16
)

func addrIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	if addr == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// parsePeerID extracts the numeric peer-id value from a PUSH_REPLY message,
// and reports whether one was pushed at all.
//
// The second return value is not a convenience: "peer-id 0" is a value a
// server really pushes, a server that pushes no peer-id directive at all is a
// different fact, and the two select different wire formats. pushed is false
// too for a directive present but unparseable or out of range, since inventing
// 0 would claim a format the server did not ask for.
//
// openvpn3-core proto.hpp: remote_peer_id is a 24-bit value (0 to 0xFFFFFE).
func parsePeerID(pushRaw string) (id uint32, pushed bool) {
	for _, field := range strings.Split(strings.TrimRight(pushRaw, "\x00"), ",") {
		parts := strings.Fields(strings.TrimSpace(field))
		if len(parts) == 2 && strings.EqualFold(parts[0], "peer-id") {
			var v uint32
			if _, err := fmt.Sscanf(parts[1], "%d", &v); err == nil && v <= 0xFFFFFE {
				return v, true
			}
		}
	}
	return 0, false
}

// pushedWireFormat maps the presence of a pushed peer-id onto the data-channel
// packet format the peer speaks: a server that assigned one puts it in every
// packet and expects one back. Nothing else contributes.
func pushedWireFormat(peerIDPushed bool) datachannel.WireFormat {
	if peerIDPushed {
		return datachannel.WireDataV2
	}
	return datachannel.WireDataV1
}
