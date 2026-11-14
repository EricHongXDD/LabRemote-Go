// SPDX-License-Identifier: LGPL-2.1-or-later
//
// transport.go: framing seam, wrap seam, dial policy, packet classification.

package vpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"syscall"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/framing"
	"github.com/buengese/go-openvpn/internal/wrap"
	"github.com/buengese/go-openvpn/profile"
)

// sendWithRetry sends pkt and retries until a packet with the expected opcode
// arrives or maxTries is exhausted.
//
// The timeout adapts based on observed RTT:
//   - If any packet arrives before the deadline (even wrong opcode), RTT is
//     recorded and subsequent intervals are set to min(RTT×2, 10 s).
//   - If the deadline fires with no response, the interval doubles
//     (exponential back-off, capped at 10 s).
//
// The adaptive interval is this client's. openvpn3 retransmits on a flat
// tls_timeout, reset on every send (reliable/relsend.hpp:50-53).
func (c *Client) sendWithRetry(conn net.Conn, pkt []byte, wantOpcode uint8, retryInterval time.Duration, maxTries int) ([]byte, error) {
	const maxInterval = 10 * time.Second
	interval := retryInterval
	var measuredRTT time.Duration

	for try := 0; try < maxTries; try++ {
		sentAt := time.Now()
		if err := c.writePacket(conn, pkt); err != nil {
			return nil, fmt.Errorf("write attempt %d: %w", try+1, err)
		}
		conn.SetReadDeadline(time.Now().Add(interval)) //nolint:errcheck
		timedOut := false
		for {
			resp, err := c.readPacket(conn)
			if err != nil {
				if isTimeout(err) {
					timedOut = true
					break
				}
				return nil, err
			}
			// Record RTT from the first received packet (any opcode).
			if measuredRTT == 0 {
				measuredRTT = time.Since(sentAt)
			}
			if len(resp) >= 1 && resp[0]>>3 == wantOpcode {
				conn.SetReadDeadline(time.Time{}) //nolint:errcheck
				return resp, nil
			}
			// Wrong opcode — keep reading until deadline.
		}
		if timedOut {
			if measuredRTT > 0 {
				interval = measuredRTT * 2
			} else {
				interval *= 2
			}
			if interval > maxInterval {
				interval = maxInterval
			}
		}
	}
	return nil, fmt.Errorf("no response after %d attempts", maxTries)
}

// controlWrapper returns the control-channel wrapping in force. New always
// installs one; a Client built as a zero value has none, and an absent wrap
// means an unwrapped control channel, which is the identity wrapper.
func (c *Client) controlWrapper() wrap.Wrapper {
	if w := c.wrapper.Load(); w != nil && *w != nil {
		return *w
	}
	return wrap.Plain()
}

// setControlWrapper installs w as the control-channel wrapping for the next
// connection; a nil w restores the "no wrap chosen" state. It is the only
// writer of the field, so the wrap changes by one atomic store.
func (c *Client) setControlWrapper(w wrap.Wrapper) {
	if w == nil {
		c.wrapper.Store(nil)
		return
	}
	c.wrapper.Store(&w)
}

// selectWrapper chooses the control-channel wrapping from the profile and
// installs it. It is called once per attempt and per remote, at the StageParse
// boundary: tls-auth authenticates the opening HARD_RESET and tls-crypt
// encrypts it, so the wrap is fixed before the socket opens, and tls-auth's
// digest is the profile's own --auth for the same reason. The repetition is a
// requirement too — the wrap owns connection-scoped state, and a replay window
// carried over reads a peer whose packet ids start again at 1 as a run of
// replays. See rewindForNextRemote.
//
// Only the key decides which wrap; tls-crypt has no --key-direction and
// tls_crypt_kt() fixes AES-256-CTR and HMAC-SHA256. A profile carrying both
// keys is refused rather than resolved, because OpenVPN refuses it too.
func (c *Client) selectWrapper() error {
	p := c.prof
	if p == nil || (p.TLSAuth == nil && p.TLSCrypt == nil) {
		c.setControlWrapper(wrap.Plain())
		return nil
	}
	if p.TLSAuth != nil && p.TLSCrypt != nil {
		return fmt.Errorf("tls-auth and tls-crypt are mutually exclusive; this profile carries both")
	}
	if p.TLSCrypt != nil {
		// The conversion copies no key material and stops compiling if
		// either type's size moves, as in the tls-auth branch below.
		w, err := wrap.NewTLSCrypt((*wrap.StaticKey)(p.TLSCrypt))
		if err != nil {
			return err
		}
		c.setControlWrapper(w)
		return nil
	}

	digestName := p.Auth
	if digestName == "" {
		digestName = crypto.DefaultAuthName
	}
	digest, err := crypto.ParseDigest(digestName)
	if err != nil {
		return fmt.Errorf("tls-auth digest: %w", err)
	}

	var direction wrap.Direction
	switch p.KeyDirection {
	case profile.KeyDirection0:
		direction = wrap.Direction0
	case profile.KeyDirection1:
		direction = wrap.Direction1
	case profile.KeyDirectionAbsent:
		// A third behaviour and not a default of 0: both directions use the
		// same half of the key. See wrap.Direction.hmacOffsets.
		direction = wrap.DirectionAbsent
	default:
		return fmt.Errorf("tls-auth: unknown key-direction %v", p.KeyDirection)
	}

	// The conversion copies no key material and stops compiling if either
	// type's size moves; internal/wrap declares its own StaticKey so that the
	// wire format does not depend on the profile parser.
	w, err := wrap.NewTLSAuth((*wrap.StaticKey)(p.TLSAuth), direction, digest)
	if err != nil {
		return err
	}
	c.setControlWrapper(w)
	return nil
}

// wrapsPacket reports whether pkt passes through the control-channel Wrapper.
// It is the one guard that keeps the wrap seam off the data channel: tls-auth
// and tls-crypt cover control packets only, yet data packets share the
// readPacket/writePacket seam with them, and a wrap applied to everything
// corrupts the data channel *after* a successful handshake.
//
// The test is a deny-list of the two data opcodes rather than an allow-list of
// the control ones, because an unrecognised opcode is an unimplemented control
// opcode and sending that through the wrap is the harmless error. Both
// directions call it — a rule enforced one way holds until the first reply.
func wrapsPacket(pkt []byte) bool {
	if len(pkt) == 0 {
		return false
	}
	return isControlOpcode(framing.OpcodeFromByte(pkt[0]))
}

// isControlOpcode reports whether an opcode belongs to the control channel.
// Everything that is not one of the two data opcodes is, which is why an
// opcode we have never seen is treated as control rather than waved through.
func isControlOpcode(op uint8) bool {
	switch op {
	case framing.P_DATA_V1, framing.P_DATA_V2:
		return false
	default:
		return true
	}
}

// errForeignSession marks a control packet addressed to a session that is not
// ours. It is a sentinel for the drop counters, never returned to a caller.
var errForeignSession = errors.New("control packet names another session")

// controlPacketIsOurs reports whether a control packet belongs to this
// session, by the two comparisons the reference makes. The source session id
// must be the server's: tls_pre_decrypt drops a packet whose id matches no
// session it knows (openvpn-2.6.22 src/openvpn/ssl.c:3777, :3860-3868), and a
// client keeps one session, so the lookup is an equality. Where the packet
// echoes a session id back — only alongside an ack array, by the wire layout —
// it must be ours (reliable.c:159-168). A HARD_RESET is the exception on both
// counts and does not reach here; connect.go adopts the server's id from it.
//
// The session ids are passed in rather than read off the Client, where reading
// them is a data race: the only caller is the inbound relay, which no
// WaitGroup covers, so it outlives its attempt while a failover and a
// Reconnect zero both fields under the lock.
func controlPacketIsOurs(pkt []byte, clientSID, serverSID [8]byte) bool {
	src, ok := framing.ControlSrcSessionID(pkt)
	if !ok || src != serverSID {
		return false
	}
	if dst, present := framing.ControlDstSessionID(pkt); present && dst != clientSID {
		return false
	}
	return true
}

// readPacket reads one OpenVPN packet from conn using the framing of the
// dialed remote's protocol — 2-byte length prefix for TCP, raw datagram for
// UDP — and not the profile's --proto, which failover can make differ. A
// control packet is then unwrapped; data packets bypass the wrapper (see
// wrapsPacket).
//
// A control packet the wrap refuses is **dropped and counted, and the read
// continues**, as OpenVPN silently drops a packet that fails its HMAC: on UDP,
// returning an error lets anyone who can guess the four-tuple end the session
// with one garbage datagram, and turns ordinary crosstalk into a spurious
// connection failure. See countControlDrop. The read itself stays
// connection-fatal — a closed socket, a truncated length prefix or a deadline
// have no next packet to go back for.
func (c *Client) readPacket(conn net.Conn) ([]byte, error) {
	for {
		var (
			pkt []byte
			err error
		)
		if c.activeProto() == profile.ProtoUDP {
			pkt, err = framing.ReadUDP(conn)
		} else {
			pkt, err = framing.ReadTCP(conn)
		}
		if err != nil || !wrapsPacket(pkt) {
			return pkt, err
		}
		plain, err := c.controlWrapper().Unwrap(pkt)
		if err != nil {
			// Each turn of this loop consumes one packet the transport
			// already delivered, so a flood costs a read apiece and any
			// deadline the caller set still fires.
			c.countControlDrop(err)
			continue
		}
		return plain, nil
	}
}

// resetFailureClass classifies a HARD_RESET exchange that produced no usable
// reply, and returns a suffix naming the evidence.
//
// The evidence is that we *heard* something and could not authenticate a
// single packet of it: bytes arrived carrying a tag that did not verify under
// the profile's static key, which is ClassCrypto by diag's own definition.
// Silence stays ClassNetwork, because a server wrapped with a key we do not
// have and a server that is gone both say nothing. Replays and stale
// timestamps are deliberately not evidence: both mean the packet *did*
// authenticate, so the key is right and the fault is on the path.
func (c *Client) resetFailureClass() (diag.Class, string) {
	n := c.stats().ctl.authFailures.Load()
	if n == 0 {
		return diag.ClassNetwork, ""
	}
	return diag.ClassCrypto, fmt.Sprintf(
		" (%d control packets arrived and none authenticated: the %s key or key-direction does not match the server's)",
		n, c.controlWrapper().Name())
}

// countControlDrop tallies one control packet the wrap refused, by reason. An
// authentication failure means the static key or the key-direction does not
// match the server's, and is the evidence resetFailureClass reads to call a
// silent server ClassCrypto rather than ClassNetwork; a replay or a stale
// timestamp means the key is right and the path duplicated or reordered a
// packet. Anything else counts with the authentication failures.
func (c *Client) countControlDrop(err error) {
	ctl := &c.stats().ctl
	switch {
	case errors.Is(err, wrap.ErrReplay):
		ctl.replays.Add(1)
	case errors.Is(err, wrap.ErrStaleTimestamp):
		ctl.staleTimestamps.Add(1)
	case errors.Is(err, errForeignSession):
		ctl.foreignSession.Add(1)
	default:
		ctl.authFailures.Add(1)
	}
}

// writePacket writes one complete OpenVPN packet to conn using the framing of
// the dialed remote, as readPacket does.  A net.Conn permits concurrent calls
// to Write, but it does not keep the two writes that make up a TCP-framed
// OpenVPN packet contiguous; serialize them here for every outbound path.
//
// A control packet is wrapped here under writeMu rather than before it: a wrap
// that stamps a packet ID assigns it inside the lock, which keeps those IDs in
// the same order as the frames that carry them, or two send goroutines hand
// the peer's replay window a pair whose IDs run backwards. Data packets bypass
// the wrapper — see wrapsPacket.
func (c *Client) writePacket(conn net.Conn, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if wrapsPacket(payload) {
		wrapped, err := c.controlWrapper().Wrap(payload)
		if err != nil {
			return fmt.Errorf("wrap control packet: %w", err)
		}
		payload = wrapped
	}
	if c.activeProto() == profile.ProtoUDP {
		return framing.WriteUDP(conn, payload)
	}
	return framing.WriteTCP(conn, payload)
}

// randomSubdomain prepends a random 8-hex-char label to host.
// AWS Client VPN requires a random subdomain prefix — the bare endpoint DNS
// name does not resolve, but <random>.cvpn-endpoint-... does.
func randomSubdomain(host string) string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "rand." + host
	}
	return hex.EncodeToString(b[:]) + "." + host
}

// ---- The dialed remote --------------------------------------------------
//
// Downstream of the dial the endpoint is read here, never from the profile.

// activeRemote returns the remote this attempt is dialing. Before failover has
// chosen one — and for a profile assembled in code, which has no Remotes list
// — it answers from Remote, Port and Proto, i.e. Remotes[0] once parsed.
func (c *Client) activeRemote() profile.Remote {
	if r := c.active.Load(); r != nil {
		return *r
	}
	if c.prof == nil {
		return profile.Remote{}
	}
	return profile.Remote{Host: c.prof.Remote, Port: c.prof.Port, Proto: c.prof.Proto}
}

// activeProto returns the transport of the remote this attempt is dialing. It
// decides framing, MSS arithmetic and the advertised link-mtu, and is not
// c.prof.Proto: a --remote line's third field overrides --proto for that line.
func (c *Client) activeProto() profile.Proto {
	return c.activeRemote().Proto
}

// setActiveRemote records the remote the next dial will use. Its value has to
// survive as long as the connection does: a rekey an hour later re-runs the
// key-method-2 exchange and advertises a link-mtu that depends on the transport.
func (c *Client) setActiveRemote(rem profile.Remote) {
	c.active.Store(&rem)
}

// dialTarget is one entry of a dial order: a remote and the line of the
// profile it came from. The index travels with the remote because a shuffled
// order cannot be searched back to file order by value.
type dialTarget struct {
	// Index is the remote's 0-based position in the profile's --remote list.
	Index int
	// Remote is the remote itself, with its port and transport resolved.
	Remote profile.Remote
}

// dialOrder returns the remotes to try, in the order to try them: the
// profile's --remote list in file order, which is the order OpenVPN dials them
// in, unless --remote-random asked for a shuffle. The shuffle is made here,
// per attempt, rather than written back into the profile, which New keeps a
// pointer to and a caller may attempt many times.
//
// A profile with no Remotes — one assembled in code rather than parsed —
// yields the single remote its scalar fields describe, so the list is never
// empty and the loop that consumes it has no no-remote case.
func (c *Client) dialOrder() []dialTarget {
	if c.prof == nil {
		return []dialTarget{{}}
	}
	if len(c.prof.Remotes) == 0 {
		return []dialTarget{{Remote: profile.Remote{
			Host: c.prof.Remote, Port: c.prof.Port, Proto: c.prof.Proto,
		}}}
	}
	order := make([]dialTarget, len(c.prof.Remotes))
	for i, rem := range c.prof.Remotes {
		order[i] = dialTarget{Index: i, Remote: rem}
	}
	// Profile.Remote, Port and Proto are Remotes[0] as the parser leaves them;
	// a caller that has written them since — pinning a resolved address, or
	// pointing a parsed profile at a mock — means them, and the reverse is not.
	if first := &order[0].Remote; first.Host != c.prof.Remote ||
		first.Port != c.prof.Port || first.Proto != c.prof.Proto {
		first.Host, first.Port, first.Proto = c.prof.Remote, c.prof.Port, c.prof.Proto
	}
	if c.prof.RemoteRandom {
		// Not crypto/rand: this spreads a fleet of clients across a
		// provider's endpoints, which is a load question and not a secrecy
		// one. OpenVPN's own --remote-random uses its ordinary PRNG too.
		mrand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	}
	return order
}

// failoverContinues reports whether a remote that failed with class leaves any
// reason to try the next one: whether the failure was a property of the
// endpoint, or of everything we brought to it and would bring to the next.
//
//	network, tls, protocol, crypto  — the endpoint's, try the next one
//	config, unsupported, auth, local — ours, and the next endpoint would
//	                                   fail identically
//
// ClassServerBusy continues too: an AUTH_FAILED,TEMP carries an "advance" flag
// naming the next address, the next remote, or staying put, and the reference
// assumes "addr" — move on — when it is absent. The flag does not reach here,
// so an explicit "advance no" is not honoured.
func failoverContinues(class diag.Class) bool {
	switch class {
	case diag.ClassNetwork, diag.ClassTLS, diag.ClassProtocol, diag.ClassCrypto, diag.ClassServerBusy:
		return true
	default:
		return false
	}
}

// tcpKeepaliveIdle is the time a TCP connection must be idle before the kernel
// starts sending keepalive probes. Combined with tcpKeepaliveInterval and
// tcpKeepaliveCount this makes the OS declare the link dead in about 15 s,
// well before any application-level timeout fires.
const (
	tcpKeepaliveIdle     = 5 * time.Second
	tcpKeepaliveInterval = 3 * time.Second
	tcpKeepaliveCount    = 3 // 5 + 3*3 = 14 s total
)

// dialWithContext dials addr, enables TCP keepalives on the socket, and — if
// c.ProtectFn is set — calls it with the raw fd so Android can exclude the
// socket from VPN routing.
func (c *Client) dialWithContext(ctx context.Context, proto profile.Proto, addr string) (net.Conn, error) {
	d := &net.Dialer{
		// 单个备用服务器的 TCP 拨号不得耗尽整体认证等待时间。
		Timeout: 10 * time.Second,
		// OS-level TCP keepalive: kernel detects dead links in ~15 s regardless
		// of whether the server pushes ping/ping-restart in PUSH_REPLY.
		KeepAlive: tcpKeepaliveIdle,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     tcpKeepaliveIdle,
			Interval: tcpKeepaliveInterval,
			Count:    tcpKeepaliveCount,
		},
	}
	if c.ProtectFn != nil {
		// Control callback fires after socket creation but before connect(2).
		d.Control = func(network, address string, rawConn syscall.RawConn) error {
			return rawConn.Control(func(fd uintptr) {
				_ = c.ProtectFn(int(fd)) //nolint:errcheck
			})
		}
	}
	switch proto {
	case profile.ProtoTCP:
		return d.DialContext(ctx, "tcp", addr)
	case profile.ProtoUDP:
		return d.DialContext(ctx, "udp", addr)
	default:
		return nil, fmt.Errorf("unknown proto %v", proto)
	}
}

// controlSegmentBudget is the size of one outbound control-channel packet's
// payload before wrap overhead. Control-channel fragmentation is a local
// budget, not a negotiated MTU: the peer reassembles whatever it is sent.
const controlSegmentBudget = 1024

// controlSegmentSize is the most TLS payload this client puts in one
// P_CONTROL_V1 packet, after the control-channel wrap has taken its share. The
// wrap covers the whole control packet on its way out, so whatever it adds
// comes out of the same budget the TLS payload does: Plain adds nothing,
// tls-auth adds 28, 40 or 72 depending on the profile's --auth, which is why
// the arithmetic reads Overhead rather than a constant.
//
// The floor of one byte keeps a pathological Overhead from producing an empty
// segment and a send loop that never advances.
func (c *Client) controlSegmentSize() int {
	size := controlSegmentBudget - c.controlWrapper().Overhead()
	if size < 1 {
		return 1
	}
	return size
}

// isTimeout reports whether err is a network timeout error.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
