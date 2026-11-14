// Package vpn is the top-level go-openvpn package.
//
// It provides an OpenVPN client that runs the whole connection lifecycle: the
// control channel and its TLS session, authentication, the data channel, and
// the tunnel device and routes. A profile authenticates with a client
// certificate, with a username and password, or — for an AWS Client VPN
// endpoint — with a federated SAML assertion.
//
// Typical usage. ParsePath rather than ParseFile, because a profile may name
// its CA in a file beside it and only the path form can resolve that:
//
//	p, err := profile.ParsePath(path)
//	if err != nil {
//	    return err
//	}
//	c := vpn.New(p)
//	c.EventFn = vpn.StderrEvents // or your own sink; nil is silent
//	c.CredentialsFn = func(ctx context.Context) (vpn.Credentials, error) {
//	    return vpn.Credentials{Username: user, Password: pass}, nil
//	}
//	if err := c.Connect(ctx); err != nil {
//	    return err
//	}
//	// tunnel is now up; data flows through the TUN device
//	defer c.WaitForDisconnect() //nolint:errcheck
//	defer c.Disconnect()        //nolint:errcheck
//
// A caller with no file to parse builds a *profile.Profile from profile.Spec.
// A cert-only profile needs no callback; a federated one needs SAMLTokenFn,
// which is called with the identity provider's URL and returns the assertion.
package vpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buengese/go-openvpn/device"
	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/internal/prf"
	"github.com/buengese/go-openvpn/internal/wrap"
	"github.com/buengese/go-openvpn/profile"
	"github.com/buengese/go-openvpn/routing"
)

// SAMLChallenge holds the parsed fields from a CRV1 SAML challenge.
// The caller must open URL in a browser; the IdP will POST the SAMLResponse
// to 127.0.0.1:35001, which the caller can capture via auth/saml.NewACSServer.
type SAMLChallenge struct {
	// URL is the identity-provider URL the user must visit.
	URL string
	// StateID is the opaque session token that must be returned in Phase 2.
	StateID string
}

// ErrReauthRequired is returned by Reconnect when a federated session cannot
// be resumed: the cached assertion has expired, or the server refused it. An
// assertion is cryptographically bound to the AuthnRequest that obtained it
// and cannot be presented to a new session, so the caller's next move is the
// browser flow — which Connect runs, from the state Reconnect leaves behind.
// No other authentication method returns it.
var ErrReauthRequired = fmt.Errorf("vpn: SAML re-authentication required: token rejected by server")

// Version is the release this build came from, stamped at link time:
//
//	-ldflags "-X github.com/buengese/go-openvpn.Version=v1.2.3"
//
// It is empty in a plain `go build`, where BuildVersion falls back to what the
// toolchain recorded.
var Version string

// BuildVersion reports the release this binary was built from: the link-time
// stamp, else the version the module was built as, else "unknown" — a `go
// build` from a source archive has no VCS information at all.
func BuildVersion() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "unknown"
}

// AWSSAMLUnsupportedNotice describes the AWS support boundary for this
// independent CRV1 implementation.
const AWSSAMLUnsupportedNotice = "This client is not AWS-supported for SAML Client VPN authentication. For AWS-supported operation, use the AWS VPN Client."

// Stats is a snapshot of per-session traffic counters.
type Stats struct {
	// BytesSent is the total number of plaintext bytes sent through the tunnel.
	BytesSent uint64
	// BytesRecv is the total number of plaintext bytes received through the tunnel.
	BytesRecv uint64
	// Uptime is the duration since the tunnel was established (zero if not up yet).
	Uptime time.Duration
}

// state tracks the internal lifecycle of a Client.
type state int

const (
	stateNew           state = iota // New() called, no connection
	stateConnecting                 // Connect / dialAndAuthenticate / bringUpTunnel in progress
	stateTunnelUp                   // bringUpTunnel completed, data channel running
	stateDisconnecting              // Disconnect() called, teardown in progress
	stateDisconnected               // fully torn down
)

// String names the state, because one of these reaches the caller: refusing a
// second Connect on a client that is already connecting reports the state it
// found, and "state 1" told nobody anything.
func (s state) String() string {
	switch s {
	case stateNew:
		return "new"
	case stateConnecting:
		return "connecting"
	case stateTunnelUp:
		return "tunnel-up"
	case stateDisconnecting:
		return "disconnecting"
	case stateDisconnected:
		return "disconnected"
	default:
		return "state(" + strconv.Itoa(int(s)) + ")"
	}
}

// Client is a go-openvpn VPN client. It is not safe for concurrent use by
// multiple goroutines except where noted — Stats and WaitForDisconnect may be
// called concurrently with the data channel.
type Client struct {
	prof *profile.Profile

	mu    sync.Mutex
	state state

	// phase1 connection and TLS (retained across phases)
	rawConn net.Conn
	tlsConn *tls.Conn     // the underlying *tls.Conn for ConnectionState()
	tlsRW   io.ReadWriter // control-message I/O: tlsConn, or tlsConn behind a preread replay
	// tlsSecrets belongs to the handshake tlsConn came out of, and only the
	// connect path touches it: tlsHandshake installs it, deriveDataKeys and
	// cleanup empty it, a rekey uses its own (see installTLSSecrets). It is
	// nil for any entry point that runs no handshake, and every method
	// tolerates nil.
	tlsSecrets *prf.Capture
	// reply is what the method made of the server's answer to the first
	// PUSH_REQUEST; replyNone means the first half of the connect flow never
	// ran. A reply in hand is read back from tlsRW, a second exchange dials.
	reply authReply
	// samlSession is the CRV1 session a first exchange obtained: the state id
	// the second exchange authenticates with and the URL the caller must
	// visit. Only the SAML method writes it; nil after a single exchange.
	samlSession *SAMLChallenge
	backendIP   string // the address the handshake dialled, reused by a second exchange

	// session identifiers for the reliable control channel
	clientSID [8]byte
	serverSID [8]byte
	// sendSeq is the next outbound packet_id for the HARD_RESET / initial sequence.
	// After tlsHandshake, sequence numbers are owned by each controlSession.
	sendSeq uint32
	// writeMu serializes complete OpenVPN frames on rawConn. TCP framing writes
	// a length prefix then the payload, and the control, ACK, retransmit, TUN
	// and keepalive paths all write from independent goroutines.
	writeMu sync.Mutex
	// recvExp is the next expected inbound packet_id for the initial session,
	// used only before tlsHandshake runs. After that, recvWindow in each
	// controlSession owns receive sequencing.
	recvExp uint32
	// wrapper is the control-channel wrapping in force for this connection,
	// fixed for its life because tls-auth and tls-crypt both authenticate the
	// opening HARD_RESET. Read it through controlWrapper, which supplies the
	// identity wrapper when this is nil, and write it through setControlWrapper.
	//
	// It is atomic because failover replaces it while the previous remote's
	// goroutines may still be draining: tlsHandshake leaves a raw reader and a
	// send goroutine behind, and neither is joined before the attempt returns.
	wrapper atomic.Pointer[wrap.Wrapper]

	// active is the remote this attempt is dialing: its host, its port and its
	// own transport. Read it through activeRemote and activeProto.
	//
	// Profile.Remote, Port and Proto are Remotes[0] and stay that way, so once
	// a second remote is on the wire a reader asking the profile gets the
	// first remote's answer — for readPacket and writePacket a misframed
	// connection rather than a failed one. It lives here rather than being
	// written back because New stores the caller's profile without copying it,
	// and it is atomic because readPacket and writePacket read it on every
	// packet from goroutines holding no lock. Nil means no remote has been
	// chosen and activeRemote answers from the profile, which is what the
	// mobile and relay Phase 2 entry points get.
	active atomic.Pointer[profile.Remote]

	// data channel
	manager *datachannel.Manager
	peerID  uint32 // 24-bit peer_id from PUSH_REPLY, connection-scoped
	// wire is the data-channel packet format this connection speaks, chosen in
	// applyPushReply from whether a peer-id was pushed. It is connection-scoped
	// for the reason peerID is: a rekey renegotiates keys, not the format.
	wire datachannel.WireFormat
	// serverOpts is the peer's OCC options string from its key-method-2 packet.
	// The report keeps a copy; this one is on the connection path, because the
	// peer's expectation of a compression framing is decided from it alone.
	serverOpts string
	// dev is the tunnel device the data path moves IP packets through. What it
	// installed to exist — an interface, routes, DNS — is the backend's
	// business, and Close is the only thing the core knows about unwinding it.
	dev      device.Device
	pushOpts *routing.PushOptions
	// dataCh receives data-channel wire packets from the control-channel
	// relay goroutine (which owns all reads from rawConn). wireToTun drains
	// it.
	dataCh chan []byte
	// codec is the compression the data channel installed, built in
	// startDataChannel from what compress.EffectiveMode settled on. Atomic
	// because the report reads its count without the lock.
	codec atomic.Pointer[compress.Codec]
	// mssFix is an explicit maximum-MSS clamp in bytes (0 = not configured).
	// A server-pushed value takes precedence over a profile value.
	mssFix int
	// nextKeyID is the key_id for the next renegotiated TLS session.
	// Incremented mod 8 after each renegotiation (key_id 0 is reserved for
	// the initial session). Protected by mu.
	//
	// Reference: openvpn3-core ssl/proto.hpp ProtoContext::next_key_id() line ~4740:
	//   if ((upcoming_key_id = (upcoming_key_id+1) & KEY_ID_MASK) == 0)
	//     upcoming_key_id = 1;
	nextKeyID uint8

	// rekeySessionCh delivers a new controlSession from rekeyLoop to the
	// inbound relay, which routes packets by key_id, and the outbound relay,
	// which starts a per-session send goroutine.
	rekeySessionCh chan *controlSession

	// peerRekeyCh carries a control session the *inbound relay* built, for a
	// renegotiation the server started: doRekey creates the session for a
	// client-initiated rekey, while for a server-initiated one the relay has
	// the peer's SOFT_RESET in hand before any session exists.
	//
	// Buffered by one and written without blocking, because the relay is the
	// only reader of the socket and must never park. A second reset arriving
	// mid-negotiation is dropped: the negotiation in flight answers it.
	peerRekeyCh chan *controlSession

	// rekeyActive is true from the moment either direction claims a
	// renegotiation until it finishes. Both directions allocate a key_id, and
	// without it two timers firing together claim the same one.
	rekeyActive atomic.Bool

	// lifecycle
	connectedAt time.Time
	cancelFn    context.CancelFunc
	wg          sync.WaitGroup
	doneErr     error
	doneCh      chan struct{}
	// clearCredentialsOnCleanup is set by an explicit caller-initiated
	// Disconnect. Transient link failures preserve credentials only long enough
	// for the controlled Reconnect path.
	clearCredentialsOnCleanup bool

	// SAMLTokenFn is called during Connect when the server issues a SAML/CRV1
	// challenge: it must open challenge.URL in a browser, wait for the
	// SAMLResponse via the ACS server on 127.0.0.1:35001, and return the
	// base64-encoded token. Required for AWS Client VPN profiles.
	SAMLTokenFn func(ctx context.Context, challenge SAMLChallenge) (string, error)

	// CredentialsFn supplies the username and password for a profile that
	// requires them. It is called at most once per attempt, before the
	// key-method-2 packet is sent, and may block on a UI or a keychain.
	// Without it a profile.FlowUserPass attempt ends at StageParse with
	// diag.ClassConfig; every other flow ignores it. Set it before Connect;
	// the client stores nothing it returns beyond the session.
	CredentialsFn func(ctx context.Context) (Credentials, error)

	// creds is what CredentialsFn returned, cached so the callback runs at most
	// once per attempt and a Reconnect puts no second prompt in front of the
	// user. Guarded by mu and cleared by clearCredentialsLocked, like the
	// cached SAML token below. The callback is never called with mu held: it
	// may block on a user interface, and a Disconnect must not deadlock on it.
	creds Credentials
	// credsCached distinguishes "not asked yet" from "asked, and the answer
	// was empty".
	credsCached bool

	// ProtectFn, if set, is called with the raw file descriptor of every
	// transport socket before it is used. On Android it must call
	// VpnService.protect(fd), so the socket reaches the real network.
	ProtectFn func(fd int) error

	// Device selects the tunnel backend. Nil selects the platform default: the
	// kernel backend on Linux and macOS, and an error on Android and iOS,
	// where the mobile wrapper sets this field itself. Set it to a netstack
	// backend for an unprivileged tunnel that touches no host state. It is
	// read once, when the tunnel comes up.
	Device device.Backend

	// EventFn, if set, is called for every notable lifecycle event: state
	// transitions, log lines and periodic stats. It is called concurrently
	// from several goroutines, must not block, and is set before Connect.
	//
	// Nil is silent. The one exception is the SSLKEYLOGFILE notice, which the
	// TLS layer writes to stderr as the caller's own opt-in.
	EventFn EventFn

	// PreflightMode selects what the StageParse capability preflight does with
	// a diag.SeverityFatal gap. The zero value, diag.PreflightFailFast, ends
	// the attempt there with diag.ClassUnsupported before a socket is opened;
	// diag.PreflightAdvisory records the same gaps and lets the attempt fail
	// wherever it really fails. The mode is recorded in the session report, so
	// aggregated reports cannot silently mix the two. Read at StageParse.
	PreflightMode diag.PreflightMode

	// DataV2 selects whether the IV_PROTO advertisement claims
	// IV_PROTO_DATA_V2. The zero value claims it, which is what every
	// production connection wants: P_DATA_V2 is this client's preferred
	// data-channel format.
	//
	// The format is not a client choice — see datachannel.WireFormat — and a
	// server decides it from this advertisement alone, so withholding it is
	// the only way to put a P_DATA_V1 server in front of this client (see
	// WithholdDataV2). It is read at each key-method-2 packet.
	DataV2 DataV2Advertisement

	// auth is this attempt's authentication method, nil until an attempt starts
	// and derived from the profile then. The relay and mobile entry points,
	// which reach a second exchange without Connect, set it themselves.
	auth authMethod

	// reconnect
	// MaxReconnects is the maximum number of reconnect attempts before giving
	// up. A value of 0 means unlimited retries. Default is 0 (unlimited).
	MaxReconnects int
	// cachedSAMLToken is stored by bringUpTunnel and reused by Reconnect.
	cachedSAMLToken  string
	cachedSAMLExpiry time.Time // zero means unknown/no expiry
	// cachedStateID is the CRV1 state_id from the last successful handshake.
	// Preserved across reconnects so the second exchange can be resumed into
	// directly.
	cachedStateID string
	// cachedBackendIP is the server IP the last successful handshake dialled.
	// Preserved so a resumed second exchange hits the same backend instance.
	cachedBackendIP string
	reconnectCount  int
	// lastTransientErr is the most recent failure the session recovered from
	// rather than ended on. See LastTransientError.
	lastTransientErr error

	// attempts is one slot per attempt of the current or most recent reconnect
	// sequence, in order, and is what Attempts reports. Guarded by mu. reset
	// replaces the recorder between attempts, so freezeAttemptLocked copies
	// the finished report here before the next attempt destroys it.
	attempts []*attemptSlot
	// reconnecting is true for the duration of a Reconnect, and tells
	// registerAttempt to extend the sequence rather than start a new one: a
	// Connect is a sequence of one, a reconnect however many it takes.
	reconnecting bool

	// rec accumulates the diag.SessionReport for the current attempt. It is an
	// atomic pointer because reset replaces it between attempts while Report
	// may be called from any goroutine, and some recording sites hold mu.
	rec atomic.Pointer[sessionRecorder]
	// counts holds the current attempt's tallies; see stats. Replaced, not
	// zeroed, between attempts, for the reason rec is.
	counts atomic.Pointer[attemptStats]

	// keySource is our own key-method-2 contribution for the current key
	// epoch, kept because the classic derivation consumes it after PUSH_REPLY,
	// long after it was sent.
	keySource prf.KeySource

	// serverKeySource is the peer's contribution, parsed out of its
	// key-method-2 packet by keymethod2.ConsumeServerAuth. Its PreMaster is
	// always nil: the server's key_source carries randoms alone.
	serverKeySource prf.KeySource

	// dataParams is the negotiated cipher and digest. It is settled once, when
	// the first data channel is built, and reused by every rekey — a rekey
	// renegotiates keys, not the cipher suite.
	dataParams datachannel.Params
}

// Credentials is one username and password. Both are secrets and are
// registered with the session report's redaction before use.
type Credentials struct {
	// Username is the user name to present in the key-method-2 packet.
	Username string
	// Password is the password to present alongside it.
	Password string
}

// emit delivers an event to EventFn; a nil EventFn is silent.
//
// Safe to call from any goroutine.
func (c *Client) emit(e Event) {
	if c.EventFn == nil {
		return
	}
	e.At = time.Now()
	c.EventFn(e)
}

// StderrEvents is an EventFn that writes log lines and state changes to
// standard error.
func StderrEvents(e Event) {
	writeEvent(os.Stderr, e)
}

// writeEvent renders one event to w.
func writeEvent(w io.Writer, e Event) {
	switch e.Type {
	case EventLog:
		fmt.Fprintf(w, "%s\n", e.Message)
	case EventStateChanged:
		if e.Message != "" {
			fmt.Fprintf(w, "vpn: state → %s: %s\n", e.State, e.Message)
		} else {
			fmt.Fprintf(w, "vpn: state → %s\n", e.State)
		}
	}
}

// New creates a new Client from the given profile.
// The Client is idle until Connect is called.
func New(p *profile.Profile) *Client {
	c := &Client{
		prof:           p,
		state:          stateNew,
		doneCh:         make(chan struct{}),
		MaxReconnects:  0, // unlimited by default; set to a positive value to cap
		rekeySessionCh: make(chan *controlSession, 1),
		peerRekeyCh:    make(chan *controlSession, 1),
		nextKeyID:      1, // key_id 0 is the initial session; rekey starts at 1
	}
	// No profile yet selects a wrap, so every connection runs the identity
	// wrapper. Setting it here rather than leaving it nil means the seam is
	// exercised by every connection this client makes.
	c.setControlWrapper(wrap.Plain())
	// Report must be callable before Connect, so the recorder exists from the
	// start rather than being created by the first stage transition.
	c.rec.Store(newSessionRecorder())
	return c
}

// Disconnect initiates a graceful teardown of the VPN tunnel. It signals the
// background goroutines to stop and begins cleaning up; call WaitForDisconnect
// to block until it completes. It is the client's only deliberate teardown, and
// so the only one that sends an explicit-exit-notify.
func (c *Client) Disconnect() error {
	return c.teardown(false, true)
}

// disconnect tears down the active transport after something went wrong.
// Internal transient-failure paths may preserve credentials for Reconnect;
// public Disconnect never does. preserveCredentials does not mean
// "deliberate" — that is the separate flag teardown takes.
func (c *Client) disconnect(preserveCredentials bool) error {
	return c.teardown(preserveCredentials, false)
}

// teardown is the single teardown path behind Disconnect and disconnect.
// deliberate says the caller chose to end a working session rather than react
// to one that had stopped working; exitNotifyCopies turns on it.
func (c *Client) teardown(preserveCredentials, deliberate bool) error {
	c.mu.Lock()
	if !preserveCredentials {
		c.clearCredentialsOnCleanup = true
	}
	st := c.state
	if st == stateDisconnecting || st == stateDisconnected {
		if st == stateDisconnected && !preserveCredentials {
			c.clearCredentialsLocked()
		}
		c.mu.Unlock()
		return nil
	}
	c.state = stateDisconnecting
	cancel, conn := c.cancelFn, c.rawConn
	c.mu.Unlock()

	c.emit(Event{Type: EventStateChanged, State: StateDisconnecting})

	// Before anything below is closed: the notification is a data packet, so it
	// needs the key and the socket that cancelFn and rawConn.Close are about to
	// take away. The state swap above makes it happen exactly once.
	if n := c.exitNotifyCopies(deliberate); n > 0 {
		c.sendExitNotify(n)
	}

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		conn.Close()
	}

	go func() {
		c.wg.Wait()
		// announceIdle: a caller that asked for this teardown is told the
		// client went idle. A failed attempt is not — Connect has already told
		// it StateError.
		c.finish(nil, true)
	}()

	return nil
}

// WaitForDisconnect blocks until the client is fully disconnected and returns
// the disconnect reason (nil for a clean Disconnect call). It is safe to call
// concurrently. Called while Reconnect is running, it waits for whichever
// attempt is current when it reads the channel — each attempt gets its own
// channel from reset — so it returns when the client has stopped for good.
func (c *Client) WaitForDisconnect() error {
	// Through Done rather than the field, which reset swaps under the lock.
	<-c.Done()
	c.mu.Lock()
	err := c.doneErr
	c.mu.Unlock()
	return err
}

// Done returns a channel that is closed when the client disconnects (for any
// reason — graceful, keepalive timeout, server-initiated, etc.).
// The disconnect reason is available via WaitForDisconnect after it closes.
func (c *Client) Done() <-chan struct{} {
	c.mu.Lock()
	ch := c.doneCh
	c.mu.Unlock()
	return ch
}

// TunnelDevice returns the device carrying the tunnel, or nil when none is up.
// It lets a wrapper that supplied the backend recover its own concrete device;
// the core itself only ever uses the device.Device interface.
func (c *Client) TunnelDevice() device.Device {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dev
}

// Stats returns a snapshot of current traffic counters and uptime.
// Safe to call concurrently while the tunnel is up.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	up := c.connectedAt
	c.mu.Unlock()

	st := c.stats()
	s := Stats{
		BytesSent: st.tx.bytes.Load(),
		BytesRecv: st.rx.bytes.Load(),
	}
	if !up.IsZero() {
		s.Uptime = time.Since(up)
	}
	return s
}

// ConnectedAt returns when the current tunnel was established, or the zero
// time if none is up. It is what Stats.Uptime is measured from, exposed
// separately because the instant does not go stale the moment it is read.
func (c *Client) ConnectedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectedAt
}

// Reconnects returns how many times Reconnect has re-established this tunnel.
// It counts successes, not attempts: a sequence that came up on its fourth try
// adds one, and Attempts holds the other three, each with its own report.
func (c *Client) Reconnects() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconnectCount
}

// LastTransientError returns the most recent failure this session recovered
// from and went on running, or nil if there has not been one.
//
// It is narrower than "the last error": a failure that ended the session is
// the session's outcome and belongs in the report, while this records the kind
// nothing else would mention — a renegotiation that failed while the old key
// epoch stayed installed, which is this client's one recoverable failure.
func (c *Client) LastTransientError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastTransientErr
}

// noteTransient records a failure the session recovered from.
func (c *Client) noteTransient(err error) {
	if err == nil {
		return
	}
	c.mu.Lock()
	c.lastTransientErr = err
	c.mu.Unlock()
}

// Phase1IP returns the sticky backend IP the handshake reached, or "" before
// the handshake completes. It is what a relay agent must dial for the second
// exchange, because AWS binds a CRV1 state id to one backend instance and
// re-resolving the hostname may route elsewhere.
func (c *Client) Phase1IP() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backendIP
}

// LocalIP returns the tunnel-side IP address assigned by the server after a
// successful Phase 2, or "" if the tunnel is not up.
func (c *Client) LocalIP() string {
	c.mu.Lock()
	opts := c.pushOpts
	c.mu.Unlock()
	if opts == nil || opts.Ifconfig == nil {
		return ""
	}
	return opts.Ifconfig.Local.String()
}

// clearCredentialsLocked removes logical references to authentication
// material. Go strings cannot be reliably zeroized, so callers must also avoid
// retaining extra copies and must never serialize these values into logs.
// c.mu must be held.
func (c *Client) clearCredentialsLocked() {
	c.cachedSAMLToken = ""
	c.cachedSAMLExpiry = time.Time{}
	c.cachedStateID = ""
	c.cachedBackendIP = ""
	c.samlSession = nil
	if c.pushOpts != nil {
		c.pushOpts.AuthToken = ""
	}
	c.keySource = prf.KeySource{}
	c.serverKeySource = prf.KeySource{}

	// What CredentialsFn returned goes the same way as the SAML token: the
	// next attempt asks for it again rather than reusing a password the caller
	// may since have changed.
	c.creds = Credentials{}
	c.credsCached = false
}

// setDisconnected ends the client after an attempt failed: finish, plus the
// fact that a connection-setup failure has no session left to reconnect, so
// nothing cached survives it.
func (c *Client) setDisconnected(err error) {
	c.mu.Lock()
	c.clearCredentialsOnCleanup = true
	c.mu.Unlock()
	c.finish(err, false)
}

// finish ends the client, once, however it got here: a failed attempt through
// setDisconnected, a live session through teardown's goroutine. One end, so
// there is no subset of the release work for either path to get wrong.
//
// announceIdle is about what the caller is told, not what is released: a
// failed attempt has already heard StateError from Connect, and StateIdle
// after it would change what the D-Bus service and the GTK front end display.
func (c *Client) finish(err error, announceIdle bool) {
	c.mu.Lock()
	if c.state == stateDisconnected {
		c.mu.Unlock()
		return
	}
	c.state = stateDisconnected
	if err != nil && c.doneErr == nil {
		c.doneErr = err
	}
	if c.clearCredentialsOnCleanup {
		c.clearCredentialsLocked()
	}
	// Taken under the lock, released below it: Wipe zeroes the master secret in
	// place and a backend may block in Close, so neither belongs under the
	// mutex Stats and Report contend for. Each is handed out exactly once.
	secrets, dev := c.tlsSecrets, c.dev
	c.tlsSecrets, c.dev = nil, nil
	c.mu.Unlock()

	secrets.Wipe()
	if dev != nil {
		// Closing the device is the whole of the tunnel's teardown: addresses,
		// routes and DNS are unwound by whichever backend installed them.
		dev.Close() //nolint:errcheck
	}

	// dataCh is deliberately not closed. wireToTun leaves on ctx.Done and
	// teardown cancels before it waits, but the sender is the inbound relay, a
	// bare goroutine inside tlsHandshake that is not in c.wg — nothing orders a
	// close against it. reset installs a fresh channel per attempt.

	if announceIdle {
		c.emit(Event{Type: EventStateChanged, State: StateIdle})
	}
	// Last, so a caller released by WaitForDisconnect has already seen the
	// state change and everything above is released. Guarded, because a failing
	// attempt may have closed the channel while teardown's goroutine drained.
	c.closeDone()
}

// installTLSSecrets puts the capture for the handshake about to run in place
// and empties whatever the last one left. The swap is under the lock and the
// wipe outside it, because Wipe zeroes the master secret in place rather than
// dropping a reference: a teardown reading the field while this reassigned it
// could hand deriveDataKeys a capture whose bytes were being zeroed.
func (c *Client) installTLSSecrets(capture *prf.Capture) {
	c.mu.Lock()
	old := c.tlsSecrets
	c.tlsSecrets = capture
	c.mu.Unlock()
	old.Wipe()
}

// takeTLSSecrets removes the capture from the client and hands it over. The
// caller owns wiping what it gets, and a second caller gets nil, so the secret
// is emptied exactly once however many teardown paths run.
func (c *Client) takeTLSSecrets() *prf.Capture {
	c.mu.Lock()
	defer c.mu.Unlock()
	secrets := c.tlsSecrets
	c.tlsSecrets = nil
	return secrets
}

// sessionIDs returns this attempt's control-channel session ids, taken under
// the lock and handed out by value: the caller is the inbound relay, nothing
// waits for it, and the fields are zeroed when the next attempt begins.
func (c *Client) sessionIDs() (clientSID, serverSID [8]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clientSID, c.serverSID
}

// dataChannel returns the channel inbound data packets are handed to, or nil
// when the attempt has not built one. The inbound relay starts inside
// tlsHandshake, before it exists, so it asks once and keeps what it gets.
func (c *Client) dataChannel() chan []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dataCh
}

// closeDone closes doneCh, and does nothing if it is already closed. Two paths
// end a client and both must arrive last: teardown moves the state to
// stateDisconnecting and leaves the rest to a goroutine, while setDisconnected
// skips only on stateDisconnected. The lock makes the check and the close one
// step, and keeps this from closing the wrong channel — reset installs a fresh
// doneCh for the next attempt under the same lock.
func (c *Client) closeDone() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeDoneLocked()
}

// closeDoneLocked is closeDone for a caller that already holds c.mu.
func (c *Client) closeDoneLocked() {
	select {
	case <-c.doneCh:
	default:
		close(c.doneCh)
	}
}

// ---- preread helpers ---------------------------------------------------------

// prereadRW is the control channel as it looks to everything after a
// one-exchange authentication: the PUSH_REPLY that exchange already took off
// the wire, replayed once, and then the live connection it came from. The
// replay is what bringUpTunnel reads, because the exchange that authenticated
// the session had to read the server's answer to PUSH_REQUEST to know whether
// it had succeeded.
//
// The live connection underneath is what sessionMonitor reads for the rest of
// the session, so reads must fall through to conn rather than to an empty
// reader: a server may end an established session at any point with a plain
// AUTH_FAILED or a RESTART/HALT push (openvpn-2.6.22 src/openvpn/push.c:72-76
// and push.c:91-109). Reaching conn costs the replayed read nothing:
// control.ReadControlMsg stops on the message terminator and the replay holds
// exactly one terminated message, so the buffered read ends inside the replay.
type prereadRW struct {
	// r is the replay followed by conn. io.MultiReader moves on only once the
	// replay reports io.EOF, which is one byte past its terminator.
	r    io.Reader
	conn io.ReadWriter
}

// newPrereadRW returns the control channel conn with pre replayed in front of
// it. pre is the bytes already consumed from conn, message terminator
// included.
func newPrereadRW(pre []byte, conn io.ReadWriter) *prereadRW {
	return &prereadRW{r: io.MultiReader(bytes.NewReader(pre), conn), conn: conn}
}

func (p *prereadRW) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *prereadRW) Write(b []byte) (int, error) { return p.conn.Write(b) }

// SetReadDeadline forwards to the live connection, so a holder of the wrapper
// can still interrupt a read parked on it: control.SessionMonitor unblocks its
// reader goroutine that way on cancellation. A reader without the method stays
// parked until the socket closes underneath it.
func (p *prereadRW) SetReadDeadline(t time.Time) error {
	d, ok := p.conn.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		return errors.ErrUnsupported
	}
	return d.SetReadDeadline(t)
}

// ---- Events and client state ---------------------------------------------
//
// Event, EventType, ClientState and EventFn are what a caller observes.

// EventType identifies the kind of event emitted by the Client.
type EventType int

const (
	// EventLog is an informational log line.
	EventLog EventType = iota
	// EventStateChanged signals a connection state transition.
	EventStateChanged
	// EventStatsUpdate carries a traffic statistics snapshot.
	EventStatsUpdate
	// EventStage signals that the connection entered a new stage of the
	// handshake. Stage carries the stage and Message its name. It is last on
	// purpose: consumers switch on EventType, so the values above cannot move.
	EventStage
)

// ClientState is the connection lifecycle state reported via events.
type ClientState int

const (
	// StateIdle means no active connection.
	StateIdle ClientState = iota
	// StateConnecting covers everything from the first dial to the tunnel
	// coming up, including a second authentication exchange where one happens.
	StateConnecting
	// StateWaitingSAML means the server asked for a federated assertion and
	// the caller must open the identity provider's URL.
	StateWaitingSAML
	// StateConnected means the TUN interface is up and data flows.
	StateConnected
	// StateDisconnecting means teardown is in progress.
	StateDisconnecting
	// StateError means connection failed; Message carries the reason.
	StateError
)

// String returns a lowercase D-Bus-friendly representation of the state.
func (s ClientState) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateConnecting:
		return "connecting"
	case StateWaitingSAML:
		return "waiting_saml"
	case StateConnected:
		return "connected"
	case StateDisconnecting:
		return "disconnecting"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// Event is emitted by the Client for every notable lifecycle transition or log line.
type Event struct {
	// Type identifies the event category.
	Type EventType

	// State is set when Type == EventStateChanged.
	State ClientState

	// Message carries a log line (EventLog), an error description
	// (StateError), or the assigned tunnel IP (StateConnected). It never
	// carries the SAML URL, which consumers would log.
	Message string

	// ServerIP is the VPN server IP (set when State == StateConnected).
	ServerIP string

	// Stats is set when Type == EventStatsUpdate.
	Stats Stats

	// Stage is set when Type == EventStage: the connection stage just
	// entered. It is the zero value (diag.StageParse) for every other event
	// type, so consumers must gate on Type before reading it.
	Stage diag.Stage

	// At is the wall-clock time of the event.
	At time.Time
}

// EventFn is a callback invoked for every Event emitted by the Client.
//
// It is called from several internal goroutines — the two data-path pumps, the
// keepalive and inactivity timers, and a renegotiation — which can emit at the
// same time, so an implementation must be safe for concurrent calls as well as
// quick to return. Set Client.EventFn before calling Connect.
type EventFn func(Event)
