// Package wrap implements the OpenVPN control-channel wrappings — the
// transform tls-auth and tls-crypt apply to every control packet on its way to
// the wire, and undo on the way back. A Wrapper takes one packet and returns
// one packet, so a wrap is testable against known-answer vectors without a
// client, a socket or a handshake. Data packets never reach one: both wraps
// cover the control channel only, and the caller checks the opcode first.
//
// The wire formats here are *measured*, not read: testdata/vectors.json was
// captured from an instrumented OpenVPN 2.4.12 and the known-answer tests are
// the specification. Every reference cited in this package names the pinned
// 2.4.12 source that capture used, per docs/openvpn3-reference-policy.md §3.3,
// and says where a fact came from rather than standing in for the vector that
// checks it (§3.4). See docker/TLS-WRAP-VECTORS.md.
package wrap

// Wrapper transforms control packets on their way to and from the wire; data
// packets never reach it. A Wrapper is fixed for the life of a connection and
// chosen from the profile before the first packet is sent, because both wraps
// authenticate the opening HARD_RESET.
//
// Implementations must be safe for use from more than one goroutine: a wrap
// carrying a packet-ID counter has mutable state, and the client's control,
// ACK, retransmit and rekey paths all send from goroutines of their own.
type Wrapper interface {
	// Wrap returns the on-wire form of one outbound control packet.
	Wrap(pkt []byte) ([]byte, error)

	// Unwrap returns the plain form of one inbound control packet, or an
	// error if authentication, decryption or replay checking fails.
	Unwrap(pkt []byte) ([]byte, error)

	// Overhead is the number of bytes Wrap adds, for MTU accounting.
	Overhead() int

	// Name is the wrap as the session report should record it:
	// "none", "tls-auth" or "tls-crypt".
	Name() string
}

// NameNone is what Name reports for an unwrapped control channel, which has
// no authentication and no replay protection of its own — a fact about
// OpenVPN rather than an omission here.
const NameNone = "none"

// Plain returns the identity wrapper, so that the client carries no special
// case for an unwrapped control channel. Wrap and Unwrap return the packet
// they were given, without copying it.
func Plain() Wrapper { return plain{} }

// plain is the identity Wrapper. It is an empty struct, so Plain costs
// nothing to call and is concurrency-safe for free.
type plain struct{}

// Wrap returns pkt unchanged.
func (plain) Wrap(pkt []byte) ([]byte, error) { return pkt, nil }

// Unwrap returns pkt unchanged. It cannot fail: there is nothing to
// authenticate, decrypt or replay-check.
func (plain) Unwrap(pkt []byte) ([]byte, error) { return pkt, nil }

// Overhead is zero: the identity transform adds no bytes.
func (plain) Overhead() int { return 0 }

// Name reports the unwrapped control channel as "none".
func (plain) Name() string { return NameNone }
