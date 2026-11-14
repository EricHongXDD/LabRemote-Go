package wrap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/buengese/go-openvpn/internal/crypto"
)

// The identity wrap, the fixtures every wrap's unit tests share, and the
// properties all of them have to satisfy — driven from one table, so that a
// wrap added later has to answer the same questions.

// -------------------------------------------------------------------------
// Plain: the identity wrap
// -------------------------------------------------------------------------

// TestPlainIsIdentity pins the one property the seam relies on: installing
// Plain changes no byte on the wire. Routing the control channel through a
// Wrapper stays a pure refactor only for as long as this holds.
func TestPlainIsIdentity(t *testing.T) {
	w := Plain()
	cases := map[string][]byte{
		"empty":       {},
		"hard reset":  {0x38, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00},
		"control v1":  {0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x16, 0x03, 0x01},
		"ack":         {0x28, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00},
		"all bit set": bytes.Repeat([]byte{0xff}, 1500),
	}
	for name, pkt := range cases {
		t.Run(name, func(t *testing.T) {
			wrapped, err := w.Wrap(pkt)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if !bytes.Equal(wrapped, pkt) {
				t.Fatalf("Wrap changed the packet:\n got %x\nwant %x", wrapped, pkt)
			}
			plainAgain, err := w.Unwrap(wrapped)
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if !bytes.Equal(plainAgain, pkt) {
				t.Fatalf("Unwrap changed the packet:\n got %x\nwant %x", plainAgain, pkt)
			}
		})
	}
}

// TestPlainAcceptsNil guards the boundary the client can reach: a reset packet
// carries no payload, and several send paths build one from a nil slice.
func TestPlainAcceptsNil(t *testing.T) {
	w := Plain()
	if got, err := w.Wrap(nil); err != nil || len(got) != 0 {
		t.Fatalf("Wrap(nil) = %x, %v; want empty, nil", got, err)
	}
	if got, err := w.Unwrap(nil); err != nil || len(got) != 0 {
		t.Fatalf("Unwrap(nil) = %x, %v; want empty, nil", got, err)
	}
}

// TestPlainOverheadIsZero is what lets the seam be installed without moving an
// MTU. The client subtracts Overhead from the control-channel segment budget,
// so a non-zero value here would silently reshape every control packet.
func TestPlainOverheadIsZero(t *testing.T) {
	if got := Plain().Overhead(); got != 0 {
		t.Fatalf("Plain().Overhead() = %d, want 0", got)
	}
}

// TestWrapNamesAreTheReportedValues pins the strings the session report
// records, which an aggregator reads as values and not as prose.
func TestWrapNamesAreTheReportedValues(t *testing.T) {
	auth, err := NewTLSAuth(testKey(), Direction1, crypto.DigestSHA1)
	if err != nil {
		t.Fatalf("NewTLSAuth: %v", err)
	}
	crypt, err := NewTLSCrypt(testKey())
	if err != nil {
		t.Fatalf("NewTLSCrypt: %v", err)
	}
	for _, tc := range []struct {
		w        Wrapper
		constant string
		want     string
	}{
		{Plain(), NameNone, "none"},
		{auth, NameTLSAuth, "tls-auth"},
		{crypt, NameTLSCrypt, "tls-crypt"},
	} {
		if got := tc.w.Name(); got != tc.want {
			t.Errorf("Name() = %q, want %q", got, tc.want)
		}
		if tc.constant != tc.want {
			t.Errorf("the exported constant beside %q is %q", tc.want, tc.constant)
		}
	}
}

// -------------------------------------------------------------------------
// Shared fixtures
// -------------------------------------------------------------------------

// testKey builds a 256-byte static key whose every byte is distinguishable, so
// a wrong offset produces a wrong key rather than a coincidence.
func testKey() *StaticKey {
	var k StaticKey
	for i := range k {
		k[i] = byte(i)
	}
	return &k
}

// controlPacket builds a plausible plain control packet of the given size.
func controlPacket(n int) []byte {
	pkt := make([]byte, n)
	pkt[0] = 0x38 // P_CONTROL_HARD_RESET_CLIENT_V2, key_id 0
	for i := 1; i < n; i++ {
		pkt[i] = byte(i * 7)
	}
	return pkt
}

// pair builds the two tls-auth wrappers a client and a server run for one
// direction, as the client's .ovpn spells it: the server runs the complement.
func pair(t *testing.T, clientDir Direction, digest crypto.Digest) (client, server Wrapper) {
	t.Helper()
	serverDir := clientDir
	switch clientDir {
	case Direction0:
		serverDir = Direction1
	case Direction1:
		serverDir = Direction0
	case DirectionAbsent:
		// Both peers use slot 0 in both directions; there is no complement
		// to take.
	}
	key := testKey()
	c, err := NewTLSAuth(key, clientDir, digest)
	if err != nil {
		t.Fatalf("client NewTLSAuth: %v", err)
	}
	s, err := NewTLSAuth(key, serverDir, digest)
	if err != nil {
		t.Fatalf("server NewTLSAuth: %v", err)
	}
	return c, s
}

// cryptPair builds the two tls-crypt wrappers a client and a server run over
// one static key. There is no direction to pass: tls-crypt's halves follow the
// role.
func cryptPair(t *testing.T) (client, server Wrapper) {
	t.Helper()
	key := testKey()
	c, err := NewTLSCrypt(key)
	if err != nil {
		t.Fatalf("client NewTLSCrypt: %v", err)
	}
	s, err := newTLSCrypt(key, roleServer)
	if err != nil {
		t.Fatalf("server newTLSCrypt: %v", err)
	}
	return c, s
}

// refusal is one unusable constructor input and the error the constructor gave
// back for it.
type refusal struct {
	what string
	err  error
}

// wrapCase is one wrap in one configuration, together with everything the
// shared properties below need in order to drive it.
type wrapCase struct {
	name string
	// peers builds the client and the server that run this configuration
	// over one static key.
	peers func(t *testing.T) (client, server Wrapper)
	// packetIDOffset is where the 4-byte replay counter lands on the wire:
	// tls-auth carries the replay header after the tag, tls-crypt
	// immediately after the 9-byte clear header.
	packetIDOffset int
	// refusals runs the constructor's guards over a usable key and returns
	// what each one said. Every guard is a configuration error that must
	// surface before a socket opens.
	refusals func(key *StaticKey) []refusal
}

// wrapCases is every wrap the shared properties are asserted over. tls-auth
// appears once per direction and digest — the key halves move with the
// direction, the tag length with the digest — and tls-crypt has neither axis.
func wrapCases() []wrapCase {
	var cases []wrapCase
	for _, dir := range []Direction{DirectionAbsent, Direction0, Direction1} {
		for _, digest := range []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512} {
			cases = append(cases, wrapCase{
				name: fmt.Sprintf("tls-auth/kd=%s/%s", dir, digest),
				peers: func(t *testing.T) (Wrapper, Wrapper) {
					return pair(t, dir, digest)
				},
				packetIDOffset: controlHeaderLen + digest.Size(),
				refusals: func(key *StaticKey) []refusal {
					_, nilKey := NewTLSAuth(nil, dir, digest)
					_, badDigest := NewTLSAuth(key, dir, crypto.Digest(99))
					_, badDir := NewTLSAuth(key, Direction(99), digest)
					return []refusal{
						{"a nil key", nilKey},
						{"an undefined digest", badDigest},
						{"an undefined direction", badDir},
					}
				},
			})
		}
	}
	return append(cases, wrapCase{
		name:           "tls-crypt",
		peers:          cryptPair,
		packetIDOffset: controlHeaderLen,
		refusals: func(key *StaticKey) []refusal {
			// No digest to parse and no direction to validate:
			// tls_crypt_kt() fixes the algorithms and the role is
			// not configurable, so a missing key is the whole surface.
			_, nilKey := NewTLSCrypt(nil)
			_, badRole := newTLSCrypt(key, peerRole(99))
			return []refusal{
				{"a nil key", nilKey},
				{"an undefined role", badRole},
			}
		},
	})
}

// -------------------------------------------------------------------------
// The properties every wrap has
// -------------------------------------------------------------------------

// TestWrapRoundTripsBetweenPeers drives both peers against each other — the
// vectors record one peer's output, not two peers agreeing — and ties Overhead
// to what Wrap actually costs on every packet shape, including the boundary of
// a bare 9-byte header carrying no payload.
func TestWrapRoundTripsBetweenPeers(t *testing.T) {
	for _, tc := range wrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			client, server := tc.peers(t)
			for i, size := range []int{controlHeaderLen, 14, 22, 26, 287, 1088, 1144} {
				plain := controlPacket(size)

				wire, err := client.Wrap(plain)
				if err != nil {
					t.Fatalf("client Wrap: %v", err)
				}
				if got := len(wire) - len(plain); got != client.Overhead() {
					t.Fatalf("packet %d: Wrap added %d bytes to a %d-byte packet, Overhead() says %d",
						i, got, len(plain), client.Overhead())
				}
				got, err := server.Unwrap(wire)
				if err != nil {
					t.Fatalf("server Unwrap of packet %d: %v", i, err)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("client→server: got %x, want %x", got, plain)
				}

				wire, err = server.Wrap(plain)
				if err != nil {
					t.Fatalf("server Wrap: %v", err)
				}
				got, err = client.Unwrap(wire)
				if err != nil {
					t.Fatalf("client Unwrap of packet %d: %v", i, err)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("server→client: got %x, want %x", got, plain)
				}
			}
		})
	}
}

// TestWrapRefusesAHeaderlessPacket pins the outbound boundary: a packet with no
// opcode and session id cannot be split around the wrap's own fields, and
// tls-crypt would encrypt the header the peer needs to find the session at all.
func TestWrapRefusesAHeaderlessPacket(t *testing.T) {
	for _, tc := range wrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := tc.peers(t)
			for n := 0; n < controlHeaderLen; n++ {
				if _, err := client.Wrap(make([]byte, n)); err == nil {
					t.Fatalf("Wrap of a %d-byte packet succeeded", n)
				}
			}
			if _, err := client.Wrap(make([]byte, controlHeaderLen)); err != nil {
				t.Fatalf("Wrap of a bare %d-byte header: %v", controlHeaderLen, err)
			}
		})
	}
}

// TestWrapCounterStartsAtOneAndClimbs pins the send-side counter: it starts at
// 1, not the 0 the peer rejects. Reading it back off the wire also checks that
// the replay header sits where each wrap puts it, which the two disagree on.
func TestWrapCounterStartsAtOneAndClimbs(t *testing.T) {
	for _, tc := range wrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := tc.peers(t)
			for want := uint32(1); want <= 5; want++ {
				wire, err := client.Wrap(controlPacket(14))
				if err != nil {
					t.Fatalf("Wrap: %v", err)
				}
				if got := binary.BigEndian.Uint32(wire[tc.packetIDOffset:]); got != want {
					t.Fatalf("packet id %d, want %d", got, want)
				}
			}
		})
	}
}

// TestWrapReplayWindowIsPerWrapper pins that a duplicate is ErrReplay and not
// ErrAuth — a replayed packet authenticated, so the key is right and the path
// duplicated it — and that a fresh wrap starts a fresh window, or a peer
// restarting its packet ids at 1 would look like a run of replays.
func TestWrapReplayWindowIsPerWrapper(t *testing.T) {
	for _, tc := range wrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			client, server := tc.peers(t)
			wire, err := server.Wrap(controlPacket(14))
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if _, err := client.Unwrap(wire); err != nil {
				t.Fatalf("first delivery: %v", err)
			}
			if _, err := client.Unwrap(wire); !errors.Is(err, ErrReplay) {
				t.Fatalf("second delivery: err = %v, want ErrReplay", err)
			}

			fresh, _ := tc.peers(t)
			if _, err := fresh.Unwrap(wire); err != nil {
				t.Fatalf("a new connection's window must not remember the old one's ids: %v", err)
			}
		})
	}
}

// TestWrapRejectsAStaleTimestamp pins that a packet whose timestamp goes
// backwards is refused even though it authenticates. It has to be built rather
// than mutated: under both wraps the replay header is inside the digest, so
// changing the timestamp on the wire invalidates the tag.
func TestWrapRejectsAStaleTimestamp(t *testing.T) {
	for _, tc := range wrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			client, server := tc.peers(t)

			SetReplayHeaderForTest(server, 1, 2000)
			first, err := server.Wrap(controlPacket(14))
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			SetReplayHeaderForTest(server, 2, 1000)
			stale, err := server.Wrap(controlPacket(14))
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}

			if _, err := client.Unwrap(first); err != nil {
				t.Fatalf("first delivery: %v", err)
			}
			if _, err := client.Unwrap(stale); !errors.Is(err, ErrStaleTimestamp) {
				t.Fatalf("stale delivery: err = %v, want ErrStaleTimestamp", err)
			}
		})
	}
}

// TestWrapIsConcurrencySafe drives one wrapper from many goroutines in both
// directions at once, which is what Wrapper's doc comment promises. The
// assertion is that every packet id the send side stamps is distinct: two
// goroutines sharing a counter corrupts a session under load. Run with -race.
func TestWrapIsConcurrencySafe(t *testing.T) {
	const (
		goroutines = 8
		each       = 100
	)
	for _, tc := range wrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			client, server := tc.peers(t)

			// Give the receiving side something to do at the same time.
			inbound, err := server.Wrap(controlPacket(64))
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}

			var mu sync.Mutex
			ids := make(map[uint32]bool, goroutines*each)

			var wg sync.WaitGroup
			for g := 0; g < goroutines; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < each; i++ {
						wire, werr := client.Wrap(controlPacket(40))
						if werr != nil {
							t.Errorf("Wrap: %v", werr)
							return
						}
						id := binary.BigEndian.Uint32(wire[tc.packetIDOffset:])
						mu.Lock()
						dup := ids[id]
						ids[id] = true
						mu.Unlock()
						if dup {
							t.Errorf("packet id %d stamped twice", id)
							return
						}
						// Exactly one of these succeeds; the rest are
						// replays. Either answer is fine, a data race
						// is not.
						client.Unwrap(inbound) //nolint:errcheck
					}
				}()
			}
			wg.Wait()

			if len(ids) != goroutines*each {
				t.Fatalf("%d distinct packet ids from %d packets", len(ids), goroutines*each)
			}
		})
	}
}

// TestConstructorsRefuseUnusableInputs covers each wrap's guards. See
// wrapCase.refusals for why they all have to fire in the constructor.
func TestConstructorsRefuseUnusableInputs(t *testing.T) {
	for _, tc := range wrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, r := range tc.refusals(testKey()) {
				if r.err == nil {
					t.Errorf("the constructor accepted %s", r.what)
				}
			}
		})
	}
}

// TestErrorsCarryNoKeyMaterial applies the profile parser's redaction check to
// the wraps: a static key is a secret, and an error is the easiest way for one
// to escape into a log.
func TestErrorsCarryNoKeyMaterial(t *testing.T) {
	for _, tc := range wrapCases() {
		t.Run(tc.name, func(t *testing.T) {
			key := testKey()
			w, _ := tc.peers(t)

			var messages []string
			if _, err := w.Wrap(controlPacket(4)); err != nil {
				messages = append(messages, err.Error())
			}
			if _, err := w.Unwrap(make([]byte, 5)); err != nil {
				messages = append(messages, err.Error())
			}
			for _, r := range tc.refusals(key) {
				if r.err != nil {
					messages = append(messages, r.err.Error())
				}
			}
			messages = append(messages, fmt.Sprintf("%v %s %#v", key, key, key))
			messages = append(messages, fmt.Sprintf("%v %s", w, w))
			j, err := key.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			messages = append(messages, string(j))

			// Every 8-byte run of the key, as hex — a substring scan of the
			// kind diag's redaction is tested with, rather than a check
			// that any single rendering happens to be safe.
			for off := 0; off+8 <= len(key); off += 8 {
				needle := fmt.Sprintf("%x", key[off:off+8])
				for _, m := range messages {
					if strings.Contains(strings.ToLower(m), needle) {
						t.Fatalf("key bytes at offset %d leaked into %q", off, m)
					}
				}
			}
			if len(messages) < 6 {
				t.Fatalf("only %d renderings scanned; the guard is not covering the error paths",
					len(messages))
			}
		})
	}
}
