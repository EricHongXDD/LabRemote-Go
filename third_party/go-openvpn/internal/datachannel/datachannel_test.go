package datachannel_test

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/internal/datachannel"
)

// ---- GCM (default) helpers --------------------------------------------------

func newChannel(t *testing.T) *datachannel.Channel {
	t.Helper()
	txKey := bytes.Repeat([]byte{0x01}, 32)
	txIV := bytes.Repeat([]byte{0x02}, 8) // 8-byte nonce tail
	rxKey := bytes.Repeat([]byte{0x03}, 32)
	rxIV := bytes.Repeat([]byte{0x04}, 8)
	ch, err := datachannel.New(datachannel.WireDataV2, 1, 0, txKey, txIV, rxKey, rxIV)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

// loopbackPair creates two GCM channels wired together:
// channel A's tx == channel B's rx and vice-versa.
func loopbackPair(t *testing.T) (a, b *datachannel.Channel) {
	t.Helper()
	keyA := bytes.Repeat([]byte{0xAA}, 32)
	ivA := bytes.Repeat([]byte{0xBB}, 8)
	keyB := bytes.Repeat([]byte{0xCC}, 32)
	ivB := bytes.Repeat([]byte{0xDD}, 8)

	var err error
	// A sends with keyA/ivA, receives with keyB/ivB
	a, err = datachannel.New(datachannel.WireDataV2, 42, 0, keyA, ivA, keyB, ivB)
	if err != nil {
		t.Fatal(err)
	}
	// B sends with keyB/ivB, receives with keyA/ivA
	b, err = datachannel.New(datachannel.WireDataV2, 42, 0, keyB, ivB, keyA, ivA)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

// ---- CBC helpers ------------------------------------------------------------

// cbcLoopbackPair creates two AES-256-CBC + HMAC-SHA256 channels wired
// together. It is the isolate used wherever one CBC combination is enough; the
// full matrix is in TestCBCMatrixRoundTrip.
func cbcLoopbackPair(t *testing.T) (a, b *datachannel.Channel) {
	t.Helper()
	return cbcLoopbackPairWith(t, 32, crypto.DigestSHA256)
}

// cbcLoopbackPairWith creates two CBC channels wired together for a given AES
// key length and digest. The HMAC keys are full 64-byte static-key slots, which
// is what the client passes: the digest-sized prefix is taken inside
// crypto.NewCBCCipher, so a SHA1 channel and a SHA512 channel built from the
// same slot hold different keys and neither is the whole slot.
func cbcLoopbackPairWith(t *testing.T, keyLen int, digest crypto.Digest) (a, b *datachannel.Channel) {
	t.Helper()
	aesA := bytes.Repeat([]byte{0x11}, keyLen)
	hmacA := bytes.Repeat([]byte{0x22}, 64)
	aesB := bytes.Repeat([]byte{0x33}, keyLen)
	hmacB := bytes.Repeat([]byte{0x44}, 64)

	var err error
	a, err = datachannel.NewCBC(datachannel.WireDataV2, 10, 1, digest, aesA, hmacA, aesB, hmacB)
	if err != nil {
		t.Fatal(err)
	}
	b, err = datachannel.NewCBC(datachannel.WireDataV2, 10, 1, digest, aesB, hmacB, aesA, hmacA)
	if err != nil {
		t.Fatal(err)
	}
	return a, b
}

// ---- Behaviour both cipher suites must share --------------------------------
//
// What is here is the behaviour that has to hold identically whichever suite is
// negotiated, stated once instead of twice.

// suitePairs returns one loopback-pair constructor per cipher suite the data
// channel supports.
func suitePairs() []struct {
	name string
	pair func(*testing.T) (a, b *datachannel.Channel)
} {
	return []struct {
		name string
		pair func(*testing.T) (a, b *datachannel.Channel)
	}{
		{"GCM", loopbackPair},
		{"CBC", cbcLoopbackPair},
	}
}

// TestSequentialPacketsRoundTrip carries a run of packets over one pair, so
// that the packet_id advance is exercised rather than only the first packet.
func TestSequentialPacketsRoundTrip(t *testing.T) {
	for _, s := range suitePairs() {
		t.Run(s.name, func(t *testing.T) {
			a, b := s.pair(t)
			for i := 0; i < 20; i++ {
				msg := []byte{byte(i), byte(i + 10), byte(i + 20)}
				pkt, err := a.Encrypt(msg)
				if err != nil {
					t.Fatalf("i=%d encrypt: %v", i, err)
				}
				plain, err := b.Decrypt(pkt)
				if err != nil {
					t.Fatalf("i=%d decrypt: %v", i, err)
				}
				if !bytes.Equal(plain, msg) {
					t.Fatalf("i=%d mismatch: got % x want % x", i, plain, msg)
				}
			}
		})
	}
}

// TestReplayDetection checks that a packet the receiver has already accepted is
// refused the second time it arrives.
func TestReplayDetection(t *testing.T) {
	for _, s := range suitePairs() {
		t.Run(s.name, func(t *testing.T) {
			a, b := s.pair(t)
			msg := []byte("ip packet")

			pkt, err := a.Encrypt(msg)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if _, err := b.Decrypt(pkt); err != nil {
				t.Fatalf("first decrypt: %v", err)
			}
			// Replay the same packet.
			if _, err := b.Decrypt(pkt); err == nil {
				t.Fatal("expected replay error on second decrypt of same packet")
			}
		})
	}
}

// TestConcurrentReplayRejected delivers one packet from several goroutines at
// once and requires that exactly one of them is accepted: Channel documents
// itself as safe for concurrent use, and a window tested and marked under two
// separate acquisitions of the mutex lets two goroutines both pass before
// either marks. Both ways into the window are raced, because they are separate
// branches — a packet id above the high-water mark, which slides the window,
// and one inside it filling a gap left by reordering.
func TestConcurrentReplayRejected(t *testing.T) {
	const (
		rounds = 20
		racers = 8
	)
	// Each case delivers `deliver` ahead of the contended packet and then
	// hands every racer packet id `contended`.
	cases := []struct {
		name      string
		deliver   []int
		contended int
	}{
		// id 5 arrives with the window topped out at 4: the branch that
		// slides the window up.
		{"AboveWindowTop", []int{1, 2, 3, 4}, 5},
		// id 5 arrives with the window topped out at 8, its bit still
		// clear: the branch that fills a gap inside the window.
		{"InsideWindowGap", []int{1, 2, 3, 4, 6, 7, 8}, 5},
	}

	for _, s := range suitePairs() {
		for _, tc := range cases {
			t.Run(s.name+"/"+tc.name, func(t *testing.T) {
				for round := range rounds {
					a, b := s.pair(t)

					// One pass of Encrypt numbers the packets 1..n in
					// order; the ones this case does not deliver are
					// dropped, which is what reordering looks like from
					// the receiver.
					var pkts []([]byte)
					for i := 1; i <= tc.contended+len(tc.deliver); i++ {
						p, err := a.Encrypt([]byte("ip packet"))
						if err != nil {
							t.Fatalf("encrypt %d: %v", i, err)
						}
						pkts = append(pkts, p)
					}
					for _, id := range tc.deliver {
						if _, err := b.Decrypt(pkts[id-1]); err != nil {
							t.Fatalf("decrypt %d: %v", id, err)
						}
					}
					pkt := pkts[tc.contended-1]

					var (
						wg       sync.WaitGroup
						accepted atomic.Int64
						start    = make(chan struct{})
					)
					for range racers {
						wg.Add(1)
						go func() {
							defer wg.Done()
							<-start
							if _, err := b.Decrypt(pkt); err == nil {
								accepted.Add(1)
							}
						}()
					}
					close(start)
					wg.Wait()

					if got := accepted.Load(); got != 1 {
						t.Fatalf("round %d: %d of %d concurrent deliveries of packet id %d accepted, want exactly 1",
							round, got, racers, tc.contended)
					}
				}
			})
		}
	}
}

// TestShortPacketRejected checks that a packet too short to hold its own
// header, tag and body is refused rather than sliced. For CBC the minimum has
// to track the digest instead of a constant, so a body one byte short of the
// smallest legal one is offered for every digest.
func TestShortPacketRejected(t *testing.T) {
	t.Run("GCM", func(t *testing.T) {
		ch := newChannel(t)
		if _, err := ch.Decrypt(make([]byte, 10)); err == nil {
			t.Fatal("expected error for short packet")
		}
	})
	for _, digest := range []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512} {
		t.Run("CBC/"+digest.String(), func(t *testing.T) {
			_, b := cbcLoopbackPairWith(t, 32, digest)
			// header(4) + tag + IV(16) + one block(16), minus one byte.
			short := make([]byte, 4+digest.Size()+16+16-1)
			if _, err := b.Decrypt(short); err == nil {
				t.Fatal("expected short-packet error")
			}
		})
	}
}

// ---- The cipher-suite matrices ----------------------------------------------

// TestCBCMatrixRoundTrip carries a packet across every AES key length and
// digest the cipher table admits for CBC. It exists at the channel level and
// not just the cipher level because a SHA1 channel produces bodies 12 bytes
// shorter than a 32-byte tag and a SHA512 channel 32 bytes longer, so a
// short-packet check built on a constant fails in both directions.
func TestCBCMatrixRoundTrip(t *testing.T) {
	keyLens := []int{16, 24, 32}
	digests := []crypto.Digest{crypto.DigestSHA1, crypto.DigestSHA256, crypto.DigestSHA512}
	for _, keyLen := range keyLens {
		for _, digest := range digests {
			name := fmt.Sprintf("AES-%d-CBC/%s", keyLen*8, digest)
			t.Run(name, func(t *testing.T) {
				a, b := cbcLoopbackPairWith(t, keyLen, digest)
				// A single-byte payload is the smallest packet the channel
				// can be asked to carry, and the one closest to the
				// short-packet boundary.
				for _, msg := range [][]byte{{0x45}, []byte("ip-over-cbc matrix payload")} {
					pkt, err := a.Encrypt(msg)
					if err != nil {
						t.Fatalf("encrypt: %v", err)
					}
					plain, err := b.Decrypt(pkt)
					if err != nil {
						t.Fatalf("decrypt: %v", err)
					}
					if !bytes.Equal(plain, msg) {
						t.Fatalf("roundtrip mismatch: got %v want %v", plain, msg)
					}
				}
			})
		}
	}
}

// TestGCMKeyLengthsRoundTrip carries a packet across all three AES-GCM key
// lengths, which are now a property of the cipher table rather than something
// the caller slices for itself.
func TestGCMKeyLengthsRoundTrip(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("AES-%d-GCM", keyLen*8), func(t *testing.T) {
			keyA := bytes.Repeat([]byte{0xAA}, keyLen)
			ivA := bytes.Repeat([]byte{0xBB}, 8)
			keyB := bytes.Repeat([]byte{0xCC}, keyLen)
			ivB := bytes.Repeat([]byte{0xDD}, 8)

			a, err := datachannel.New(datachannel.WireDataV2, 42, 0, keyA, ivA, keyB, ivB)
			if err != nil {
				t.Fatal(err)
			}
			b, err := datachannel.New(datachannel.WireDataV2, 42, 0, keyB, ivB, keyA, ivA)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("ip-over-gcm matrix payload")
			pkt, err := a.Encrypt(msg)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			plain, err := b.Decrypt(pkt)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(plain, msg) {
				t.Fatalf("roundtrip mismatch: got %v want %v", plain, msg)
			}
		})
	}
}
