// Package compress implements OpenVPN's data-channel compression framing and
// LZO decompression.
//
// Nothing is compressed on send: every payload goes out behind the
// uncompressed marker. A payload the peer LZO-compressed is decompressed; one
// it LZ4-compressed is refused with ErrCompressed.
//
// # Why the framing is load-bearing
//
// A peer with a compression directive frames *every* data packet, whether or
// not it compressed that packet, and drops what it cannot parse. A client that
// sends an unframed packet to such a peer is silently dropped, and a client
// that strips the wrong number of bytes hands the tunnel an IP packet shifted
// by one — one that decrypts cleanly, passes every authentication check, and
// means nothing.
//
// # The four framings
//
// There are four distinct shapes on the wire, and which one applies is decided
// by the directive *and* its COMP_F_SWAP flag rather than by the algorithm's
// name. All four were measured from real 2.4.12, 2.5.11 and 2.6.22 peers; see
// docker/COMPRESSION-VECTORS.md §6 and testdata/vectors.json.
//
//	directive           payload           wire
//	comp-lzo            not compressed    0xFA ‖ plain
//	comp-lzo            compressed        0x66 ‖ LZO(plain)
//	compress (bare)     not compressed    0xFB ‖ plain[1:] ‖ plain[0]
//	compress lz4        not compressed    0xFB ‖ plain[1:] ‖ plain[0]
//	compress lz4        compressed        0x69 ‖ LZ4(plain), swapped the same way
//	compress lz4-v2     not compressed    plain, unchanged
//	compress lz4-v2     compressed        0x50 0x01 ‖ LZ4(plain)
//	compress stub-v2    not compressed    plain, unchanged
//	comp-lzo no         not compressed    0xFA ‖ plain
//
// The swap is the one a reading of the header cannot predict: the framing byte
// *replaces* the payload's first byte, which moves to the tail, so that the
// rest of the payload keeps its alignment. Prepending where OpenVPN swaps
// shifts every subsequent byte by one, which is the shape of corruption that
// looks like a decryption failure.
//
// # References
//
// Read from the OpenVPN 2.4.12, 2.5.11 and 2.6.22 release tarballs the test rig
// pins (SHA-256 in docker/openvpn-server/versions.env):
//
//   - src/openvpn/comp.h — the framing bytes and COMP_F_SWAP
//   - src/openvpn/options.c, add_option() — which directive sets which flags
//   - src/openvpn/lzo.c — lzo_compress(), lzo_decompress()
//   - src/openvpn/compstub.c — stub_compress(), stubv2_decompress()
//   - src/openvpn/comp-lz4.c — lz4_compress(), lz4v2_compress()
//   - src/openvpn/comp.c — check_compression_settings_valid()
//
// The LZO1X codec is github.com/buengese/go-lzo.
package compress

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	lzo "github.com/buengese/go-lzo"
)

// OpenVPN's compression framing bytes, from src/openvpn/comp.h.
//
// 0x69 announces an LZ4-compressed payload and 0xFA an uncompressed one. A
// reading of comp.h says so, and the vectors in testdata/vectors.json confirm
// it from a real peer's wire bytes.
const (
	// lzoCompressByte is LZO_COMPRESS_BYTE: the payload behind it IS
	// LZO-compressed.
	lzoCompressByte = 0x66
	// lz4CompressByte is LZ4_COMPRESS_BYTE: the payload behind it IS
	// LZ4-compressed.
	lz4CompressByte = 0x69
	// noCompressByte is NO_COMPRESS_BYTE: prepended, payload not compressed.
	noCompressByte = 0xFA
	// noCompressByteSwap is NO_COMPRESS_BYTE_SWAP: payload not compressed,
	// and its first byte has been moved to the tail to keep the remainder
	// aligned.
	noCompressByteSwap = 0xFB
	// algV2IndicatorByte is COMP_ALGV2_INDICATOR_BYTE, the first byte of the
	// two-byte v2 header.
	algV2IndicatorByte = 0x50
	// algV2UncompressedByte is COMP_ALGV2_UNCOMPRESSED_BYTE, the second byte
	// of that header when the payload is not compressed. It is what every
	// v2 *decoder* in 2.4.12, 2.5.11 and 2.6.22 checks for.
	algV2UncompressedByte = 0x00
	// algV2LZ4Byte is COMP_ALGV2_LZ4_BYTE, the second byte of that header
	// when the payload is LZ4-compressed.
	algV2LZ4Byte = 0x01
	// algV2UncompressedAlgID is COMP_ALGV2_UNCOMPRESSED, the *algorithm id* 10,
	// which compv2_escape_data_ifneeded() writes where its own decoder checks
	// for algV2UncompressedByte — see the comment on Wrap's v2 case.
	algV2UncompressedAlgID = 0x0A
)

// Framing is the wire framing a mode uses, which is not the same question as
// which algorithm it names: COMP_F_SWAP is an option flag rather than a
// property of the codec, so two modes over one algorithm can differ on it.
type Framing int

// The four framings OpenVPN puts on a data-channel payload. The prepending and
// swapping forms are distinct: COMP_F_SWAP is set independently of the
// algorithm, so the two cannot be one framing.
const (
	// FramingNone adds nothing on send and strips nothing on receive.
	FramingNone Framing = iota
	// FramingV1 prepends one byte: the algorithm's compress marker, or
	// NO_COMPRESS_BYTE. Used by comp-lzo, and by the non-swapping stub that
	// "comp-lzo no" selects.
	FramingV1
	// FramingV1Swap writes one byte in place of the payload's first byte and
	// moves that byte to the tail. Used by bare "compress" and by
	// "compress lz4" — every mode carrying COMP_F_SWAP.
	FramingV1Swap
	// FramingV2 writes nothing at all for an uncompressed payload, and a
	// 0x50 indicator plus an algorithm byte otherwise. Used by
	// "compress lz4-v2" and "compress stub-v2".
	FramingV2
)

// String names the framing as this package's documentation does.
func (f Framing) String() string {
	switch f {
	case FramingNone:
		return "none"
	case FramingV1:
		return "v1-prepend"
	case FramingV1Swap:
		return "v1-swap"
	case FramingV2:
		return "v2"
	default:
		return fmt.Sprintf("Framing(%d)", int(f))
	}
}

// Mode is the compression setting in force on the data channel: an algorithm
// together with the option flags that decide its framing.
//
// It is deliberately finer-grained than the algorithm name. Bare "compress"
// and "comp-lzo no" both select COMP_ALG_STUB and neither ever compresses, yet
// they put different bytes on the wire, because only the first carries
// COMP_F_SWAP — a flag the directive does not spell out.
type Mode int

// The compression modes this client can frame for. None of them compresses on
// send; ModeLZO, ModeLZ4 and ModeLZ4v2 differ from the stubs only in that a
// peer using them may compress.
const (
	// ModeNone is no compression framing at all: nothing is added on send
	// and nothing is stripped on receive. It is what a profile with no
	// compression directive gets, and what most servers push.
	ModeNone Mode = iota
	// ModeStub is bare "compress" (and "compress stub"): COMP_ALG_STUB with
	// COMP_F_SWAP.
	ModeStub
	// ModeStubNoSwap is "comp-lzo no": COMP_ALG_STUB with no flags, which is
	// the only spelling that reaches the non-swapping stub framing.
	ModeStubNoSwap
	// ModeLZO is "comp-lzo", "comp-lzo yes", "comp-lzo adaptive" and
	// "compress lzo": COMP_ALG_LZO, which never swaps —
	// lzo_compress_init() asserts !(flags & COMP_F_SWAP).
	ModeLZO
	// ModeLZ4 is "compress lz4": COMP_ALG_LZ4 with COMP_F_SWAP, which
	// lz4_compress_init() asserts is set.
	ModeLZ4
	// ModeLZ4v2 is "compress lz4-v2": COMP_ALGV2_LZ4, the v2 framing that
	// adds nothing unless it compressed.
	ModeLZ4v2
	// ModeStubV2 is "compress stub-v2": COMP_ALGV2_UNCOMPRESSED, the v2
	// framing with no codec behind it, which is a way of asking for no
	// framing at all.
	ModeStubV2
)

// String returns the directive that selects this mode, as a .ovpn file or a
// PUSH_REPLY spells it. It is the protocol's own vocabulary rather than a
// diagnostic one, which is why it can serve both.
func (m Mode) String() string {
	switch m {
	case ModeNone:
		return "none"
	case ModeStub:
		return "compress"
	case ModeStubNoSwap:
		return "comp-lzo no"
	case ModeLZO:
		return "comp-lzo"
	case ModeLZ4:
		return "compress lz4"
	case ModeLZ4v2:
		return "compress lz4-v2"
	case ModeStubV2:
		return "compress stub-v2"
	default:
		return fmt.Sprintf("Mode(%d)", int(m))
	}
}

// Algorithm returns OpenVPN's own name for the algorithm behind the mode:
// "lzo", "stub", "stubv2", "lz4" or "lz4v2", matching the compress_alg.name
// field the capture recorded. ModeNone has none and returns "".
func (m Mode) Algorithm() string {
	switch m {
	case ModeNone:
		return ""
	case ModeStub, ModeStubNoSwap:
		return "stub"
	case ModeLZO:
		return "lzo"
	case ModeLZ4:
		return "lz4"
	case ModeLZ4v2:
		return "lz4v2"
	case ModeStubV2:
		return "stubv2"
	default:
		return ""
	}
}

// Framing returns the wire framing this mode uses.
func (m Mode) Framing() Framing {
	switch m {
	case ModeNone:
		return FramingNone
	case ModeLZO, ModeStubNoSwap:
		return FramingV1
	case ModeStub, ModeLZ4:
		return FramingV1Swap
	case ModeLZ4v2, ModeStubV2:
		return FramingV2
	default:
		return FramingNone
	}
}

// Compresses reports whether a peer in this mode may put a genuinely
// compressed payload on the wire. Only these modes are refused by
// "allow-compression no".
func (m Mode) Compresses() bool {
	switch m {
	case ModeLZO, ModeLZ4, ModeLZ4v2:
		return true
	default:
		return false
	}
}

// Decompresses reports whether a Codec decompresses what a peer in this mode
// compresses. Only ModeLZO does; ModeLZ4 and ModeLZ4v2 yield ErrCompressed.
func (m Mode) Decompresses() bool {
	return m == ModeLZO
}

// Overhead is the number of bytes this mode's framing adds to an uncompressed
// payload on send: 1 for the two one-byte framings, 0 for the rest. A v2
// framing adds nothing unless the payload's first byte collides with the
// indicator, which no IP packet's does.
func (m Mode) Overhead() int {
	switch m.Framing() {
	case FramingV1, FramingV1Swap:
		return 1
	default:
		return 0
	}
}

// compressMarker returns the framing byte that announces a genuinely
// compressed payload in this mode, and whether the mode has one. For the v2
// framings it is the *second* header byte rather than the first.
func (m Mode) compressMarker() (byte, bool) {
	switch m {
	case ModeLZO:
		return lzoCompressByte, true
	case ModeLZ4:
		return lz4CompressByte, true
	case ModeLZ4v2:
		return algV2LZ4Byte, true
	default:
		return 0, false
	}
}

// AllowCompression is the --allow-compression policy, which 2.5 introduced and
// which decides whether a compressing algorithm may be enabled at all.
type AllowCompression int

// The --allow-compression values, from src/openvpn/options.c, add_option().
const (
	// AllowUnset is the directive being absent, which is OpenVPN's default
	// and places no restriction of its own.
	AllowUnset AllowCompression = iota
	// AllowNo is "allow-compression no": COMP_F_ALLOW_STUB_ONLY. A framing
	// stub stays legal; an algorithm that can compress is refused, which is
	// what check_compression_settings_valid() enforces.
	AllowNo
	// AllowAsym is "allow-compression asym": accept a compressed payload from
	// the peer, never send one, which this client does whatever the policy.
	AllowAsym
	// AllowYes is "allow-compression yes": compression permitted in both
	// directions. It is the only value under which a 2.5 or 2.6 peer will
	// compress on send at all.
	AllowYes
)

// String names the policy as the directive spells its argument.
func (a AllowCompression) String() string {
	switch a {
	case AllowUnset:
		return "unset"
	case AllowNo:
		return "no"
	case AllowAsym:
		return "asym"
	case AllowYes:
		return "yes"
	default:
		return fmt.Sprintf("AllowCompression(%d)", int(a))
	}
}

// ParseAllowCompression maps the argument of an --allow-compression directive
// to a policy, reporting false for a value OpenVPN would refuse.
func ParseAllowCompression(arg string) (AllowCompression, bool) {
	switch strings.ToLower(strings.TrimSpace(arg)) {
	case "no":
		return AllowNo, true
	case "asym":
		return AllowAsym, true
	case "yes":
		return AllowYes, true
	default:
		return AllowUnset, false
	}
}

// ModeForDirective maps a compression directive — keyword and optional
// argument — to the Mode whose framing it selects, reporting false for a
// keyword that is not a compression directive or an argument OpenVPN refuses.
//
// This is the single place the directive-to-flags table lives: the profile
// parser, the PUSH_REPLY parser and ParseMode all go through it, because a
// mode the profile spells one way and the push spells another must still frame
// the same.
//
// Reference: src/openvpn/options.c, add_option(), the "comp-lzo" and
// "compress" cases, verified against the 2.4.12 tarball the rig pins.
func ModeForDirective(keyword, arg string) (Mode, bool) {
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	arg = strings.ToLower(strings.TrimSpace(arg))

	switch keyword {
	case "comp-lzo":
		// Bare and "adaptive" differ from "yes" only in COMP_F_ADAPTIVE,
		// which decides how eagerly the peer *attempts* compression. The
		// framing is identical, so all three are ModeLZO.
		switch arg {
		case "", "yes", "adaptive":
			return ModeLZO, true
		case "no":
			// COMP_ALG_STUB with flags 0 — the only spelling in OpenVPN
			// that reaches the non-swapping stub.
			return ModeStubNoSwap, true
		default:
			return ModeNone, false
		}
	case "compress":
		switch arg {
		case "", "stub":
			// Both are COMP_ALG_STUB|COMP_F_SWAP. "stub" additionally sets
			// COMP_F_ADVERTISE_STUBS_ONLY, which is a peer-info matter and
			// not a framing one.
			return ModeStub, true
		case "stub-v2":
			return ModeStubV2, true
		case "lzo":
			return ModeLZO, true
		case "lz4":
			return ModeLZ4, true
		case "lz4-v2":
			return ModeLZ4v2, true
		default:
			return ModeNone, false
		}
	default:
		return ModeNone, false
	}
}

// ParseMode inspects a comma-separated option list — a PUSH_REPLY, or a single
// directive on its own — and returns the compression Mode it asks for.
//
// The last compression directive wins, as it does in OpenVPN, where each
// option is applied in turn over the same options struct; a list with no
// compression directive yields ModeNone. Every mode that reaches the data
// channel reaches it through here, so a framing that is right for a Mode this
// parser never produces is not right for anything.
func ParseMode(options string) Mode {
	mode := ModeNone
	for _, token := range strings.Split(options, ",") {
		fields := strings.Fields(token)
		if len(fields) == 0 {
			continue
		}
		arg := ""
		if len(fields) > 1 {
			arg = fields[1]
		}
		if m, ok := ModeForDirective(fields[0], arg); ok {
			mode = m
		}
	}
	return mode
}

// ErrCompressed reports a peer that compressed a payload with an algorithm
// this package cannot decompress. Codec.Unwrap returns a
// *CompressedPayloadError, which names the algorithm and satisfies errors.Is
// against this sentinel.
var ErrCompressed = errors.New("compress: peer sent a compressed payload and no codec is linked")

// CompressedPayloadError is the error Codec.Unwrap returns for a payload
// compressed with an algorithm it cannot decompress. It carries the algorithm
// so that the caller can name it in a ClassUnsupported failure.
type CompressedPayloadError struct {
	// Mode is the session's compression mode.
	Mode Mode
	// Algorithm is OpenVPN's name for the codec the peer used: "lz4" or
	// "lz4v2".
	Algorithm string
	// Marker is the framing byte that announced the compression.
	Marker byte
	// Length is the size of the compressed payload that was refused.
	Length int
}

// Error describes the refused payload, naming the algorithm and the marker.
func (e *CompressedPayloadError) Error() string {
	return fmt.Sprintf("compress: peer compressed this payload with %s (marker 0x%02x, %d bytes) "+
		"and no codec is linked", e.Algorithm, e.Marker, e.Length)
}

// Unwrap returns ErrCompressed so that errors.Is identifies the class of
// failure without the caller having to know the algorithm.
func (e *CompressedPayloadError) Unwrap() error { return ErrCompressed }

// Codec is one session's compression: Wrap frames outgoing payloads for its
// mode, Unwrap strips the framing from incoming ones and decompresses those the
// peer LZO-compressed. It is safe for concurrent use.
type Codec struct {
	mode         Mode
	maxLen       int
	decompressed atomic.Uint64
}

// NewCodec returns the codec for mode m. A decompressed payload may be at most
// maxLen bytes, the tunnel MTU.
func NewCodec(m Mode, maxLen int) *Codec {
	return &Codec{mode: m, maxLen: maxLen}
}

// Mode returns the mode the codec frames for.
func (c *Codec) Mode() Mode { return c.mode }

// Decompressed returns how many payloads Unwrap has decompressed.
func (c *Codec) Decompressed() uint64 { return c.decompressed.Load() }

// Wrap applies the codec's outgoing framing to payload.
//
// The payload is never compressed: the byte written is always the uncompressed
// marker for the framing in force. A peer accepts that marker in every mode,
// and OpenVPN's own compressors emit exactly this whenever compression would
// not shrink the packet.
//
// For ModeNone, and for a v2 framing over a payload that needs no escaping, the
// payload is returned unchanged and unaliased-from; every other case returns a
// fresh slice.
func (c *Codec) Wrap(payload []byte) ([]byte, error) {
	m := c.mode
	framing := m.Framing()
	if framing == FramingNone {
		return payload, nil
	}
	if len(payload) == 0 {
		// OpenVPN's compressors return early on an empty buffer rather than
		// framing one: an empty payload is not a packet, and the swapping
		// form has no first byte to move.
		return nil, fmt.Errorf("compress: %s: refusing to frame an empty payload", m)
	}

	switch framing {
	case FramingV1:
		// lzo_compress() and the non-swapping stub_compress() both prepend
		// one byte and leave the payload alone.
		out := make([]byte, 1+len(payload))
		out[0] = noCompressByte
		copy(out[1:], payload)
		return out, nil

	case FramingV1Swap:
		// stub_compress() and lz4_compress() under COMP_F_SWAP: the framing
		// byte takes the place of the payload's first byte, which moves to
		// the tail. lz4_compress() does this whether or not it compressed.
		out := make([]byte, 1+len(payload))
		out[0] = noCompressByteSwap
		copy(out[1:], payload[1:])
		out[len(out)-1] = payload[0]
		return out, nil

	case FramingV2:
		// stubv2_compress() and lz4v2_compress() add nothing at all unless
		// the payload's first byte collides with the indicator, in which
		// case compv2_escape_data_ifneeded() prepends a two-byte header.
		if payload[0] != algV2IndicatorByte {
			return payload, nil
		}
		// UNTESTED against a real peer, and it cannot be tested by this
		// rig: the first byte of an IPv4 packet is 0x45 and of an IPv6
		// packet 0x6…, never 0x50, so no kernel produces a packet that
		// reaches this branch and no captured vector covers it.
		//
		// The byte written is COMP_ALGV2_UNCOMPRESSED_BYTE (0), which is
		// what stubv2_decompress() and lz4v2_decompress() check for.
		// compv2_escape_data_ifneeded() itself writes COMP_ALGV2_UNCOMPRESSED
		// (the algorithm id, 10) here — identically in 2.4.12, 2.5.11 and
		// 2.6.22 — so upstream's own encoder emits a header its own decoder
		// rejects. We encode from the decoder's constant: what we send has
		// to be readable by the peer, not by us. Unwrap accepts both.
		out := make([]byte, 2+len(payload))
		out[0] = algV2IndicatorByte
		out[1] = algV2UncompressedByte
		copy(out[2:], payload)
		return out, nil

	default:
		return nil, fmt.Errorf("compress: %s: unknown framing %s", m, framing)
	}
}

// Unwrap strips the codec's incoming framing from payload and returns the IP
// packet. An LZO payload decompresses to at most the codec's maxLen; a longer
// or malformed stream is an error.
//
// A payload the peer compressed with LZ4 returns a *CompressedPayloadError,
// which errors.Is matches against ErrCompressed. A framing byte that belongs
// to no known state is an error too: OpenVPN drops such a packet.
func (c *Codec) Unwrap(payload []byte) ([]byte, error) {
	m := c.mode
	framing := m.Framing()
	if framing == FramingNone {
		return payload, nil
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("compress: %s: empty payload, missing framing byte", m)
	}
	marker, hasMarker := m.compressMarker()

	switch framing {
	case FramingV1:
		// lzo_decompress() and the non-swapping stub_decompress(): read the
		// leading byte, drop it, and accept only NO_COMPRESS_BYTE or the
		// algorithm's own compress marker.
		switch head := payload[0]; {
		case head == noCompressByte:
			return payload[1:], nil
		case hasMarker && head == marker:
			return c.decompress(head, payload[1:])
		default:
			return nil, fmt.Errorf("compress: %s: bad framing byte 0x%02x, want 0x%02x",
				m, head, noCompressByte)
		}

	case FramingV1Swap:
		// The inverse of the swap: the framing byte is read off the front,
		// the payload's own first byte comes back from the tail, and the
		// middle keeps its position.
		head := payload[0]
		if len(payload) < 2 {
			return nil, fmt.Errorf("compress: %s: %d-byte payload carries a framing byte and no packet",
				m, len(payload))
		}
		switch {
		case head == noCompressByteSwap:
			out := make([]byte, len(payload)-1)
			out[0] = payload[len(payload)-1]
			copy(out[1:], payload[1:len(payload)-1])
			return out, nil
		case hasMarker && head == marker:
			return c.decompress(head, payload[1:])
		default:
			return nil, fmt.Errorf("compress: %s: bad framing byte 0x%02x, want 0x%02x",
				m, head, noCompressByteSwap)
		}

	case FramingV2:
		// stubv2_decompress() and lz4v2_decompress(): a payload that does
		// not begin with the indicator carries no header and is returned as
		// it stands. This is the branch every stub-v2 packet takes.
		if payload[0] != algV2IndicatorByte {
			return payload, nil
		}
		if len(payload) < 2 {
			return nil, fmt.Errorf("compress: %s: v2 indicator with no algorithm byte", m)
		}
		switch alg := payload[1]; {
		case alg == algV2UncompressedByte, alg == algV2UncompressedAlgID:
			// 0 is what every v2 decoder checks for; 10 is what
			// compv2_escape_data_ifneeded() actually writes. Both are
			// accepted so that a peer's escape is readable whichever of its
			// own two constants it used.
			return payload[2:], nil
		case hasMarker && alg == marker:
			return c.decompress(alg, payload[2:])
		default:
			return nil, fmt.Errorf("compress: %s: bad v2 algorithm byte 0x%02x", m, alg)
		}

	default:
		return nil, fmt.Errorf("compress: %s: unknown framing %s", m, framing)
	}
}

// decompress returns the packet behind a payload the peer compressed, announced
// by marker, or refuses it when the mode's codec is not linked.
func (c *Codec) decompress(marker byte, src []byte) ([]byte, error) {
	if !c.mode.Decompresses() {
		return nil, &CompressedPayloadError{
			Mode: c.mode, Algorithm: c.mode.Algorithm(), Marker: marker, Length: len(src),
		}
	}
	// lzo_decompress() caps the output at the frame size and drops a packet
	// that fails to decode; so does this, at maxLen.
	// Reference: openvpn3-core compress/lzo.hpp CompressLZO::decompress_work() line ~58
	plain, err := lzo.Decompress(make([]byte, c.maxLen), src)
	if err != nil {
		return nil, fmt.Errorf("compress: %s: %w", c.mode, err)
	}
	c.decompressed.Add(1)
	return plain, nil
}

// EffectiveMode returns the compression the data channel must use.
//
// A pushed directive outranks the profile's, because the server names the
// framing it will actually apply and a client that keeps its own frames every
// packet wrong. A profile directive applies when the server pushes nothing,
// the usual case: OpenVPN 2.4's server does not push its compression setting
// at all, so a config saying comp-lzo and a server saying comp-lzo agree
// without a word about it on the wire.
//
// "allow-compression no" refuses a compressing algorithm from *either* source:
// COMP_F_ALLOW_STUB_ONLY, which check_compression_settings_valid() fails the
// connection over rather than quietly downgrading. A framing stub survives.
// pushedMode is ModeNone when the server pushed nothing; "comp-lzo no" pushes
// ModeStubNoSwap, which is distinguishable from it.
func EffectiveMode(profileMode, pushedMode Mode, allow AllowCompression) (Mode, error) {
	mode, source := profileMode, "the profile"
	if pushedMode != ModeNone {
		mode, source = pushedMode, "the server's PUSH_REPLY"
	}
	if allow == AllowNo && mode.Compresses() {
		return ModeNone, fmt.Errorf("compress: %q from %s is refused by "+
			"\"allow-compression no\", which permits framing stubs only", mode, source)
	}
	return mode, nil
}

// PeerDeclaresFraming reports whether a peer's options string says it has a
// compression framework enabled.
//
// The options string is OpenVPN's OCC block, exchanged inside the key-method-2
// packet, and it is the only place a peer states its compression setting: 2.4,
// 2.5 and 2.6 all omit the directive from PUSH_REPLY entirely.
//
// What it can answer is narrower than it looks, and was measured rather than
// assumed. OpenVPN writes the literal token "comp-lzo" whenever any framework
// is on, the v2 stub included: a server configured "compress stub-v2", with no
// comp-lzo directive anywhere, still advertises "comp-lzo" here, while a server
// with no compression advertises nothing. So this answers whether the peer
// expects a framing at all, and never which one — the profile answers that. A
// client that framed on its own profile against a peer that declared nothing
// would put a leading byte on every packet the peer discards: a handshake that
// completes over a tunnel that carries nothing.
func PeerDeclaresFraming(occ string) bool {
	for _, tok := range strings.Split(occ, ",") {
		field := strings.Fields(strings.TrimSpace(tok))
		if len(field) == 0 {
			continue
		}
		switch field[0] {
		case "comp-lzo":
			// "comp-lzo no" is the explicit off form: framing stays on, and
			// OpenVPN writes it here exactly because the peer still expects
			// the byte.
			return true
		case "compress":
			return true
		}
	}
	return false
}
