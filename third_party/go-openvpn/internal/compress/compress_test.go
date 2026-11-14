// Unit tests for the compression framing: the parser, the four wire framings,
// the refusals, and the precedence between a profile's directive and a pushed
// one.
//
// What is here is what no captured vector can reach: directives no probe
// produces ("comp-lzo no", "compress stub"), hostile framing bytes a
// well-behaved peer never emits, and allow-compression, which is a client-side
// policy and puts nothing on the wire at all. Section 6 of
// docker/COMPRESSION-VECTORS.md names those as the gaps.
package compress_test

import (
	"bytes"
	"errors"
	"testing"

	lzo "github.com/buengese/go-lzo"

	"github.com/buengese/go-openvpn/internal/compress"
)

// mtu bounds decompression in the tests that do not exercise the bound.
const mtu = 1500

// TestParseModeReadsEveryDirective walks the directive-to-mode table: a
// directive read as ModeNone sends unframed packets to a peer that frames
// every one of them.
func TestParseModeReadsEveryDirective(t *testing.T) {
	cases := []struct {
		options string
		want    compress.Mode
		why     string
	}{
		{"PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,cipher AES-256-GCM", compress.ModeNone,
			"a reply with no compression directive"},
		{"PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,comp-lzo", compress.ModeLZO,
			"bare comp-lzo is COMP_ALG_LZO with COMP_F_ADAPTIVE"},
		{"comp-lzo yes", compress.ModeLZO, "yes is the same algorithm with adaptive off"},
		{"comp-lzo adaptive", compress.ModeLZO, "adaptive is the bare form spelled out"},
		{"comp-lzo no", compress.ModeStubNoSwap,
			"the only spelling that reaches COMP_ALG_STUB with no flags"},
		{"compress", compress.ModeStub, "bare compress is COMP_ALG_STUB with COMP_F_SWAP"},
		{"compress stub", compress.ModeStub, "stub sets the same two"},
		{"compress stub-v2", compress.ModeStubV2, "COMP_ALGV2_UNCOMPRESSED"},
		{"compress lzo", compress.ModeLZO, "COMP_ALG_LZO with flags 0"},
		{"compress lz4", compress.ModeLZ4, "COMP_ALG_LZ4 with COMP_F_SWAP"},
		{"compress lz4-v2", compress.ModeLZ4v2, "COMP_ALGV2_LZ4"},
		{"PUSH_REPLY,route 10.0.0.0 255.255.0.0,compress lz4,ping 10", compress.ModeLZ4,
			"a directive in the middle of a reply"},
		{"  compress   lz4  ", compress.ModeLZ4, "surrounding and inner whitespace"},
		{"PUSH_REPLY,comp-lzo,compress lz4", compress.ModeLZ4,
			"the last compression option wins, as it does in OpenVPN's options struct"},
		{"compress snappy", compress.ModeNone,
			"an algorithm OpenVPN refuses is not a mode this client invents one for"},
		{"comp-noadapt", compress.ModeNone,
			"comp-noadapt changes COMP_F_ADAPTIVE and selects no algorithm of its own"},
	}
	for _, tc := range cases {
		if got := compress.ParseMode(tc.options); got != tc.want {
			t.Errorf("ParseMode(%q) = %v, want %v — %s", tc.options, got, tc.want, tc.why)
		}
	}
}

// TestModeFramingAndOverhead pins which framing each mode uses: the prepending
// and the swapping form are distinct and cannot share one code path.
func TestModeFramingAndOverhead(t *testing.T) {
	cases := []struct {
		mode       compress.Mode
		framing    compress.Framing
		overhead   int
		compresses bool
	}{
		{compress.ModeNone, compress.FramingNone, 0, false},
		{compress.ModeLZO, compress.FramingV1, 1, true},
		{compress.ModeStubNoSwap, compress.FramingV1, 1, false},
		{compress.ModeStub, compress.FramingV1Swap, 1, false},
		{compress.ModeLZ4, compress.FramingV1Swap, 1, true},
		{compress.ModeLZ4v2, compress.FramingV2, 0, true},
		{compress.ModeStubV2, compress.FramingV2, 0, false},
	}
	for _, tc := range cases {
		if got := tc.mode.Framing(); got != tc.framing {
			t.Errorf("%v.Framing() = %v, want %v", tc.mode, got, tc.framing)
		}
		if got := tc.mode.Overhead(); got != tc.overhead {
			t.Errorf("%v.Overhead() = %d, want %d", tc.mode, got, tc.overhead)
		}
		if got := tc.mode.Compresses(); got != tc.compresses {
			t.Errorf("%v.Compresses() = %v, want %v", tc.mode, got, tc.compresses)
		}
	}
}

// TestRoundTripEveryFraming requires that whatever Wrap writes, Unwrap
// recovers, for every mode and for payload lengths either side of the
// framings' own edges.
func TestRoundTripEveryFraming(t *testing.T) {
	modes := []compress.Mode{
		compress.ModeNone, compress.ModeStub, compress.ModeStubNoSwap,
		compress.ModeLZO, compress.ModeLZ4, compress.ModeLZ4v2, compress.ModeStubV2,
	}
	for _, m := range modes {
		for _, n := range []int{1, 2, 20, 1500} {
			plain := make([]byte, n)
			for i := range plain {
				plain[i] = byte(0x45 + i)
			}
			codec := compress.NewCodec(m, mtu)
			framed, err := codec.Wrap(plain)
			if err != nil {
				t.Fatalf("Wrap(%v, %d bytes): %v", m, n, err)
			}
			if want := n + m.Overhead(); len(framed) != want {
				t.Errorf("Wrap(%v, %d bytes) produced %d bytes, want %d", m, n, len(framed), want)
			}
			got, err := codec.Unwrap(framed)
			if err != nil {
				t.Fatalf("Unwrap(%v, %d framed bytes): %v", m, len(framed), err)
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("Unwrap(Wrap(%v, %d bytes)) = %x, want %x", m, n, got, plain)
			}
		}
	}
}

// TestWrapDoesNotAliasThePayload guards the aliasing mistake that would be
// invisible: a framing that returns a slice of the caller's buffer, which the
// next packet then reuses. Only the pass-through cases may share.
func TestWrapDoesNotAliasThePayload(t *testing.T) {
	plain := []byte{0x45, 0x11, 0x22, 0x33}
	for _, m := range []compress.Mode{compress.ModeLZO, compress.ModeStub, compress.ModeLZ4} {
		framed, err := compress.NewCodec(m, mtu).Wrap(plain)
		if err != nil {
			t.Fatalf("Wrap(%v): %v", m, err)
		}
		framed[1] = 0xEE
		if plain[1] == 0xEE {
			t.Errorf("Wrap(%v) returned a slice aliasing the caller's payload", m)
		}
	}
}

// TestSwapMovesTheFirstByteToTheTail states the shape of the swap on its own:
// it is the half of the contract a reading of comp.h does not give, and the
// half whose absence shifts every byte of every packet by one.
func TestSwapMovesTheFirstByteToTheTail(t *testing.T) {
	plain := []byte{0x45, 0xAA, 0xBB, 0xCC}
	want := []byte{0xFB, 0xAA, 0xBB, 0xCC, 0x45}
	for _, m := range []compress.Mode{compress.ModeStub, compress.ModeLZ4} {
		got, err := compress.NewCodec(m, mtu).Wrap(plain)
		if err != nil {
			t.Fatalf("Wrap(%v): %v", m, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Wrap(%v, %x) = %x, want %x — the framing byte replaces the "+
				"first byte, which moves to the tail", m, plain, got, want)
		}
	}
	// And the prepending form, for the same payload, so the two shapes are
	// side by side in one failure message.
	got, err := compress.NewCodec(compress.ModeLZO, mtu).Wrap(plain)
	if err != nil {
		t.Fatalf("Wrap(comp-lzo): %v", err)
	}
	if wantLZO := []byte{0xFA, 0x45, 0xAA, 0xBB, 0xCC}; !bytes.Equal(got, wantLZO) {
		t.Errorf("Wrap(comp-lzo, %x) = %x, want %x — comp-lzo never swaps", plain, got, wantLZO)
	}
}

// TestUnwrapDecompressesLZO covers the LZO path and its bound: a payload past
// maxLen, or a stream that does not decode, is an error but not ErrCompressed,
// so the data path drops the packet rather than the session.
func TestUnwrapDecompressesLZO(t *testing.T) {
	plain := bytes.Repeat([]byte{0x45, 0x00, 0x05, 0xdc}, 300)
	framed := append([]byte{0x66}, lzo.Compress(nil, plain)...)

	codec := compress.NewCodec(compress.ModeLZO, len(plain))
	got, err := codec.Unwrap(framed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Unwrap = %d bytes, %v; want the %d-byte packet", len(got), err, len(plain))
	}
	if n := codec.Decompressed(); n != 1 {
		t.Errorf("Decompressed = %d, want 1", n)
	}

	for _, tc := range []struct {
		framed []byte
		maxLen int
		why    string
	}{
		{framed, len(plain) - 1, "one byte past the bound"},
		{framed[:len(framed)-1], mtu, "a truncated stream"},
		{append(framed, 0x00), mtu, "bytes after the end of the stream"},
		{[]byte{0x66, 0x01, 0x02, 0x03}, mtu, "a stream that is not LZO at all"},
	} {
		_, err := compress.NewCodec(compress.ModeLZO, tc.maxLen).Unwrap(tc.framed)
		if err == nil || errors.Is(err, compress.ErrCompressed) {
			t.Errorf("%s: Unwrap = %v, want a decompression error", tc.why, err)
		}
	}
}

// TestUnwrapRefusesACompressedPayload covers each mode whose codec is not
// linked, with the marker its own algorithm uses.
func TestUnwrapRefusesACompressedPayload(t *testing.T) {
	cases := []struct {
		mode    compress.Mode
		framed  []byte
		wantAlg string
	}{
		{compress.ModeLZ4, []byte{0x69, 0x01, 0x02, 0x03}, "lz4"},
		{compress.ModeLZ4v2, []byte{0x50, 0x01, 0x02, 0x03}, "lz4v2"},
	}
	for _, tc := range cases {
		got, err := compress.NewCodec(tc.mode, mtu).Unwrap(tc.framed)
		if err == nil {
			t.Errorf("Unwrap(%v, %x) returned %x and no error; a compressed blob must "+
				"never reach the tunnel as an IP packet", tc.mode, tc.framed, got)
			continue
		}
		if !errors.Is(err, compress.ErrCompressed) {
			t.Errorf("Unwrap(%v, %x) = %v, want ErrCompressed", tc.mode, tc.framed, err)
		}
		var cpe *compress.CompressedPayloadError
		if !errors.As(err, &cpe) {
			t.Errorf("Unwrap(%v, %x) = %v, want a *CompressedPayloadError so the "+
				"failure can name the algorithm", tc.mode, tc.framed, err)
			continue
		}
		if cpe.Algorithm != tc.wantAlg {
			t.Errorf("Unwrap(%v, %x) named %q, want %q", tc.mode, tc.framed, cpe.Algorithm, tc.wantAlg)
		}
	}
}

// TestUnwrapRefusesAHostileFramingByte requires that a byte belonging to no
// state is refused rather than stripped: stripping it hands the tunnel a
// packet short of its first byte.
func TestUnwrapRefusesAHostileFramingByte(t *testing.T) {
	cases := []struct {
		mode   compress.Mode
		framed []byte
		why    string
	}{
		{compress.ModeLZO, []byte{0x00, 0x45, 0x01}, "0x00 is neither 0xFA nor 0x66"},
		{compress.ModeLZO, []byte{0xFB, 0x45, 0x01}, "the swapping marker in a mode that never swaps"},
		{compress.ModeStubNoSwap, []byte{0x66, 0x45, 0x01}, "a stub cannot have compressed anything"},
		{compress.ModeStub, []byte{0xFA, 0x45, 0x01}, "the prepending marker in a swapping mode"},
		{compress.ModeStub, []byte{0x69, 0x45, 0x01}, "a stub cannot have compressed anything"},
		{compress.ModeLZ4, []byte{0xFF, 0x45, 0x01}, "0xFF is not a framing byte at all"},
		{compress.ModeLZ4, []byte{0xFB}, "a framing byte and no packet behind it"},
		{compress.ModeLZO, []byte{}, "an empty payload has no framing byte"},
		{compress.ModeLZ4v2, []byte{0x50}, "a v2 indicator with no algorithm byte"},
		{compress.ModeLZ4v2, []byte{0x50, 0x7F, 0x45}, "0x7F is no v2 algorithm"},
		{compress.ModeStubV2, []byte{0x50, 0x7F, 0x45}, "same, on the codec-free v2 mode"},
	}
	for _, tc := range cases {
		got, err := compress.NewCodec(tc.mode, mtu).Unwrap(tc.framed)
		if err == nil {
			t.Errorf("Unwrap(%v, %x) returned %x and no error — %s", tc.mode, tc.framed, got, tc.why)
		}
	}
}

// TestV2FramingLeavesAnIPPacketAlone pins that the v2 framings add nothing to
// a packet that does not begin with the indicator, and no IP packet does.
func TestV2FramingLeavesAnIPPacketAlone(t *testing.T) {
	plain := []byte{0x45, 0x00, 0x00, 0x3c, 0x11, 0x22}
	for _, m := range []compress.Mode{compress.ModeStubV2, compress.ModeLZ4v2} {
		codec := compress.NewCodec(m, mtu)
		framed, err := codec.Wrap(plain)
		if err != nil {
			t.Fatalf("Wrap(%v): %v", m, err)
		}
		if !bytes.Equal(framed, plain) {
			t.Errorf("Wrap(%v, %x) = %x, want the payload unchanged", m, plain, framed)
		}
		got, err := codec.Unwrap(plain)
		if err != nil {
			t.Fatalf("Unwrap(%v): %v", m, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("Unwrap(%v, %x) = %x, want the payload unchanged", m, plain, got)
		}
	}
}

// TestV2EscapeUsesTheDecodersConstant covers compv2_escape_data_ifneeded(),
// unreachable against a real peer because no IP packet starts with 0x50. The
// encoder writes COMP_ALGV2_UNCOMPRESSED_BYTE (0) because that is what every v2
// decoder in 2.4.12, 2.5.11 and 2.6.22 checks for, while upstream's own encoder
// writes the algorithm id 10, so the decoder accepts both.
func TestV2EscapeUsesTheDecodersConstant(t *testing.T) {
	plain := []byte{0x50, 0xAA, 0xBB}
	for _, m := range []compress.Mode{compress.ModeStubV2, compress.ModeLZ4v2} {
		codec := compress.NewCodec(m, mtu)
		framed, err := codec.Wrap(plain)
		if err != nil {
			t.Fatalf("Wrap(%v): %v", m, err)
		}
		want := []byte{0x50, 0x00, 0x50, 0xAA, 0xBB}
		if !bytes.Equal(framed, want) {
			t.Errorf("Wrap(%v, %x) = %x, want %x — the escape must carry the byte "+
				"stubv2_decompress() checks for", m, plain, framed, want)
		}
		got, err := codec.Unwrap(framed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("Unwrap(%v, %x) = %x, %v; want %x and no error", m, framed, got, err, plain)
		}
		// What a real peer's encoder actually writes.
		upstream := []byte{0x50, 0x0A, 0x50, 0xAA, 0xBB}
		got, err = codec.Unwrap(upstream)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("Unwrap(%v, %x) = %x, %v; want %x and no error — 0x0A is what "+
				"compv2_escape_data_ifneeded() emits", m, upstream, got, err, plain)
		}
	}
}

// TestEffectiveModePrecedence states the rule the data channel needs and the
// two sources it reconciles: OpenVPN 2.4's server does not push its compression
// setting, so a comp-lzo profile against a comp-lzo server negotiates by
// silence, and a client reading only the PUSH_REPLY frames nothing.
func TestEffectiveModePrecedence(t *testing.T) {
	cases := []struct {
		name    string
		profile compress.Mode
		pushed  compress.Mode
		allow   compress.AllowCompression
		want    compress.Mode
		wantErr bool
	}{
		{"neither side asks for anything",
			compress.ModeNone, compress.ModeNone, compress.AllowUnset, compress.ModeNone, false},
		{"the profile asks and the server is silent",
			compress.ModeLZO, compress.ModeNone, compress.AllowUnset, compress.ModeLZO, false},
		{"the server pushes and the profile is silent",
			compress.ModeNone, compress.ModeStub, compress.AllowUnset, compress.ModeStub, false},
		{"a pushed directive outranks the profile's",
			compress.ModeLZO, compress.ModeLZ4, compress.AllowUnset, compress.ModeLZ4, false},
		{"a pushed comp-lzo no outranks a profile comp-lzo",
			compress.ModeLZO, compress.ModeStubNoSwap, compress.AllowUnset, compress.ModeStubNoSwap, false},
		{"allow-compression no over nothing is still nothing",
			compress.ModeNone, compress.ModeNone, compress.AllowNo, compress.ModeNone, false},
		{"allow-compression no refuses the profile's own compressor",
			compress.ModeLZO, compress.ModeNone, compress.AllowNo, compress.ModeNone, true},
		{"allow-compression no refuses a pushed compressor",
			compress.ModeNone, compress.ModeLZ4, compress.AllowNo, compress.ModeNone, true},
		{"allow-compression no permits a framing stub",
			compress.ModeStub, compress.ModeNone, compress.AllowNo, compress.ModeStub, false},
		{"allow-compression yes changes nothing here: we never compress on send",
			compress.ModeLZO, compress.ModeNone, compress.AllowYes, compress.ModeLZO, false},
		{"allow-compression asym likewise",
			compress.ModeLZO, compress.ModeNone, compress.AllowAsym, compress.ModeLZO, false},
	}
	for _, tc := range cases {
		got, err := compress.EffectiveMode(tc.profile, tc.pushed, tc.allow)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: EffectiveMode(%v, %v, %v) error = %v, want error: %v",
				tc.name, tc.profile, tc.pushed, tc.allow, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("%s: EffectiveMode(%v, %v, %v) = %v, want %v",
				tc.name, tc.profile, tc.pushed, tc.allow, got, tc.want)
		}
	}
}

// TestParseAllowCompression covers the three values OpenVPN accepts and the
// refusal of anything else.
func TestParseAllowCompression(t *testing.T) {
	cases := []struct {
		arg  string
		want compress.AllowCompression
		ok   bool
	}{
		{"no", compress.AllowNo, true},
		{"asym", compress.AllowAsym, true},
		{"yes", compress.AllowYes, true},
		{"NO", compress.AllowNo, true},
		{"", compress.AllowUnset, false},
		{"maybe", compress.AllowUnset, false},
	}
	for _, tc := range cases {
		got, ok := compress.ParseAllowCompression(tc.arg)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ParseAllowCompression(%q) = %v, %v; want %v, %v", tc.arg, got, ok, tc.want, tc.ok)
		}
	}
}
