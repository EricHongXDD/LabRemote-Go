// Known-answer vectors for OpenVPN's data-channel compression framing.
//
// testdata/vectors.json was captured from real OpenVPN 2.4.12, 2.5.11 and
// 2.6.22 peers, so this package is measured against a server rather than
// against its own reading of the reference. An instrumented build interposes on
// compress_alg.compress and .decompress (src/openvpn/comp.c, comp_init()) and
// dumps the buffer on both sides of the framing; two containers of that build
// complete a real handshake, push four probe datagrams through the finished
// tunnel in both directions, and each vector is confirmed twice — once by the
// sender's compress() and once by the receiver's decompress(). See
// docker/COMPRESSION-VECTORS.md.
//
// A wrong compression byte does not look wrong: it produces packets that
// decrypt cleanly, pass every authentication check and mean nothing.
package compress_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/buengese/go-openvpn/internal/compress"
)

// vectorsPath is the captured ground truth, relative to this package.
const vectorsPath = "testdata/vectors.json"

// OpenVPN's compression framing bytes, read from src/openvpn/comp.h of the
// 2.4.12 / 2.5.11 / 2.6.22 release tarballs this rig pins (SHA-256 recorded in
// docker/openvpn-server/versions.env).
//
// They are restated here rather than taken from internal/compress: a
// known-answer test that read the package's own constants could not tell a
// correct framing from a self-consistent wrong one.
const (
	// lzoCompressByte is LZO_COMPRESS_BYTE: this payload IS lzo-compressed.
	lzoCompressByte = 0x66
	// lz4CompressByte is LZ4_COMPRESS_BYTE: this payload IS lz4-compressed.
	lz4CompressByte = 0x69
	// noCompressByte is NO_COMPRESS_BYTE: this payload is NOT compressed.
	noCompressByte = 0xFA
	// noCompressByteSwap is NO_COMPRESS_BYTE_SWAP: not compressed, and the
	// payload's first byte has been moved to the tail to keep the rest of it
	// aligned.
	noCompressByteSwap = 0xFB
	// algV2IndicatorByte is COMP_ALGV2_INDICATOR_BYTE, the first byte of the
	// two-byte v2 header.
	algV2IndicatorByte = 0x50
	// algV2LZ4Byte is COMP_ALGV2_LZ4_BYTE, the second byte of that header
	// when the payload is lz4-compressed.
	algV2LZ4Byte = 0x01
	// compFSwap is COMP_F_SWAP, the option flag that selects the swapping
	// form of the one-byte framing.
	compFSwap = 1 << 2
)

// vector is one captured crossing of the compression layer: a plain IP packet
// and the payload that appeared inside the data channel for it, in one
// direction, from one peer of one OpenVPN version.
type vector struct {
	// Name identifies the run, direction and probe size.
	Name string `json:"name"`
	// Mode is the compression family, spelled as a PUSH_REPLY or a .ovpn
	// spells it, and is what ParseMode is fed.
	Mode string `json:"mode"`
	// Directive is the exact line both peers' configs carried.
	Directive string `json:"directive"`
	// Alg is OpenVPN's own name for the algorithm that ran.
	Alg string `json:"alg"`
	// CompFlags is compctx->flags as options.c computed it.
	CompFlags int `json:"comp_flags"`
	// Swap reports COMP_F_SWAP, restated for readability.
	Swap bool `json:"swap"`
	// OpenVPNVersion is the release both peers ran.
	OpenVPNVersion string `json:"openvpn_version"`
	// Sender is the peer that produced Framed.
	Sender string `json:"sender"`
	// Receiver is the peer whose decompress() accepted Framed.
	Receiver string `json:"receiver"`
	// Direction is Sender to Receiver, spelled out.
	Direction string `json:"direction"`
	// Compressed reports whether the sender actually compressed this payload.
	Compressed bool `json:"compressed"`
	// FramingByte is the leading framing byte in hex, empty when the framing
	// adds none.
	FramingByte string `json:"framing_byte"`
	// Plain is the IP packet, as hex.
	Plain string `json:"plain"`
	// Framed is the data-channel payload for it, as hex.
	Framed string `json:"framed"`
}

// vectorFile is testdata/vectors.json.
type vectorFile struct {
	// Provenance records where the vectors came from.
	Provenance struct {
		// CapturedAt is when the capture ran.
		CapturedAt string `json:"captured_at"`
		// OpenVPNVersions are the releases the capture drove.
		OpenVPNVersions []string `json:"openvpn_versions"`
		// Patch is the instrumentation the capture depended on.
		Patch string `json:"patch"`
	} `json:"provenance"`
	// Vectors is every recorded crossing.
	Vectors []vector `json:"vectors"`
}

// loadVectors reads and parses testdata/vectors.json.
func loadVectors(t testing.TB) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse %s: %v", vectorsPath, err)
	}
	return vf
}

// mustHex decodes a hex field, failing the test with the field's name.
func mustHex(t testing.TB, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: not hex: %v", name, err)
	}
	return b
}

// diffAt renders the first byte at which two buffers differ, so a failure names
// an offset rather than two walls of hex.
func diffAt(got, want []byte) string {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			return fmt.Sprintf("first difference at byte %d: got 0x%02x, want 0x%02x", i, got[i], want[i])
		}
	}
	if len(got) != len(want) {
		return fmt.Sprintf("identical for %d bytes, then lengths differ: got %d, want %d", n, len(got), len(want))
	}
	return "identical"
}

// head renders the first n bytes of b as hex, with an ellipsis when truncated.
func head(b []byte, n int) string {
	if len(b) <= n {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:n]) + "…"
}

// swapped returns the framing OpenVPN's swapping form produces for plain under
// the given leading byte: the byte, then the payload from its second byte on,
// then the payload's original first byte moved to the tail.
//
// Reference: stub_compress() in src/openvpn/compstub.c and lz4_compress() in
// src/openvpn/comp-lz4.c, when COMP_F_SWAP is set.
func swapped(lead byte, plain []byte) []byte {
	out := make([]byte, 0, len(plain)+1)
	out = append(out, lead)
	out = append(out, plain[1:]...)
	out = append(out, plain[0])
	return out
}

// TestVectorsAreWellFormed guards the testdata itself: that every field parses,
// that the file covers the axes it promises, and that it carries genuinely
// compressed payloads.
func TestVectorsAreWellFormed(t *testing.T) {
	vf := loadVectors(t)

	if len(vf.Vectors) < 6 {
		t.Fatalf("got %d vectors, want at least 6", len(vf.Vectors))
	}
	if vf.Provenance.CapturedAt == "" || vf.Provenance.Patch == "" {
		t.Errorf("provenance is incomplete: %+v", vf.Provenance)
	}

	seenName := map[string]bool{}
	// modeVersions records which OpenVPN releases each mode was measured on,
	// and haveDirection which directions each mode covers.
	modeVersions := map[string]map[string]bool{}
	haveDirection := map[string]map[string]bool{}
	framings := map[string]bool{}
	compressed := 0

	for _, v := range vf.Vectors {
		if v.Name == "" {
			t.Fatalf("a vector has no name")
		}
		if seenName[v.Name] {
			t.Errorf("%s: duplicate vector name", v.Name)
		}
		seenName[v.Name] = true

		plain := mustHex(t, v.Name+".plain", v.Plain)
		framed := mustHex(t, v.Name+".framed", v.Framed)
		if len(plain) == 0 || len(framed) == 0 {
			t.Errorf("%s: empty plain or framed", v.Name)
			continue
		}
		if plain[0]>>4 != 4 {
			t.Errorf("%s: plain is not an IPv4 packet (first byte 0x%02x)", v.Name, plain[0])
		}
		if v.Swap != (v.CompFlags&compFSwap != 0) {
			t.Errorf("%s: swap=%v disagrees with comp_flags=%d", v.Name, v.Swap, v.CompFlags)
		}
		if v.Sender == v.Receiver {
			t.Errorf("%s: sender and receiver are both %q", v.Name, v.Sender)
		}
		if want := v.Sender + "-to-" + v.Receiver; v.Direction != want {
			t.Errorf("%s: direction %q does not match sender/receiver (%q)", v.Name, v.Direction, want)
		}
		if v.FramingByte == "" {
			if !bytes.Equal(plain, framed) {
				t.Errorf("%s: no framing byte recorded, but plain and framed differ", v.Name)
			}
		} else {
			b := mustHex(t, v.Name+".framing_byte", v.FramingByte)
			if !bytes.HasPrefix(framed, b) {
				t.Errorf("%s: framed does not begin with the recorded framing byte %s", v.Name, v.FramingByte)
			}
		}

		if modeVersions[v.Mode] == nil {
			modeVersions[v.Mode] = map[string]bool{}
			haveDirection[v.Mode] = map[string]bool{}
		}
		modeVersions[v.Mode][v.OpenVPNVersion] = true
		haveDirection[v.Mode][v.Direction] = true
		framings[v.FramingByte] = true
		if v.Compressed {
			compressed++
		}
	}

	// The required coverage, mode by mode. comp-lzo stops at 2.5 because a
	// 2.6 server refuses it outright unless compression is re-enabled — the
	// same reason MatrixEntry.SkipReason gives.
	want := map[string][]string{
		"comp-lzo":         {"2.4.12", "2.5.11"},
		"compress":         {"2.4.12"},
		"compress stub-v2": {"2.5.11", "2.6.22"},
	}
	for mode, versions := range want {
		if modeVersions[mode] == nil {
			t.Errorf("no vectors for mode %q", mode)
			continue
		}
		for _, ver := range versions {
			if !modeVersions[mode][ver] {
				t.Errorf("mode %q has no vector from OpenVPN %s", mode, ver)
			}
		}
		for _, dir := range []string{"client-to-server", "server-to-client"} {
			if !haveDirection[mode][dir] {
				t.Errorf("mode %q has no %s vector; the marker a peer sends and "+
					"the marker it accepts are different questions", mode, dir)
			}
		}
	}

	// Both server-side framings: the one-byte form and the no-byte v2 form.
	// Without one of them a Wrap that always prepends and a Wrap that never
	// does are indistinguishable.
	if !framings[""] {
		t.Errorf("no vector uses the v2 framing, which adds no byte at all")
	}
	if len(framings) < 2 {
		t.Errorf("every vector shares one framing byte (%v); the set cannot "+
			"discriminate between framings", framings)
	}
	if compressed == 0 {
		t.Errorf("no vector carries a genuinely compressed payload; " +
			"Unwrap's decompression and refusal would have nothing to meet")
	}
}

// TestVectorsDecomposeAsRecorded pins the wire layout of each framing into the
// repository, so that a hand-edit, a truncated field or a re-capture against a
// different series shows up as a structural failure rather than as an
// inscrutable byte mismatch.
func TestVectorsDecomposeAsRecorded(t *testing.T) {
	for _, v := range loadVectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			plain := mustHex(t, "plain", v.Plain)
			framed := mustHex(t, "framed", v.Framed)

			switch {
			case v.Alg == "lzo" && !v.Compressed:
				want := append([]byte{noCompressByte}, plain...)
				if !bytes.Equal(framed, want) {
					t.Errorf("comp-lzo, not compressed: framed is not NO_COMPRESS_BYTE ‖ plain: %s", diffAt(framed, want))
				}
			case v.Alg == "lzo" && v.Compressed:
				if framed[0] != lzoCompressByte {
					t.Errorf("comp-lzo, compressed: leading byte is 0x%02x, want LZO_COMPRESS_BYTE 0x%02x", framed[0], lzoCompressByte)
				}
				if bytes.Equal(framed[1:], plain) {
					t.Errorf("comp-lzo: LZO_COMPRESS_BYTE over an unchanged payload")
				}
			case v.Alg == "stub" && v.Swap:
				want := swapped(noCompressByteSwap, plain)
				if !bytes.Equal(framed, want) {
					t.Errorf("compress (stub, swap): framed is not NO_COMPRESS_BYTE_SWAP ‖ plain[1:] ‖ plain[0]: %s", diffAt(framed, want))
				}
			case v.Alg == "stub" && !v.Swap:
				want := append([]byte{noCompressByte}, plain...)
				if !bytes.Equal(framed, want) {
					t.Errorf("compress (stub, no swap): framed is not NO_COMPRESS_BYTE ‖ plain: %s", diffAt(framed, want))
				}
			case v.Alg == "lz4" && !v.Compressed:
				want := swapped(noCompressByteSwap, plain)
				if !bytes.Equal(framed, want) {
					t.Errorf("compress lz4, not compressed: framed is not NO_COMPRESS_BYTE_SWAP ‖ plain[1:] ‖ plain[0]: %s", diffAt(framed, want))
				}
			case v.Alg == "lz4" && v.Compressed:
				if framed[0] != lz4CompressByte {
					t.Errorf("compress lz4, compressed: leading byte is 0x%02x, want LZ4_COMPRESS_BYTE 0x%02x", framed[0], lz4CompressByte)
				}
			case v.Alg == "lz4v2" && v.Compressed:
				if len(framed) < 2 || framed[0] != algV2IndicatorByte || framed[1] != algV2LZ4Byte {
					t.Errorf("compress lz4-v2, compressed: framed does not begin 0x%02x 0x%02x, got %s",
						algV2IndicatorByte, algV2LZ4Byte, head(framed, 4))
				}
			case v.Alg == "lz4v2" || v.Alg == "stubv2":
				if !bytes.Equal(framed, plain) {
					t.Errorf("v2 framing, not compressed: framed is not plain: %s", diffAt(framed, plain))
				}
			default:
				t.Fatalf("unknown algorithm %q", v.Alg)
			}
		})
	}
}

// TestCompressReproducesCapturedFraming is the known-answer test: for every
// captured vector, Wrap must produce the bytes a real OpenVPN peer put on the
// wire and Unwrap must recover the packet a real OpenVPN peer accepted. An LZO
// payload must decompress to the captured packet; an LZ4 one must be refused.
func TestCompressReproducesCapturedFraming(t *testing.T) {
	for _, v := range loadVectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			plain := mustHex(t, "plain", v.Plain)
			framed := mustHex(t, "framed", v.Framed)

			// The mode reaches the data channel through ParseMode, so that is
			// what the vector is fed: a framing that is right for a Mode the
			// parser never produces is not right for anything.
			mode := compress.ParseMode(v.Mode)

			if v.Compressed && mode.Decompresses() {
				// Never a Wrap assertion here: we do not compress on send. The
				// packet must come back exactly, and not one byte past the
				// bound.
				codec := compress.NewCodec(mode, len(plain))
				got, err := codec.Unwrap(framed)
				if err != nil || codec.Decompressed() != 1 || !bytes.Equal(got, plain) {
					t.Errorf("Unwrap(%v, <%s payload>) = %s (%d bytes), %v; want the "+
						"captured %d-byte packet, decompressed", mode, v.Directive,
						head(got, 8), len(got), err, len(plain))
				}
				if _, err := compress.NewCodec(mode, len(plain)-1).Unwrap(framed); err == nil ||
					errors.Is(err, compress.ErrCompressed) {
					t.Errorf("Unwrap(%v, <%s payload>, %d) = %v; want a decompression "+
						"error for a packet one byte past the bound", mode, v.Directive, len(plain)-1, err)
				}
				return
			}
			if v.Compressed {
				got, err := compress.NewCodec(mode, len(plain)).Unwrap(framed)
				if err == nil {
					t.Errorf("Unwrap(%v, <%s payload, %d bytes>) returned %d bytes and no error; "+
						"want a compressed-payload error naming %s. This is the "+
						"silent corruption this framing exists to prevent: those %d bytes "+
						"are a compressed blob about to be handed to the tunnel as an IP packet",
						mode, v.Directive, len(framed), len(got), v.Alg, len(got))
				} else if !errors.Is(err, compress.ErrCompressed) {
					t.Errorf("Unwrap(%v, <%s payload>) failed with %q; want an error that "+
						"is compress.ErrCompressed — the peer compressed the payload, and "+
						"an error that merely says the leading byte was unrecognised would "+
						"pass this test for the wrong reason", mode, v.Directive, err)
				}
				var cpe *compress.CompressedPayloadError
				if errors.As(err, &cpe) && cpe.Algorithm != v.Alg {
					t.Errorf("Unwrap(%v, <%s payload>) named algorithm %q; the capture "+
						"recorded %q, and a ClassUnsupported failure has to name the right one",
						mode, v.Directive, cpe.Algorithm, v.Alg)
				}
				return
			}

			got, err := compress.NewCodec(mode, mtu).Wrap(plain)
			if err != nil {
				t.Fatalf("Wrap(%v, plain): %v", mode, err)
			}
			if !bytes.Equal(got, framed) {
				t.Errorf("Wrap(%v, plain) = %s (%d bytes)\n  want         %s (%d bytes)\n  %s\n  "+
					"captured from OpenVPN %s with %q",
					mode, head(got, 8), len(got), head(framed, 8), len(framed),
					diffAt(got, framed), v.OpenVPNVersion, v.Directive)
			}

			got, err = compress.NewCodec(mode, len(plain)).Unwrap(framed)
			if err != nil {
				t.Errorf("Unwrap(%v, framed): %v", mode, err)
				return
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("Unwrap(%v, framed) = %s (%d bytes)\n  want          %s (%d bytes)\n  %s\n  "+
					"captured from OpenVPN %s with %q",
					mode, head(got, 8), len(got), head(plain, 8), len(plain),
					diffAt(got, plain), v.OpenVPNVersion, v.Directive)
			}
		})
	}
}
