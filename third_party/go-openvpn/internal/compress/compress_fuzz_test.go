package compress_test

import (
	"errors"
	"testing"

	lzo "github.com/buengese/go-lzo"

	"github.com/buengese/go-openvpn/internal/compress"
)

// FuzzUnwrap feeds arbitrary payloads to Codec.Unwrap in every mode. A
// decrypted payload is peer-controlled, so Unwrap must not panic, must keep a
// decompressed packet within maxLen, and may report ErrCompressed only for a
// codec it does not link. The seeds include the captured LZO payloads.
func FuzzUnwrap(f *testing.F) {
	for _, v := range loadVectors(f).Vectors {
		f.Add(mustHex(f, "framed", v.Framed), uint16(len(v.Plain)/2))
	}
	f.Add(append([]byte{0x66}, lzo.Compress(nil, make([]byte, 2000))...), uint16(mtu))
	f.Add([]byte{0x66, 0x11, 0x00, 0x00}, uint16(mtu))
	f.Add([]byte{0x66}, uint16(0))

	modes := []compress.Mode{
		compress.ModeNone, compress.ModeStub, compress.ModeStubNoSwap,
		compress.ModeLZO, compress.ModeLZ4, compress.ModeLZ4v2, compress.ModeStubV2,
	}
	f.Fuzz(func(t *testing.T, payload []byte, maxLen uint16) {
		for _, m := range modes {
			codec := compress.NewCodec(m, int(maxLen))
			got, err := codec.Unwrap(payload)
			if err != nil {
				if errors.Is(err, compress.ErrCompressed) && m.Decompresses() {
					t.Errorf("Unwrap(%v) = %v; this mode's codec is linked", m, err)
				}
				continue
			}
			if codec.Decompressed() > 0 && (!m.Decompresses() || len(got) > int(maxLen)) {
				t.Errorf("Unwrap(%v, maxLen %d) decompressed %d bytes", m, maxLen, len(got))
			}
		}
	})
}
