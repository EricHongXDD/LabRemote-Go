package profile

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// StaticKeySize is the length of an OpenVPN static key in bytes, what OpenVPN
// calls a 2048-bit key.
const StaticKeySize = 256

// staticKeyHeader and staticKeyFooter delimit a generated key; both are
// optional on input.
const (
	staticKeyHeader = "-----BEGIN OpenVPN Static key V1-----"
	staticKeyFooter = "-----END OpenVPN Static key V1-----"
)

// redactedStaticKey stands in for the bytes in every rendering of a StaticKey.
const redactedStaticKey = "[OpenVPN static key: 256 bytes, redacted]"

// StaticKey is an OpenVPN static key, the material behind a <tls-auth> or
// <tls-crypt> block.
//
// String, GoString and MarshalJSON yield a placeholder, so a key does not leak
// through %v or json.Marshal of a struct holding it. Encode, or indexing the
// array, gets the bytes.
type StaticKey [StaticKeySize]byte

// String returns a placeholder rather than the key.
func (k StaticKey) String() string { return redactedStaticKey }

// GoString returns the same placeholder, for %#v.
func (k StaticKey) GoString() string { return redactedStaticKey }

// MarshalJSON encodes the placeholder string. It does not decode back into a
// key.
func (k StaticKey) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(redactedStaticKey)), nil
}

// Encode renders the key as the block "openvpn --genkey" writes, which
// ParseStaticKey reads back to the same bytes. The result is key material.
func (k StaticKey) Encode() []byte {
	const perLine = 16 // bytes per line: 32 hex digits
	var b strings.Builder
	b.Grow(len(staticKeyHeader) + len(staticKeyFooter) + 2 + 2*StaticKeySize + StaticKeySize/perLine)
	b.WriteString(staticKeyHeader)
	b.WriteByte('\n')
	for i := 0; i < StaticKeySize; i += perLine {
		b.WriteString(hex.EncodeToString(k[i : i+perLine]))
		b.WriteByte('\n')
	}
	b.WriteString(staticKeyFooter)
	b.WriteByte('\n')
	return []byte(b.String())
}

// ParseStaticKey parses the body of a <tls-auth> or <tls-crypt> block: an
// optional header, 512 hexadecimal digits in any line arrangement, and an
// optional footer. Blank and comment lines are ignored.
//
// The error never contains any part of body, which is key material even when
// malformed.
func ParseStaticKey(body []byte) (*StaticKey, error) {
	digits := make([]byte, 0, 2*StaticKeySize)
	sawHeader, sawFooter := false, false

	for n, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, ";"):
			continue
		case strings.EqualFold(line, staticKeyHeader):
			if sawHeader {
				return nil, fmt.Errorf("profile: static key: repeated header on line %d", n+1)
			}
			sawHeader = true
			continue
		case strings.EqualFold(line, staticKeyFooter):
			if sawFooter {
				return nil, fmt.Errorf("profile: static key: repeated footer on line %d", n+1)
			}
			sawFooter = true
			continue
		}
		// Digits after the footer would be a second key; refuse them.
		if sawFooter {
			return nil, fmt.Errorf("profile: static key: content after the footer, on line %d", n+1)
		}
		for i := 0; i < len(line); i++ {
			if !isHexDigit(line[i]) {
				return nil, fmt.Errorf("profile: static key: line %d is not hexadecimal", n+1)
			}
		}
		digits = append(digits, line...)
	}

	if len(digits) != 2*StaticKeySize {
		return nil, fmt.Errorf("profile: static key: %d hex digits, want %d (%d bytes)",
			len(digits), 2*StaticKeySize, StaticKeySize)
	}

	var k StaticKey
	if _, err := hex.Decode(k[:], digits); err != nil {
		// Unreachable. The cause is dropped: it quotes a key byte.
		return nil, fmt.Errorf("profile: static key: hex decode failed")
	}
	return &k, nil
}

// isHexDigit reports whether c is an ASCII hexadecimal digit in either case.
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// KeyDirection is the --key-direction value: 0, 1, or absent. With a
// direction the static key is split into per-direction halves; absent uses the
// whole key both ways, so it is not the same as 0.
type KeyDirection int

const (
	// KeyDirectionAbsent means no key-direction directive.
	KeyDirectionAbsent KeyDirection = iota
	// KeyDirection0 is "key-direction 0".
	KeyDirection0
	// KeyDirection1 is "key-direction 1".
	KeyDirection1
)

// keyDirectionNames maps each KeyDirection to its name.
var keyDirectionNames = [...]string{
	KeyDirectionAbsent: "absent",
	KeyDirection0:      "0",
	KeyDirection1:      "1",
}

// String returns "absent", "0" or "1", or "key-direction(N)" out of range.
func (d KeyDirection) String() string {
	if d < 0 || int(d) >= len(keyDirectionNames) {
		return "key-direction(" + strconv.Itoa(int(d)) + ")"
	}
	return keyDirectionNames[d]
}

// Value returns the numeric direction and whether the profile gave one. Use it
// rather than int(d), which is not the direction.
func (d KeyDirection) Value() (int, bool) {
	switch d {
	case KeyDirection0:
		return 0, true
	case KeyDirection1:
		return 1, true
	default:
		return 0, false
	}
}

// ParseKeyDirection parses the argument of a key-direction directive: 0 or 1.
func ParseKeyDirection(s string) (KeyDirection, error) {
	switch strings.TrimSpace(s) {
	case "0":
		return KeyDirection0, nil
	case "1":
		return KeyDirection1, nil
	default:
		return KeyDirectionAbsent, fmt.Errorf("profile: key-direction: must be 0 or 1")
	}
}

// MarshalText implements encoding.TextMarshaler. An out-of-range value
// marshals as its String placeholder, which UnmarshalText refuses.
func (d KeyDirection) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, accepting "absent", "0"
// and "1". An unrecognised name is an error.
func (d *KeyDirection) UnmarshalText(text []byte) error {
	name := string(text)
	for i, n := range keyDirectionNames {
		if n == name {
			*d = KeyDirection(i)
			return nil
		}
	}
	return fmt.Errorf("profile: unknown key direction %q", name)
}
