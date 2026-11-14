package profile_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/profile"
)

const (
	testKeyFill      = 0xa5
	testKeyFillOther = 0x3c
)

// testKey returns 256 bytes of well-formed key material in which every byte
// differs from its neighbours, so a partial leak is visible.
func testKey(fill byte) []byte {
	key := make([]byte, profile.StaticKeySize)
	for i := range key {
		key[i] = byte(i) ^ fill
	}
	return key
}

func staticKeyHex(fill byte) string { return hex.EncodeToString(testKey(fill)) }

func staticKeyBlock(fill byte) string {
	digits := staticKeyHex(fill)
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(digits); i += 32 {
		b.WriteString(digits[i : i+32])
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}

func wrappedProfile(tag string, fill byte, extra string) string {
	return "client\nremote vpn.example.test 1194\nproto udp\n" + extra +
		"<" + tag + ">\n" + staticKeyBlock(fill) + "</" + tag + ">\n"
}

// ---- Format ----------------------------------------------------------

func TestParseStaticKeyAcceptsDeployedForms(t *testing.T) {
	digits := staticKeyHex(testKeyFill)
	lines := func(width int) string {
		var b strings.Builder
		for i := 0; i < len(digits); i += width {
			end := i + width
			if end > len(digits) {
				end = len(digits)
			}
			b.WriteString(digits[i:end])
			b.WriteByte('\n')
		}
		return b.String()
	}

	cases := []struct {
		name string
		body string
	}{
		{"header and footer, 32 digits per line", staticKeyBlock(testKeyFill)},
		{"no header or footer", lines(32)},
		{"header only", "-----BEGIN OpenVPN Static key V1-----\n" + lines(32)},
		{"one long line", digits + "\n"},
		{"no trailing newline", strings.TrimRight(staticKeyBlock(testKeyFill), "\n")},
		{"ragged line lengths", lines(7)},
		{"uppercase digits", strings.ToUpper(lines(32))},
		// openvpn --genkey writes a comment banner above the header.
		{"generated comment banner", "#\n# 2048 bit OpenVPN static key\n#\n" + staticKeyBlock(testKeyFill)},
		{"semicolon comments and blank lines", ";note\n\n" + staticKeyBlock(testKeyFill) + "\n;end\n"},
		{"leading and trailing whitespace", "   \t" + lines(32) + "  \n"},
		{"carriage returns", strings.ReplaceAll(staticKeyBlock(testKeyFill), "\n", "\r\n")},
	}

	want := testKey(testKeyFill)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := profile.ParseStaticKey([]byte(tc.body))
			if err != nil {
				t.Fatalf("ParseStaticKey: %v", err)
			}
			if len(key) != profile.StaticKeySize {
				t.Fatalf("key is %d bytes, want %d", len(key), profile.StaticKeySize)
			}
			if string(key[:]) != string(want) {
				t.Fatal("parsed key does not match the bytes it was rendered from")
			}
		})
	}
}

func TestParseStaticKeyRejects(t *testing.T) {
	digits := staticKeyHex(testKeyFill)
	cases := []struct {
		name string
		body string
		want string
	}{
		{"empty", "", "hex digits"},
		{"header and footer only", "-----BEGIN OpenVPN Static key V1-----\n-----END OpenVPN Static key V1-----\n", "hex digits"},
		{"truncated by one line", digits[:len(digits)-32], "hex digits"},
		{"truncated by one digit", digits[:len(digits)-1], "hex digits"},
		{"one digit too many", digits + "0", "hex digits"},
		{"two keys concatenated", digits + "\n" + staticKeyHex(testKeyFillOther), "hex digits"},
		{"a second key after the footer", staticKeyBlock(testKeyFill) + staticKeyHex(testKeyFillOther), "after the footer"},
		{"two blocks concatenated", staticKeyBlock(testKeyFill) + staticKeyBlock(testKeyFillOther), "repeated header"},
		{"non-hex digit", digits[:len(digits)-1] + "g", "not hexadecimal"},
		{"base64 body", base64.StdEncoding.EncodeToString(testKey(testKeyFill)), "not hexadecimal"},
		{"a certificate by mistake", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", "not hexadecimal"},
		{"repeated header", "-----BEGIN OpenVPN Static key V1-----\n" + staticKeyBlock(testKeyFill), "repeated header"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := profile.ParseStaticKey([]byte(tc.body))
			if err == nil {
				t.Fatalf("ParseStaticKey accepted %s", tc.name)
			}
			if key != nil {
				t.Error("ParseStaticKey returned a key alongside an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// ---- Loading into the profile ----------------------------------------

func TestParseLoadsWrapKeys(t *testing.T) {
	for _, tag := range []string{"tls-auth", "tls-crypt"} {
		t.Run(tag, func(t *testing.T) {
			p, err := profile.ParseString(wrappedProfile(tag, testKeyFill, ""))
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			got, other := p.TLSAuth, p.TLSCrypt
			if tag == "tls-crypt" {
				got, other = p.TLSCrypt, p.TLSAuth
			}
			if got == nil {
				t.Fatalf("<%s> body was not loaded", tag)
			}
			if string(got[:]) != string(testKey(testKeyFill)) {
				t.Fatalf("<%s> loaded the wrong bytes", tag)
			}
			if other != nil {
				t.Errorf("<%s> body reached the other wrap field", tag)
			}
			// The block must still be recorded alongside the loaded key.
			if len(p.InlineBlocks) != 1 || p.InlineBlocks[0].Tag != tag {
				t.Errorf("InlineBlocks = %v, want one %s entry", p.InlineBlocks, tag)
			}
		})
	}
}

// TestParseUnterminatedWrapBlockLoadsNothing: as for <ca>, not a parse error.
func TestParseUnterminatedWrapBlockLoadsNothing(t *testing.T) {
	src := "remote vpn.example.test 1194\n<tls-auth>\n" + staticKeyBlock(testKeyFill)
	p, err := profile.ParseString(src)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if p.TLSAuth != nil {
		t.Error("an unterminated <tls-auth> block loaded a key")
	}
	if len(p.InlineBlocks) != 1 || p.InlineBlocks[0].Tag != "tls-auth" {
		t.Errorf("InlineBlocks = %v, want the opening tag recorded", p.InlineBlocks)
	}
}

// TestParseMalformedWrapBlockIsClassConfig pins ClassConfig naming the block.
func TestParseMalformedWrapBlockIsClassConfig(t *testing.T) {
	digits := staticKeyHex(testKeyFill)
	cases := []struct {
		name string
		tag  string
		body string
	}{
		{"truncated", "tls-auth", digits[:64] + "\n"},
		{"over-long", "tls-auth", digits + digits + "\n"},
		{"non-hex", "tls-auth", strings.Repeat("z", 512) + "\n"},
		{"empty", "tls-auth", ""},
		{"truncated tls-crypt", "tls-crypt", digits[:510] + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "remote vpn.example.test 1194\n<" + tc.tag + ">\n" + tc.body + "</" + tc.tag + ">\n"
			p, err := profile.ParseString(src)
			if err == nil {
				t.Fatalf("ParseString accepted a %s <%s> body", tc.name, tc.tag)
			}
			if p != nil {
				t.Error("ParseString returned a profile alongside an error")
			}
			var derr *diag.Error
			if !errors.As(err, &derr) {
				t.Fatalf("error is not a *diag.Error: %v", err)
			}
			if derr.Class != diag.ClassConfig {
				t.Errorf("Class = %v, want %v", derr.Class, diag.ClassConfig)
			}
			if derr.Stage != diag.StageParse {
				t.Errorf("Stage = %v, want %v", derr.Stage, diag.StageParse)
			}
			if !strings.Contains(err.Error(), "<"+tc.tag+">") {
				t.Errorf("error does not name the block: %q", err)
			}
		})
	}
}

// ---- key-direction ---------------------------------------------------

// TestKeyDirectionAbsentIsNotZero pins that an absent key-direction is not
// read as 0: OpenVPN uses the whole key in both directions then.
func TestKeyDirectionAbsentIsNotZero(t *testing.T) {
	absent, err := profile.ParseString(wrappedProfile("tls-auth", testKeyFill, ""))
	if err != nil {
		t.Fatal(err)
	}
	zero, err := profile.ParseString(wrappedProfile("tls-auth", testKeyFill, "key-direction 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if absent.KeyDirection == zero.KeyDirection {
		t.Fatal("an absent key-direction is indistinguishable from key-direction 0")
	}
	if absent.KeyDirection != profile.KeyDirectionAbsent {
		t.Errorf("absent: KeyDirection = %v, want absent", absent.KeyDirection)
	}
	if _, ok := absent.KeyDirection.Value(); ok {
		t.Error("absent: Value() reports a direction was given")
	}
	if n, ok := zero.KeyDirection.Value(); !ok || n != 0 {
		t.Errorf("key-direction 0: Value() = %d, %v; want 0, true", n, ok)
	}
	if (&profile.Profile{}).KeyDirection != profile.KeyDirectionAbsent {
		t.Error("the zero value of KeyDirection is not absent")
	}
}

func TestParseKeyDirection(t *testing.T) {
	cases := []struct {
		arg  string
		want profile.KeyDirection
		num  int
	}{
		{"0", profile.KeyDirection0, 0},
		{"1", profile.KeyDirection1, 1},
	}
	for _, tc := range cases {
		p, err := profile.ParseString(wrappedProfile("tls-auth", testKeyFill, "key-direction "+tc.arg+"\n"))
		if err != nil {
			t.Fatalf("key-direction %s: %v", tc.arg, err)
		}
		if p.KeyDirection != tc.want {
			t.Errorf("key-direction %s = %v, want %v", tc.arg, p.KeyDirection, tc.want)
		}
		n, ok := p.KeyDirection.Value()
		if !ok || n != tc.num {
			t.Errorf("key-direction %s: Value() = %d, %v", tc.arg, n, ok)
		}
		if got := p.KeyDirection.String(); got != tc.arg {
			t.Errorf("String() = %q, want %q", got, tc.arg)
		}
	}
	if got := profile.KeyDirectionAbsent.String(); got != "absent" {
		t.Errorf("KeyDirectionAbsent.String() = %q, want \"absent\"", got)
	}
	if got := profile.KeyDirection(99).String(); !strings.Contains(got, "99") {
		t.Errorf("out-of-range String() = %q, want it to name the value", got)
	}
}

func TestParseKeyDirectionInvalid(t *testing.T) {
	for _, arg := range []string{"", " 2", " -1", " both", " 01"} {
		src := "remote vpn.example.test 1194\nkey-direction" + arg + "\n"
		if _, err := profile.ParseString(src); err == nil {
			t.Errorf("ParseString accepted \"key-direction%s\"", arg)
		}
	}
}

// ---- Leak scan -------------------------------------------------------

// needle is one rendering of the test key that must never be emitted.
type needle struct {
	name string
	text string
}

func keyNeedles(fill byte) []needle {
	key := testKey(fill)
	digits := staticKeyHex(fill)
	return []needle{
		{"hex, whole key", digits},
		{"hex, uppercase", strings.ToUpper(digits)},
		{"hex, first line", digits[:32]},
		{"hex, last line", digits[len(digits)-32:]},
		{"raw bytes", string(key)},
		{"raw bytes, first eight", string(key[:8])},
		{"decimal listing, as %v of a byte array", strings.TrimSuffix(fmt.Sprintf("%d", key[:8]), "]")},
		{"base64, as json.Marshal of a byte slice", base64.StdEncoding.EncodeToString(key)},
	}
}

func scan(text string, needles []needle) []string {
	var found []string
	for _, n := range needles {
		if strings.Contains(text, n.text) {
			found = append(found, n.name)
		}
	}
	return found
}

// TestKeyNeedlesAreDiscriminating proves the leak scan is not vacuous.
func TestKeyNeedlesAreDiscriminating(t *testing.T) {
	needles := keyNeedles(testKeyFill)
	key := testKey(testKeyFill)
	leaky := strings.Join([]string{
		staticKeyHex(testKeyFill),
		strings.ToUpper(staticKeyHex(testKeyFill)),
		string(key),
		fmt.Sprintf("%d", key),
		base64.StdEncoding.EncodeToString(key),
	}, " ")
	if got := scan(leaky, needles); len(got) != len(needles) {
		t.Fatalf("only %d of %d needles matched a deliberately leaky rendering: %v",
			len(got), len(needles), got)
	}
}

// TestStaticKeyNeverLeaks scans all package output for every keyNeedles form.
func TestStaticKeyNeverLeaks(t *testing.T) {
	needles := keyNeedles(testKeyFill)
	src := wrappedProfile("tls-auth", testKeyFill, "key-direction 1\ncipher AES-256-CBC\n")
	p, err := profile.ParseString(src)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if p.TLSAuth == nil {
		t.Fatal("the key was not loaded; the scan would be vacuous")
	}

	blob, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("json.Marshal(profile): %v", err)
	}
	keyJSON, err := json.Marshal(p.TLSAuth)
	if err != nil {
		t.Fatalf("json.Marshal(key): %v", err)
	}

	emissions := map[string]string{
		"%v of the profile":         fmt.Sprintf("%v", p),
		"%+v of the profile":        fmt.Sprintf("%+v", p),
		"%#v of the profile":        fmt.Sprintf("%#v", p),
		"fmt.Sprint of the profile": fmt.Sprint(p),
		"%v of the dereferenced":    fmt.Sprintf("%v", *p),
		"%+v of the dereferenced":   fmt.Sprintf("%+v", *p),
		"json.Marshal(profile)":     string(blob),
		"%v of the key":             fmt.Sprintf("%v", p.TLSAuth),
		"%+v of the key":            fmt.Sprintf("%+v", p.TLSAuth),
		"%#v of the key":            fmt.Sprintf("%#v", p.TLSAuth),
		// The brackets stop staticcheck folding this into String().
		"%s of the key":            fmt.Sprintf("<%s>", p.TLSAuth),
		"%v of the key value":      fmt.Sprintf("%v", *p.TLSAuth),
		"%#v of the key value":     fmt.Sprintf("%#v", *p.TLSAuth),
		"StaticKey.String":         p.TLSAuth.String(),
		"StaticKey.GoString":       p.TLSAuth.GoString(),
		"json.Marshal(key)":        string(keyJSON),
		"%v of InlineBlocks":       fmt.Sprintf("%v", p.InlineBlocks),
		"%v of Directives":         fmt.Sprintf("%v", p.Directives),
		"KeyDirection.String":      p.KeyDirection.String(),
		"%v of a zero StaticKey":   fmt.Sprintf("%v", profile.StaticKey{}),
		"%v of a nil *StaticKey":   fmt.Sprintf("%v", (*profile.StaticKey)(nil)),
		"error text, whole parse":  parseErrorText(t, wrappedProfile("tls-auth", testKeyFill, "")+"proto sideways\n"),
		"error text, short key":    parseErrorText(t, "remote r.test 1194\n<tls-auth>\n"+staticKeyHex(testKeyFill)[:400]+"\n</tls-auth>\n"),
		"error text, long key":     parseErrorText(t, "remote r.test 1194\n<tls-auth>\n"+staticKeyHex(testKeyFill)+"00\n</tls-auth>\n"),
		"error text, non-hex key":  parseErrorText(t, "remote r.test 1194\n<tls-auth>\n"+staticKeyHex(testKeyFill)+"zz\n</tls-auth>\n"),
		"error text, doubled key":  parseErrorText(t, "remote r.test 1194\n<tls-auth>\n"+staticKeyHex(testKeyFill)+staticKeyHex(testKeyFill)+"\n</tls-auth>\n"),
		"error text, bare key":     staticKeyError(t, []byte(staticKeyHex(testKeyFill)[:64])),
		"error text, non-hex bare": staticKeyError(t, []byte(strings.ToUpper(staticKeyHex(testKeyFill))+"XY")),
	}

	for _, d := range p.Directives {
		emissions["Directive.String: "+d.Name] = d.String()
	}

	for name, text := range emissions {
		if found := scan(text, needles); found != nil {
			t.Errorf("%s leaked key material as %v", name, found)
		}
	}
}

// parseErrorText returns the full error chain of a failing parse, flattened.
func parseErrorText(t *testing.T, src string) string {
	t.Helper()
	_, err := profile.ParseString(src)
	if err == nil {
		t.Fatal("expected this profile to fail parsing; the scan would be vacuous")
	}
	return strings.Join(diag.ErrorChain(err), "\n")
}

func staticKeyError(t *testing.T, body []byte) string {
	t.Helper()
	_, err := profile.ParseStaticKey(body)
	if err == nil {
		t.Fatal("expected this body to be rejected; the scan would be vacuous")
	}
	return strings.Join(diag.ErrorChain(err), "\n")
}

func TestStaticKeyRenderingsAreThePlaceholder(t *testing.T) {
	var k profile.StaticKey
	copy(k[:], testKey(testKeyFill))

	want := k.String()
	if want == "" || !strings.Contains(want, "static key") {
		t.Fatalf("String() = %q, want it to name what was withheld", want)
	}
	if got := k.GoString(); got != want {
		t.Errorf("GoString() = %q, want %q", got, want)
	}
	blob, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded string
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("the marshalled key is not a JSON string: %v", err)
	}
	if decoded != want {
		t.Errorf("json.Marshal = %q, want %q", decoded, want)
	}
}
