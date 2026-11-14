package caps_test

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/caps"
	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/profile"
)

// staticKeyHex is 256 bytes of made-up but well-formed key material, rendered
// as the 512 hex digits an OpenVPN static key file holds. A <tls-auth> or
// <tls-crypt> body that is not exactly this long fails profile.ParseFile with
// diag.ClassConfig, so classifying a wrapped profile needs a real one.
func staticKeyHex() string {
	key := make([]byte, profile.StaticKeySize)
	for i := range key {
		key[i] = byte(i) ^ 0xa5
	}
	return hex.EncodeToString(key)
}

// staticKeyBlock renders staticKeyHex as the body of a static key file:
// header, sixteen lines of thirty-two digits, footer.
func staticKeyBlock() string {
	digits := staticKeyHex()
	var b strings.Builder
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(digits); i += 32 {
		b.WriteString(digits[i : i+32])
		b.WriteByte('\n')
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}

// awsProfile is the shape AWS Client VPN hands out: SAML federation, a CA
// bundle, no client certificate, AES-256-GCM, no control-channel wrapping.
// It must not produce a fatal gap.
const awsProfile = `client
dev tun
proto udp
remote cvpn-endpoint-0123456789abcdef.prod.clientvpn.eu-central-1.amazonaws.com 443
remote-random-hostname
resolv-retry infinite
nobind
remote-cert-tls server
cipher AES-256-GCM
verb 3
reneg-sec 0
verify-x509-name vpn.example.test name
auth-federate
auth-retry interact
<ca>
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
</ca>
`

func parse(t *testing.T, s string) *profile.Profile {
	t.Helper()
	p, err := profile.ParseString(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

// gapFor returns the first gap for a directive, and whether it was found.
func gapFor(gaps []diag.Gap, directive string) (diag.Gap, bool) {
	for _, g := range gaps {
		if g.Directive == directive {
			return g, true
		}
	}
	return diag.Gap{}, false
}

func TestInspectAWSProfileHasNoFatalGaps(t *testing.T) {
	gaps := caps.Inspect(parse(t, awsProfile))
	if len(gaps) == 0 {
		t.Fatal("no gaps reported at all")
	}
	for _, g := range gaps {
		if g.Severity == diag.SeverityFatal {
			t.Errorf("fatal gap on an AWS profile: %s (%s) — %s", g.Directive, g.Value, g.Detail)
		}
	}
	if worst := caps.Worst(gaps); worst == diag.SeverityFatal {
		t.Errorf("Worst() = %v, want at most degraded", worst)
	}
	// Every directive in the profile must be classified.
	if len(gaps) < len(parse(t, awsProfile).Directives) {
		t.Errorf("got %d gaps for %d directives", len(gaps), len(parse(t, awsProfile).Directives))
	}
}

func TestInspectNilAndEmpty(t *testing.T) {
	if got := caps.Inspect(nil); got != nil {
		t.Errorf("Inspect(nil) = %v, want nil", got)
	}
	// A hand-built profile, as the integration tests use, records no
	// directives and must therefore report no gaps.
	if got := caps.Inspect(&profile.Profile{Remote: "127.0.0.1", Port: 4433}); got != nil {
		t.Errorf("Inspect(hand-built) = %v, want nil", got)
	}
}

func TestInspectUnrecognisedDirectiveIsFatal(t *testing.T) {
	gaps := caps.Inspect(parse(t, "remote vpn.example.test 443\nplugin /usr/lib/openvpn/x.so\n"))
	g, ok := gapFor(gaps, "plugin")
	if !ok {
		t.Fatalf("plugin not classified: %+v", gaps)
	}
	if g.Severity != diag.SeverityFatal {
		t.Errorf("plugin severity = %v, want fatal", g.Severity)
	}
	if !strings.HasPrefix(g.Detail, "unrecognised") {
		t.Errorf("plugin detail = %q, want it to say unrecognised", g.Detail)
	}
}

func TestInspectUnrecognisedBlockIsFatal(t *testing.T) {
	gaps := caps.Inspect(parse(t, "remote vpn.example.test 443\n<http-proxy-user-pass>\nsecret\n</http-proxy-user-pass>\n"))
	g, ok := gapFor(gaps, "<http-proxy-user-pass>")
	if !ok {
		t.Fatalf("unknown block not classified: %+v", gaps)
	}
	if g.Severity != diag.SeverityFatal {
		t.Errorf("severity = %v, want fatal", g.Severity)
	}
	for _, gg := range gaps {
		if strings.Contains(gg.Detail, "secret") || gg.Value == "secret" {
			t.Fatal("block body leaked into a gap")
		}
	}
}

// TestInspectTLSAuthIsSupported is the registry half of the tls-auth wrap, and
// it is the block row that says supported, because a wrapped config inlines its
// key. key-direction goes with it: it selects which halves of that key sign and
// verify, which is a thing the client does rather than a thing it parses.
func TestInspectTLSAuthIsSupported(t *testing.T) {
	src := "remote vpn.example.test 1194\ncipher AES-256-GCM\nauth SHA256\nkey-direction 1\n" +
		"<tls-auth>\n" + staticKeyBlock() + "</tls-auth>\n"
	gaps := caps.Inspect(parse(t, src))

	g, ok := gapFor(gaps, "<tls-auth>")
	if !ok {
		t.Fatalf("tls-auth block not classified: %+v", gaps)
	}
	if g.Severity != diag.SeveritySupported {
		t.Errorf("<tls-auth> severity = %v, want supported", g.Severity)
	}
	kd, ok := gapFor(gaps, "key-direction")
	if !ok {
		t.Fatal("key-direction not classified")
	}
	if kd.Severity != diag.SeveritySupported {
		t.Errorf("key-direction severity = %v, want supported alongside tls-auth", kd.Severity)
	}
	if kd.Value != "1" {
		t.Errorf("key-direction value = %q, want %q", kd.Value, "1")
	}
	// Nothing about the classification may put key material into a gap.
	for _, gg := range gaps {
		text := gg.Directive + " " + gg.Value + " " + gg.Detail
		if strings.Contains(text, staticKeyHex()[:32]) {
			t.Fatal("tls-auth key body leaked into a gap")
		}
	}
	// The preflight must let such a profile through in fail-fast mode.
	if fatal := caps.Filter(gaps, diag.SeverityFatal); len(fatal) != 0 {
		t.Errorf("a tls-auth profile still has fatal gaps: %+v", fatal)
	}
}

// TestInspectTLSCrypt covers the wrap and the direction beside it, and is the
// reason the key-direction row is refined rather than flat. The block is
// supported; a key-direction line beside it is ignored, because OpenVPN gives
// tls-crypt no --key-direction at all — the server is always on slot 0 and the
// client always on slot 1 (tls_crypt_init_key()) — so a client that honoured
// the line would pick the wrong slot for one of the two peers.
//
// Ignored and not fatal, because the reference reads the directive into
// options->key_direction and never consults it on the tls-crypt path
// (openvpn-2.6.22 src/openvpn/options.c:9252-9265): it starts, and ignores it.
func TestInspectTLSCrypt(t *testing.T) {
	t.Run("with a key-direction", func(t *testing.T) {
		src := "remote vpn.example.test 1194\nkey-direction 1\n<tls-crypt>\n" +
			staticKeyBlock() + "</tls-crypt>\n"
		gaps := caps.Inspect(parse(t, src))

		g, ok := gapFor(gaps, "<tls-crypt>")
		if !ok {
			t.Fatalf("tls-crypt block not classified: %+v", gaps)
		}
		if g.Severity != diag.SeveritySupported {
			t.Errorf("<tls-crypt> severity = %v, want supported", g.Severity)
		}

		kd, ok := gapFor(gaps, "key-direction")
		if !ok {
			t.Fatal("key-direction not classified")
		}
		if kd.Severity != diag.SeverityIgnored {
			t.Errorf("key-direction beside tls-crypt = %v, want ignored — "+
				"tls-crypt has no such option and the reference starts anyway", kd.Severity)
		}
		if !strings.Contains(kd.Detail, "no key-direction") {
			t.Errorf("key-direction detail = %q, want it to say tls-crypt has none", kd.Detail)
		}
		// The point of the severity: a preflight in fail-fast mode must dial
		// this profile rather than refuse it.
		if fatal := caps.Filter(gaps, diag.SeverityFatal); len(fatal) != 0 {
			t.Errorf("a tls-crypt profile with a key-direction is refused before it dials: %+v", fatal)
		}
	})

	t.Run("without a key-direction", func(t *testing.T) {
		src := "remote vpn.example.test 1194\n<tls-crypt>\n" +
			staticKeyBlock() + "</tls-crypt>\n"
		gaps := caps.Inspect(parse(t, src))
		if fatal := caps.Filter(gaps, diag.SeverityFatal); len(fatal) != 0 {
			t.Errorf("a tls-crypt profile still has fatal gaps: %+v", fatal)
		}
	})
}

// TestInspectTLSCryptV2StaysFatal keeps the non-goal honest: tls-crypt-v2 needs
// a per-client wrapped key the measurement system has no way to obtain, and it
// must not inherit tls-crypt's verdict on the strength of sharing a prefix.
func TestInspectTLSCryptV2StaysFatal(t *testing.T) {
	src := "remote vpn.example.test 1194\n<tls-crypt-v2>\n" +
		staticKeyBlock() + "</tls-crypt-v2>\n"
	gaps := caps.Inspect(parse(t, src))
	g, ok := gapFor(gaps, "<tls-crypt-v2>")
	if !ok {
		t.Fatalf("tls-crypt-v2 block not classified: %+v", gaps)
	}
	if g.Severity != diag.SeverityFatal {
		t.Errorf("<tls-crypt-v2> severity = %v, want fatal", g.Severity)
	}
}

// TestPreflightNeverSeesAMalformedWrapKey pins the boundary blockRegistry's
// comment claims: the parser validates a <tls-auth> body as it loads it, so a
// profile with an unusable key fails ParseFile with diag.ClassConfig and the
// preflight is never reached. By the time Inspect runs, every key is 256 bytes.
func TestPreflightNeverSeesAMalformedWrapKey(t *testing.T) {
	src := "remote vpn.example.test 1194\n<tls-auth>\ndeadbeef\n</tls-auth>\n"
	p, err := profile.ParseString(src)
	if err == nil {
		t.Fatalf("a four-byte <tls-auth> body parsed; Inspect would then classify it as %+v",
			caps.Inspect(p))
	}
	var derr *diag.Error
	if !errors.As(err, &derr) || derr.Class != diag.ClassConfig {
		t.Fatalf("error = %v, want a *diag.Error of class config", err)
	}
	if !strings.Contains(err.Error(), "<tls-auth>") {
		t.Errorf("error does not name the block: %q", err)
	}
}

// TestInspectWrapFileReferenceIsFatal covers the file spelling: a
// "tls-auth ta.key 1" line names a file the parser will not open, on top of a
// wrap that is not implemented in that form, and the detail has to say so
// rather than falling back on the block wording. A profile carrying both
// spellings is fatal for a second reason — the file is not read, the block is
// read and then unused — and the detail must not claim the key is missing.
func TestInspectWrapFileReferenceIsFatal(t *testing.T) {
	for _, directive := range []string{"tls-auth", "tls-crypt"} {
		t.Run(directive, func(t *testing.T) {
			src := "remote vpn.example.test 1194\n" + directive + " /etc/openvpn/secret-ta.key 1\n"
			gaps := caps.Inspect(parse(t, src))
			g, ok := gapFor(gaps, directive)
			if !ok {
				t.Fatalf("%s file reference not classified: %+v", directive, gaps)
			}
			if g.Severity != diag.SeverityFatal {
				t.Errorf("%s severity = %v, want fatal", directive, g.Severity)
			}
			if !strings.Contains(g.Detail, "file reference is not read") {
				t.Errorf("%s detail does not name the file problem: %q", directive, g.Detail)
			}
			if g.Value != "file" {
				t.Errorf("%s value = %q, want \"file\"", directive, g.Value)
			}
			if strings.Contains(g.Detail+g.Value, "secret-ta.key") {
				t.Errorf("%s recorded the path: %q / %q", directive, g.Value, g.Detail)
			}
		})
	}

	t.Run("beside its own inline block", func(t *testing.T) {
		src := "remote vpn.example.test 1194\ntls-auth ta.key 1\n<tls-auth>\n" +
			staticKeyBlock() + "</tls-auth>\n"
		gaps := caps.Inspect(parse(t, src))
		g, ok := gapFor(gaps, "tls-auth")
		if !ok {
			t.Fatalf("tls-auth directive not classified: %+v", gaps)
		}
		if g.Severity != diag.SeverityFatal {
			t.Errorf("tls-auth severity = %v, want fatal", g.Severity)
		}
		if !strings.Contains(g.Detail, "inline <tls-auth> block") {
			t.Errorf("detail does not say the inline block is used instead: %q", g.Detail)
		}
	})
}

func TestInspectKeyDirectionWithoutWrappingIsIgnored(t *testing.T) {
	gaps := caps.Inspect(parse(t, "remote vpn.example.test 1194\nkey-direction 1\n"))
	g, ok := gapFor(gaps, "key-direction")
	if !ok {
		t.Fatal("key-direction not classified")
	}
	if g.Severity != diag.SeverityIgnored {
		t.Errorf("key-direction severity = %v, want ignored without a tls-auth block", g.Severity)
	}
}

func TestInspectMultipleRemotes(t *testing.T) {
	// Two remote lines, a hostname and its address: every one is parsed, kept
	// and dialed in order. Asserted as a set rather than by position.
	gaps := caps.Inspect(parse(t, "remote a.example.test 1195\nremote 203.0.113.9 1195\nproto tcp\n"))
	var remotes []diag.Gap
	for _, g := range gaps {
		if g.Directive == "remote" {
			remotes = append(remotes, g)
		}
	}
	if len(remotes) != 2 {
		t.Fatalf("got %d remote gaps, want 2", len(remotes))
	}
	for i, g := range remotes {
		if g.Severity != diag.SeveritySupported {
			t.Errorf("remote %d = %v, want supported: every remote is dialed if the ones before it did not answer",
				i, g.Severity)
		}
	}
}

// TestInspectRemoteRandomIsHonoured pins the row at supported: the remote list
// is shuffled before it is dialed. The detail is asserted and not only the
// severity, because the detail is the entire difference between the two arms —
// both grade supported, so a test reading the severity alone passes just as
// happily with classifyRemoteRandom's one-remote branch deleted.
func TestInspectRemoteRandomIsHonoured(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		// wantDetail is the phrase only this arm produces.
		wantDetail string
	}{
		{
			name:       "one remote",
			src:        "remote a.example.test 1195\nremote-random\n",
			wantDetail: "this profile has one remote, so the order cannot vary",
		},
		{
			name:       "several remotes",
			src:        "remote a.example.test 1195\nremote b.example.test 1195\nremote-random\n",
			wantDetail: "tried in a different order each attempt",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, ok := gapFor(caps.Inspect(parse(t, tc.src)), "remote-random")
			if !ok {
				t.Fatal("remote-random not classified")
			}
			if g.Severity != diag.SeveritySupported {
				t.Errorf("severity = %v, want supported — the list is shuffled before it is dialed", g.Severity)
			}
			if !strings.Contains(g.Detail, tc.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q: the two arms are told apart by this alone",
					g.Detail, tc.wantDetail)
			}
		})
	}
}

func TestInspectCipherAndDigest(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		directive string
		wantSev   diag.Severity
		wantValue string
	}{
		// The data channel supports AES-128/192/256 in GCM and CBC, and the
		// CBC digest SHA1/SHA256/SHA512. These verdicts come from the cipher
		// table in internal/crypto rather than from a list written out here.
		{"gcm256", "remote r.test 1194\ncipher AES-256-GCM\n", "cipher", diag.SeveritySupported, "AES-256-GCM"},
		{"gcm128", "remote r.test 1194\ncipher AES-128-GCM\n", "cipher", diag.SeveritySupported, "AES-128-GCM"},
		{"gcm192", "remote r.test 1194\ncipher AES-192-GCM\n", "cipher", diag.SeveritySupported, "AES-192-GCM"},
		{"cbc256", "remote r.test 1194\ncipher AES-256-CBC\n", "cipher", diag.SeveritySupported, "AES-256-CBC"},
		{"cbc192", "remote r.test 1194\ncipher AES-192-CBC\n", "cipher", diag.SeveritySupported, "AES-192-CBC"},
		{"cbc128", "remote r.test 1194\ncipher AES-128-CBC\n", "cipher", diag.SeveritySupported, "AES-128-CBC"},
		// CHACHA20-POLY1305 is out of scope and is not advertised. It must
		// classify as fatal, not as a cipher we quietly claim.
		{"chacha20", "remote r.test 1194\ncipher CHACHA20-POLY1305\n", "cipher", diag.SeverityFatal, "CHACHA20-POLY1305"},
		{"blowfish", "remote r.test 1194\ncipher BF-CBC\n", "cipher", diag.SeverityFatal, "BF-CBC"},
		{"sha1cbc", "remote r.test 1194\ncipher AES-256-CBC\nauth SHA1\n", "auth", diag.SeveritySupported, "SHA1"},
		{"sha256cbc", "remote r.test 1194\ncipher AES-256-CBC\nauth SHA256\n", "auth", diag.SeveritySupported, "SHA256"},
		{"sha512cbc", "remote r.test 1194\ncipher AES-256-CBC\nauth sha512\n", "auth", diag.SeveritySupported, "SHA512"},
		{"md5cbc", "remote r.test 1194\ncipher AES-256-CBC\nauth MD5\n", "auth", diag.SeverityFatal, "MD5"},
		{"nulldigestcbc", "remote r.test 1194\ncipher AES-256-CBC\nauth none\n", "auth", diag.SeverityFatal, "NONE"},
		{"digestmootwithgcm", "remote r.test 1194\ncipher AES-256-GCM\nauth SHA512\n", "auth", diag.SeverityIgnored, "SHA512"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, ok := gapFor(caps.Inspect(parse(t, tc.src)), tc.directive)
			if !ok {
				t.Fatalf("%s not classified", tc.directive)
			}
			if g.Severity != tc.wantSev {
				t.Errorf("severity = %v, want %v (%s)", g.Severity, tc.wantSev, g.Detail)
			}
			if g.Value != tc.wantValue {
				t.Errorf("value = %q, want %q", g.Value, tc.wantValue)
			}
		})
	}
}

// TestInspectImpliedSHA1Default covers a CBC cipher with no auth directive at
// all, so OpenVPN's SHA1 default applies. The absence has to be reported or it
// is invisible, and it is reported as supported rather than fatal, because the
// CBC path can produce a SHA1 tag and the parser records SHA1 as the default.
func TestInspectImpliedSHA1Default(t *testing.T) {
	gaps := caps.Inspect(parse(t, "remote r.test 1194\ncipher AES-256-CBC\n"))
	g, ok := gapFor(gaps, "auth")
	if !ok {
		t.Fatalf("implied digest not reported: %+v", gaps)
	}
	if g.Severity != diag.SeveritySupported {
		t.Errorf("implied digest severity = %v, want supported", g.Severity)
	}
	if !strings.Contains(g.Value, "implied") {
		t.Errorf("value = %q, want it marked as implied", g.Value)
	}

	// Not reported for an AEAD cipher, where the digest is unused.
	if _, ok := gapFor(caps.Inspect(parse(t, "remote r.test 1194\ncipher AES-256-GCM\n")), "auth"); ok {
		t.Error("implied digest reported for a GCM profile")
	}
	// Not reported when an explicit auth directive is present.
	explicit := caps.Inspect(parse(t, "remote r.test 1194\ncipher AES-256-CBC\nauth SHA256\n"))
	for _, g := range explicit {
		if g.Directive == "auth" && strings.Contains(g.Value, "implied") {
			t.Error("implied digest reported alongside an explicit auth directive")
		}
	}
}

func TestInspectCertificateVerificationDependsOnCA(t *testing.T) {
	// remote-cert-tls server is honoured: requiresRemoteCertTLSServer reads it
	// and the verifier requires serverAuth and a key usage extension on the
	// leaf.
	withCA := "remote r.test 1194\nremote-cert-tls server\n<ca>\nMIIB\n</ca>\n"
	g, ok := gapFor(caps.Inspect(parse(t, withCA)), "remote-cert-tls")
	if !ok {
		t.Fatal("remote-cert-tls not classified")
	}
	if g.Severity != diag.SeveritySupported {
		t.Errorf("with a CA: severity = %v, want supported", g.Severity)
	}

	// Without a CA there is nothing to verify against, and the client refuses
	// the profile at StageParse rather than dialing unverified.
	noCA := "remote r.test 1194\nremote-cert-tls server\n"
	g, ok = gapFor(caps.Inspect(parse(t, noCA)), "remote-cert-tls")
	if !ok {
		t.Fatal("remote-cert-tls not classified")
	}
	if g.Severity != diag.SeverityFatal {
		t.Errorf("without a CA: severity = %v, want fatal", g.Severity)
	}

	// Only the "server" form is honoured; the registry must not claim a check
	// it does not make.
	other := "remote r.test 1194\nremote-cert-tls client\n<ca>\nMIIB\n</ca>\n"
	g, ok = gapFor(caps.Inspect(parse(t, other)), "remote-cert-tls")
	if !ok {
		t.Fatal("remote-cert-tls not classified")
	}
	if g.Severity != diag.SeverityDegraded {
		t.Errorf("remote-cert-tls client: severity = %v, want degraded", g.Severity)
	}
}

// TestInspectVerifyX509Name pins all three match types as real checks, with the
// gap recording the match type rather than the name. The detail is asserted
// because the directive means a match on the subject, not a SAN match and not
// the TLS ServerName.
func TestInspectVerifyX509Name(t *testing.T) {
	for _, tc := range []struct {
		line      string
		wantSev   diag.Severity
		wantValue string
	}{
		{"verify-x509-name server-1 name", diag.SeveritySupported, "name"},
		{"verify-x509-name server-1 name-prefix", diag.SeveritySupported, "name-prefix"},
		{"verify-x509-name server-1 subject", diag.SeveritySupported, "subject"},
		// The omitted type is OpenVPN's default, which is subject.
		{"verify-x509-name server-1", diag.SeveritySupported, "subject"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			src := "remote r.test 1194\n" + tc.line + "\n<ca>\nMIIB\n</ca>\n"
			g, ok := gapFor(caps.Inspect(parse(t, src)), "verify-x509-name")
			if !ok {
				t.Fatal("verify-x509-name not classified")
			}
			if g.Severity != tc.wantSev {
				t.Errorf("severity = %v, want %v", g.Severity, tc.wantSev)
			}
			if g.Value != tc.wantValue {
				t.Errorf("value = %q, want %q", g.Value, tc.wantValue)
			}
			if strings.Contains(g.Detail, "ServerName") {
				t.Errorf("detail still claims the value feeds ServerName: %q", g.Detail)
			}
		})
	}

	// An unrecognised match type never reaches Inspect through the parser,
	// which refuses the profile outright, so it is asserted against a directive
	// placed on a hand-assembled Profile.
	assembled := &profile.Profile{Directives: []profile.Directive{
		{Name: "verify-x509-name", Args: []string{"server-1", "san"}, Line: 1},
	}}
	g, ok := gapFor(caps.Inspect(assembled), "verify-x509-name")
	if !ok {
		t.Fatal("verify-x509-name not classified")
	}
	if g.Severity != diag.SeverityFatal {
		t.Errorf("an unrecognised match type = %v, want fatal", g.Severity)
	}
}

// TestInspectArgumentDecidesSeverity covers the directives whose verdict turns
// on the argument they carry rather than on the keyword alone. ns-cert-type
// server is a real check on the leaf, so grading it degraded with "the
// extension is not checked" would be untrue; the client form is valid OpenVPN
// that nothing checks, and the registry must not claim otherwise.
func TestInspectArgumentDecidesSeverity(t *testing.T) {
	const caBlock = "<ca>\nMIIB\n</ca>\n"
	cases := []struct {
		name      string
		src       string
		directive string
		wantSev   diag.Severity
		// wantValue is the argument the gap carries into the session report.
		// Every row has one, including the two dev rows, whose whole point is
		// the value classifyDev puts there.
		wantValue string
	}{
		// classifyDev answers with the device *kind*, not the name the profile
		// wrote: a profile naming tun0 gets a tun device named by the client.
		// The numbered and bare spellings are the rows that make that a claim
		// rather than an echo.
		{"dev tun", "dev tun\n", "dev", diag.SeveritySupported, "tun"},
		{"dev tun0", "dev tun0\n", "dev", diag.SeveritySupported, "tun"},
		{"dev with no argument", "dev\n", "dev", diag.SeveritySupported, "tun"},
		{"dev tap", "dev tap\n", "dev", diag.SeverityFatal, "tap"},
		{"dev tap0", "dev tap0\n", "dev", diag.SeverityFatal, "tap"},
		// Neither kind: the name is reported as written, because there is
		// nothing to normalise it to.
		{"dev of neither kind", "dev myvpn\n", "dev", diag.SeverityFatal, "myvpn"},
		// tls-version-min may carry a second argument, and the client's floor
		// is already 1.2 — so asking for 1.2 changes nothing and asking for 1.3
		// asks for more than it will negotiate.
		{"tls-version-min 1.2", "tls-version-min 1.2 or-highest\n", "tls-version-min", diag.SeverityIgnored, "1.2"},
		{"tls-version-min 1.3", "tls-version-min 1.3\n", "tls-version-min", diag.SeverityDegraded, "1.3"},
		{"ns-cert-type server", "ns-cert-type server\n" + caBlock, "ns-cert-type", diag.SeveritySupported, "server"},
		{"ns-cert-type client", "ns-cert-type client\n" + caBlock, "ns-cert-type", diag.SeverityDegraded, "client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, ok := gapFor(caps.Inspect(parse(t, "remote r.test 1194\n"+tc.src)), tc.directive)
			if !ok {
				t.Fatalf("%s not classified", tc.directive)
			}
			if g.Severity != tc.wantSev {
				t.Errorf("severity = %v, want %v (%s)", g.Severity, tc.wantSev, g.Detail)
			}
			if g.Value != tc.wantValue {
				t.Errorf("value = %q, want %q", g.Value, tc.wantValue)
			}
		})
	}
}

// TestInspectFileReferences covers the two verdicts a "ca ca.crt" line can
// produce and the third only a hand-assembled profile can. Reading
// profile.FileRefs rather than inferring from a populated Profile.CA is what
// keeps the redundant reference beside an inline block from moving.
func TestInspectFileReferences(t *testing.T) {
	// Both "ca ca.crt" and an inline <ca> block: the block wins and the file is
	// never opened, which is why this profile parses from a string with no
	// directory at all.
	withBlock := "remote r.test 1194\nca ca.crt\n<ca>\nMIIB\n</ca>\n"
	g, _ := gapFor(caps.Inspect(parse(t, withBlock)), "ca")
	if g.Severity != diag.SeverityIgnored {
		t.Errorf("ca file reference beside a block = %v, want ignored", g.Severity)
	}
	// A file reference and no block. Parsed from its directory the file is
	// read, and the row is supported.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("MIIB\n"), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	cfgPath := filepath.Join(dir, "p.ovpn")
	if err := os.WriteFile(cfgPath, []byte("remote r.test 1194\nca ca.crt\n"), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	p, err := profile.ParsePath(cfgPath)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	resolved := caps.Inspect(p)
	g, _ = gapFor(resolved, "ca")
	if g.Severity != diag.SeveritySupported {
		t.Errorf("ca file reference read from the profile's directory = %v, want supported", g.Severity)
	}

	// The third case reaches Inspect only from a profile assembled by hand:
	// ParsePath reads the file and ParseString refuses the profile, so
	// neither entry point can produce it. The row must still be honest.
	unresolved := &profile.Profile{
		Directives: []profile.Directive{{Name: "ca", Args: []string{"ca.crt"}, Line: 2}},
	}
	g, _ = gapFor(caps.Inspect(unresolved), "ca")
	if g.Severity != diag.SeverityFatal {
		t.Errorf("ca file reference nothing resolved = %v, want fatal", g.Severity)
	}

	for _, gg := range resolved {
		if strings.Contains(gg.Value+gg.Detail, "ca.crt") {
			t.Errorf("file name recorded in a gap: %q / %q", gg.Value, gg.Detail)
		}
	}
}

func TestInspectDHCPOption(t *testing.T) {
	src := "remote r.test 1194\ndhcp-option DNS 8.8.8.8\ndhcp-option WINS 10.0.0.1\n"
	gaps := caps.Inspect(parse(t, src))
	var got []diag.Gap
	for _, g := range gaps {
		if g.Directive == "dhcp-option" {
			got = append(got, g)
		}
	}
	if len(got) != 2 {
		t.Fatalf("got %d dhcp-option gaps, want 2", len(got))
	}
	if got[0].Severity != diag.SeveritySupported || got[0].Value != "DNS" {
		t.Errorf("DNS = %v/%q, want supported/DNS", got[0].Severity, got[0].Value)
	}
	if got[1].Severity != diag.SeverityIgnored || got[1].Value != "WINS" {
		t.Errorf("WINS = %v/%q, want ignored/WINS", got[1].Severity, got[1].Value)
	}
	for _, g := range got {
		if strings.Contains(g.Value, "8.8.8.8") || strings.Contains(g.Value, "10.0.0.1") {
			t.Error("dhcp-option address recorded in a gap value")
		}
	}
}

func TestInspectReportsInFileOrder(t *testing.T) {
	src := "client\n<ca>\nMIIB\n</ca>\nremote r.test 1194\n<tls-auth>\n" +
		staticKeyBlock() + "</tls-auth>\nfast-io\n"
	gaps := caps.Inspect(parse(t, src))
	var order []string
	for _, g := range gaps {
		order = append(order, g.Directive)
	}
	want := "client <ca> remote <tls-auth> fast-io"
	if got := strings.Join(order, " "); got != want {
		t.Errorf("order = %q, want %q", got, want)
	}
}

func TestFilterAndWorst(t *testing.T) {
	gaps := []diag.Gap{
		{Directive: "nobind", Severity: diag.SeverityIgnored},
		{Directive: "client", Severity: diag.SeveritySupported},
		{Directive: "comp-lzo", Severity: diag.SeverityDegraded},
		{Directive: "tls-auth", Severity: diag.SeverityFatal},
	}
	if got := caps.Worst(gaps); got != diag.SeverityFatal {
		t.Errorf("Worst = %v, want fatal", got)
	}
	if got := caps.Worst(nil); got != diag.SeveritySupported {
		t.Errorf("Worst(nil) = %v, want supported", got)
	}
	got := caps.Filter(gaps, diag.SeverityDegraded)
	if len(got) != 2 || got[0].Directive != "comp-lzo" || got[1].Directive != "tls-auth" {
		t.Errorf("Filter = %+v, want comp-lzo and tls-auth in order", got)
	}
	if n := len(caps.Filter(gaps, diag.SeveritySupported)); n != 4 {
		t.Errorf("Filter(supported) kept %d, want 4", n)
	}
}

// Gaps are aggregated and serialised into session reports, so nothing
// identifying may reach them.
func TestInspectLeaksNothingIdentifying(t *testing.T) {
	src := `client
dev tun
proto tcp
remote secret-host.example.invalid 1195
remote 198.51.100.7 1195
verify-x509-name secret-cn.example.invalid name
dhcp-option DNS 198.51.100.53
dhcp-option DOMAIN corp.example.invalid
user secretuser
group secretgroup
up /etc/openvpn/secret-script
down /etc/openvpn/secret-script
ca /etc/openvpn/secret-ca.crt
setenv UV_SERVERID 4242
<ca>
-----BEGIN CERTIFICATE-----
SECRETCERTBODY
-----END CERTIFICATE-----
</ca>
<tls-auth>
` + staticKeyBlock() + `</tls-auth>
`
	secrets := []string{
		"secret-host", "198.51.100", "secret-cn", "corp.example.invalid",
		"secretuser", "secretgroup", "secret-script", "secret-ca.crt",
		"SECRETCERTBODY", "4242",
		// The wrap key itself, whole and by its first line. The parser loads
		// this body, so "the block was never read" is not the reason it
		// cannot reach a gap.
		staticKeyHex(), staticKeyHex()[:32],
	}
	for _, g := range caps.Inspect(parse(t, src)) {
		text := g.Directive + " " + g.Value + " " + g.Detail
		for _, s := range secrets {
			if strings.Contains(text, s) {
				t.Errorf("gap %q leaked %q: %q", g.Directive, s, text)
			}
		}
	}
}

// TestInspectCompression grades the compression directives on the codec rather
// than the framing. Every one of them is read from the profile and framed
// correctly on the wire; LZO is decompressed, while LZ4 may meet a peer that
// compressed with a codec this client lacks.
func TestInspectCompression(t *testing.T) {
	cases := []struct {
		src       string
		directive string
		value     string
		want      diag.Severity
		why       string
	}{
		{"comp-lzo\n", "comp-lzo", "", diag.SeveritySupported,
			"COMP_ALG_LZO: the peer may compress and we decompress"},
		{"comp-lzo yes\n", "comp-lzo", "yes", diag.SeveritySupported,
			"adaptive off, so the peer compresses whatever shrinks, and we decompress it"},
		{"compress lzo\n", "compress", "lzo", diag.SeveritySupported,
			"the same COMP_ALG_LZO, spelled the 2.4 way"},
		{"comp-lzo no\n", "comp-lzo", "no", diag.SeveritySupported,
			"COMP_ALG_STUB with no flags: framing only, and we produce it"},
		{"compress\n", "compress", "", diag.SeveritySupported,
			"COMP_ALG_STUB with COMP_F_SWAP: framing only, and we produce it"},
		{"compress stub-v2\n", "compress", "stub-v2", diag.SeveritySupported,
			"the v2 framing writes no byte at all"},
		{"compress lz4\n", "compress", "lz4", diag.SeverityDegraded,
			"a real codec behind the swapping framing"},
		{"compress lz4-v2\n", "compress", "lz4-v2", diag.SeverityDegraded,
			"a real codec behind the v2 framing"},
		{"allow-compression no\n", "allow-compression", "no", diag.SeveritySupported,
			"refused from both sources, exactly as COMP_F_ALLOW_STUB_ONLY does"},
		{"allow-compression yes\n", "allow-compression", "yes", diag.SeveritySupported,
			"permitted; the codec is graded on the compression directive"},
		{"comp-noadapt\n", "comp-noadapt", "", diag.SeverityIgnored,
			"adaptive only decides how eagerly a peer compresses; we never do"},
	}
	for _, tc := range cases {
		p := parse(t, "client\ndev tun\nremote host.example.test 1194\n"+tc.src)
		g, ok := gapFor(caps.Inspect(p), tc.directive)
		if !ok {
			t.Errorf("%q produced no %q gap", tc.src, tc.directive)
			continue
		}
		if g.Severity != tc.want {
			t.Errorf("%q = %v, want %v — %s (%s)", tc.src, g.Severity, tc.want, tc.why, g.Detail)
		}
		if g.Value != tc.value {
			t.Errorf("%q recorded value %q, want %q", tc.src, g.Value, tc.value)
		}
	}
}

// TestInspectFragment pins that "fragment 0" is ignored and any other
// argument, malformed ones included, is fatal.
func TestInspectFragment(t *testing.T) {
	cases := []struct {
		src   string
		value string
		want  diag.Severity
		why   string
	}{
		{"fragment 0\n", "0", diag.SeverityIgnored,
			"ce->fragment of 0 allocates no fragment frame; this client fragments nothing either"},
		{"fragment 1300\n", "1300", diag.SeverityFatal,
			"a peer with it enabled frames every data packet with 4 bytes this client cannot strip"},
		{"fragment 68\n", "68", diag.SeverityFatal,
			"the reference's lower bound is still a real fragment size"},
		{"fragment 1\n", "1", diag.SeverityFatal,
			"below the reference's bound, but non-zero is non-zero here"},
		{"fragment\n", "", diag.SeverityFatal,
			"no argument at all is malformed, not a request for zero"},
		{"fragment mtu\n", "mtu", diag.SeverityFatal,
			"positive_atoi would read this as zero; a malformed argument must not buy a pass"},
	}
	for _, tc := range cases {
		p := parse(t, "client\ndev tun\nremote host.example.test 1194\n"+tc.src)
		g, ok := gapFor(caps.Inspect(p), "fragment")
		if !ok {
			t.Errorf("%q produced no fragment gap", tc.src)
			continue
		}
		if g.Severity != tc.want {
			t.Errorf("%q = %v, want %v — %s (%s)", tc.src, g.Severity, tc.want, tc.why, g.Detail)
		}
		if g.Value != tc.value {
			t.Errorf("%q recorded value %q, want %q", tc.src, g.Value, tc.value)
		}
	}
}
