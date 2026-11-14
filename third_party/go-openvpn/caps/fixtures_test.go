// The profiles the registry matrix is measured over.
//
// One fixture per structural shape a deployed profile exhibits, and between
// them they instantiate every row in the capability registry — which is the
// point: a row nothing instantiates can be regraded without moving a number.
// They also cover how a profile is *written*: CRLF, comment and blank lines
// inside the inline blocks, an endpoint given as an address, a directive
// spelled in the case OpenVPN itself refuses.
//
// The certificate bodies are inert. The parser carries key material without
// parsing it and caps.Inspect grades directives, not bytes, so a fixture that
// needed a real certificate would be paying for something nothing here reads.
// profile's own fixtures generate one where an assertion needs it.
//
// testdata/shape-inventory.txt is the published claim about what these cover:
// a holder of a corpus of real provider profiles checks it against that file,
// and anything such a corpus exercises that the file does not name is a shape
// these tests have stopped seeing.

package caps_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// shape is one profile the fixtures carry, and what it is there to exercise.
type fixtureShape struct {
	// Group is the subdirectory it is written to, and the dimension caps'
	// matrix aggregates by.
	Group string
	// Name is the file's base name, without the extension.
	Name string
	// Refused says the parser must decline this profile.
	Refused bool

	// directives is the body, after the prelude every profile shares. A shape
	// naming no remote is given one.
	directives string
	// inline names the blocks to embed, in order.
	inline []string
	// beside names the files to write next to the profile.
	beside []string
	// crlf writes the profile with CRLF line endings. Over half the profiles
	// in a real corpus are written that way, and a tokenizer that keeps the
	// carriage return puts it in an argument.
	crlf bool
	// padded pads the inline blocks with the blank and comment lines real
	// generators leave in them, and the profile with comment lines of its own.
	padded bool
}

// prelude opens every generated profile. Both lines are graded, so they are
// part of what the fixtures cover rather than boilerplate around them.
const prelude = "client\ndev tun\n"

// defaultRemote is appended to a shape that names no endpoint of its own: a
// profile with no remote line is refused, and only the shape that means to be
// refused may be.
const defaultRemote = "remote vpn.example.test 1194\n"

// fixtureShapes is the table. Each entry is one structural pattern a deployed profile
// exhibits, or one group of directives that would otherwise be graded by
// nothing.
//
// The groups after "misc" exist for coverage rather than realism: no deployed
// profile carries every routing directive at once, but a registry row nothing
// instantiates is a row whose grading can change without moving a number.
var fixtureShapes = []fixtureShape{
	// ---- Trust store -------------------------------------------------

	{Group: "trust", Name: "inline-ca-userpass",
		directives: "auth-user-pass\nverb 3\n",
		inline:     []string{"ca"}},

	{Group: "trust", Name: "inline-ca-cert-key",
		directives: "verb 3\n",
		inline:     []string{"ca", "cert", "key"}},

	{Group: "trust", Name: "fileref-ca",
		directives: "ca ca.crt\nauth-user-pass\n",
		beside:     []string{"ca.crt"}},

	// The named file is deliberately not written. The inline block supersedes
	// it, so a parser that opened it anyway would fail here rather than
	// quietly load the wrong trust store.
	{Group: "trust", Name: "fileref-ca-superseded",
		directives: "ca ca.crt\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "trust", Name: "fileref-cert-key",
		directives: "ca ca.crt\ncert client.crt\nkey client.key\n",
		beside:     []string{"ca.crt", "client.crt", "client.key"}},

	// ---- Control-channel wrap ----------------------------------------

	{Group: "wrap", Name: "tls-auth-direction-1",
		directives: "key-direction 1\nauth-user-pass\n",
		inline:     []string{"ca", "tls-auth"}},

	{Group: "wrap", Name: "tls-auth-direction-0",
		directives: "key-direction 0\nauth-user-pass\n",
		inline:     []string{"ca", "tls-auth"}},

	{Group: "wrap", Name: "tls-auth-no-direction",
		directives: "auth-user-pass\n",
		inline:     []string{"ca", "tls-auth"}},

	{Group: "wrap", Name: "tls-crypt",
		directives: "auth-user-pass\n",
		inline:     []string{"ca", "tls-crypt"}},

	{Group: "wrap", Name: "tls-auth-file-reference",
		directives: "tls-auth ta.key 1\nauth-user-pass\n",
		inline:     []string{"ca"},
		beside:     []string{"ta.key"}},

	{Group: "wrap", Name: "tls-crypt-v2-file-reference",
		directives: "tls-crypt-v2 client-v2.key\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "wrap", Name: "key-direction-without-wrap",
		directives: "key-direction 1\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// An inline wrap block whose body is not a 256-byte static key.
	{Group: "wrap", Name: "tls-auth-empty",
		directives: "auth-user-pass\n",
		inline:     []string{"ca", "tls-auth-empty"},
		Refused:    true},

	// ---- Endpoints and transport -------------------------------------

	{Group: "transport", Name: "several-remotes",
		directives: "remote vpn1.example.test 1194\nremote vpn2.example.test 1194\n" +
			"remote vpn3.example.test 443\nauth-user-pass\n",
		inline: []string{"ca"}},

	// The third field is the only statement of transport these make.
	{Group: "transport", Name: "per-remote-proto",
		directives: "remote vpn1.example.test 1194 udp\nremote vpn2.example.test 443 tcp-client\n" +
			"auth-user-pass\n",
		inline: []string{"ca"}},

	// remote-random with somewhere to shuffle to. Deployed profiles pair it
	// with a single remote, where a shuffle is unobservable; without this one
	// the shuffle is never actually exercised.
	{Group: "transport", Name: "remote-random-several",
		directives: "remote vpn1.example.test 1194\nremote vpn2.example.test 1194\n" +
			"remote-random\nauth-user-pass\n",
		inline: []string{"ca"}},

	{Group: "transport", Name: "remote-random-single",
		directives: "remote-random\nremote-random-hostname\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "transport", Name: "tcp-explicit",
		directives: "remote vpn.example.test 443\nproto tcp-client\nport 443\nfloat\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// An endpoint given as an address rather than a name, and a flag written
	// bare where the same directive elsewhere carries a count.
	{Group: "transport", Name: "address-literal-remote",
		directives: "remote 203.0.113.9 1194\nexplicit-exit-notify\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// proto spelled in upper case. OpenVPN matches the argument case-sensitively
	// and refuses the file; this client lowercases it first, so the two
	// disagree about a profile that is otherwise ordinary.
	{Group: "transport", Name: "uppercase-proto",
		directives: "remote vpn.example.test 1194 UDP\nproto UDP\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// ---- Compression --------------------------------------------------

	{Group: "compression", Name: "comp-lzo-bare",
		directives: "comp-lzo\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "comp-lzo-no",
		directives: "comp-lzo no\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "comp-noadapt",
		directives: "comp-lzo\ncomp-noadapt\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "compress-stub",
		directives: "compress\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "compress-stub-v2",
		directives: "compress stub-v2\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "compress-lz4",
		directives: "compress lz4\nauth-user-pass\n", inline: []string{"ca"}},
	{Group: "compression", Name: "allow-compression-no",
		directives: "allow-compression no\nauth-user-pass\n", inline: []string{"ca"}},

	// A compressing algorithm beside the directive that forbids one. The pair
	// parses: the refusal belongs to compress.EffectiveMode, at the point the
	// framing is chosen, and a set in which the two never meet states nothing
	// about it.
	{Group: "compression", Name: "allow-compression-no-with-lzo",
		directives: "allow-compression no\ncomp-lzo\nauth-user-pass\n", inline: []string{"ca"}},

	// ---- Data channel --------------------------------------------------

	{Group: "crypto", Name: "cbc-explicit-digest",
		directives: "cipher AES-256-CBC\nauth SHA256\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// No auth directive, so the digest is the SHA1 OpenVPN implies. That gap
	// is reported for something the profile does not say.
	{Group: "crypto", Name: "cbc-implied-digest",
		directives: "cipher AES-256-CBC\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "crypto", Name: "gcm",
		directives: "cipher AES-256-GCM\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// Cipher and digest in lower case. Both are looked up case-insensitively,
	// and a profile that writes them this way is the only thing that says so.
	{Group: "crypto", Name: "lowercase-cipher-and-digest",
		directives: "cipher aes-256-cbc\nauth sha256\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "crypto", Name: "negotiable-ciphers",
		directives: "data-ciphers AES-256-GCM:AES-128-GCM\ndata-ciphers-fallback AES-256-CBC\n" +
			"ncp-disable\nauth-user-pass\n",
		inline: []string{"ca"}},

	{Group: "crypto", Name: "legacy-knobs",
		directives: "keysize 256\ntls-cipher TLS-DHE-RSA-WITH-AES-256-CBC-SHA\ntls-version-min 1.2\n" +
			"auth-user-pass\n",
		inline: []string{"ca"}},

	// ---- Session ------------------------------------------------------

	{Group: "session", Name: "renegotiation",
		directives: "reneg-sec 3600\nreneg-bytes 0\nbecome-primary 0\nhand-window 60\ntran-window 3600\n" +
			"auth-user-pass\n",
		inline: []string{"ca"}},

	{Group: "session", Name: "keepalive",
		directives: "keepalive 10 60\nping 10\nping-restart 60\nping-timer-rem\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "session", Name: "ping-exit",
		directives: "ping 10\nping-exit 60\nexplicit-exit-notify 2\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "session", Name: "peer-verification",
		directives: "remote-cert-tls server\nverify-x509-name vpn.example.test name\nns-cert-type server\n" +
			"auth-user-pass\n",
		inline: []string{"ca"}},

	{Group: "session", Name: "credential-flow",
		directives: "auth-user-pass\nauth-nocache\nauth-retry nointeract\nauth-federate\n" +
			"x-go-openvpn-flow aws\nx-openlawsvpn-flow aws\n",
		inline: []string{"ca"}},

	// ---- Coverage ------------------------------------------------------

	{Group: "misc", Name: "routing",
		directives: "route 10.0.0.0 255.0.0.0\nroute-delay 5\nroute-method exe\nroute-metric 1\n" +
			"redirect-gateway def1\nmax-routes 100\nblock-outside-dns\nallow-recursive-routing\n" +
			"dhcp-option DNS 203.0.113.1\nauth-user-pass\n",
		inline: []string{"ca"}},

	{Group: "misc", Name: "framing",
		directives: "tun-mtu 1500\ntun-mtu-extra 32\ntun-mtu-max 1600\nlink-mtu 1500\nmssfix 1400\n" +
			"fragment 1300\ntun-ipv6\nauth-user-pass\n",
		inline: []string{"ca"}},

	// "fragment 0", as published provider archives ship it.
	{Group: "misc", Name: "fragment-disabled",
		directives: "fragment 0\nmssfix 1400\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// A published provider profile, directive for directive, with the CA as a
	// sibling file as its archive ships it.
	{Group: "provider", Name: "legacy-udp-fileref",
		directives: "proto udp\nnobind\nremote-random\n" +
			"remote vpn1.example.test 443\nremote vpn2.example.test 1912\n" +
			"ca ca.crt\nauth-user-pass\nremote-cert-tls server\ncipher BF-CBC\n" +
			"resolv-retry 5\ntun-mtu 48000\nfragment 0\nmssfix 0\nroute-delay 5 30\n" +
			"ping-restart 0\nkeepalive 5 30\ncomp-lzo\nmute-replay-warnings\nfast-io\n" +
			"sndbuf 524288\nrcvbuf 524288\n",
		beside: []string{"ca.crt"}},

	{Group: "misc", Name: "hooks",
		directives: "up /etc/openvpn/up.sh\ndown /etc/openvpn/down.sh\nup-restart\n" +
			"script-security 2\nsetenv opt example\nuser nobody\ngroup nogroup\n" +
			"remap-usr1 SIGHUP\nauth-user-pass\n",
		inline: []string{"ca"}},

	// ---- Lexical shape --------------------------------------------------
	//
	// How a profile is written, rather than what it says. A real corpus is
	// full of this and none of it is visible in a directive table: over half
	// the profiles use CRLF, and the generators that produce them leave
	// comment and blank lines both around the directives and inside the
	// inline blocks.

	{Group: "lexical", Name: "crlf-line-endings",
		directives: "auth-user-pass\ncipher AES-256-GCM\n",
		inline:     []string{"ca", "tls-auth"},
		crlf:       true},

	{Group: "lexical", Name: "comments-and-blank-lines",
		directives: "auth-user-pass\ncipher AES-256-GCM\n",
		inline:     []string{"ca", "tls-crypt"},
		padded:     true},

	// Both at once, which is what most of a real corpus looks like.
	{Group: "lexical", Name: "crlf-with-comments",
		directives: "key-direction 1\nauth-user-pass\ncomp-lzo\n",
		inline:     []string{"ca", "cert", "key", "tls-auth"},
		crlf:       true, padded: true},

	{Group: "misc", Name: "housekeeping",
		directives: "nobind\npersist-key\npersist-tun\npersist-remote-ip\nresolv-retry infinite\n" +
			"fast-io\nrcvbuf 262144\nsndbuf 262144\nmute 20\nmute-replay-warnings\n" +
			"connect-retry-max 3\nconnect-timeout 10\npush-peer-info\npull\ntls-client\nverb 3\n" +
			"auth-user-pass\n",
		inline: []string{"ca"}},
}

// writeFixtures writes every fixture into dir, one subdirectory per group,
// and returns what it wrote.
func writeFixtures(t *testing.T, dir string) []fixtureFile {
	t.Helper()
	out := make([]fixtureFile, 0, len(fixtureShapes))
	for _, s := range fixtureShapes {
		group := filepath.Join(dir, s.Group)
		if err := os.MkdirAll(group, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		for _, name := range s.beside {
			if err := os.WriteFile(filepath.Join(group, name), []byte(besideFile(name)), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
		body, err := s.render()
		if err != nil {
			t.Fatalf("%s/%s: %v", s.Group, s.Name, err)
		}
		path := filepath.Join(group, s.Name+".ovpn")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		out = append(out, fixtureFile{group: s.Group, name: s.Name, path: path, refused: s.Refused})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// render assembles one profile.
func (s fixtureShape) render() (string, error) {
	var b strings.Builder
	if s.padded {
		b.WriteString("# generated fixture\n;\n")
	}
	b.WriteString(prelude)
	if !strings.Contains(s.directives, "remote ") {
		b.WriteString(defaultRemote)
	}
	if s.padded {
		b.WriteString("\n# the rest of the profile\n")
	}
	b.WriteString(s.directives)
	for _, tag := range s.inline {
		block, err := inlineBlock(tag)
		if err != nil {
			return "", err
		}
		if s.padded {
			block = pad(block)
		}
		b.WriteString(block)
	}
	out := b.String()
	if s.crlf {
		out = strings.ReplaceAll(out, "\n", "\r\n")
	}
	return out, nil
}

// pad puts a comment and a blank line inside an inline block, where a real
// generator's banner and its spacing end up. The body between the tags is the
// part a parser has to skip over to find the material.
func pad(block string) string {
	open, rest, ok := strings.Cut(block, "\n")
	if !ok {
		return block
	}
	return open + "\n#\n# key material follows\n#\n\n" + rest
}

// wrapBlock renders body between an opening and closing tag.
func wrapBlock(tag, body string) string {
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return "<" + tag + ">\n" + body + "</" + tag + ">\n"
}

// fixtureFile is one written fixture.
type fixtureFile struct {
	group, name, path string
	// refused says the parser must decline it.
	refused bool
}

// id names the fixture in output — "wrap/tls-auth-empty".
func (f fixtureFile) id() string { return f.group + "/" + f.name }

// Inert key material. Nothing here parses it: the profile parser carries a
// certificate body without reading it, and caps.Inspect grades the directive
// that named it. A real PKI would be ceremony.
const (
	inertCert = "-----BEGIN CERTIFICATE-----\nMIIBinertfixturebody\n-----END CERTIFICATE-----\n"
	inertKey  = "-----BEGIN PRIVATE KEY-----\nMIIBinertfixturebody\n-----END PRIVATE KEY-----\n"
)

// inertStaticKey is a well-formed OpenVPN static key: the parser *does* read
// these, and refuses a body that is not 256 bytes, so this one has to be real
// hex of the right length even though its value means nothing.
var inertStaticKey = func() string {
	var b strings.Builder
	b.WriteString("#\n# 2048 bit OpenVPN static key\n#\n")
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for range 16 {
		b.WriteString("0123456789abcdef0123456789abcdef\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String()
}()

// inlineBlock renders one inline block. The tag "tls-auth-empty" is the wrap
// block with nothing between the tags, which is a shape and not an omission.
func inlineBlock(tag string) (string, error) {
	switch tag {
	case "ca", "cert":
		return wrapBlock(tag, inertCert), nil
	case "key":
		return wrapBlock(tag, inertKey), nil
	case "tls-auth", "tls-crypt":
		return wrapBlock(tag, inertStaticKey), nil
	case "tls-auth-empty":
		return "<tls-auth>\n</tls-auth>\n", nil
	}
	return "", fmt.Errorf("no inline block named %q", tag)
}

// besideFile returns the contents of a file written next to a profile.
func besideFile(name string) string {
	switch name {
	case "client.key":
		return inertKey
	case "ta.key":
		return inertStaticKey
	default:
		return inertCert
	}
}
