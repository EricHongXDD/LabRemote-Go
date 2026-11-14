// The profiles the parser properties range over: one fixture per shape the
// parser treats differently.

package profile_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// fixtureShape is one profile the fixtures carry.
type fixtureShape struct {
	// Group is the subdirectory it is written to.
	Group string
	Name  string
	// Refused says the parser must decline this profile.
	Refused bool

	// directives is the body after the prelude; a shape naming no remote is
	// given one.
	directives string
	inline     []string
	// beside names files to write next to the profile.
	beside []string
	crlf   bool
	// padded adds blank and comment lines to the profile and its blocks.
	padded bool
}

// prelude opens every generated profile.
const prelude = "client\ndev tun\n"

// defaultRemote is appended to a shape that names no endpoint of its own.
const defaultRemote = "remote vpn.example.test 1194\n"

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

	// A published provider profile, directive for directive.
	{Group: "provider", Name: "legacy-udp-fileref",
		directives: "proto udp\nnobind\nremote-random\n" +
			"remote vpn1.example.test 443\nremote vpn2.example.test 1912\n" +
			"ca ca.crt\nauth-user-pass\nremote-cert-tls server\ncipher BF-CBC\n" +
			"resolv-retry 5\ntun-mtu 48000\nfragment 0\nmssfix 0\nroute-delay 5 30\n" +
			"ping-restart 0\nkeepalive 5 30\ncomp-lzo\nmute-replay-warnings\nfast-io\n" +
			"sndbuf 524288\nrcvbuf 524288\n",
		beside: []string{"ca.crt"}},

	// ca.crt is deliberately not written; the inline block supersedes it.
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

	{Group: "transport", Name: "per-remote-proto",
		directives: "remote vpn1.example.test 1194 udp\nremote vpn2.example.test 443 tcp-client\n" +
			"auth-user-pass\n",
		inline: []string{"ca"}},

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

	{Group: "transport", Name: "address-literal-remote",
		directives: "remote 203.0.113.9 1194\nexplicit-exit-notify\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// Stock openvpn refuses upper-case proto; this client accepts it.
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

	{Group: "compression", Name: "allow-compression-no-with-lzo",
		directives: "allow-compression no\ncomp-lzo\nauth-user-pass\n", inline: []string{"ca"}},

	// ---- Data channel --------------------------------------------------

	{Group: "crypto", Name: "cbc-explicit-digest",
		directives: "cipher AES-256-CBC\nauth SHA256\nauth-user-pass\n",
		inline:     []string{"ca"}},

	// No auth directive: the digest is the implied SHA1.
	{Group: "crypto", Name: "cbc-implied-digest",
		directives: "cipher AES-256-CBC\nauth-user-pass\n",
		inline:     []string{"ca"}},

	{Group: "crypto", Name: "gcm",
		directives: "cipher AES-256-GCM\nauth-user-pass\n",
		inline:     []string{"ca"}},

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

// pad puts comment and blank lines inside an inline block.
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
	refused           bool
}

// id names the fixture in output — "wrap/tls-auth-empty".
func (f fixtureFile) id() string { return f.group + "/" + f.name }

// inertKey is a stand-in private key; the parser never reads it.
const inertKey = "-----BEGIN PRIVATE KEY-----\nMIIBinertfixturebody\n-----END PRIVATE KEY-----\n"

// inertCert is a real self-signed certificate, generated once per run, so a
// CA can build a trust store.
var inertCert = func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("fixture CA: " + err.Error())
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic("fixture CA: " + err.Error())
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}()

// inertStaticKey is a well-formed 256-byte OpenVPN static key.
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

// inlineBlock renders one inline block; "tls-auth-empty" is an empty
// <tls-auth>.
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
