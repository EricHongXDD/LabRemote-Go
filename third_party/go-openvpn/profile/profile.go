// Package profile parses OpenVPN .ovpn configuration files, and builds
// profiles programmatically from a Spec.
//
// Every directive line is recorded on Profile.Directives, and every inline
// block tag on Profile.InlineBlocks, for the capability preflight in the caps
// package. A profile that names its CA, certificate or key in a separate file
// needs a directory to resolve it: ParsePath, ParseFileIn and ParseFileInFS
// have one, ParseFile and ParseString refuse such a profile with
// ErrNoProfileDir.
package profile

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/buengese/go-openvpn/internal/compress"

	"github.com/buengese/go-openvpn/dns"
)

// Directive is one directive line as the parser saw it.
type Directive struct {
	// Name is the directive keyword, lowercased.
	Name string `json:"name"`
	// Args are the whitespace-separated arguments after the keyword, nil for
	// a bare directive.
	Args []string `json:"args,omitempty"`
	// Line is the 1-based line number, zero when the directive has no source
	// line.
	Line int `json:"line,omitempty"`
}

// String renders the directive back into its source form.
func (d Directive) String() string {
	if len(d.Args) == 0 {
		return d.Name
	}
	return d.Name + " " + strings.Join(d.Args, " ")
}

// InlineBlock records that an inline <tag>...</tag> block was present. The
// body is never kept, so an InlineBlock is safe to log.
type InlineBlock struct {
	// Tag is the block's tag name, verbatim.
	Tag string
	// Line is the 1-based line number of the opening tag.
	Line int
}

// FileRef records a ca, cert or key directive that named a file, and what the
// parser did with it. The file name is not kept, since these records reach
// session reports.
type FileRef struct {
	// Tag is the directive keyword: "ca", "cert" or "key".
	Tag string
	// Line is the 1-based line number the directive appeared on.
	Line int
	// Loaded reports that the file was read into the matching field.
	Loaded bool
	// Superseded reports that an inline block of the same tag was used
	// instead, and the file was not opened.
	Superseded bool
}

// Proto is the transport protocol for the VPN tunnel.
type Proto int

const (
	// ProtoTCP uses TCP with the 2-byte length-prefix framing.
	ProtoTCP Proto = iota
	// ProtoUDP uses raw UDP packets.
	ProtoUDP
)

// String is the profile spelling of the transport: "tcp" or "udp".
func (p Proto) String() string {
	if p == ProtoTCP {
		return "tcp"
	}
	return "udp"
}

// ParseProto normalises an OpenVPN transport spelling, as used by --proto and
// the third field of --remote. Address-family spellings (udp4, tcp6-client)
// reduce to their transport; the -server spellings are refused.
func ParseProto(s string) (Proto, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "udp", "udp4", "udp6":
		return ProtoUDP, true
	case "tcp", "tcp4", "tcp6",
		"tcp-client", "tcp4-client", "tcp6-client":
		return ProtoTCP, true
	default:
		return 0, false
	}
}

// X509NameMatch is the match type of --verify-x509-name: which part of the
// server certificate's subject the value is compared against.
type X509NameMatch int

const (
	// X509NameSubject compares against the whole subject DN, OpenVPN's
	// default.
	X509NameSubject X509NameMatch = iota
	// X509NameCN compares against the common name, spelled "name".
	X509NameCN
	// X509NameCNPrefix requires the common name to start with the value,
	// spelled "name-prefix".
	X509NameCNPrefix
)

// String returns the directive spelling of the match type.
func (m X509NameMatch) String() string {
	switch m {
	case X509NameSubject:
		return "subject"
	case X509NameCN:
		return "name"
	case X509NameCNPrefix:
		return "name-prefix"
	default:
		return "unknown"
	}
}

// MarshalText implements encoding.TextMarshaler. An out-of-range value
// marshals as "unknown", which UnmarshalText refuses.
func (m X509NameMatch) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler. An unrecognised name is
// an error.
func (m *X509NameMatch) UnmarshalText(text []byte) error {
	switch name := string(text); name {
	case "subject":
		*m = X509NameSubject
	case "name":
		*m = X509NameCN
	case "name-prefix":
		*m = X509NameCNPrefix
	default:
		return fmt.Errorf("profile: unknown verify-x509-name match type %q", name)
	}
	return nil
}

// ParseX509NameMatch normalises the optional second argument of
// --verify-x509-name, case-insensitively. The empty string is "subject". An
// unrecognised type is refused, as OpenVPN refuses it.
func ParseX509NameMatch(s string) (X509NameMatch, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "subject":
		return X509NameSubject, true
	case "name":
		return X509NameCN, true
	case "name-prefix":
		return X509NameCNPrefix, true
	default:
		return 0, false
	}
}

// Remote is one --remote line. Port and Proto are resolved against the
// profile's --port and --proto when the line does not name them.
type Remote struct {
	// Host is the hostname or address as written in the profile.
	Host string
	// Port is the port to dial.
	Port int
	// Proto is the transport to dial.
	Proto Proto
	// ProtoSet reports whether the remote line named a protocol itself.
	ProtoSet bool
}

// Profile holds the parsed contents of an .ovpn file.
//
// It holds key material. TLSAuth and TLSCrypt redact under %v and
// json.Marshal; CA, Cert and Key do not.
type Profile struct {
	// Remote, Port and Proto are Remotes[0].
	Remote string
	Port   int
	Proto  Proto

	// Remotes is every --remote line, in file order. Never empty in a parsed
	// profile.
	Remotes []Remote

	// CA, Cert and Key are PEM bodies, from inline blocks or referenced files.
	CA   []byte
	Cert []byte
	Key  []byte

	// FileRefs records every ca, cert or key directive that named a file, in
	// file order.
	FileRefs []FileRef

	// TLSAuth and TLSCrypt are the <tls-auth> and <tls-crypt> keys, or nil.
	// The parser loads both if both are present; the connect path refuses the
	// pair.
	TLSAuth  *StaticKey
	TLSCrypt *StaticKey
	// KeyDirection is --key-direction: 0, 1, or absent.
	KeyDirection KeyDirection

	// Cipher is the data-channel cipher name, e.g. "AES-256-GCM".
	Cipher string
	// Auth is the HMAC digest, e.g. "SHA256"; SHA1 when absent.
	Auth string
	// AuthSet reports whether the profile carried an explicit auth directive.
	AuthSet bool
	// Verb is OpenVPN's 0–11 verbosity; the default is 3. At 4 the verified
	// server certificate is logged on each handshake.
	Verb int

	// RenegSec is the key renegotiation interval in seconds; 3600 when
	// absent, and 0 disables client-initiated renegotiation.
	RenegSec int
	// RenegBytes is the renegotiation byte threshold; 0 means none.
	RenegBytes int64
	// BecomePrimarySec delays a renegotiated key becoming the send key; 0
	// uses the default derived from reneg-sec.
	BecomePrimarySec int

	// HandWindowSec is --hand-window; 0 means the reference's 60
	// (openvpn-2.6.22 src/openvpn/options.c:880).
	HandWindowSec int

	// PingInterval is the keepalive send interval in seconds, from ping or
	// keepalive; 0 means the client default.
	PingInterval int
	// PingTimeout is the dead-link timeout in seconds, from ping-restart,
	// ping-exit or keepalive. One field for all three, as in
	// openvpn-2.6.22 src/openvpn/options.c:6963-6975. PingTimeoutSet
	// distinguishes an explicit 0, which disables the timer, from an absent
	// directive, which leaves the client default.
	PingTimeout    int
	PingTimeoutSet bool
	// PingExit reports that PingTimeout came from ping-exit. Nothing acts on
	// it; the client's dead-link teardown is terminal either way.
	PingExit bool

	// ExplicitExitNotify is how many exit notifications a disconnect sends. A
	// bare directive means 1 (openvpn-2.4.12 src/openvpn/options.c:6133).
	ExplicitExitNotify int

	// Compression is the data-channel framing the profile asked for, from
	// comp-lzo or compress. The server does not push its own, so a client that
	// ignored this would send packets a comp-lzo peer drops.
	Compression compress.Mode
	// AllowCompression is the --allow-compression policy.
	AllowCompression compress.AllowCompression

	// TunMTU is --tun-mtu; 0 means 1500.
	TunMTU int

	// MSSFix is the --mssfix clamp and MSSFixMode how it is measured.
	// MSSFixSet distinguishes "mssfix 0", which disables clamping, from an
	// absent directive, which applies OpenVPN's default.
	MSSFix     int
	MSSFixMode MSSFixMode
	MSSFixSet  bool

	// RemoteRandom asks the dialer to shuffle Remotes on each attempt.
	// Remotes itself stays in file order.
	RemoteRandom bool

	// RandomHostname asks the dialer to prepend a random label to the
	// hostname; some deployments have no DNS record for the bare name.
	RandomHostname bool

	// VerifyX509Name is the subject DN or common name the server certificate
	// must present, empty for no check. It is not a hostname and is not
	// matched against a SAN.
	VerifyX509Name string
	// VerifyX509NameMatch says which part of the subject is compared.
	VerifyX509NameMatch X509NameMatch

	// AuthUserPass reports that the profile carried auth-user-pass.
	AuthUserPass bool
	// RemoteCertTLSServer and NSCertTypeServer report "remote-cert-tls server"
	// and "ns-cert-type server".
	RemoteCertTLSServer bool
	NSCertTypeServer    bool

	// Federated is set by auth-federate or "x-go-openvpn-flow saml" (formerly
	// x-openlawsvpn-flow): authenticate against an identity provider.
	Federated bool

	// DNS is the resolver configuration from the profile's dhcp-option
	// directives. What the server pushes wins where the two overlap.
	DNS dns.Config

	// Directives records every directive line in file order, including those
	// the parser ignores, for the capability preflight.
	Directives []Directive

	// InlineBlocks records every inline block's tag and line, in file order,
	// for the capability preflight.
	InlineBlocks []InlineBlock
}

// AuthFlow describes which authentication mechanism the profile asks for.
type AuthFlow int

const (
	// FlowCertAuth is mutual-TLS client certificate authentication: the
	// profile embeds <cert> and <key> and asks for no credentials.
	FlowCertAuth AuthFlow = iota
	// FlowUserPass is username/password authentication, and the fallback.
	FlowUserPass
	// FlowFederated is the SAML/CRV1 flow against an identity provider.
	FlowFederated
)

// String names the flow.
func (f AuthFlow) String() string {
	switch f {
	case FlowCertAuth:
		return "cert"
	case FlowUserPass:
		return "user-pass"
	case FlowFederated:
		return "federated"
	default:
		return fmt.Sprintf("AuthFlow(%d)", int(f))
	}
}

// RequiresCredentials reports whether the profile carries auth-user-pass. The
// values come from the client's credential callback.
func (p *Profile) RequiresCredentials() bool {
	return p.AuthUserPass
}

// AuthFlow reports which authentication mechanism the profile asks for, from
// the profile alone. A profile with auth-user-pass and a certificate is
// FlowUserPass; the certificate is still used.
func (p *Profile) AuthFlow() AuthFlow {
	if p.Federated {
		return FlowFederated
	}
	if p.RequiresCredentials() {
		return FlowUserPass
	}
	if len(p.Cert) > 0 && len(p.Key) > 0 {
		return FlowCertAuth
	}
	return FlowUserPass
}

// ParseFile parses an .ovpn profile from r. A profile that names a file is
// refused with ErrNoProfileDir.
func ParseFile(r io.Reader) (*Profile, error) {
	return parse(r, nil)
}

// ParseFileIn parses an .ovpn profile from r, resolving file-referenced ca,
// cert and key directives against baseDir. An empty baseDir behaves as
// ParseFile.
func ParseFileIn(r io.Reader, baseDir string) (*Profile, error) {
	if baseDir == "" {
		return parse(r, nil)
	}
	return parse(r, dirResolver{baseDir})
}

// ParseFileInFS parses an .ovpn profile from r, resolving file-referenced ca,
// cert and key directives against fsys. A nil fsys behaves as ParseFile.
//
// fs.FS does not confine symlinks, and os.DirFS follows one out of the tree.
// For a real directory pass os.OpenRoot(dir).FS(), or use ParseFileIn.
func ParseFileInFS(r io.Reader, fsys fs.FS) (*Profile, error) {
	if fsys == nil {
		return parse(r, nil)
	}
	return parse(r, fsResolver{fsys})
}

// parse is the parser proper; the entry points differ only in the resolver.
func parse(r io.Reader, res fileResolver) (*Profile, error) {
	a := newAssembler()

	scanner := bufio.NewScanner(r)
	var inlineTag string
	var inlineBuf bytes.Buffer
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// An unterminated block consumes the rest of the file and loads
		// nothing, as in OpenVPN.
		if inlineTag != "" {
			if line == "</"+inlineTag+">" {
				if err := a.closeBlock(inlineTag, inlineBuf.Bytes()); err != nil {
					return nil, err
				}
				inlineTag = ""
				inlineBuf.Reset()
			} else {
				inlineBuf.WriteString(line)
				inlineBuf.WriteByte('\n')
			}
			continue
		}

		if tag, ok := inlineOpenTag(line); ok {
			inlineTag = tag
			inlineBuf.Reset()
			a.openBlock(tag, lineNo)
			continue
		}

		// A stray closing tag or malformed markup, not a directive.
		if strings.HasPrefix(line, "<") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		d := Directive{Name: strings.ToLower(fields[0]), Line: lineNo}
		if len(fields) > 1 {
			d.Args = append([]string(nil), fields[1:]...)
		}
		if err := a.directive(d); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("profile: read: %w", err)
	}

	return a.finish(res)
}

// inlineOpenTag reports whether line is an opening inline block tag such as
// "<tls-auth>", returning the tag name: a non-empty run of letters, digits,
// '-' and '_'.
func inlineOpenTag(line string) (string, bool) {
	if len(line) < 3 || line[0] != '<' || line[len(line)-1] != '>' {
		return "", false
	}
	tag := line[1 : len(line)-1]
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return "", false
		}
	}
	return tag, true
}

// ParseString parses an in-memory profile, as ParseFile.
func ParseString(s string) (*Profile, error) {
	return ParseFile(strings.NewReader(s))
}

// ParsePath opens path and parses it, resolving file references against the
// profile's own directory and confined to it.
func ParsePath(path string) (*Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("profile: open %s: %w", path, err)
	}
	defer f.Close()
	return parse(f, dirResolver{filepath.Dir(path)})
}

// MSSFixMode says how a numeric mssfix value is measured, from the directive's
// optional second word.
type MSSFixMode int

const (
	// MSSFixLink counts the tunnel encapsulation but not the outer IP and
	// UDP/TCP headers: a bare "mssfix N".
	MSSFixLink MSSFixMode = iota
	// MSSFixEncap counts the outer headers as well: "mssfix N mtu".
	MSSFixEncap
	// MSSFixFixed counts no encapsulation, only the inner IPv4 and TCP
	// headers: "mssfix N fixed".
	MSSFixFixed
)

// mssFixModeNames maps each MSSFixMode to its name.
var mssFixModeNames = [...]string{
	MSSFixLink:  "link",
	MSSFixEncap: "mtu",
	MSSFixFixed: "fixed",
}

// String names the mode, or returns "mssfix-mode(N)" out of range.
func (m MSSFixMode) String() string {
	if m < 0 || int(m) >= len(mssFixModeNames) {
		return "mssfix-mode(" + strconv.Itoa(int(m)) + ")"
	}
	return mssFixModeNames[m]
}

// ParseMSSFixMode parses a mode name; the empty string is MSSFixLink. An
// unrecognised word is refused.
func ParseMSSFixMode(s string) (MSSFixMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "link":
		return MSSFixLink, true
	case "mtu":
		return MSSFixEncap, true
	case "fixed":
		return MSSFixFixed, true
	default:
		return 0, false
	}
}

// MarshalText implements encoding.TextMarshaler. An out-of-range value
// marshals as its String placeholder, which UnmarshalText refuses.
func (m MSSFixMode) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler. An unrecognised name is
// an error.
func (m *MSSFixMode) UnmarshalText(text []byte) error {
	name := string(text)
	for i, n := range mssFixModeNames {
		if n == name {
			*m = MSSFixMode(i)
			return nil
		}
	}
	return fmt.Errorf("profile: unknown mssfix mode %q", name)
}
