package caps

import (
	"sort"
	"strconv"
	"strings"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/compress"
	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/profile"
)

// Inspect classifies everything a parsed profile asks for, without touching
// the network.
//
// It returns one diag.Gap per directive line and per inline block the parser
// recorded, in file order, including the ones the client honours fully — the
// severity distinguishes them, and Filter narrows the list to problems. A
// directive with no registry row yields diag.SeverityFatal, so a profile
// asking for something nobody has classified fails here rather than obscurely
// later. An absent directive gets no gap, with one exception: a CBC cipher
// with no auth directive asks for OpenVPN's SHA1 default, reported on "auth"
// with an "(implied default)" value.
//
// Gaps carry no hostnames, paths, user names or credential material.
func Inspect(p *profile.Profile) []diag.Gap {
	if p == nil {
		return nil
	}

	placed := make([]placedGap, 0, len(p.Directives)+len(p.InlineBlocks))
	for _, d := range p.Directives {
		placed = append(placed, placedGap{line: d.Line, gap: classifyDirective(p, d)})
	}
	for _, b := range p.InlineBlocks {
		placed = append(placed, placedGap{line: b.Line, gap: classifyBlock(b)})
	}

	// Directives and blocks were collected separately; interleave them back
	// into file order so a report reads the way the profile does.
	sort.SliceStable(placed, func(i, j int) bool { return placed[i].line < placed[j].line })

	gaps := make([]diag.Gap, 0, len(placed)+1)
	for _, pg := range placed {
		gaps = append(gaps, pg.gap)
	}
	if g, ok := impliedDigestGap(p); ok {
		gaps = append(gaps, g)
	}
	if len(gaps) == 0 {
		return nil
	}
	return gaps
}

// placedGap pairs a gap with the profile line it came from, so directives and
// inline blocks can be merged back into file order.
type placedGap struct {
	line int
	gap  diag.Gap
}

// classifyDirective resolves one recorded directive against the registry.
func classifyDirective(p *profile.Profile, d profile.Directive) diag.Gap {
	e, ok := registry[d.Name]
	if !ok {
		return diag.Gap{
			Directive: d.Name,
			Severity:  fatal,
			Detail:    unrecognisedDirective,
		}
	}
	s, value := e.Support, ""
	if e.refine != nil {
		s, value = e.refine(p, d)
	}
	return diag.Gap{
		Directive: d.Name,
		Value:     value,
		Severity:  s.Severity,
		Detail:    s.Detail,
	}
}

// classifyBlock resolves one recorded inline block tag against the registry.
func classifyBlock(b profile.InlineBlock) diag.Gap {
	tag := strings.ToLower(b.Tag)
	s, ok := blockRegistry[tag]
	if !ok {
		return diag.Gap{
			Directive: "<" + tag + ">",
			Severity:  fatal,
			Detail:    unrecognisedBlock,
		}
	}
	return diag.Gap{
		Directive: "<" + tag + ">",
		Severity:  s.Severity,
		Detail:    s.Detail,
	}
}

// Filter returns the gaps whose severity is min or worse, preserving order.
// Filter(gaps, diag.SeverityDegraded) is "everything that will not behave as
// the profile asks".
func Filter(gaps []diag.Gap, min diag.Severity) []diag.Gap {
	var out []diag.Gap
	for _, g := range gaps {
		if g.Severity >= min {
			out = append(out, g)
		}
	}
	return out
}

// Worst returns the highest severity among gaps, or diag.SeveritySupported
// when there are none.
func Worst(gaps []diag.Gap) diag.Severity {
	worst := diag.SeveritySupported
	for _, g := range gaps {
		if g.Severity > worst {
			worst = g.Severity
		}
	}
	return worst
}

// ---- Refinements ------------------------------------------------------
// Each decides a directive's verdict from its arguments and the rest of the
// profile; none returns a value that could identify a server, file or person.

// arg returns the i-th argument of d, lowercased, or "" when absent.
func arg(d profile.Directive, i int) string {
	if i >= len(d.Args) {
		return ""
	}
	return strings.ToLower(d.Args[i])
}

// hasBlock reports whether the profile contained an inline block with any of
// the given tags.
func hasBlock(p *profile.Profile, tags ...string) bool {
	for _, b := range p.InlineBlocks {
		for _, want := range tags {
			if strings.EqualFold(b.Tag, want) {
				return true
			}
		}
	}
	return false
}

// classifyRemote grades a remote line. Every line is dialed, in order, until
// one completes the handshake, each with its own port and transport. The value
// is never the hostname: gaps reach session reports.
func classifyRemote(_ *profile.Profile, _ profile.Directive) (Support, string) {
	return Support{supported,
		"dialed as an endpoint, with the optional second field as the port and the third as the transport; " +
			"several remote lines are tried in order until one connects"}, ""
}

// classifyRemoteRandom reports how completely the shuffle is honoured.
//
// The client shuffles, so the directive is supported — including for a
// one-remote profile, where the list being of length one is the profile's
// doing rather than a gap in the client. The detail still separates the two.
func classifyRemoteRandom(p *profile.Profile, _ profile.Directive) (Support, string) {
	if len(p.Remotes) <= 1 {
		return Support{supported,
			"the remote list is shuffled before it is dialed; this profile has one remote, so the order cannot vary"}, ""
	}
	return Support{supported,
		"the remote list is shuffled before it is dialed, so the endpoints are tried in a different order each attempt"}, ""
}

// classifyProto reports how completely a transport spelling is honoured.
//
// Every spelling profile.ParseProto accepts — the classifier asks the parser
// rather than keeping a second list — is dialed on the transport it names. The
// address-family spellings are degraded because the family half restricts
// which addresses the hostname may resolve to and the client does not apply
// it: udp4 is dialed as udp, over whatever the resolver returns.
func classifyProto(_ *profile.Profile, d profile.Directive) (Support, string) {
	v := arg(d, 0)
	if _, ok := profile.ParseProto(v); !ok {
		return Support{fatal,
			"not a transport this client can dial; only the udp and tcp client spellings are implemented"}, v
	}
	switch v {
	case "udp", "tcp", "tcp-client":
		return Support{supported,
			"udp and tcp/tcp-client are both implemented, including the TCP length-prefix framing"}, v
	default:
		return Support{degraded,
			"the transport is honoured; the address-family restriction the spelling adds is not"}, v
	}
}

// classifyDev rejects tap mode. The client always creates a layer-3 tun
// device and never passes a device name through, so a tap profile connects
// and then silently carries nothing.
func classifyDev(_ *profile.Profile, d profile.Directive) (Support, string) {
	v := arg(d, 0)
	switch {
	case v == "" || strings.HasPrefix(v, "tun"):
		return Support{supported,
			"a layer-3 tun device is created; a specific device name is not honoured"}, "tun"
	case strings.HasPrefix(v, "tap"):
		return Support{fatal,
			"tap/layer-2 mode is not implemented; the client only ever creates a tun device"}, "tap"
	default:
		return Support{fatal,
			"only tun devices are implemented"}, v
	}
}

// classifyFileRef handles the "ca ca.crt" spelling of ca, cert and key.
//
// profile.ParsePath resolves the name against the profile's own directory and
// refuses anything outside it. The verdict comes from profile.FileRefs, not
// from whether the matching field is populated: a profile carrying both an
// inline <ca> block and a "ca ca.crt" line loads the CA from the block, as
// OpenVPN does, never opening the file. A reference neither read nor
// superseded cannot come out of ParsePath, which refuses the profile instead:
// what a profile parsed from bytes with no directory shows. Paths are not kept.
func classifyFileRef(p *profile.Profile, d profile.Directive) (Support, string) {
	ref, ok := fileRefFor(p, d)
	switch {
	case ok && ref.Superseded:
		return Support{ignored,
			"not read: this profile also carries an inline <" + d.Name +
				"> block, which is what OpenVPN prefers and what the client uses"}, ""
	case ok && ref.Loaded:
		return Support{supported,
			"read from the profile's own directory; a name that resolves outside that directory is refused"}, ""
	}
	return Support{fatal,
		"not read: this profile was parsed from bytes rather than a path, " +
			"so there was no directory to resolve the name against"}, ""
}

// fileRefFor finds the record the parser kept of one ca, cert or key
// directive, matching on the line so that a profile naming two of the three
// is not answered from the wrong one.
func fileRefFor(p *profile.Profile, d profile.Directive) (profile.FileRef, bool) {
	for _, ref := range p.FileRefs {
		if ref.Line == d.Line && ref.Tag == d.Name {
			return ref, true
		}
	}
	return profile.FileRef{}, false
}

// classifyAuthUserPass separates the two forms of the directive. The bare form
// is supported: CredentialsFn supplies the username and password before the
// key-method-2 packet goes out. The file form names a path holding the
// credentials and nothing reads it; it is fatal rather than degraded because
// proceeding would send an empty username to a server that requires one, and
// the AUTH_FAILED would then be recorded as ClassAuth — a wrong password —
// when the client never read the file.
func classifyAuthUserPass(_ *profile.Profile, d profile.Directive) (Support, string) {
	if arg(d, 0) == "" {
		return Support{supported,
			"the username and password are supplied by the caller's CredentialsFn"}, ""
	}
	return Support{fatal,
		"a credentials file is not read; supply the username and password through CredentialsFn"}, ""
}

// classifyCompression grades a compression directive by whether this client
// can decompress what a peer using it sends. A stub never compresses; LZO is
// decompressed; LZ4 ends the session at StageData, so it is degraded.
func classifyCompression(_ *profile.Profile, d profile.Directive) (Support, string) {
	v := arg(d, 0)
	mode, ok := compress.ModeForDirective(d.Name, v)
	if !ok {
		return Support{fatal,
			"not a compression algorithm this client — or OpenVPN — recognises"}, v
	}
	switch {
	case mode.Decompresses():
		return Support{supported,
			"the framing is applied and a compressed payload is decompressed; " +
				"nothing is compressed on send"}, v
	case mode.Compresses():
		return Support{degraded,
			"the framing is applied and nothing is compressed on send; a peer that " +
				"compresses ends the session rather than corrupting it"}, v
	}
	return Support{supported,
		"a framing stub: the wire framing is applied in full and neither peer compresses"}, v
}

// classifyAllowCompression reports the policy the directive sets.
//
// 'no' is honoured: compress.EffectiveMode refuses a compressing algorithm
// from the profile and from the PUSH_REPLY alike, as
// check_compression_settings_valid() does with COMP_F_ALLOW_STUB_ONLY. 'yes'
// and 'asym' permit a peer to compress; whether this client can decompress it
// is graded on the compression directive.
func classifyAllowCompression(_ *profile.Profile, d profile.Directive) (Support, string) {
	v := arg(d, 0)
	allow, ok := compress.ParseAllowCompression(v)
	if !ok {
		return Support{fatal,
			"not an allow-compression value; OpenVPN accepts only no, asym and yes"}, v
	}
	if allow == compress.AllowNo {
		return Support{supported,
			"a compressing algorithm is refused from the profile and from the PUSH_REPLY alike, " +
				"and a framing stub is permitted"}, v
	}
	return Support{supported,
		"the peer may compress; this client decompresses and never compresses on send"}, v
}

// classifyRemoteCertTLS reports the directive as honoured.
//
// internal/tlsverify requiresRemoteCertTLSServer reads it to decide whether the
// leaf must carry the serverAuth extended key usage — deliberately not
// accepting anyExtendedKeyUsage — and a key usage extension, which the
// directive also asks for (options.c:9159-9170 sets remote_cert_ku[0] beside
// the EKU string). Only the "server" form means anything in a client profile;
// a profile with no CA is fatal, refused at StageParse before a socket opens.
func classifyRemoteCertTLS(p *profile.Profile, d profile.Directive) (Support, string) {
	v := arg(d, 0)
	if len(p.CA) == 0 {
		return Support{fatal,
			"the profile carries no CA, so the attempt is refused before it dials and there is nothing to check the certificate against"}, v
	}
	if v == "server" {
		return Support{supported,
			"the server certificate is required to carry the serverAuth extended key usage and a key usage extension"}, v
	}
	return Support{degraded,
		"only the 'server' form is honoured; any other peer type is not checked"}, v
}

// classifyVerifyX509Name reports the directive as honoured, for each of the
// three match types OpenVPN defines. tlsverify.Verifier compares the value
// against the leaf's subject DN or common name, never a SAN; routing it to the
// TLS ServerName would match a SAN instead. An unrecognised match type is
// fatal because profile.ParseX509NameMatch refuses it, so such a profile never
// parses — the same answer OpenVPN gives. The value is a certificate name and
// is not recorded; the match type is.
func classifyVerifyX509Name(_ *profile.Profile, d profile.Directive) (Support, string) {
	mode := arg(d, 1)
	match, ok := profile.ParseX509NameMatch(mode)
	if !ok {
		return Support{fatal,
			"the match type is not one of subject, name or name-prefix, so the profile is refused at parse"}, mode
	}
	switch match {
	case profile.X509NameCN:
		return Support{supported,
			"the server certificate's common name must equal the value"}, match.String()
	case profile.X509NameCNPrefix:
		return Support{supported,
			"the server certificate's common name must start with the value"}, match.String()
	default:
		return Support{supported,
			"the server certificate's whole subject DN must equal the value"}, match.String()
	}
}

// classifyNSCertType reports the legacy Netscape certificate-type check.
//
// The detail says "usable as an SSL server" rather than naming the extension,
// because that is what the reference tests: since 2.4 the extension is only
// the fallback for a certificate the SSL-server purpose check rejects
// (openvpn-2.6.22 src/openvpn/ssl_verify_openssl.c:611-676), so a row
// promising the extension would describe a client stricter than OpenVPN. Only
// the "server" form is honoured — "ns-cert-type client" would demand the
// SSL-client bit of the server's own certificate.
func classifyNSCertType(_ *profile.Profile, d profile.Directive) (Support, string) {
	v := arg(d, 0)
	if v == "server" {
		return Support{supported,
			"the server certificate must pass OpenSSL's SSL-server purpose check, or carry the Netscape SSL-server bit"}, v
	}
	return Support{degraded,
		"only the 'server' form is checked; any other peer type is not"}, v
}

// classifyTLSVersionMin compares the requested floor against the hard-coded
// one. TLS 1.2 asks for exactly what the client already does.
func classifyTLSVersionMin(_ *profile.Profile, d profile.Directive) (Support, string) {
	v := arg(d, 0)
	switch v {
	case "1.2":
		return Support{ignored,
			"not read; the TLS floor is hard-coded to 1.2, which is what this asks for"}, v
	case "1.0", "1.1":
		return Support{degraded,
			"not read; the hard-coded TLS 1.2 floor is stricter, so an old server will be refused"}, v
	default:
		return Support{degraded,
			"not read; the TLS floor is hard-coded to 1.2 and a higher minimum is not enforced"}, v
	}
}

// classifyWrapFileRef handles the "tls-auth ta.key [direction]" and
// "tls-crypt tc.key" file-reference spellings of the two wrap directives.
//
// Every outcome is fatal, and not because the wrap is missing: the parser
// loads inline block bodies and nothing else, so a profile that names a key
// file leaves the client with no key at all, and a wrap with no key cannot
// authenticate the opening HARD_RESET. The path is never recorded; the value
// distinguishes the spellings.
func classifyWrapFileRef(p *profile.Profile, d profile.Directive) (Support, string) {
	if len(d.Args) == 0 {
		return Support{fatal,
			"malformed: " + d.Name + " names no key file and there is no key to read"}, ""
	}
	if hasBlock(p, d.Name) {
		return Support{fatal,
			"the file reference is not read; this profile's inline <" + d.Name +
				"> block is what the wrap uses"}, "file"
	}
	return Support{fatal,
		"a file reference is not read; the key must be an inline <" + d.Name + "> block"}, "file"
}

// classifyKeyDirection answers according to the wrap the direction applies to.
//
// Beside a tls-auth block it is supported: the wrap uses it to choose which
// halves of the 256-byte key sign and verify.
//
// Beside a tls-crypt block it is ignored. OpenVPN gives tls-crypt no
// --key-direction at all — tls_crypt_init_key() hard-codes the server to slot
// 0 and the client to slot 1 — and the reference stores key_direction from its
// own option without reading it on the tls-crypt path (openvpn-2.6.22
// src/openvpn/options.c:8556-8578 stores it, options.c:9252-9265 is the whole
// of the tls-crypt branch and does not consult it), so it starts and ignores
// the line. With no wrapping key at all it is ignored for the same reason.
func classifyKeyDirection(p *profile.Profile, d profile.Directive) (Support, string) {
	if hasBlock(p, "tls-auth") {
		return Support{supported,
			"read; selects which half of the tls-auth key signs outgoing control packets " +
				"and which verifies incoming ones"}, arg(d, 0)
	}
	if hasBlock(p, "tls-crypt", "tls-crypt-v2") {
		return Support{ignored,
			"parsed and not applied, as in the reference: tls-crypt has no key-direction, and " +
				"its key halves follow the peer role instead"}, arg(d, 0)
	}
	return Support{ignored,
		"no tls-auth or tls-crypt block in this profile, so there is no key for a direction to apply to"}, arg(d, 0)
}

// isCBC reports whether name is a CBC cipher suite.
func isCBC(name string) bool {
	return strings.HasSuffix(strings.ToUpper(name), "-CBC")
}

// classifyCipher grades the requested data-channel cipher against the cipher
// table in internal/crypto — the same table IV_CIPHERS is generated from and
// the same one startDataChannel builds through.
func classifyCipher(_ *profile.Profile, d profile.Directive) (Support, string) {
	v := strings.ToUpper(arg(d, 0))
	if _, ok := crypto.LookupCipher(v); ok {
		return Support{supported,
			"the data channel can build this cipher, and it is in the advertised IV_CIPHERS list"}, v
	}
	return Support{fatal,
		"not implemented: the data channel can build " +
			strings.Join(crypto.CipherNames(), ", ") + " and nothing else"}, v
}

// classifyAuth grades the requested packet-authentication digest. With an AEAD
// cipher it is unused and the directive is moot; with a CBC cipher it selects
// the HMAC from SHA1, SHA256 and SHA512.
func classifyAuth(p *profile.Profile, d profile.Directive) (Support, string) {
	v := strings.ToUpper(arg(d, 0))
	if !isCBC(p.Cipher) {
		return Support{ignored,
			"unused: the profile selects an AEAD cipher, which authenticates without a separate digest"}, v
	}
	switch v {
	case "NONE", "[NULL-DIGEST]":
		return Support{fatal,
			"a CBC data channel without packet authentication is not implemented"}, v
	}
	if _, err := crypto.ParseDigest(v); err == nil {
		return Support{supported,
			"CBC packet authentication can use this digest"}, v
	}
	return Support{fatal,
		"not implemented: CBC packet authentication has SHA1, SHA256 and SHA512"}, v
}

// classifyFragment passes "fragment 0", which asks for no fragmentation. Any
// other argument is fatal: the peer would frame every data packet with a
// 4-byte header this client neither writes nor strips.
//
// Reference: openvpn-2.5.11 src/openvpn/options.c:6156 (positive_atoi, no
// lower bound); openvpn-2.6.22 src/openvpn/options.c:6630 adds "< 68"; a zero
// gates off the fragment frame (openvpn-2.5.11 options.c:2898).
func classifyFragment(_ *profile.Profile, d profile.Directive) (Support, string) {
	v := arg(d, 0)
	if n, err := strconv.Atoi(v); err == nil && n == 0 {
		return Support{ignored,
			"not read; no datagram fragmentation is performed, which is what this asks for"}, v
	}
	return Support{fatal,
		"not implemented; a peer using it frames every data packet with 4 bytes this client cannot strip"}, v
}

// classifyDHCPOption keeps the sub-option keyword, which decides the verdict,
// and discards the value, which is an address or a domain.
func classifyDHCPOption(_ *profile.Profile, d profile.Directive) (Support, string) {
	switch kind := strings.ToUpper(arg(d, 0)); kind {
	case "DNS", "DOMAIN", "DOMAIN-ROUTE":
		return Support{supported,
			"merged with the server-pushed DNS configuration and applied to the host resolver"}, kind
	case "":
		return Support{fatal,
			"dhcp-option with no sub-option is malformed"}, ""
	default:
		return Support{ignored,
			"only the DNS, DOMAIN and DOMAIN-ROUTE sub-options are read"}, kind
	}
}

// impliedDigestGap reports the digest a profile asks for by omission: a CBC
// cipher with no auth directive gets OpenVPN's built-in default of SHA1, which
// is invisible unless the absence itself is reported. "What this profile will
// actually use" is the question the preflight answers, and a silent default is
// the easiest thing for it to get wrong.
func impliedDigestGap(p *profile.Profile) (diag.Gap, bool) {
	if !isCBC(p.Cipher) || p.AuthSet {
		return diag.Gap{}, false
	}
	severity := supported
	detail := "no auth directive with a CBC cipher means OpenVPN's SHA1 default, which the data channel can build"
	if _, err := crypto.ParseDigest(p.Auth); err != nil {
		severity = fatal
		detail = "no auth directive with a CBC cipher means OpenVPN's SHA1 default, which is not implemented"
	}
	return diag.Gap{
		Directive: "auth",
		Value:     "SHA1 (implied default)",
		Severity:  severity,
		Detail:    detail,
	}, true
}
