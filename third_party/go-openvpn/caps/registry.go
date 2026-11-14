// Package caps answers one question about a parsed profile: what does it ask
// for that this client cannot honour?
//
// It is a static preflight. Inspect never opens a socket, never reads a file
// and never touches credential material. It classifies the directives the
// parser recorded on profile.Profile against a registry of what the client is
// known to do, and reports the result as diag.Gap values.
//
// The registry is deliberately closed. A directive that is not in it
// classifies as diag.SeverityFatal with an "unrecognised" detail, so a profile
// using a feature nobody has considered fails loudly during preflight instead
// of obscurely in the middle of a handshake. Widening the registry is a
// deliberate act: add the row, and say honestly what the client does today.
package caps

import (
	"sort"
	"strings"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/profile"
)

// Support is the registry's verdict on one directive: how far the client's
// behaviour departs from what the directive asks for, and a one-line
// explanation of what happens instead.
type Support struct {
	// Severity ranks the departure, from SeveritySupported to SeverityFatal.
	Severity diag.Severity
	// Detail is a single line naming what the client actually does.
	Detail string
}

// classify refines a registry row from the directive's arguments and the
// profile it appeared in.
//
// It returns the support to report and the value to record on the Gap. The
// returned value must never contain a hostname, a path, a user name or any
// other identifying text: gaps are aggregated and serialised into session
// reports. Return "" when the keyword alone decided.
type classify func(p *profile.Profile, d profile.Directive) (Support, string)

// entry is one registry row: a base verdict plus an optional refinement.
type entry struct {
	Support
	refine classify
}

// sup is shorthand for a row that the keyword alone decides.
func sup(sev diag.Severity, detail string) entry {
	return entry{Support: Support{Severity: sev, Detail: detail}}
}

// ref is shorthand for a row whose verdict depends on its arguments. The base
// Support is what a caller of Lookup sees, and what applies if refine
// declines to override.
func ref(sev diag.Severity, detail string, fn classify) entry {
	return entry{Support: Support{Severity: sev, Detail: detail}, refine: fn}
}

const (
	supported = diag.SeveritySupported
	ignored   = diag.SeverityIgnored
	degraded  = diag.SeverityDegraded
	fatal     = diag.SeverityFatal
)

// registry maps a lowercased directive keyword to its verdict. A keyword with
// no row here is unrecognised by design.
var registry = map[string]entry{
	// ---- Endpoint and transport -------------------------------------

	"remote": ref(supported,
		"dialed as an endpoint; several remote lines are tried in order until one connects",
		classifyRemote),
	"port": sup(supported,
		"sets the destination port for every remote that does not carry one of its own"),
	// The third field of a remote line names the same transports as this
	// directive and is normalised by the same profile.ParseProto.
	"proto": ref(supported,
		"udp and tcp/tcp-client are both implemented, including the TCP length-prefix framing",
		classifyProto),
	"dev": ref(supported,
		"the client always creates a layer-3 tun device",
		classifyDev),
	"nobind": sup(ignored,
		"the client never binds a local address, so this is already the behaviour"),
	"remote-random": ref(supported,
		"the remote list is shuffled before it is dialed",
		classifyRemoteRandom),
	"remote-random-hostname": sup(supported,
		"a random label is prepended to the remote before it is resolved"),
	"resolv-retry": sup(ignored,
		"the remote is resolved once per attempt; retrying is the caller's concern"),
	"float": sup(degraded,
		"the UDP socket is connected to the dialed address, so a peer that moves is not followed"),

	// ---- Session mode -----------------------------------------------

	"client": sup(supported,
		"TLS client mode is the only mode implemented"),
	"tls-client": sup(supported,
		"TLS client mode is the only mode implemented"),
	"pull": sup(supported,
		"the client always sends PUSH_REQUEST and applies the PUSH_REPLY it gets back"),

	// ---- Credentials ------------------------------------------------

	"auth-user-pass": ref(supported,
		"the username and password are supplied by the caller's CredentialsFn",
		classifyAuthUserPass),
	"auth-nocache": sup(ignored,
		"no credentials are cached, so there is nothing to disable"),
	"auth-retry": sup(ignored,
		"authentication is attempted once; reconnect policy is the caller's concern"),
	"auth-federate": sup(supported,
		"selects the AWS CRV1/SAML two-phase flow"),
	"x-go-openvpn-flow": sup(supported,
		"non-standard: forces the CRV1/SAML flow for a non-AWS server"),
	// The same directive under the name it had before the project was
	// renamed. Profiles already written against it keep working; the registry
	// says so rather than failing them as unrecognised.
	"x-openlawsvpn-flow": sup(supported,
		"deprecated spelling of x-go-openvpn-flow; forces the CRV1/SAML flow"),

	// ---- Certificates and TLS ---------------------------------------

	// The three file-reference spellings, all of them readable: ParsePath
	// resolves the name against the profile's own directory and refuses
	// anything that resolves outside it, and an inline block for the same tag
	// still wins.
	//
	// The base verdict names the condition rather than leaving it to the
	// refinement, because Lookup shows this line with no profile in hand and
	// "read" without "from a path" would claim more than the client does.
	"ca": ref(supported,
		"read from the profile's directory when it was parsed from a path; an inline <ca> block wins over the reference",
		classifyFileRef),
	"cert": ref(supported,
		"read from the profile's directory when it was parsed from a path; an inline <cert> block wins over the reference",
		classifyFileRef),
	"key": ref(supported,
		"read from the profile's directory when it was parsed from a path; an inline <key> block wins over the reference",
		classifyFileRef),
	"remote-cert-tls": ref(supported,
		"the server certificate is required to carry the serverAuth extended key usage and a key usage extension",
		classifyRemoteCertTLS),
	"ns-cert-type": ref(supported,
		"the server certificate must pass OpenSSL's SSL-server purpose check, or carry the Netscape SSL-server bit",
		classifyNSCertType),
	"verify-x509-name": ref(supported,
		"the server certificate's subject DN or common name must match the value, according to the match type",
		classifyVerifyX509Name),
	"tls-version-min": ref(degraded,
		"not read; the TLS floor is hard-coded to 1.2 and the ceiling to whatever crypto/tls offers",
		classifyTLSVersionMin),
	// Both wraps are implemented: internal/wrap wraps and unwraps every
	// control packet, against vectors captured from a real OpenVPN peer. They
	// are separate implementations rather than one parameterised by a flag,
	// because the wire formats are not the same shape — they carry the same
	// fields in different orders, and a client that treated the two alike
	// would send a tag of the right length that no server accepts.
	//
	// tls-crypt-v2 is fatal: it needs a per-client wrapped key.
	//
	// Both rows are refined because the *file-argument* form of either
	// directive is fatal, the parser loading inline block bodies only. The
	// verdict a caller sees for an inline key comes from blockRegistry below,
	// so the two tables have to agree.
	"tls-auth": ref(supported,
		"the control channel is authenticated with this key; the digest is --auth and the halves are chosen by key-direction",
		classifyWrapFileRef),
	"tls-crypt": ref(supported,
		"the control channel is encrypted and authenticated with this key; AES-256-CTR and HMAC-SHA256 are fixed",
		classifyWrapFileRef),
	"tls-crypt-v2": sup(fatal,
		"control-channel encryption with a per-client wrapped key is not implemented"),
	// The direction selects which halves of the 256-byte key sign and verify.
	// An absent one is kept distinct from 0 because it is a third behaviour
	// rather than a default, and the wrap implements all three. The row is
	// refined because the answer depends on which wrap the key belongs to:
	// OpenVPN gives tls-crypt no --key-direction at all, so a direction beside
	// a tls-crypt block applies to nothing.
	"key-direction": ref(supported,
		"read; selects which halves of the tls-auth key sign outgoing packets and verify incoming ones",
		classifyKeyDirection),

	// ---- Data-channel crypto ----------------------------------------

	"cipher": ref(supported,
		"read; the data channel builds it unless PUSH_REPLY selects another, and it is advertised in IV_CIPHERS",
		classifyCipher),
	"auth": ref(supported,
		"read; selects the CBC HMAC digest from SHA1, SHA256 and SHA512",
		classifyAuth),
	"data-ciphers": sup(degraded,
		"not read; IV_CIPHERS advertises the fixed AES-GCM and AES-CBC set instead"),
	"data-ciphers-fallback": sup(degraded,
		"not read; the data channel uses whatever PUSH_REPLY selects"),
	"ncp-disable": sup(degraded,
		"the client always advertises IV_NCP=2 and a cipher list; negotiation cannot be switched off"),
	"keysize": sup(degraded,
		"not read; the options string advertises the negotiated cipher's own key size"),

	// ---- Compression -------------------------------------------------

	"comp-lzo": ref(supported,
		"the framing is applied and a compressed payload is decompressed; nothing is compressed on send",
		classifyCompression),
	"compress": ref(supported,
		"the framing is applied, in the prepending and the swapping form alike",
		classifyCompression),
	"comp-noadapt": sup(ignored,
		"adaptive only decides how eagerly a peer compresses; this client never does, and the framing is one"),
	"allow-compression": ref(supported,
		"'no' refuses a compressing algorithm from the profile and the PUSH_REPLY alike",
		classifyAllowCompression),

	// ---- MTU and framing ---------------------------------------------

	"tun-mtu": sup(supported,
		"applied to the tun device, and used as the upper bound for any pushed tun-mtu"),
	"tun-mtu-extra": sup(ignored,
		"a tap-mode buffer allowance; it has no effect on a layer-3 tunnel"),
	"tun-mtu-max": sup(ignored,
		"the advertised IV_MTU is the reference's floor of 1600, which already covers any value below it"),
	"link-mtu": sup(degraded,
		"not read; the advertised link MTU is derived from tun-mtu (+21 UDP, +43 TCP)"),
	"mssfix": sup(supported,
		"clamps TCP SYN segments on the tun-to-wire path; honours the mtu and fixed words; a pushed value wins"),
	"fragment": ref(fatal,
		"not implemented; a peer using it frames every data packet with 4 bytes this client cannot strip",
		classifyFragment),

	// ---- Renegotiation and liveness ----------------------------------

	"reneg-sec": sup(supported,
		"drives the rekey timer; an explicit 0 disables client-initiated renegotiation"),
	"reneg-bytes": sup(supported,
		"drives the byte-threshold rekey trigger"),
	"become-primary": sup(supported,
		"non-standard: delays promotion of a renegotiated key to the send key"),
	"hand-window": sup(supported,
		"bounds a key exchange, and caps how long a renegotiated key waits to become the send key"),
	"tran-window": sup(ignored,
		"a renegotiated key is accepted for decryption until the next one replaces it, without a timer"),
	"keepalive": sup(supported,
		"sets probe interval and dead-link timeout; outranks ping and ping-restart, loses to a pushed value"),
	"ping": sup(supported,
		"sets the probe interval, below a pushed one and above the 8 s default"),
	"ping-restart": sup(supported,
		"sets the dead-link timeout, below a pushed one and above the 40 s default; 0 disables it"),
	// "rem" is remote: don't start the timers until a peer is known, which a
	// client that dials already satisfies.
	// Reference: openvpn3-core client/cliopt.hpp ~773 refuses it as a
	// listen-mode feature; the divergence is deliberate.
	"ping-timer-rem": sup(ignored,
		"the dead-link timer starts only once a dialled peer is up, which is what this asks for"),
	"ping-exit": sup(degraded,
		"read as the dead-link timeout; this client ends the session where the reference exits the process"),
	"explicit-exit-notify": sup(supported,
		"a deliberate disconnect sends the OCC exit notification, once per retry, over UDP"),

	// ---- Routing and DNS ---------------------------------------------

	"dhcp-option": ref(supported,
		"DNS, DOMAIN and DOMAIN-ROUTE are merged with the server-pushed DNS configuration",
		classifyDHCPOption),
	"route": sup(degraded,
		"profile-level routes are not installed; only routes from PUSH_REPLY are applied"),
	"redirect-gateway": sup(degraded,
		"profile-level redirect-gateway is not applied; only the pushed form is"),
	"route-metric": sup(ignored,
		"routes are installed without a metric, at the kernel default priority"),
	"max-routes": sup(ignored,
		"no route-count limit is enforced"),
	"block-outside-dns": sup(ignored,
		"a Windows-only directive; this client has no Windows support"),
	"route-method": sup(ignored,
		"a Windows-only directive selecting how routes are installed; this client has no Windows support"),
	"tun-ipv6": sup(ignored,
		"obsolete since OpenVPN 2.4, where tun devices carry IPv6 without it"),
	"persist-remote-ip": sup(ignored,
		"the remote is resolved once per attempt; there is no in-process restart to persist an address across"),
	"connect-retry-max": sup(ignored,
		"a single connection is attempted; retry policy is the caller's concern"),
	"route-delay": sup(ignored,
		"routes are installed as soon as PUSH_REPLY is applied, so there is nothing to delay"),
	"connect-timeout": sup(degraded,
		"not read; the dial deadline is the client's own and does not honour the configured value"),
	"tls-cipher": sup(degraded,
		"not read; the control channel offers Go's default TLS cipher suites"),
	"allow-recursive-routing": sup(ignored,
		"no recursive-route filtering is performed, so this is already the behaviour"),

	// ---- Process, scripts, logging -----------------------------------

	"verb": sup(supported,
		"sets diagnostic verbosity; verb 4 and above logs the verified server certificate"),
	"mute": sup(ignored,
		"log rate limiting is not implemented"),
	"mute-replay-warnings": sup(ignored,
		"replay warnings are never logged, so there is nothing to mute"),
	"setenv": sup(ignored,
		"no environment is exported to scripts, and UV_* names are not forwarded as peer-info"),
	"push-peer-info": sup(degraded,
		"peer-info is always sent, but as a fixed IV_ set; setenv UV_* names are not included"),
	"persist-tun": sup(ignored,
		"the tun device is torn down on disconnect; there is no in-process restart to persist across"),
	"persist-key": sup(ignored,
		"key material stays in memory for the process lifetime; nothing is re-read from disk"),
	"fast-io": sup(ignored,
		"no effect in userspace"),
	"sndbuf": sup(ignored,
		"socket buffer sizes are left at the operating-system default"),
	"rcvbuf": sup(ignored,
		"socket buffer sizes are left at the operating-system default"),
	"user": sup(ignored,
		"the library does not drop privileges; that is the host application's job"),
	"group": sup(ignored,
		"the library does not drop privileges; that is the host application's job"),
	"script-security": sup(ignored,
		"no external script is ever executed"),
	"up": sup(degraded,
		"up scripts are never executed; DNS and routes are applied by the library instead"),
	"down": sup(degraded,
		"down scripts are never executed; DNS and routes are reverted by the library instead"),
	"up-restart": sup(ignored,
		"no external script is ever executed"),
	"remap-usr1": sup(ignored,
		"signal handling is left to the host application"),
}

// blockRegistry maps a lowercased inline block tag to its verdict.
//
// Block bodies are credential material and are never inspected here; only the
// presence of the tag is classified. The parser does validate the <tls-auth>
// and <tls-crypt> bodies as it loads them, but that happens before Inspect is
// ever called: a profile whose static key is malformed fails ParseFile with
// diag.ClassConfig and never reaches the preflight at all. There is
// consequently no severity here for "the key is unusable" — a profile that gets
// this far has a well-formed 256-byte key.
var blockRegistry = map[string]Support{
	"ca":       {supported, "the CA bundle used to verify the server certificate"},
	"cert":     {supported, "the client certificate presented during the TLS handshake"},
	"key":      {supported, "the client private key used for the TLS handshake"},
	"tls-auth": {supported, "the static key authenticating every control packet, including the opening HARD_RESET"},
	"tls-crypt": {supported,
		"the static key encrypting and authenticating every control packet, including the opening HARD_RESET"},
	"tls-crypt-v2": {fatal, "control-channel encryption with a per-client wrapped key is not implemented"},
}

// unrecognisedDirective is the verdict for a directive with no registry row.
// It is fatal on purpose: a profile asking for something nobody has
// considered must fail at preflight, not halfway through a handshake.
const unrecognisedDirective = "unrecognised directive: the client has no classification for it and will silently ignore it"

// unrecognisedBlock is the verdict for an inline block tag with no registry row.
const unrecognisedBlock = "unrecognised inline block: the client has no classification for it and will discard its contents"

// Lookup returns the registry's verdict for a directive keyword, ignoring
// case. The second result is false when the directive is unrecognised.
//
// The verdict returned is the row's base classification. Some directives —
// cipher and auth among them — are refined from their arguments and the
// surrounding profile; Inspect reports the refined result, and this reports
// what the keyword alone says.
func Lookup(directive string) (Support, bool) {
	e, ok := registry[strings.ToLower(directive)]
	return e.Support, ok
}

// LookupBlock returns the registry's verdict for an inline block tag such as
// "tls-auth", ignoring case. The second result is false when the tag is
// unrecognised.
func LookupBlock(tag string) (Support, bool) {
	s, ok := blockRegistry[strings.ToLower(tag)]
	return s, ok
}

// Known returns every directive keyword the registry classifies, sorted.
// It is the row set for the coverage matrix.
func Known() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// KnownBlocks returns every inline block tag the registry classifies, sorted.
func KnownBlocks() []string {
	names := make([]string, 0, len(blockRegistry))
	for name := range blockRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
