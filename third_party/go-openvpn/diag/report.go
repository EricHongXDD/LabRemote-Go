// Package diag defines the diagnostics vocabulary shared by the client, the
// capability registry and the measurement harness: the connection stages, the
// error taxonomy, capability gaps, and the per-attempt session report. It holds
// types and no behaviour and deliberately does not import the root vpn package,
// so counters are declared here rather than reused from vpn.Stats.
//
// Three surfaces, available at three different times:
//
//   - Gap, produced by capability preflight before dialing.
//   - Stage, emitted as the connection progresses.
//   - SessionReport, produced when an attempt ends, however it ends.
//
// Redaction is a property of the type rather than a discipline at the call
// site. SessionReport deliberately does not implement json.Marshaler; call
// Redacted and marshal its result.
package diag

import (
	"reflect"
	"slices"
	"strings"
	"time"
)

// RedactedPlaceholder is substituted for every secret value and every
// credential-bearing field in a report returned by SessionReport.Redacted.
const RedactedPlaceholder = "[REDACTED]"

// SessionReport is the record of one connection attempt, produced on success
// and on failure alike. For the measurement system it is the unit of data
// collection; for a client it is what turns "connection failed" into a
// message someone can act on.
//
// Never marshal a SessionReport directly. It carries client key material,
// credentials and the raw PUSH_REPLY. Marshal the value returned by Redacted
// instead, which is safe to serialise and aggregate.
//
// The zero value is usable: every group is a struct, and Redacted is safe on
// a partially populated report.
type SessionReport struct {
	// Preflight is how the capability preflight at StageParse was configured.
	// It qualifies everything below it: under PreflightFailFast, the zero
	// value, a profile with a fatal gap never reaches the network, so its
	// stage timeline says nothing about the protocol code.
	Preflight PreflightMode `json:"preflight"`
	// Profile is what the profile said and what of it we cannot honour.
	Profile ProfileInfo `json:"profile"`
	// Endpoint is what we dialed and what it resolved to.
	Endpoint EndpointInfo `json:"endpoint"`
	// Stages is the sequence of connection stages entered, in order. The
	// last entry is the furthest stage reached.
	Stages []StageRecord `json:"stages,omitempty"`
	// TLS is the control-channel TLS session, including the measurement
	// instrument EKMAvailable.
	TLS TLSInfo `json:"tls"`
	// Advertised is what we told the server we could do.
	Advertised AdvertisedInfo `json:"advertised"`
	// ServerOpts is the server's own options string, from its key-method-2
	// packet. It carries the deployment's link-mtu, cipher, auth and
	// key-method: the best available fingerprint of what a server runs.
	ServerOpts string `json:"server_opts,omitempty"`
	// Negotiated is what the two sides settled on.
	Negotiated NegotiatedInfo `json:"negotiated"`
	// Push is the PUSH_REPLY, raw and parsed, plus the options we did not
	// recognise.
	Push PushInfo `json:"push"`
	// Device is the tunnel backend that served the attempt. It is empty for
	// an attempt that never reached the data stage.
	Device DeviceInfo `json:"device,omitzero"`
	// Counters are the data-channel tallies for the lifetime of the
	// attempt.
	Counters Counters `json:"counters"`
	// Outcome is how the attempt ended.
	Outcome Outcome `json:"outcome"`

	// Credentials records the credential material used for this attempt, so
	// that redaction has something definite to blank. Nothing in it survives
	// Redacted.
	Credentials CredentialInfo `json:"credentials,omitzero"`

	// secrets holds the literal values Redacted scrubs out of every free-text
	// field. It is populated by the setters below and by AddSecret, and is
	// never serialised.
	secrets []string
}

// ProfileInfo summarises the parsed profile and the capability preflight run
// over it.
type ProfileInfo struct {
	// Fingerprint is a stable identifier for the profile contents. It is a
	// hash, so it carries no hostnames, certificates or credentials and is
	// safe to aggregate across a sweep.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Directives lists the name of every directive the parser encountered,
	// in file order, including ones it does not recognise. Arguments are
	// deliberately excluded: they carry credentials and hostnames.
	Directives []string `json:"directives,omitempty"`
	// Gaps is what the capability preflight found, one entry per directive
	// we cannot fully honour.
	Gaps []Gap `json:"gaps,omitempty"`
}

// EndpointInfo describes the remote we dialed. The scalars describe the
// endpoint the attempt ended on — the one that carried the session, or the
// last tried when none did — and Attempts is the whole list, as
// profile.Profile's Remote/Port/Proto stand to its Remotes.
type EndpointInfo struct {
	// Host is the remote as written in the profile.
	Host string `json:"host,omitempty"`
	// ResolvedIP is the address Host resolved to, in textual form.
	ResolvedIP string `json:"resolved_ip,omitempty"`
	// Proto is the transport protocol, "udp" or "tcp". It is the dialed
	// remote's own, which a --remote line's third field may set against the
	// profile's --proto.
	Proto string `json:"proto,omitempty"`
	// Port is the remote port.
	Port int `json:"port,omitempty"`
	// Remotes is how many --remote lines the profile carried: its breadth,
	// not the attempt's. How many were tried, and what became of each, is
	// len(Attempts) and Attempts.
	Remotes int `json:"remotes,omitempty"`
	// Attempts is one record per remote actually dialed, in the order tried —
	// file order unless --remote-random shuffled it. A measurement client
	// collects this rather than the scalars above: a profile that named four
	// endpoints and connected on the third has measured three, and reporting
	// only the one that answered throws two away. Empty before StageDial.
	Attempts []EndpointAttempt `json:"attempts,omitempty"`
	// DialRTT is how long the transport took to come up, in nanoseconds
	// when serialised. For UDP this is the socket setup only.
	DialRTT time.Duration `json:"dial_rtt,omitempty"`
}

// EndpointAttempt is one remote the client dialed and what became of it. Every
// remote reached gets one, whether it answered or not, so that a sweep counts
// endpoints rather than profiles. The failure fields carry the class and stage
// the Outcome would have carried had this been the only remote.
type EndpointAttempt struct {
	// Index is the remote's 0-based position in the profile's --remote list,
	// not its position in Attempts: --remote-random shuffles the order they
	// are tried in.
	Index int `json:"index"`
	// Host is the remote as written in the profile.
	Host string `json:"host,omitempty"`
	// ResolvedIP is the address Host resolved to, empty when the dial never
	// produced a socket.
	ResolvedIP string `json:"resolved_ip,omitempty"`
	// Proto is this remote's own transport, "udp" or "tcp".
	Proto string `json:"proto,omitempty"`
	// Port is this remote's port.
	Port int `json:"port,omitempty"`
	// DialRTT is how long this remote's transport took to come up. It is
	// zero for a dial that failed.
	DialRTT time.Duration `json:"dial_rtt,omitempty"`
	// Succeeded reports the remote that completed the handshake. At most one
	// entry has it set, and it is always the last.
	Succeeded bool `json:"succeeded,omitempty"`
	// Class is the class this remote failed with, meaningless when Succeeded.
	// ClassNetwork and ClassTLS are the ones the client moves on from; a
	// ClassConfig or ClassUnsupported entry is the last in the list, because
	// the profile, not the endpoint, is what could not be honoured.
	Class Class `json:"class"`
	// Stage is the stage this remote failed in, meaningless when Succeeded
	// for the reason Outcome's is: the zero value of both Class and Stage is
	// a real one, so neither can be omitted from the serialised form.
	Stage Stage `json:"stage"`
	// Err is the message of the failure, scrubbed like every other free-text
	// field in the report.
	Err string `json:"err,omitempty"`
}

// StageRecord is one entry in the stage timeline.
type StageRecord struct {
	// Stage is the stage entered.
	Stage Stage `json:"stage"`
	// EnteredAt is when the stage was entered.
	EnteredAt time.Time `json:"entered_at,omitzero"`
	// Duration is how long the stage took. It is zero for a stage that was
	// still in progress when the attempt ended.
	Duration time.Duration `json:"duration,omitempty"`
	// Err is the message of the error that ended this stage, empty when the
	// stage completed. It is a string so the report stays serialisable and
	// its text can be scrubbed; the typed error survives in Outcome.
	Err string `json:"err,omitempty"`
}

// TLSInfo describes the control-channel TLS session and the certificate
// material either side presented.
type TLSInfo struct {
	// Version is the negotiated TLS version, for example "TLS 1.3".
	Version string `json:"version,omitempty"`
	// CipherSuite is the negotiated TLS cipher suite name.
	CipherSuite string `json:"ciphersuite,omitempty"`
	// Chain summarises the certificate chain the server presented, leaf
	// first.
	Chain []CertSummary `json:"chain,omitempty"`
	// EKMAvailable reports whether the peer supports RFC 5705 exported
	// keying material for data-channel key derivation. It is a measurement
	// instrument: a strong proxy for OpenVPN 2.6 or newer.
	EKMAvailable bool `json:"ekm_available"`
	// EMSExportFallback reports that the peer pushed key-derivation tls-ekm,
	// crypto/tls refused the RFC 5705 export because the session negotiated
	// TLS 1.2 without Extended Master Secret, and the key block was derived
	// from captured session material instead — what stock openvpn's OpenSSL
	// does unasked. It is a property of the endpoint, not of this client.
	EMSExportFallback bool `json:"ems_export_fallback,omitempty"`
	// ClientCert summarises the certificate we presented, if any. The
	// summary carries no key material and survives redaction.
	ClientCert *CertSummary `json:"client_cert,omitempty"`
	// ClientCertPEM is the PEM-encoded client certificate. Redacted blanks
	// it.
	ClientCertPEM string `json:"client_cert_pem,omitempty"`
	// ClientKeyPEM is the PEM-encoded client private key. Redacted blanks
	// it.
	ClientKeyPEM string `json:"client_key_pem,omitempty"`
}

// CertSummary is the non-secret summary of one X.509 certificate. It holds
// identifiers and validity only — never key material — so it survives
// redaction intact.
type CertSummary struct {
	// Subject is the certificate subject in RFC 2253 form.
	Subject string `json:"subject,omitempty"`
	// Issuer is the certificate issuer in RFC 2253 form.
	Issuer string `json:"issuer,omitempty"`
	// SerialNumber is the certificate serial in decimal.
	SerialNumber string `json:"serial_number,omitempty"`
	// NotBefore is the start of the validity window.
	NotBefore time.Time `json:"not_before,omitzero"`
	// NotAfter is the end of the validity window.
	NotAfter time.Time `json:"not_after,omitzero"`
	// SignatureAlgorithm is the algorithm the issuer signed with.
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	// PublicKeyAlgorithm is the certificate's public key algorithm.
	PublicKeyAlgorithm string `json:"public_key_algorithm,omitempty"`
	// SHA256 is the hex-encoded SHA-256 fingerprint of the DER encoding.
	SHA256 string `json:"sha256,omitempty"`
	// DNSNames are the subject alternative names, when present.
	DNSNames []string `json:"dns_names,omitempty"`
}

// AdvertisedInfo is what the client told the server it could do, in the
// key-method-2 exchange.
type AdvertisedInfo struct {
	// IVProto is the IV_PROTO bitmask sent in the peer-info block.
	IVProto uint32 `json:"iv_proto,omitempty"`
	// IVCiphers is the IV_CIPHERS list sent in the peer-info block, for
	// example "AES-128-GCM:AES-256-GCM".
	IVCiphers string `json:"iv_ciphers,omitempty"`
	// PeerInfo is the complete peer-info block we sent, newline separated.
	PeerInfo string `json:"peer_info,omitempty"`
	// Options is the tunnel options string we sent, for example
	// "V4,dev-type tun,link-mtu 1541,...".
	Options string `json:"options,omitempty"`
}

// NegotiatedInfo is what the two sides settled on for the data channel.
type NegotiatedInfo struct {
	// Cipher is the data-channel cipher, for example "AES-256-GCM".
	Cipher string `json:"cipher,omitempty"`
	// Digest is the data-channel HMAC digest for CBC mode, empty for AEAD
	// ciphers.
	Digest string `json:"digest,omitempty"`
	// Compression is the compression mode in force, for example "none" or
	// "lz4-v2".
	Compression string `json:"compression,omitempty"`
	// PeerCompression is what the peer's own options string said about
	// compression framing: "framing" when it declared a framework, "none" when
	// it declared none, and empty for an attempt that never read one.
	//
	// It is a different question from Compression, which is what this client
	// settled on. A peer that declares none disables a framing the profile
	// asked for, and a peer that compresses with a codec this client lacks
	// ends the session. The conclusion is recorded rather than left to be
	// recomputed from ServerOpts, so that a reader of this report and the data
	// channel cannot disagree about the same peer.
	PeerCompression string `json:"peer_compression,omitempty"`
	// PeerID is the 24-bit peer-id the server assigned, used in P_DATA_V2
	// packets. It is 0 and meaningless when WireFormat is "P_DATA_V1",
	// which is the case in which no peer-id was pushed at all.
	PeerID uint32 `json:"peer_id"`
	// WireFormat is the data-channel packet format in force, "P_DATA_V2" or
	// "P_DATA_V1", and empty for an attempt that never reached the push. It
	// cannot be inferred from PeerID — a server that pushes "peer-id 0" and one
	// that pushes none both leave that field 0 and speak different formats — and
	// a client sending the wrong one completes its handshake, reports every
	// stage green and carries no traffic.
	WireFormat string `json:"wire_format,omitempty"`
	// KeyDerivation is how data-channel keys were derived, "tls-ekm" or
	// "prf".
	KeyDerivation string `json:"key_derivation,omitempty"`
	// TLSWrap is the control-channel wrapping in force, as wrap.Wrapper.Name
	// reports it: "none", "tls-auth" or "tls-crypt".
	TLSWrap string `json:"tls_wrap,omitempty"`
}

// PushInfo is the server's PUSH_REPLY.
type PushInfo struct {
	// Raw is the PUSH_REPLY exactly as received. It carries pushed internal
	// addresses and may carry an auth token, so Redacted blanks it whole.
	Raw string `json:"raw,omitempty"`
	// Parsed maps each pushed option keyword to the argument text of every
	// occurrence, in the order received; one appearing twice has two entries.
	// It is neutral on purpose: diag stays free of platform routing code.
	//
	// Redacted blanks the arguments of credential-bearing keywords.
	Parsed map[string][]string `json:"parsed,omitempty"`
	// UnknownOptions lists every pushed option whose keyword the client does
	// not handle. Redacted blanks the arguments of credential-bearing
	// keywords.
	UnknownOptions []string `json:"unknown_options,omitempty"`
}

// DeviceInfo records which tunnel backend served an attempt. Kind, Name and
// MTU are measurement fields and survive redaction, because which backend
// carried a tunnel qualifies every timing in the report. The two addresses do
// not — a pushed internal address identifies the account it was issued to — so
// Redacted blanks them.
type DeviceInfo struct {
	// Kind is the backend that served the attempt: "kernel", "fd" or
	// "netstack". The values are device.Kind, spelled as strings so that diag
	// needs no dependency on the device package.
	Kind string `json:"kind,omitempty"`
	// Name is the interface name for the kernel and fd backends, and a
	// synthetic name for netstack.
	Name string `json:"name,omitempty"`
	// MTU is the negotiated tunnel MTU in bytes.
	MTU int `json:"mtu,omitempty"`
	// IPv4 is the address assigned to this end of the tunnel. Redacted
	// blanks it.
	IPv4 string `json:"ipv4,omitempty"`
	// IPv6 is the IPv6 address assigned to this end of the tunnel, when the
	// server pushed one. Redacted blanks it.
	IPv6 string `json:"ipv6,omitempty"`
}

// Counters are the data-channel tallies for one attempt. They are declared
// here rather than reused from vpn.Stats so that diag stays free of a
// dependency on the root package.
type Counters struct {
	// BytesSent is plaintext bytes written into the tunnel.
	BytesSent uint64 `json:"bytes_sent"`
	// BytesRecv is plaintext bytes read out of the tunnel.
	BytesRecv uint64 `json:"bytes_recv"`
	// PacketsSent is data-channel packets sent.
	PacketsSent uint64 `json:"packets_sent"`
	// PacketsRecv is data-channel packets received.
	PacketsRecv uint64 `json:"packets_recv"`
	// DecryptFailures is packets that failed authentication or decryption.
	DecryptFailures uint64 `json:"decrypt_failures"`
	// Decompressed is data-channel packets the peer compressed and this client
	// decompressed.
	Decompressed uint64 `json:"decompressed"`
	// Replays is data-channel packets dropped by the replay window.
	Replays uint64 `json:"replays"`
	// ControlAuthFailures is control packets the control-channel wrap could
	// not authenticate — a tls-auth HMAC mismatch. It is separate from
	// DecryptFailures because the data channel's keys are negotiated, while the
	// control channel's key comes from the profile: a failure here means the
	// static key or the key-direction is wrong. A non-zero count with no packet
	// ever accepted distinguishes a wrapped server we cannot speak to from one
	// that is not there.
	ControlAuthFailures uint64 `json:"control_auth_failures"`
	// ControlReplays is control packets that authenticated but whose
	// wrap-level packet id had already been seen. This is a different ID
	// space from Replays, which counts the data channel, and from the
	// reliable layer's own message sequencing.
	ControlReplays uint64 `json:"control_replays"`
	// ControlStaleTimestamps is control packets that authenticated but
	// carried a replay timestamp older than one already accepted from the
	// peer, which retires every packet id below it.
	ControlStaleTimestamps uint64 `json:"control_stale_timestamps"`
	// ControlForeignSession is control packets that authenticated, or needed
	// no authentication, but carried another session's id. The reference calls
	// these unroutable and drops them (openvpn-2.6.22
	// src/openvpn/ssl.c:3860-3868); a non-zero count on a bare control channel
	// means something on the path is putting packets into our four-tuple.
	ControlForeignSession uint64 `json:"control_foreign_session"`
	// Retransmits is control-channel packets retransmitted by the reliable
	// layer.
	Retransmits uint64 `json:"retransmits"`
	// Rekeys is completed data-channel key renegotiations.
	Rekeys uint64 `json:"rekeys"`
}

// CredentialInfo holds the credential material an attempt used, so that
// redaction has something definite to blank rather than relying on the caller
// to keep secrets out of the report. Redacted replaces every non-empty field
// with RedactedPlaceholder.
type CredentialInfo struct {
	// Username is the auth-user-pass username presented to the server.
	Username string `json:"username,omitempty"`
	// Password is the auth-user-pass password. For AWS Client VPN this
	// field carries the CRV1 SAML response.
	Password string `json:"password,omitempty"`
	// AuthToken is the session token the server pushed via auth-token.
	AuthToken string `json:"auth_token,omitempty"`
}

// Outcome is how an attempt ended.
type Outcome struct {
	// Succeeded reports whether the attempt reached a working tunnel. The
	// remaining fields describe the failure and are meaningless when it is
	// true.
	Succeeded bool `json:"succeeded"`
	// Class is the error class the attempt ended with.
	Class Class `json:"class"`
	// Stage is the stage the attempt failed in — the furthest stage
	// reached.
	Stage Stage `json:"stage"`
	// Feature names the missing capability when Class is
	// ClassUnsupported.
	Feature string `json:"feature,omitempty"`
	// ErrorChain is the message of every error in the unwrap chain, outermost
	// first, as produced by ErrorChain. Strings rather than errors, so the
	// report serialises and Redacted can scrub credentials out of the text.
	ErrorChain []string `json:"error_chain,omitempty"`
}

// AddSecret registers literal values that Redacted must scrub out of every
// free-text field in the report, including the flattened error chain. Empty
// values are ignored and duplicates dropped. Scrubbing is by known value only,
// with no pattern guessing, so every credential that could be quoted in an
// error message must be registered here; a very short value scrubs
// aggressively, since every occurrence of that substring is replaced.
func (r *SessionReport) AddSecret(values ...string) {
	for _, v := range values {
		if v == "" {
			continue
		}
		if slices.Contains(r.secrets, v) {
			continue
		}
		r.secrets = append(r.secrets, v)
	}
}

// Secrets returns the number of distinct secret values registered for
// scrubbing. The values themselves are deliberately not exposed.
func (r *SessionReport) Secrets() int {
	return len(r.secrets)
}

// SetClientCertPEM records the PEM-encoded client certificate and registers
// it for scrubbing.
func (r *SessionReport) SetClientCertPEM(pem string) {
	r.TLS.ClientCertPEM = pem
	r.AddSecret(pem)
}

// SetClientKeyPEM records the PEM-encoded client private key and registers it
// for scrubbing.
func (r *SessionReport) SetClientKeyPEM(pem string) {
	r.TLS.ClientKeyPEM = pem
	r.AddSecret(pem)
}

// SetCredentials records the username and password used and registers both for
// scrubbing: a user name reaches the report through certificate subjects and
// authentication error strings, not only through this field. Pass an empty user
// name rather than a protocol placeholder — AddSecret skips empty values, and
// registering a short literal such as OpenVPN's "N/A" would blank every
// incidental occurrence of it.
func (r *SessionReport) SetCredentials(username, password string) {
	r.Credentials.Username = username
	r.Credentials.Password = password
	r.AddSecret(username, password)
}

// SetAuthToken records the session auth token the server pushed and registers
// it for scrubbing.
func (r *SessionReport) SetAuthToken(token string) {
	r.Credentials.AuthToken = token
	r.AddSecret(token)
}

// Redacted returns a copy safe to serialise and aggregate. It is the form to
// marshal; SessionReport itself deliberately does not implement
// json.Marshaler, so marshalling a report directly is always a deliberate
// act.
//
// It blanks the client certificate and key material, Push.Raw and every
// credential field, and replaces every registered secret value with
// RedactedPlaceholder wherever it appears in free text — including the
// flattened error chain, where credentials most often leak.
//
// The receiver is not modified, no memory is shared with it, and a nil,
// zero-value or partially populated report is handled. The returned report
// carries no registered secrets, so calling Redacted on it again is a no-op.
func (r *SessionReport) Redacted() *SessionReport {
	if r == nil {
		return nil
	}

	replace := r.replacer()
	out := &SessionReport{}
	src := reflect.ValueOf(r).Elem()
	dst := reflect.ValueOf(out).Elem()
	for i := range src.NumField() {
		if !src.Type().Field(i).IsExported() {
			continue
		}
		dst.Field(i).Set(scrubbedCopy(src.Field(i), replace))
	}

	// Blank the credential-bearing fields outright. Scrubbing already
	// covers anything registered through the setters; this also catches a
	// field assigned directly.
	out.TLS.ClientCertPEM = blank(out.TLS.ClientCertPEM)
	out.TLS.ClientKeyPEM = blank(out.TLS.ClientKeyPEM)
	out.Credentials.Username = blank(out.Credentials.Username)
	out.Credentials.Password = blank(out.Credentials.Password)
	out.Credentials.AuthToken = blank(out.Credentials.AuthToken)
	out.Push.Raw = blank(out.Push.Raw)
	// Denied by keyword rather than via AddSecret, which a malformed
	// PUSH_REPLY never reaches.
	redactPushOptions(&out.Push)
	// A pushed internal address identifies the account it was issued to,
	// so it is blanked for the same reason a credential is. The rest of
	// DeviceInfo is a measurement field and survives.
	out.Device.IPv4 = blank(out.Device.IPv4)
	out.Device.IPv6 = blank(out.Device.IPv6)

	return out
}

// credentialPushOptions are the pushed keywords whose arguments are a
// credential (auth-token, auth-token-user) or the account's tunnel address.
var credentialPushOptions = map[string]struct{}{
	"auth-token":      {},
	"auth-token-user": {},
	"ifconfig":        {},
	"ifconfig-ipv6":   {},
}

// redactPushOptions blanks the arguments of credential-bearing pushed
// options in place, keeping the keyword.
func redactPushOptions(p *PushInfo) {
	for keyword, args := range p.Parsed {
		if _, deny := credentialPushOptions[strings.ToLower(keyword)]; !deny {
			continue
		}
		for i := range args {
			args[i] = RedactedPlaceholder
		}
	}
	for i, opt := range p.UnknownOptions {
		keyword, _, _ := strings.Cut(opt, " ")
		if _, deny := credentialPushOptions[strings.ToLower(keyword)]; deny {
			p.UnknownOptions[i] = keyword + " " + RedactedPlaceholder
		}
	}
}

// replacer builds the substitution used to scrub free text. Longer secrets
// are substituted first so that a secret containing another is not left
// partially exposed.
func (r *SessionReport) replacer() func(string) string {
	if len(r.secrets) == 0 {
		return func(s string) string { return s }
	}
	ordered := slices.Clone(r.secrets)
	slices.SortStableFunc(ordered, func(a, b string) int {
		return len(b) - len(a)
	})
	pairs := make([]string, 0, 2*len(ordered))
	for _, s := range ordered {
		pairs = append(pairs, s, RedactedPlaceholder)
	}
	return strings.NewReplacer(pairs...).Replace
}

// blank returns the placeholder for a non-empty value and the empty string
// otherwise, so that redaction never invents a field that was never set.
func blank(s string) string {
	if s == "" {
		return ""
	}
	return RedactedPlaceholder
}

// scrubbedCopy returns a deep copy of v with replace applied to every string
// it contains. Reference types are copied rather than aliased, so the result
// shares no memory with v. Structs carrying unexported state — time.Time is
// the one that matters here — are copied wholesale rather than rebuilt field
// by field, which would silently drop that state; they hold no free text.
func scrubbedCopy(v reflect.Value, replace func(string) string) reflect.Value {
	t := v.Type()
	switch v.Kind() {
	case reflect.String:
		out := reflect.New(t).Elem()
		out.SetString(replace(v.String()))
		return out

	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.New(t.Elem())
		out.Elem().Set(scrubbedCopy(v.Elem(), replace))
		return out

	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.New(t).Elem()
		out.Set(scrubbedCopy(v.Elem(), replace))
		return out

	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.MakeSlice(t, v.Len(), v.Len())
		for i := range v.Len() {
			out.Index(i).Set(scrubbedCopy(v.Index(i), replace))
		}
		return out

	case reflect.Array:
		out := reflect.New(t).Elem()
		for i := range v.Len() {
			out.Index(i).Set(scrubbedCopy(v.Index(i), replace))
		}
		return out

	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.MakeMapWithSize(t, v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(
				scrubbedCopy(iter.Key(), replace),
				scrubbedCopy(iter.Value(), replace),
			)
		}
		return out

	case reflect.Struct:
		if hasUnexportedFields(t) {
			return v
		}
		out := reflect.New(t).Elem()
		for i := range t.NumField() {
			out.Field(i).Set(scrubbedCopy(v.Field(i), replace))
		}
		return out

	default:
		return v
	}
}

// hasUnexportedFields reports whether the struct type t has any unexported
// field.
func hasUnexportedFields(t reflect.Type) bool {
	for i := range t.NumField() {
		if !t.Field(i).IsExported() {
			return true
		}
	}
	return false
}
