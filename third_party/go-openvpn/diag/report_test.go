package diag_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/diag"
)

// secretValues is the table of known secrets the redaction test scans for. Every
// one of them is planted somewhere in the report below, at least one of them in
// a free-text field that only Redacted's scrubbing can reach.
var secretValues = []struct {
	name  string
	value string
}{
	{"client key PEM", "-----BEGIN PRIVATE KEY-----\nZmFrZS1rZXktbWF0ZXJpYWwtMDAx\n-----END PRIVATE KEY-----"},
	{"client cert PEM", "-----BEGIN CERTIFICATE-----\nZmFrZS1jZXJ0LW1hdGVyaWFsLTAwMg==\n-----END CERTIFICATE-----"},
	{"username", "fake-user@corp.example.test"},
	{"password", "CRV1::fake-state-1234::fake-saml-assertion-blob-5678"},
	{"auth token", "SESS_TOKEN_9f8e7d6c5b4a3210"},
	{"pushed token", "pushed-inline-secret-abcdef01"},
	// A pushed internal address is a secret for the same reason: it names
	// the account the tunnel was issued to.
	{"pushed address", "10.77.240.6"},
	{"pushed address v6", "fd42:c0de:cafe::6"},
}

func secretByName(t *testing.T, name string) string {
	t.Helper()
	for _, s := range secretValues {
		if s.name == name {
			return s.value
		}
	}
	t.Fatalf("no secret named %q in the table", name)
	return ""
}

// populatedReport builds a report with every secret from the table planted in
// it, across the field kinds Redacted has to walk: plain strings, a pointer to
// a struct, slices of structs and of strings, and a map of string slices.
func populatedReport(t *testing.T) *diag.SessionReport {
	t.Helper()

	keyPEM := secretByName(t, "client key PEM")
	certPEM := secretByName(t, "client cert PEM")
	username := secretByName(t, "username")
	password := secretByName(t, "password")
	token := secretByName(t, "auth token")
	pushed := secretByName(t, "pushed token")
	addr4 := secretByName(t, "pushed address")
	addr6 := secretByName(t, "pushed address v6")

	r := &diag.SessionReport{}

	r.Profile = diag.ProfileInfo{
		Fingerprint: "sha256:0badc0ffee",
		Directives:  []string{"client", "remote", "tls-crypt", "auth-user-pass"},
		Gaps: []diag.Gap{
			{Directive: "tls-crypt", Severity: diag.SeverityFatal, Detail: "control channel encryption unimplemented"},
			{Directive: "fast-io", Severity: diag.SeverityIgnored, Detail: "no effect in userspace"},
		},
	}
	r.Endpoint = diag.EndpointInfo{
		Host:       "vpn.example.test",
		ResolvedIP: "198.51.100.7",
		Proto:      "udp",
		Port:       1194,
		Remotes:    2,
		DialRTT:    17 * time.Millisecond,
		// Two endpoints tried: the first failed and the second carried the
		// session. The failed one's message quotes a credential, so the
		// deep copy has to reach into the slice to scrub it.
		Attempts: []diag.EndpointAttempt{
			{
				Index: 0, Host: "dead.example.test", Proto: "tcp", Port: 443,
				Class: diag.ClassNetwork, Stage: diag.StageReset,
				Err: "HARD_RESET exchange for user " + username,
			},
			{
				Index: 1, Host: "vpn.example.test", ResolvedIP: "198.51.100.7",
				Proto: "udp", Port: 1194, DialRTT: 17 * time.Millisecond,
				Succeeded: true,
			},
		},
	}
	r.Stages = []diag.StageRecord{
		{Stage: diag.StageParse, EnteredAt: time.Unix(1700000000, 0).UTC(), Duration: 2 * time.Millisecond},
		{Stage: diag.StageDial, EnteredAt: time.Unix(1700000001, 0).UTC(), Duration: 17 * time.Millisecond},
		// A stage error that quotes a credential — the case that motivates
		// scrubbing by known value.
		{
			Stage:     diag.StageAuth,
			EnteredAt: time.Unix(1700000002, 0).UTC(),
			Duration:  40 * time.Millisecond,
			Err:       "AUTH_FAILED for user " + username + " with token " + token,
		},
	}

	r.TLS = diag.TLSInfo{
		Version:      "TLS 1.3",
		CipherSuite:  "TLS_AES_256_GCM_SHA384",
		EKMAvailable: true,
		Chain: []diag.CertSummary{
			{Subject: "CN=vpn.example.test", Issuer: "CN=Example CA", SHA256: "aa:bb"},
		},
		ClientCert: &diag.CertSummary{
			// A client certificate summary may legitimately carry the
			// username as the subject CN.
			Subject:   "CN=" + username,
			Issuer:    "CN=Example CA",
			NotBefore: time.Unix(1600000000, 0).UTC(),
			NotAfter:  time.Unix(1900000000, 0).UTC(),
			DNSNames:  []string{"client." + username},
		},
	}
	r.SetClientCertPEM(certPEM)
	r.SetClientKeyPEM(keyPEM)
	r.SetCredentials(username, password)
	r.SetAuthToken(token)

	r.Advertised = diag.AdvertisedInfo{
		IVProto:   30,
		IVCiphers: "AES-128-GCM:AES-256-GCM",
		PeerInfo:  "IV_VER=3.11.6\nIV_PROTO=30\n",
		Options:   "V4,dev-type tun,link-mtu 1541,cipher AES-256-GCM",
	}
	r.ServerOpts = "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,cipher AES-256-CBC,auth SHA512,keysize 256,key-method 2,tls-server"
	r.Negotiated = diag.NegotiatedInfo{
		Cipher:        "AES-256-GCM",
		Digest:        "",
		Compression:   "none",
		PeerID:        7,
		KeyDerivation: "tls-ekm",
		TLSWrap:       "none",
	}

	r.Push = diag.PushInfo{
		Raw: "PUSH_REPLY,ifconfig " + addr4 + " 10.77.240.5,ifconfig-ipv6 " + addr6 + "/64,auth-token " + pushed + ",peer-id 7",
		// Parsed is not blanked wholesale, so the pushed address in it can
		// only be reached by scrubbing.
		Parsed: map[string][]string{
			"ifconfig":      {addr4 + " 10.77.240.5"},
			"ifconfig-ipv6": {addr6 + "/64"},
			"peer-id":       {"7"},
			"auth-token":    {token},
		},
		UnknownOptions: []string{"dhcp-option PROXY_HTTP", "block-outside-dns"},
	}
	r.Device = diag.DeviceInfo{
		Kind: "netstack",
		Name: "ns0",
		MTU:  1500,
		IPv4: addr4,
		IPv6: addr6,
	}
	r.AddSecret(addr4, addr6)
	r.Counters = diag.Counters{
		BytesSent: 4096, BytesRecv: 8192,
		PacketsSent: 12, PacketsRecv: 20,
		DecryptFailures: 1, Replays: 2, Retransmits: 3, Rekeys: 1,
	}

	// An error chain that quotes the password, which is exactly how
	// credentials leak into aggregated reports.
	cause := errors.New("server rejected password " + password)
	typed := diag.Wrap(diag.ClassAuth, diag.StageAuth, cause, "credentials rejected")
	wrapped := fmt.Errorf("vpn: connect: %w", typed)
	r.Outcome = diag.Outcome{
		Succeeded:  false,
		Class:      typed.Class,
		Stage:      typed.Stage,
		Feature:    typed.Feature,
		ErrorChain: diag.ErrorChain(wrapped),
	}

	return r
}

// TestRedactedRoundTrip is the redaction contract end to end: a report
// populated with fake secrets round-trips through Redacted and json.Marshal
// with no secret substring present in the output.
func TestRedactedRoundTrip(t *testing.T) {
	r := populatedReport(t)

	// The scan must be discriminating: prove each secret is present in the
	// unredacted form first, otherwise the test below proves nothing.
	rawJSON, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal(unredacted): %v", err)
	}
	for _, s := range secretValues {
		if !strings.Contains(string(rawJSON), jsonEscape(t, s.value)) {
			t.Fatalf("secret %q is not present in the unredacted report; the test is vacuous", s.name)
		}
	}

	redJSON, err := json.Marshal(r.Redacted())
	if err != nil {
		t.Fatalf("Marshal(redacted): %v", err)
	}
	for _, s := range secretValues {
		if strings.Contains(string(redJSON), jsonEscape(t, s.value)) {
			t.Errorf("secret %q survived redaction:\n%s", s.name, redJSON)
		}
		// Also scan the unescaped literal, in case a value contains no
		// characters JSON escapes.
		if strings.Contains(string(redJSON), s.value) {
			t.Errorf("secret %q survived redaction (literal):\n%s", s.name, redJSON)
		}
	}
	if !strings.Contains(string(redJSON), diag.RedactedPlaceholder) {
		t.Errorf("redacted report contains no %s marker:\n%s", diag.RedactedPlaceholder, redJSON)
	}
}

// jsonEscape returns v as it appears inside a JSON document, without the
// surrounding quotes.
func jsonEscape(t *testing.T, v string) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal(%q): %v", v, err)
	}
	return string(b[1 : len(b)-1])
}

// TestRedactedBlanksCredentialFields checks the fields Redacted blanks by
// name, independently of whether they were registered as secrets.
func TestRedactedBlanksCredentialFields(t *testing.T) {
	r := &diag.SessionReport{}
	// Assigned directly rather than through the setters, so nothing is
	// registered for scrubbing and only the blanking pass can catch them.
	r.TLS.ClientCertPEM = "cert"
	r.TLS.ClientKeyPEM = "key"
	r.Credentials.Username = "user"
	r.Credentials.Password = "pass"
	r.Credentials.AuthToken = "token"
	r.Push.Raw = "PUSH_REPLY,auth-token abc"
	r.Device.IPv4 = "10.77.240.6"
	r.Device.IPv6 = "fd42:c0de:cafe::6"

	red := r.Redacted()
	fields := map[string]string{
		"TLS.ClientCertPEM":     red.TLS.ClientCertPEM,
		"TLS.ClientKeyPEM":      red.TLS.ClientKeyPEM,
		"Credentials.Username":  red.Credentials.Username,
		"Credentials.Password":  red.Credentials.Password,
		"Credentials.AuthToken": red.Credentials.AuthToken,
		"Push.Raw":              red.Push.Raw,
		"Device.IPv4":           red.Device.IPv4,
		"Device.IPv6":           red.Device.IPv6,
	}
	for name, got := range fields {
		if got != diag.RedactedPlaceholder {
			t.Errorf("%s = %q, want %q", name, got, diag.RedactedPlaceholder)
		}
	}
	if red.Secrets() != 0 {
		t.Errorf("redacted report carries %d registered secrets, want 0", red.Secrets())
	}
}

// TestRedactedDoesNotBlankEmptyFields checks that redaction never invents a
// value for a field that was never set.
func TestRedactedDoesNotBlankEmptyFields(t *testing.T) {
	red := (&diag.SessionReport{}).Redacted()
	if red == nil {
		t.Fatal("Redacted on a zero-value report returned nil")
	}
	if red.Device.IPv4 != "" || red.Device.IPv6 != "" {
		t.Errorf("Redacted invented device addresses on a zero-value report: %+v", red.Device)
	}
	if red.Push.Raw != "" || red.TLS.ClientKeyPEM != "" || red.Credentials.Username != "" {
		t.Errorf("Redacted invented values on a zero-value report: %+v", red)
	}
	if _, err := json.Marshal(red); err != nil {
		t.Fatalf("Marshal(zero redacted): %v", err)
	}
}

func TestRedactedNilReceiver(t *testing.T) {
	var r *diag.SessionReport
	if got := r.Redacted(); got != nil {
		t.Errorf("nil.Redacted() = %+v, want nil", got)
	}
}

// TestRedactedDoesNotMutateReceiver checks that the full form stays available
// locally after a redacted copy has been taken.
func TestRedactedDoesNotMutateReceiver(t *testing.T) {
	r := populatedReport(t)
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	secretsBefore := r.Secrets()

	red := r.Redacted()

	after, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("Redacted mutated the receiver:\nbefore: %s\nafter:  %s", before, after)
	}
	if r.Secrets() != secretsBefore {
		t.Errorf("Redacted changed the registered secret count: %d -> %d", secretsBefore, r.Secrets())
	}

	// The copy must share no memory with the receiver either.
	red.Profile.Directives[0] = "mutated"
	red.Stages[0].Err = "mutated"
	red.Push.Parsed["ifconfig"][0] = "mutated"
	red.Push.Parsed["injected"] = []string{"mutated"}
	red.TLS.Chain[0].Subject = "mutated"
	red.TLS.ClientCert.Subject = "mutated"
	red.Outcome.ErrorChain[0] = "mutated"

	after2, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(before) != string(after2) {
		t.Errorf("mutating the redacted copy changed the receiver:\nbefore: %s\nafter:  %s", before, after2)
	}
}

// TestRedactedPreservesMeasurementFields checks that redaction blanks
// credentials without destroying the data the measurement system exists to
// collect.
func TestRedactedPreservesMeasurementFields(t *testing.T) {
	r := populatedReport(t)
	red := r.Redacted()

	if red.Endpoint.Host != "vpn.example.test" || red.Endpoint.Port != 1194 {
		t.Errorf("endpoint lost: %+v", red.Endpoint)
	}
	if red.Endpoint.DialRTT != 17*time.Millisecond {
		t.Errorf("DialRTT = %v, want 17ms", red.Endpoint.DialRTT)
	}

	// The per-endpoint records are measurement data and survive whole. A
	// redacted report that dropped them would tell an aggregator that a
	// profile which measured two endpoints had measured one.
	if len(red.Endpoint.Attempts) != 2 {
		t.Fatalf("Endpoint.Attempts = %+v, want both endpoints", red.Endpoint.Attempts)
	}
	first := red.Endpoint.Attempts[0]
	if first.Host != "dead.example.test" || first.Class != diag.ClassNetwork ||
		first.Stage != diag.StageReset || first.Index != 0 {
		t.Errorf("first endpoint record lost detail: %+v", first)
	}
	if !red.Endpoint.Attempts[1].Succeeded {
		t.Error("the successful endpoint record lost its outcome")
	}
	// ... but the free text in one is scrubbed like any other, and the copy
	// is deep: the slice header alone would leave the two reports sharing the
	// backing array.
	if strings.Contains(first.Err, secretByName(t, "username")) {
		t.Errorf("endpoint record error still quotes the user name: %q", first.Err)
	}
	if !strings.Contains(first.Err, diag.RedactedPlaceholder) {
		t.Errorf("endpoint record error was not scrubbed: %q", first.Err)
	}
	if &red.Endpoint.Attempts[0] == &r.Endpoint.Attempts[0] {
		t.Error("Redacted shares the endpoint record array with the receiver")
	}
	if !red.TLS.EKMAvailable {
		t.Error("EKMAvailable lost")
	}
	if red.ServerOpts != r.ServerOpts {
		t.Errorf("ServerOpts = %q, want it preserved", red.ServerOpts)
	}
	if len(red.Push.UnknownOptions) != 2 {
		t.Errorf("UnknownOptions = %v, want 2 entries", red.Push.UnknownOptions)
	}
	if red.Counters != r.Counters {
		t.Errorf("Counters = %+v, want %+v", red.Counters, r.Counters)
	}
	if len(red.Stages) != len(r.Stages) {
		t.Fatalf("Stages length = %d, want %d", len(red.Stages), len(r.Stages))
	}
	if !red.Stages[0].EnteredAt.Equal(r.Stages[0].EnteredAt) {
		t.Errorf("StageRecord.EnteredAt = %v, want %v", red.Stages[0].EnteredAt, r.Stages[0].EnteredAt)
	}
	if red.TLS.ClientCert == nil || !red.TLS.ClientCert.NotAfter.Equal(r.TLS.ClientCert.NotAfter) {
		t.Errorf("client cert summary timestamps lost: %+v", red.TLS.ClientCert)
	}
	if red.Outcome.Class != diag.ClassAuth || red.Outcome.Stage != diag.StageAuth {
		t.Errorf("outcome = %+v, want auth/auth", red.Outcome)
	}
	if len(red.Outcome.ErrorChain) != len(r.Outcome.ErrorChain) {
		t.Errorf("error chain length = %d, want %d", len(red.Outcome.ErrorChain), len(r.Outcome.ErrorChain))
	}
	if len(red.Profile.Gaps) != 2 || red.Profile.Gaps[0].Severity != diag.SeverityFatal {
		t.Errorf("gaps lost: %+v", red.Profile.Gaps)
	}
	// Which backend carried the tunnel qualifies every timing above it, so
	// redaction takes the addresses and leaves the rest.
	if red.Device.Kind != "netstack" || red.Device.Name != "ns0" || red.Device.MTU != 1500 {
		t.Errorf("device backend identity lost: %+v", red.Device)
	}
}

// TestAddSecretIgnoresEmpty guards the degenerate replacement that an empty
// secret would cause.
func TestAddSecretIgnoresEmpty(t *testing.T) {
	r := &diag.SessionReport{}
	r.AddSecret("", "", "abc", "abc")
	if r.Secrets() != 1 {
		t.Fatalf("Secrets() = %d, want 1", r.Secrets())
	}
	r.ServerOpts = "xxabcxx"
	if got := r.Redacted().ServerOpts; got != "xx"+diag.RedactedPlaceholder+"xx" {
		t.Errorf("ServerOpts = %q, want the secret replaced in place", got)
	}
}

// TestOverlappingSecrets checks that a secret containing another is replaced
// whole rather than leaving a fragment behind.
func TestOverlappingSecrets(t *testing.T) {
	r := &diag.SessionReport{}
	r.AddSecret("token", "token-with-suffix")
	r.ServerOpts = "value=token-with-suffix"
	got := r.Redacted().ServerOpts
	if strings.Contains(got, "with-suffix") {
		t.Errorf("ServerOpts = %q, want the longer secret replaced whole", got)
	}
}

// TestSessionReportIsNotJSONMarshaler pins the contract that redaction is not
// smuggled into json.Marshal: callers must reach for Redacted deliberately.
func TestSessionReportIsNotJSONMarshaler(t *testing.T) {
	var v any = &diag.SessionReport{}
	if _, ok := v.(json.Marshaler); ok {
		t.Error("SessionReport implements json.Marshaler; Redacted must be the marshalled form instead")
	}
	if _, ok := v.(encodingTextMarshaler); ok {
		t.Error("SessionReport implements encoding.TextMarshaler; redaction must not be implicit")
	}
}

type encodingTextMarshaler interface {
	MarshalText() ([]byte, error)
}

// TestRedactedBlanksPushedCredentials pins that pushed credentials are
// blanked in Parsed and UnknownOptions, not only in Raw.
func TestRedactedBlanksPushedCredentials(t *testing.T) {
	rep := &diag.SessionReport{}
	rep.Push.Raw = "PUSH_REPLY,auth-token TOKEN,ifconfig 10.8.0.2 255.255.255.0,route 10.0.0.0 255.0.0.0"
	rep.Push.Parsed = map[string][]string{
		"auth-token":      {"TOKEN"},
		"auth-token-user": {"dXNlcg=="},
		"ifconfig":        {"10.8.0.2", "255.255.255.0"},
		"ifconfig-ipv6":   {"fd00::2/64"},
		"route":           {"10.0.0.0", "255.0.0.0"},
	}
	rep.Push.UnknownOptions = []string{"auth-token-user dXNlcg==", "some-future-option keep-me"}

	red := rep.Redacted()

	for _, keyword := range []string{"auth-token", "auth-token-user", "ifconfig", "ifconfig-ipv6"} {
		for i, got := range red.Push.Parsed[keyword] {
			if got != diag.RedactedPlaceholder {
				t.Errorf("Push.Parsed[%q][%d] = %q, want it blanked", keyword, i, got)
			}
		}
		if len(red.Push.Parsed[keyword]) == 0 {
			t.Errorf("Push.Parsed[%q] disappeared; the keyword should survive", keyword)
		}
	}
	// A non-credential option survives.
	if got := red.Push.Parsed["route"]; len(got) != 2 || got[0] != "10.0.0.0" {
		t.Errorf("Push.Parsed[route] = %v, want it untouched", got)
	}
	if got := red.Push.UnknownOptions[1]; got != "some-future-option keep-me" {
		t.Errorf("UnknownOptions[1] = %q, want it untouched", got)
	}
	if got := red.Push.UnknownOptions[0]; strings.Contains(got, "dXNlcg==") {
		t.Errorf("UnknownOptions[0] = %q, still carries the username", got)
	}

	if got := rep.Push.Parsed["auth-token"][0]; got != "TOKEN" {
		t.Errorf("Redacted mutated the caller's report: auth-token = %q", got)
	}
	if got := rep.Push.UnknownOptions[0]; got != "auth-token-user dXNlcg==" {
		t.Errorf("Redacted mutated the caller's UnknownOptions: %q", got)
	}
}
