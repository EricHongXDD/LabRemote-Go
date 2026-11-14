// Package saml handles the AWS Client VPN CRV1 SAML challenge-response flow.
//
// AWS Client VPN authentication works in two phases:
//
//  1. The server sends AUTH_FAILED with a CRV1 challenge string that contains
//     a SAML URL. The client opens that URL in a browser.
//
//  2. The IdP redirects the browser to the ACS URL
//     (http://127.0.0.1:35001 — hardcoded by AWS). This package listens on
//     that port, captures the SAMLResponse POST parameter, and returns the
//     token to the caller so it can start Phase 2.
//
// Reference: openvpn3-core client/ovpncli.cpp (CRV1 parsing),
// openlawsvpn-android SamlCallbackServer.kt (ACS server)
package saml

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/buengese/go-openvpn/diag"
)

// IsAWSEndpoint reports whether host is an AWS Client VPN endpoint, matching the
// two fixed ends of cvpn-endpoint-<id>.prod.clientvpn.<region>.amazonaws.com as
// a fallback for a profile that has lost its auth-federate directive.
//
// host is the remote as the profile writes it. The random label AWS requires is
// prepended at dial time, so passing the dialled name fails the prefix match and
// silently disables the fallback.
func IsAWSEndpoint(host string) bool {
	return strings.HasPrefix(host, "cvpn-endpoint-") && strings.HasSuffix(host, ".amazonaws.com")
}

// ACSPort is the TCP port that AWS hardcodes for the SAML ACS callback.
// This is fixed across all AWS regions and all IdPs.
const ACSPort = 35001

// MaxSAMLResponseBytes is the maximum encoded or decoded SAML response size
// accepted by AWS Client VPN.
const MaxSAMLResponseBytes = 128 * 1024

const maxSAMLFormBytes = 3*MaxSAMLResponseBytes + 1024

// Challenge contains the parsed fields from an AUTH_FAILED,CRV1 message.
type Challenge struct {
	// StateID is the opaque session identifier that must be echoed back in
	// Phase 2 as the key-method password: "CRV1::<StateID>::<SAMLToken>".
	StateID string
	// SAMLURL is the identity-provider URL the user must visit to authenticate.
	SAMLURL string
	// RemoteIP is the VPN server IP (informational, extracted when present).
	RemoteIP string
}

// ParseCRV1 parses the CRV1 challenge string from an AUTH_FAILED message.
//
// Wire format (openvpn3-core auth/cr.hpp):
//
//	AUTH_FAILED,CRV1:<flags>:<state_id>:<base64_username>:<saml_url>
//
// All fields are separated by a single colon.  The SAML URL itself may contain
// colons (e.g. "https://..."), so parsing uses fixed-position splits: strip the
// flags field, then consume state_id and base64_username as the next two
// colon-delimited tokens; everything remaining is the URL.
//
// Examples:
//
//	AUTH_FAILED,CRV1:R:instance-1/...:b'XXXX':https://portal.sso.us-east-1.amazonaws.com/...
//	AUTH_FAILED,CRV1:R,52.1.2.3:instance-1/...:b'XXXX':https://...
func ParseCRV1(msg string) (*Challenge, error) {
	const prefix = "AUTH_FAILED,CRV1:"
	if !strings.HasPrefix(msg, prefix) {
		return nil, fmt.Errorf("saml: not a CRV1 message")
	}
	rest := msg[len(prefix):]

	// Field 1: flags (before first colon); may be "R" or "R,<remote_ip>"
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("saml: malformed CRV1 (no colon after flags)")
	}
	flagsAndIP := rest[:colonIdx]
	rest = rest[colonIdx+1:]

	c := &Challenge{}
	if commaIdx := strings.Index(flagsAndIP, ","); commaIdx >= 0 {
		c.RemoteIP = flagsAndIP[commaIdx+1:]
	}

	// Field 2: state_id (before next colon)
	colonIdx = strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("saml: malformed CRV1 (no colon after state_id)")
	}
	c.StateID = rest[:colonIdx]
	rest = rest[colonIdx+1:]

	// Field 3: base64_username (before next colon); may be empty
	colonIdx = strings.Index(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("saml: malformed CRV1 (no colon after username)")
	}
	// username field is informational; skip it
	rest = rest[colonIdx+1:]

	// Field 4: saml_url (remainder — may contain colons)
	c.SAMLURL = rest

	if c.StateID == "" {
		return nil, fmt.Errorf("saml: empty state_id in CRV1 message")
	}
	if c.SAMLURL == "" {
		return nil, fmt.Errorf("saml: empty saml_url in CRV1 message")
	}
	return c, nil
}

// BuildPhase2Password returns the key-method password that Phase 2 must send
// to the VPN server after successful SAML authentication.
//
//	Format: "CRV1::<state_id>::<base64_saml_token>"
func BuildPhase2Password(stateID, samlToken string) string {
	return "CRV1::" + stateID + "::" + samlToken
}

// normalizeAndValidateResponse canonicalises and validates a SAMLResponse value
// received from a browser POST.
//
// application/x-www-form-urlencoded encodes '+' as either '%2B' or as a raw
// '+'.  Go's http.Request.FormValue URL-decodes the body, turning both into
// either '+' or ' ' (space).  This function:
//   - converts spaces back to '+' (undoes the URL-decode artifact)
//   - permits only base64 characters plus ASCII line whitespace
//   - converts URL-safe base64 ('-' → '+', '_' → '/')
//   - re-adds '=' padding to make the length a multiple of 4
func normalizeAndValidateResponse(s string) (string, error) {
	if len(s) == 0 {
		return "", fmt.Errorf("empty SAMLResponse")
	}
	if len(s) > MaxSAMLResponseBytes {
		return "", fmt.Errorf("SAMLResponse exceeds %d bytes", MaxSAMLResponseBytes)
	}
	out := make([]byte, 0, len(s))
	defer func() { clear(out) }()
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ':
			out = append(out, '+')
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/':
			out = append(out, c)
		case c == '=':
			out = append(out, c)
		case c == '-':
			out = append(out, '+') // URL-safe → standard
		case c == '_':
			out = append(out, '/') // URL-safe → standard
		case c == '\n' || c == '\r' || c == '\t':
			// XML encoders may wrap long base64 values using ASCII whitespace.
		default:
			return "", fmt.Errorf("SAMLResponse contains invalid base64 data")
		}
	}
	out = bytes.TrimRight(out, "=")
	if bytes.ContainsRune(out, '=') {
		return "", fmt.Errorf("SAMLResponse contains invalid base64 padding")
	}
	for len(out)%4 != 0 {
		out = append(out, '=')
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(out)))
	n, err := base64.StdEncoding.Strict().Decode(decoded, out)
	if err != nil {
		return "", fmt.Errorf("SAMLResponse is not valid base64")
	}
	decoded = decoded[:n]
	defer clear(decoded)
	if len(decoded) > MaxSAMLResponseBytes {
		return "", fmt.Errorf("decoded SAMLResponse exceeds %d bytes", MaxSAMLResponseBytes)
	}
	if err := validateResponseXML(decoded); err != nil {
		return "", err
	}
	return string(out), nil
}

func validateResponseXML(data []byte) error {
	var response struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("SAMLResponse is not well-formed XML")
	}
	if response.XMLName.Local != "Response" || response.XMLName.Space != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return fmt.Errorf("SAMLResponse has an unexpected root element")
	}
	return nil
}

// acsShutdownGrace bounds how long Wait lets the success page finish reaching
// the browser after the token has arrived. It only has to cover one fixed,
// few-hundred-byte response over the loopback interface.
const acsShutdownGrace = 2 * time.Second

// ACSServer listens on 127.0.0.1:35001 for the browser's SAML POST callback.
// It captures the SAMLResponse form field, hands it to Wait, and releases the
// port.
//
// AWS hardcodes the ACS URL, so there is no second port to fall back to: the
// listener is owned for exactly as long as the ACSServer lives, and no more.
// NewACSServer binds it, Wait releases it on every path it can return through,
// Close releases it for a caller that never reaches Wait, and a lost bind is
// reported rather than absorbed — see ErrACSPortBusy.
//
// Holding the port for the process's lifetime would keep a squatter out and is
// deliberately not done: the callback is only answerable while a flow this
// client started is waiting for it (docs/security-architecture.md §5.4).
type ACSServer struct {
	ln    net.Listener
	srv   *http.Server
	token chan string

	closeOnce sync.Once
	closeErr  error
}

// ErrACSPortBusy reports that something else already held the assertion
// callback port when this client tried to take it. It is wrapped by the error
// NewACSServer returns, so recover it with errors.Is.
//
// AWS fixes the callback address, so the browser posts the assertion to
// 127.0.0.1:35001 whether or not this client is listening there: a bind lost to
// another local account delivers the identity provider's POST — the credential
// this flow exists to fetch — to that account, and loopback ports are not
// partitioned by UID while the ACS server runs in the system daemon. See
// docs/security-architecture.md §5.4. It is named so that no caller answers it
// with a paste prompt, which turns an interception into a login finished by hand.
var ErrACSPortBusy = errors.New("saml: the assertion callback port is held by another process")

// NewACSServer binds the ACS listener on 127.0.0.1:ACSPort, so the caller learns
// the port is unavailable before it opens a browser whose callback it could not
// answer. A caller that gives up before Wait must Close the server, or the port
// stays bound for the life of the process. A failure is a *diag.Error of
// ClassLocal at StageAuth, wrapping ErrACSPortBusy when the port was taken.
func NewACSServer() (*ACSServer, error) {
	return newACSServer(ACSPort)
}

// newACSServer is NewACSServer with the port as an argument, so that a test can
// hold the port first and see what the bind does about it. The argument stops
// here: AWS hardcodes the ACS URL, so ACSPort is its only working value.
func newACSServer(port int) (*ACSServer, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, acsListenError(err)
	}
	s := &ACSServer{
		ln:    ln,
		token: make(chan string, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleACS)
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	return s, nil
}

// acsListenError classifies a failed ACS bind as ClassLocal at StageAuth: the
// obstacle is on this machine, which the failover loop reads as "no endpoint can
// help", and collecting the assertion is authentication. EADDRINUSE is singled
// out because it is the one bind failure that means the assertion is going
// somewhere else rather than nowhere, which is what ErrACSPortBusy names.
func acsListenError(cause error) *diag.Error {
	const detail = "bind the SAML assertion callback port"
	if errors.Is(cause, syscall.EADDRINUSE) {
		return diag.Wrap(diag.ClassLocal, diag.StageAuth,
			fmt.Errorf("%w: %w", ErrACSPortBusy, cause), detail)
	}
	return diag.Wrap(diag.ClassLocal, diag.StageAuth, cause, detail)
}

// Close releases the ACS listener and drops any connection still open on it. It
// is idempotent and safe to call concurrently with Wait, which closes the server
// itself; Close is for a caller that binds and then abandons before Wait.
func (s *ACSServer) Close() error {
	s.closeOnce.Do(func() {
		// Server.Close only closes listeners Serve has registered with it, so a
		// server that never reached Wait needs its listener closed directly; the
		// second close of the same listener is the net.ErrClosed discarded here.
		s.closeErr = s.srv.Close()
		if err := s.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && s.closeErr == nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}

// Wait serves the ACS callback and blocks until a SAMLResponse arrives (raw,
// base64-encoded by the IdP), ctx ends, or the server fails. The listener is
// released before Wait returns, so the caller's next NewACSServer can bind.
func (s *ACSServer) Wait(ctx context.Context) (string, error) {
	// Closing from the goroutine that is returning is the whole of the contract
	// above: leave it to a separate ctx watcher and Wait returns with the
	// listener still open, which a re-authentication's immediate re-bind races.
	defer s.Close() //nolint:errcheck

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.srv.Serve(s.ln) }()

	select {
	case tok := <-s.token:
		// The handler publishes the token before its success page has left the
		// connection, and Close drops connections that are still active. Shutdown
		// frees the listener at once, then waits for the page so the browser gets
		// it instead of a reset; the deferred Close backstops a stalled one.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), acsShutdownGrace)
		defer cancel()
		s.srv.Shutdown(shutdownCtx) //nolint:errcheck
		return tok, nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return "", errors.New("saml: ACS server closed before a callback arrived")
		}
		return "", fmt.Errorf("saml: ACS server error: %w", err)
	case <-ctx.Done():
		return "", fmt.Errorf("saml: ACS timeout: %w", ctx.Err())
	}
}

// handleACS takes the identity provider's POST and publishes the assertion to
// Wait. It checks the shape of what arrived and nothing at all about who sent
// it, because there is nothing here to check it against.
//
// SAML's field for a nonce — RelayState — is unusable: a responder echoes it
// only when it accompanied the *request*, and this client sends no request, so
// whatever AuthnRequest exists is AWS's and so is its RelayState. A value out of
// the challenge serves no better, because the state_id and the IdP URL both
// travel to the browser and the daemon broadcasts the URL over SAMLRequired to
// every session the bus policy admits: a value every local account can read
// authenticates nothing against a local account, the attacker in
// docs/security-architecture.md §5.4. Nor the assertion's own fields — this
// client holds no IdP signing key, AWS verifies the signature, the audience and
// the conditions, and a Destination read out of the XML is attacker-controlled
// input checked against itself.
//
// What is left is what this code does: own the port for exactly as long as the
// flow, refuse loudly when it cannot (ErrACSPortBusy), and accept only a
// bounded, well-formed SAML protocol Response, so a malformed POST from a local
// process is rejected without ending the wait. An attacker who wins the bind
// still sees the assertion, and one holding a valid assertion of their own can
// post it here first; both are residual risk, not mitigated.
//
// Reference: saml-bindings-2.0-os §3.1.1 and §3.5.3, saml-profiles-2.0-os
// §4.1.5 — RelayState is echoed only when the request carried it.
func (s *ACSServer) handleACS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSAMLFormBytes)
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "form too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// r.FormValue URL-decodes the POST body, turning base64 '+' characters
	// (submitted as '%2B' or raw) into spaces. normalizeAndValidateResponse
	// restores the base64, rejects malformed input, and requires a SAML Response.
	tok, err := normalizeAndValidateResponse(r.FormValue("SAMLResponse"))
	if err != nil {
		http.Error(w, "invalid SAMLResponse", http.StatusBadRequest)
		return
	}
	// Return a minimal HTML page that tells the user to close the browser.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<html><body><h2>Authentication successful.</h2><p>You may close this window.</p></body></html>")
	// Non-blocking send — if the channel already has a value, discard duplicate.
	select {
	case s.token <- tok:
	default:
	}
}
