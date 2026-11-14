// SPDX-License-Identifier: LGPL-2.1-or-later

// How a connection authenticates, and which secret answers which challenge.
//
// Four things vary with the authentication method and nothing else does: what
// the caller must supply before a connection can be driven at all, what goes in
// the key-method-2 username and password for a given exchange, which wire format
// that packet takes, and what the server's answer to PUSH_REQUEST means. An
// authMethod holds them together.
//
// The interface is unexported because auth/saml cannot implement it: the root
// package imports it for the SAML protocol pieces, so the dependency cannot run
// the other way. Parsing CRV1 is protocol and lives there; deciding what to send
// and when is this package's business.

package vpn

import (
	"context"
	"errors"
	"fmt"

	"github.com/buengese/go-openvpn/auth/saml"
	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/internal/control"
	"github.com/buengese/go-openvpn/internal/keymethod2"
	"github.com/buengese/go-openvpn/profile"
)

// authReply is what a method makes of the server's answer to PUSH_REQUEST.
type authReply int

const (
	// replyNone is the zero value: no exchange has been answered yet. It is
	// what tells the second half of the connect flow that the first half never
	// ran.
	replyNone authReply = iota
	// replyPushed means the answer is the PUSH_REPLY itself. The connection
	// that carried it is the one the tunnel will run on, and the reply is
	// buffered for the caller to read back.
	replyPushed
	// replySecondExchange means the method has more to send, over a connection
	// of its own. The first one existed only to be asked.
	replySecondExchange
)

// missingFor names which caller is asking a method what it still needs. The
// two questions differ for exactly one method, which is why the caller has to
// say which it is asking.
type missingFor int

const (
	// missingForAnyEntry is the preflight's question: what must the caller
	// supply for this method to have anything to present at all, whichever entry
	// point drives the connection. It is asked before a socket is opened.
	missingForAnyEntry missingFor = iota
	// missingForConnect is Connect's stricter question: what must be set for
	// Connect to drive this method from end to end, on its own.
	missingForConnect
)

// authMethod is how one connection authenticates.
type authMethod interface {
	// missing names what the caller has not supplied, in a sentence fit to be
	// the detail of a ClassConfig failure, or "" when nothing is missing. One
	// method and not two, because only samlMethod tells the two questions apart:
	// an assertion can arrive over a relay, so a federated profile with no
	// SAMLTokenFn is refused by Connect and welcomed by ConnectPhase2.
	missing(ask missingFor) string

	// framing is the key-method-2 wire format this method's peer speaks.
	framing() keymethod2.Framing

	// credentials returns the username and password for one exchange. It may
	// call out to the caller's CredentialsFn, so it takes a context and can
	// fail.
	credentials(ctx context.Context, ex authExchange) (Credentials, error)

	// handleReply reads the server's answer to PUSH_REQUEST — a message that
	// parsed, since a read failure is the caller's to classify — and says whether
	// it finishes the handshake or asks for a second exchange.
	handleReply(cm *control.Message) (authReply, *diag.Error)

	// captureResumption takes a copy of what this method would need to attempt
	// the session again without asking the caller for anything. Reconnect takes
	// it before its first attempt: the first failure erases the client's copy.
	captureResumption() resumption
}

// authMethodFor returns the method a profile authenticates with. It is the only
// place that reads the profile's flow; everything downstream asks the method,
// which is what stops a fourth caller forgetting one of the things that vary.
func (c *Client) authMethodFor(p *profile.Profile) authMethod {
	// An AWS endpoint recognised by its hostname is federated whatever the file
	// says: a profile that lost its auth-federate line to hand-editing would
	// otherwise present a password to a server that wants an assertion.
	if saml.IsAWSEndpoint(p.Remote) {
		return samlMethod{c: c}
	}
	switch p.AuthFlow() {
	case profile.FlowFederated:
		return samlMethod{c: c}
	case profile.FlowUserPass:
		return userPassMethod{stockMethod{c: c}}
	default:
		return certMethod{stockMethod{c: c}}
	}
}

// method returns this attempt's authentication method, deriving it from the
// profile when nothing has set one.
func (c *Client) method() authMethod {
	if c.auth != nil {
		return c.auth
	}
	return c.authMethodFor(c.prof)
}

// oneExchangeReply is the answer-handling of every method that authenticates in
// a single exchange: the reply is the PUSH_REPLY or the exchange is over. A CRV1
// challenge gets its own message because it is not a malformed reply — it is the
// server naming a method this profile does not carry the material for.
func oneExchangeReply(c *Client, cm *control.Message) (authReply, *diag.Error) {
	switch cm.Kind {
	case control.MsgKindPushReply:
		return replyPushed, nil
	case control.MsgKindAuthFailedCRV1:
		// ClassAuth rather than ClassProtocol: the server rejected what was
		// presented and named what it wanted instead. Nothing about the
		// exchange was malformed.
		return replyNone, c.failStage(diag.ClassAuth, diag.StagePush, nil,
			"server asked for a federated (SAML) assertion, which this profile does not authenticate with")
	default:
		return replyNone, c.failStage(diag.ClassProtocol, diag.StagePush, nil, notPushReply(cm))
	}
}

// notPushReply describes what the server sent in place of the PUSH_REPLY an
// exchange required. The split that decides what it means is authoritative in
// oneExchangeReply; this is only the sentence.
func notPushReply(cm *control.Message) string {
	return "expected PUSH_REPLY, got message kind " + cm.Kind.String()
}

// stockMethod is what the two methods a stock OpenVPN server understands have in
// common: stock key-method-2 framing, and an answer to PUSH_REQUEST that is the
// PUSH_REPLY or the end of the exchange. Only AWS's method differs in either.
type stockMethod struct{ c *Client }

func (stockMethod) framing() keymethod2.Framing { return keymethod2.FramingStock }

func (m stockMethod) handleReply(cm *control.Message) (authReply, *diag.Error) {
	return oneExchangeReply(m.c, cm)
}

// certMethod is mutual-TLS client certificate authentication. The certificate
// is the whole credential, so the key-method-2 fields go out empty, which is
// what stock OpenVPN sends for a cert-only profile.
type certMethod struct{ stockMethod }

// missing is always satisfied: the certificate is in the profile, so there is
// nothing for a caller to supply and no callback for it to be supplied through.
func (certMethod) missing(missingFor) string { return "" }

func (certMethod) credentials(context.Context, authExchange) (Credentials, error) {
	// Including on a renegotiation with a pushed auth-token: openvpn3 stores a
	// token only when it has a credentials object to put it in, which a
	// cert-only profile does not, so the reference presents none either.
	return Credentials{}, nil
}

func (certMethod) captureResumption() resumption { return redialResumption{} }

// userPassMethod is username and password authentication, from the caller's
// CredentialsFn.
type userPassMethod struct{ stockMethod }

// missing refuses a profile that asks for a password nobody can answer for, and
// gives the same answer to both questions: CredentialsFn is the only way a
// password reaches this client. It is ClassConfig and not ClassAuth — no server
// rejected anything, because nothing was ever presented.
func (m userPassMethod) missing(missingFor) string {
	if m.c.CredentialsFn == nil {
		return "profile authenticates with a username and password, but no CredentialsFn is set"
	}
	return ""
}

func (m userPassMethod) credentials(ctx context.Context, ex authExchange) (Credentials, error) {
	creds, err := m.c.userPassCredentials(ctx)
	if err != nil {
		return Credentials{}, err
	}
	// A renegotiation re-authenticates with the token the server issued the
	// session, in the password field only. The username stays what opened the
	// session: 2.6 mixes it into the token's HMAC and rechecks it on the way back.
	if ex == authRekey {
		if token := m.c.pushedAuthToken(); token != "" {
			creds.Password = token
		}
	}
	return creds, nil
}

func (m userPassMethod) captureResumption() resumption {
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	return &userPassResumption{
		creds:  m.c.creds,
		cached: m.c.credsCached,
		mayAsk: m.c.CredentialsFn != nil,
	}
}

// ---- The AWS Client VPN SAML method --------------------------------------

const (
	// awsPlaceholderUsername is the fixed user name AWS Client VPN expects in
	// the key-method-2 packet. It is a protocol constant rather than a user
	// name, and only the SAML method sends it.
	awsPlaceholderUsername = "N/A"
	// awsACSPassword is the fixed first-exchange password for AWS Client VPN. It
	// names the ACS port the client listens on for the SAML assertion, and exists
	// to provoke the CRV1 challenge — it authenticates nothing.
	awsACSPassword = "ACS::35001"
)

// samlMethod is the AWS Client VPN SAML/CRV1 two-exchange flow. Its username is
// a placeholder throughout: the credential is the ACS callback in the first
// exchange and the assertion in the second, and AWS issues its session tokens
// against that placeholder, so a rekey repeats it.
type samlMethod struct{ c *Client }

// missing is the one implementation that tells the two questions apart, and the
// whole reason the question is a parameter. Nothing is missing for a caller that
// has not said it will drive the connection end to end: the assertion need not
// come from Connect's callback, and the relay and mobile entry points hand it to
// ConnectPhase2. Connect has no second route, so for Connect it is fatal.
func (m samlMethod) missing(ask missingFor) string {
	if ask == missingForConnect && m.c.SAMLTokenFn == nil {
		return "SAMLTokenFn must be set for a profile that authenticates with a federated assertion"
	}
	return ""
}

func (samlMethod) framing() keymethod2.Framing {
	// A SAML assertion does not fit the uint16 length prefix stock OpenVPN
	// writes, which is the whole reason AWS patched the format.
	return keymethod2.FramingAWSLargeToken
}

func (m samlMethod) credentials(_ context.Context, ex authExchange) (Credentials, error) {
	switch ex {
	case authCRV1Phase2:
		return m.c.cachedCRV1().credentials(), nil

	case authRekey:
		if token := m.c.pushedAuthToken(); token != "" {
			return Credentials{Username: awsPlaceholderUsername, Password: token}, nil
		}
		// No token, but a CRV1 session: repeat the assertion the server bound
		// it to. Falling back to the first-exchange row would resend the
		// challenge prompt, which asks an authenticated session to start over.
		if crv1 := m.c.cachedCRV1(); crv1.complete() {
			return crv1.credentials(), nil
		}
		// Neither: there is nothing to re-present.
		return Credentials{}, nil

	default:
		return Credentials{Username: awsPlaceholderUsername, Password: awsACSPassword}, nil
	}
}

// handleReply reads AWS's answer to the first PUSH_REQUEST, normally the CRV1
// challenge naming the identity provider to visit. An endpoint answering with
// the PUSH_REPLY has decided this client needs no assertion, so single-exchange
// handling applies to anything that is not a challenge.
func (m samlMethod) handleReply(cm *control.Message) (authReply, *diag.Error) {
	c := m.c
	if cm.Kind != control.MsgKindAuthFailedCRV1 {
		return oneExchangeReply(c, cm)
	}
	// The classifier only said a challenge is there. Its body is SAML's to
	// read: for AWS it carries the state id and the IdP URL.
	ch, err := saml.ParseCRV1(cm.Raw)
	if err != nil {
		return replyNone, c.failStage(diag.ClassProtocol, diag.StagePush, err, "parse CRV1 challenge")
	}
	// The state ID is session-bearing material; register it so it cannot leak
	// into the report through an error string.
	c.recorder().edit(func(r *diag.SessionReport) { r.AddSecret(ch.StateID) })
	c.mu.Lock()
	c.samlSession = &SAMLChallenge{URL: ch.SAMLURL, StateID: ch.StateID}
	// Prefer the RemoteIP embedded in the challenge — that is the backend
	// instance holding the SAML state, where the IP the first exchange dialled
	// may be a load balancer VIP that routes to a different one.
	if ch.RemoteIP != "" {
		c.backendIP = ch.RemoteIP
	}
	c.mu.Unlock()
	return replySecondExchange, nil
}

func (m samlMethod) captureResumption() resumption {
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	return samlResumption{
		assertion: m.c.cachedSAMLToken,
		stateID:   m.c.cachedStateID,
		serverIP:  m.c.cachedBackendIP,
		expiry:    m.c.cachedSAMLExpiry,
	}
}

// crv1Material is the state id and SAML assertion a CRV1 password is built
// from. It is the zero value for every exchange that does not build one.
type crv1Material struct {
	stateID   string
	assertion string
}

// complete reports whether there is enough to build a CRV1 password.
func (m crv1Material) complete() bool {
	return m.stateID != "" && m.assertion != ""
}

// credentials returns the CRV1 credential pair, or the empty pair when the
// material is incomplete. An incomplete pair is never sent: the callers that
// can reach it fall back rather than send half a password.
func (m crv1Material) credentials() Credentials {
	if !m.complete() {
		return Credentials{}
	}
	return Credentials{
		Username: awsPlaceholderUsername,
		Password: saml.BuildPhase2Password(m.stateID, m.assertion),
	}
}

// cachedCRV1 returns the CRV1 material from the last completed second
// exchange, for a rekey to re-present.
func (c *Client) cachedCRV1() crv1Material {
	c.mu.Lock()
	defer c.mu.Unlock()
	return crv1Material{stateID: c.cachedStateID, assertion: c.cachedSAMLToken}
}

// reportableUsername maps the SAML method's fixed placeholder to the empty
// string, so that neither the report's credential field nor its secret list
// carries a protocol constant that happens to look like a user name.
func reportableUsername(username string) string {
	if username == awsPlaceholderUsername {
		return ""
	}
	return username
}

// ---- The credential seam -------------------------------------------------
//
// authCredentials is the single place that decides the username and password
// every key-method-2 packet carries.

// authExchange names which key-method-2 exchange is asking for credentials.
// The method decides what the credentials are; the exchange decides which of a
// method's several answers applies.
type authExchange int

const (
	// authInitial is the first key-method-2 packet of an attempt: the only
	// one a cert-only or username/password profile sends, and the one that
	// provokes the CRV1 challenge for AWS SSO.
	authInitial authExchange = iota
	// authCRV1Phase2 is the AWS SSO second exchange, sent over a fresh
	// connection once a SAML assertion has been collected.
	authCRV1Phase2
	// authRekey is a renegotiation of a session that is already
	// authenticated.
	authRekey
)

// authCredentials returns the username and password for one key-method-2
// exchange and registers them for redaction on the way out, so that a caller
// cannot send a credential the report has not been told to scrub.
func (c *Client) authCredentials(ctx context.Context, ex authExchange) (Credentials, error) {
	creds, err := c.method().credentials(ctx, ex)
	if err != nil {
		return Credentials{}, err
	}
	c.registerCredentials(creds)
	return creds, nil
}

// userPassCredentials returns the profile's username and password, calling
// CredentialsFn at most once and caching what it returns. The cache survives the
// internal reset a Reconnect performs, so a dropped link does not put a second
// prompt in front of the user; clearCredentialsLocked drops it for good.
//
// mu is released before the callback runs and retaken afterwards: the callback
// may sit on a user interface indefinitely, and holding the client's lock across
// it would stop a Disconnect from another goroutine ever completing.
func (c *Client) userPassCredentials(ctx context.Context) (Credentials, error) {
	c.mu.Lock()
	if c.credsCached {
		creds := c.creds
		c.mu.Unlock()
		return creds, nil
	}
	fn := c.CredentialsFn
	c.mu.Unlock()

	if fn == nil {
		// beginAttempt refuses this profile at StageParse before a socket is
		// opened, so reaching here means an entry point skipped that boundary.
		// Fail rather than send the empty pair.
		return Credentials{}, errors.New("vpn: profile needs a username and password but CredentialsFn is nil")
	}
	creds, err := fn(ctx)
	if err != nil {
		// The callback's own value is dropped along with the error: a callback
		// that returns both has not agreed to have the value used, and the
		// message must not carry it either.
		return Credentials{}, fmt.Errorf("vpn: CredentialsFn: %w", err)
	}

	c.mu.Lock()
	c.creds = creds
	c.credsCached = true
	c.mu.Unlock()
	return creds, nil
}

// pushedAuthToken returns the session token the server pushed, or "" when it
// pushed none.
func (c *Client) pushedAuthToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pushOpts == nil {
		return ""
	}
	return c.pushOpts.AuthToken
}

// registerCredentials registers a credential pair with the session report's
// redaction before it is used, so a value reaching a report field or an error
// string is scrubbed whether or not anyone thought about it. The AWS placeholder
// user name is not registered: diag scrubs by substring with no minimum length,
// so three characters would blank every incidental "N/A" in the free text.
func (c *Client) registerCredentials(creds Credentials) {
	username := reportableUsername(creds.Username)
	c.recorder().edit(func(r *diag.SessionReport) { r.AddSecret(username, creds.Password) })
}
