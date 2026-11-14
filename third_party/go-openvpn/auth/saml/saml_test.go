package saml_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/auth/saml"
)

// --- ParseCRV1 tests ---

// TestParseCRV1 covers the two shapes of CRV1 challenge a server sends: the
// optional remote-IP field sits inside the flags group, before the state ID, so
// a parser that splits on ":" alone reads the address as the state.
func TestParseCRV1(t *testing.T) {
	tests := []struct {
		name         string
		msg          string
		wantState    string
		wantURL      string
		wantRemoteIP string
	}{
		{
			name:      "without remote ip",
			msg:       "AUTH_FAILED,CRV1:R:myStateID::https://idp.example.com/saml",
			wantState: "myStateID",
			wantURL:   "https://idp.example.com/saml",
		},
		{
			name:         "with remote ip",
			msg:          "AUTH_FAILED,CRV1:R,52.1.2.3:stateABC::https://login.microsoftonline.com/sso",
			wantState:    "stateABC",
			wantURL:      "https://login.microsoftonline.com/sso",
			wantRemoteIP: "52.1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := saml.ParseCRV1(tt.msg)
			if err != nil {
				t.Fatal(err)
			}
			if c.StateID != tt.wantState {
				t.Errorf("StateID = %q, want %q", c.StateID, tt.wantState)
			}
			if c.SAMLURL != tt.wantURL {
				t.Errorf("SAMLURL = %q, want %q", c.SAMLURL, tt.wantURL)
			}
			if c.RemoteIP != tt.wantRemoteIP {
				t.Errorf("RemoteIP = %q, want %q", c.RemoteIP, tt.wantRemoteIP)
			}
		})
	}
}

func TestParseCRV1Errors(t *testing.T) {
	bad := []string{
		"AUTH_FAILED",
		"AUTH_FAILED,CRV1:R",         // no separator
		"AUTH_FAILED,CRV1:R:noSep",   // no :: separator
		"AUTH_FAILED,CRV1:R:::url",   // empty state_id
		"AUTH_FAILED,CRV1:R:state::", // empty saml_url
	}
	for _, m := range bad {
		_, err := saml.ParseCRV1(m)
		if err == nil {
			t.Errorf("expected error for %q", m)
		}
	}
}

func TestParseCRV1ErrorDoesNotDiscloseInput(t *testing.T) {
	const canary = "CANARY_SAML_URL_SECRET"
	_, err := saml.ParseCRV1("AUTH_FAILED,CRV1:R:" + canary)
	if err == nil {
		t.Fatal("expected malformed challenge error")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("parse error disclosed challenge input: %v", err)
	}
}

func TestBuildPhase2Password(t *testing.T) {
	got := saml.BuildPhase2Password("myState", "base64token==")
	want := "CRV1::myState::base64token=="
	if got != want {
		t.Errorf("BuildPhase2Password = %q, want %q", got, want)
	}
}

// --- ACSServer tests ---

// TestACSHandlerSAMLResponse drives the whole ACS server the way a browser
// does: bind 127.0.0.1:35001, post a SAMLResponse form, and check that Wait
// hands back the token unchanged. The reply is read to the end because the
// handler publishes the token before its success page has left the connection.
func TestACSHandlerSAMLResponse(t *testing.T) {
	srv, err := saml.NewACSServer()
	if err != nil {
		t.Skipf("cannot bind port %d (may be in use): %v", saml.ACSPort, err)
	}
	defer srv.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	xmlResponse := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="test"></samlp:Response>`
	token := base64.StdEncoding.EncodeToString([]byte(xmlResponse))

	// Send the POST from a goroutine and report back what the browser saw.
	type browserResult struct {
		status int
		body   string
		err    error
	}
	browser := make(chan browserResult, 1)
	go func() {
		data := url.Values{"SAMLResponse": {token}}
		resp, err := http.PostForm(fmt.Sprintf("http://127.0.0.1:%d/", saml.ACSPort), data)
		if err != nil {
			browser <- browserResult{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		browser <- browserResult{status: resp.StatusCode, body: string(body), err: err}
	}()

	got, err := srv.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if got != token {
		t.Errorf("token = %q, want %q", got, token)
	}

	select {
	case res := <-browser:
		if res.err != nil {
			t.Fatalf("browser did not get a complete response: %v", res.err)
		}
		if res.status != http.StatusOK {
			t.Errorf("status = %d, want %d", res.status, http.StatusOK)
		}
		if !strings.Contains(res.body, "Authentication successful") {
			t.Errorf("browser body = %q, want the success page", res.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("browser never finished reading the response")
	}
}

// TestACSServerCloseBeforeWait covers the caller that binds the port and then
// abandons the attempt without ever reaching Wait: nothing but Close releases
// the listener, and 127.0.0.1:35001 stays bound for the life of the process.
func TestACSServerCloseBeforeWait(t *testing.T) {
	srv, err := saml.NewACSServer()
	if err != nil {
		t.Skipf("cannot bind port %d (may be in use): %v", saml.ACSPort, err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Idempotent: a caller that Closes and then defers another Close is fine.
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	second, err := saml.NewACSServer()
	if err != nil {
		t.Fatalf("port %d still bound after Close: %v", saml.ACSPort, err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second server Close: %v", err)
	}
}

func TestACSServerContextCancel(t *testing.T) {
	srv, err := saml.NewACSServer()
	if err != nil {
		t.Skipf("cannot bind port %d: %v", saml.ACSPort, err)
	}
	defer srv.Close() //nolint:errcheck
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err = srv.Wait(ctx)
	if err == nil {
		t.Fatal("expected error on immediate cancel")
	}
}

// TestACSServerReleasesThePortOnCancel pins that when Wait returns because its
// context ended, 127.0.0.1:35001 is free for the next NewACSServer; AWS
// hardcodes the ACS URL. Each round rebinds with nothing in between and the
// rounds repeat, because the window before the listener closes is short.
func TestACSServerReleasesThePortOnCancel(t *testing.T) {
	const rounds = 50

	for i := range rounds {
		srv, err := saml.NewACSServer()
		if err != nil {
			if i == 0 {
				t.Skipf("cannot bind port %d (may be in use): %v", saml.ACSPort, err)
			}
			t.Fatalf("round %d: port %d still bound after the previous Wait returned: %v",
				i, saml.ACSPort, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			srv.Wait(ctx) //nolint:errcheck // the cancel below is the point
		}()

		// Let Wait reach its serve loop before taking the context away, so the
		// listener is genuinely in the server's hands when it has to give it up.
		time.Sleep(2 * time.Millisecond)
		cancel()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("round %d: Wait did not return after its context was cancelled", i)
		}
	}
}

// TestIsAWSEndpoint pins the fallback that catches an AWS profile which has
// lost its auth-federate line. It is deliberately narrow: anything it says yes
// to is authenticated with an assertion and nothing else.
func TestIsAWSEndpoint(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"cvpn-endpoint-0123456789abcdef.prod.clientvpn.eu-central-1.amazonaws.com", true},
		// The random label AWS requires is added when the address is
		// dialled; a profile never writes one, so this is not an AWS remote
		// as a profile can state it.
		{"a1b2c3d4.cvpn-endpoint-0123.prod.clientvpn.us-east-1.amazonaws.com", false},
		// AWS China's domain, and a deliberate no: the fallback exists for a
		// profile that lost its auth-federate line, and a profile that says
		// auth-federate is federated wherever it is.
		{"cvpn-endpoint-0123.prod.clientvpn.us-east-1.amazonaws.com.cn", false},
		// Hostnames are case-insensitive in DNS; this match is not. Same
		// reason: it is a fallback, and auth-federate is the answer.
		{"CVPN-ENDPOINT-0123.PROD.CLIENTVPN.US-EAST-1.AMAZONAWS.COM", false},
		{"vpn.example.com", false},
		{"cvpn-endpoint-0123.example.com", false},
		{"ec2-1-2-3-4.compute-1.amazonaws.com", false},
		{"", false},
	} {
		if got := saml.IsAWSEndpoint(tc.host); got != tc.want {
			t.Errorf("IsAWSEndpoint(%q) = %t, want %t", tc.host, got, tc.want)
		}
	}
}
