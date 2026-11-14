package saml

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/diag"
)

// These tests drive the unexported newACSServer rather than NewACSServer, so
// that the port is theirs to control.

// freeLoopbackPort returns a loopback port nothing is listening on, by binding
// one and giving it straight back.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return port
}

// postForm posts one urlencoded form to the ACS server and reads the reply to
// the end, the way a browser does. Reading it matters: a response left unread
// keeps the connection non-idle, and Wait's graceful shutdown waits for it.
func postForm(t *testing.T, port int, form url.Values) (int, string) {
	t.Helper()
	status, body, err := tryPostForm(port, form)
	if err != nil {
		t.Fatalf("POST to the ACS server: %v", err)
	}
	return status, body
}

// tryPostForm is postForm for a caller that has something to say about the
// failure itself — a refused connection means the listener is already gone,
// which is a different finding from a POST that was answered badly.
func tryPostForm(port int, form url.Values) (int, string, error) {
	// Keep-alives off so the connection is gone the moment the body is read,
	// which is what lets Wait's Shutdown return at once instead of sitting out
	// its grace period.
	client := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: true},
		Timeout:   5 * time.Second,
	}
	resp, err := client.PostForm("http://127.0.0.1:"+strconv.Itoa(port)+"/", form)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

// TestACSBindReportsAPortHeldByAnotherProcess pins that a lost bind reaches the
// caller as itself. AWS fixes the callback address and loopback ports are not
// partitioned by UID, so a caller that cannot tell contention from any other
// listen failure answers an interception with a paste prompt.
func TestACSBindReportsAPortHeldByAnotherProcess(t *testing.T) {
	squatter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("take the port first: %v", err)
	}
	defer squatter.Close() //nolint:errcheck
	port := squatter.Addr().(*net.TCPAddr).Port

	srv, err := newACSServer(port)
	if err == nil {
		srv.Close() //nolint:errcheck
		t.Fatal("bound a port another listener already held")
	}
	if srv != nil {
		t.Error("a failed bind returned a server the caller would have to close")
	}
	if !errors.Is(err, ErrACSPortBusy) {
		t.Errorf("error does not name the condition: %v", err)
	}
	// The syscall stays reachable underneath, so the chain still says which
	// bind failed and on what address.
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Errorf("error lost its cause: %v", err)
	}
	derr := diag.AsError(err)
	if derr == nil {
		t.Fatalf("not a *diag.Error, so no report records a class for it: %v", err)
	}
	if derr.Class != diag.ClassLocal || derr.Stage != diag.StageAuth {
		t.Errorf("class/stage = %v/%v, want %v/%v",
			derr.Class, derr.Stage, diag.ClassLocal, diag.StageAuth)
	}
}

// TestACSBindClassifiesAFailureThatIsNotContention pins that a bind failing for
// any other reason must not claim the port was taken. Port 1 needs privilege
// this test does not have, and nothing is listening there.
func TestACSBindClassifiesAFailureThatIsNotContention(t *testing.T) {
	if syscall.Geteuid() == 0 {
		t.Skip("running as root, which can bind a privileged port")
	}
	srv, err := newACSServer(1)
	if err == nil {
		srv.Close() //nolint:errcheck
		t.Skip("this environment allows binding port 1")
	}
	if errors.Is(err, ErrACSPortBusy) {
		t.Errorf("a permission failure was reported as contention: %v", err)
	}
	derr := diag.AsError(err)
	if derr == nil {
		t.Fatalf("not a *diag.Error: %v", err)
	}
	if derr.Class != diag.ClassLocal || derr.Stage != diag.StageAuth {
		t.Errorf("class/stage = %v/%v, want %v/%v",
			derr.Class, derr.Stage, diag.ClassLocal, diag.StageAuth)
	}
}

// TestACSWaitReleasesThePortAfterATokenArrives pins that the success path gives
// the listener up through Wait's graceful shutdown rather than its deferred
// Close. The rebind is the assertion and it has to be immediate: there is no
// other port to move to.
func TestACSWaitReleasesThePortAfterATokenArrives(t *testing.T) {
	port := freeLoopbackPort(t)
	srv, err := newACSServer(port)
	if err != nil {
		t.Fatalf("bind the ACS server: %v", err)
	}
	defer srv.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	token := encodedValidResponse()
	type waitResult struct {
		token string
		err   error
	}
	waited := make(chan waitResult, 1)
	go func() {
		tok, err := srv.Wait(ctx)
		waited <- waitResult{token: tok, err: err}
	}()

	// The listener is bound before Wait is called, so the kernel accepts this
	// connection whether or not Serve has started yet.
	status, body := postForm(t, port, url.Values{"SAMLResponse": {token}})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	if !strings.Contains(body, "Authentication successful") {
		t.Errorf("browser body = %q, want the success page", body)
	}

	select {
	case res := <-waited:
		if res.err != nil {
			t.Fatalf("Wait: %v", res.err)
		}
		if res.token != token {
			t.Errorf("token = %q, want %q", res.token, token)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the assertion arrived")
	}

	second, err := newACSServer(port)
	if err != nil {
		t.Fatalf("port %d still bound after a successful Wait: %v", port, err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second server Close: %v", err)
	}
}

// TestACSWaitSurvivesAPOSTThatIsNotAnAssertion pins that a POST rejected on
// shape does not consume the one callback. The handler authenticates nothing
// about who posted, so any local process can post to the listener while a flow
// is waiting.
func TestACSWaitSurvivesAPOSTThatIsNotAnAssertion(t *testing.T) {
	port := freeLoopbackPort(t)
	srv, err := newACSServer(port)
	if err != nil {
		t.Fatalf("bind the ACS server: %v", err)
	}
	defer srv.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	waited := make(chan string, 1)
	failed := make(chan error, 1)
	go func() {
		tok, err := srv.Wait(ctx)
		if err != nil {
			failed <- err
			return
		}
		waited <- tok
	}()

	if status, _ := postForm(t, port, url.Values{"SAMLResponse": {"not-base64!"}}); status != http.StatusBadRequest {
		t.Fatalf("status for a malformed assertion = %d, want %d", status, http.StatusBadRequest)
	}
	select {
	case tok := <-waited:
		t.Fatalf("a malformed POST ended the wait with %q", tok)
	case err := <-failed:
		t.Fatalf("a malformed POST ended the wait: %v", err)
	default:
	}

	// The real assertion has to still have somewhere to land. A listener that
	// is already gone is the same defect seen from the other side, so say so
	// rather than reporting a bare refused connection.
	token := encodedValidResponse()
	status, _, err := tryPostForm(port, url.Values{"SAMLResponse": {token}})
	if err != nil {
		t.Fatalf("the malformed POST took the listener with it: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status for the real assertion = %d, want %d", status, http.StatusOK)
	}
	select {
	case tok := <-waited:
		if tok != token {
			t.Errorf("token = %q, want %q", tok, token)
		}
	case err := <-failed:
		t.Fatalf("Wait: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the assertion arrived")
	}
}
