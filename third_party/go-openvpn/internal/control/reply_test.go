// SPDX-License-Identifier: LGPL-2.1-or-later

package control_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/internal/control"
)

func TestReadServerReplyPushReply(t *testing.T) {
	r := strings.NewReader("PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5\x00")
	cm, err := control.ReadServerReply(r)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != control.MsgKindPushReply {
		t.Errorf("Kind = %v", cm.Kind)
	}
}

// A CRV1 challenge is not a rejection: it comes back with no error and its
// body intact, for the authentication method that asked for it to read.
func TestReadServerReplyCRV1(t *testing.T) {
	msg := "AUTH_FAILED,CRV1:R,52.1.2.3:stateXYZ::https://idp.example.com/sso"
	cm, err := control.ReadServerReply(strings.NewReader(msg + "\x00"))
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != control.MsgKindAuthFailedCRV1 {
		t.Errorf("Kind = %v", cm.Kind)
	}
	if cm.Raw != msg {
		t.Errorf("Raw = %q, want the challenge line", cm.Raw)
	}
}

// A plain AUTH_FAILED is an error that names neither what the server said
// nor an authentication method: the message is stock OpenVPN, and a
// certificate-only profile reads this error too.
func TestReadServerReplyAuthFailed(t *testing.T) {
	const canary = "CANARY_AUTH_MATERIAL_MUST_NOT_BE_LOGGED"
	r := strings.NewReader("AUTH_FAILED," + canary + "\x00")
	cm, err := control.ReadServerReply(r)
	if err == nil {
		t.Fatal("expected error for AUTH_FAILED")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("error disclosed server authentication material: %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "saml") {
		t.Errorf("a stock AUTH_FAILED was reported in SAML terms: %v", err)
	}
	if cm == nil || cm.Kind != control.MsgKindAuthFailed {
		t.Errorf("message = %+v, want it returned with its Kind so the caller can classify", cm)
	}
}

// A temporary rejection wraps ErrAuthTemp and carries the server's backoff,
// so that a caller can tell "come back later" from a credential rejection.
func TestReadServerReplyAuthFailedTemp(t *testing.T) {
	r := strings.NewReader("AUTH_FAILED,TEMP[backoff 30,advance no]:busy\x00")
	cm, err := control.ReadServerReply(r)
	if !errors.Is(err, control.ErrAuthTemp) {
		t.Fatalf("err = %v, want ErrAuthTemp", err)
	}
	if cm == nil || cm.Kind != control.MsgKindAuthFailedTemp {
		t.Errorf("message = %+v, want it returned with Kind AUTH_FAILED_TEMP", cm)
	}
	if !strings.Contains(err.Error(), "backoff 30s") || !strings.Contains(err.Error(), "advance no") {
		t.Errorf("error does not carry the server's flags: %v", err)
	}
}
