// SPDX-License-Identifier: LGPL-2.1-or-later

package control

import (
	"fmt"
	"io"
)

// ReadServerReply reads the server's answer to PUSH_REQUEST from r (typically
// the TLS session over the control channel) and classifies it.
//
// A PUSH_REPLY comes back with no error. So does a CRV1 challenge: it is not a
// rejection but a request for a second exchange, and its body is for the
// authentication method that understands it (auth/saml.ParseCRV1 for the SAML
// flow) to read out of Raw. A plain AUTH_FAILED is returned with an error, and
// so is an AUTH_FAILED,TEMP, whose error wraps ErrAuthTemp so that a caller
// can tell a server that said "come back later" from one that rejected the
// credentials. Anything else is returned unclassified for the caller to
// reject.
//
// The message is returned alongside the error in the rejection cases so that
// the caller can classify the failure by Kind.
func ReadServerReply(r io.Reader) (*Message, error) {
	cm, err := ReadControlMsg(r, 0)
	if err != nil {
		return nil, fmt.Errorf("control: read server reply: %w", err)
	}
	if cm.Kind == MsgKindAuthFailedTemp {
		t := cm.AuthTemp()
		return cm, fmt.Errorf("control: server rejected this attempt temporarily "+
			"(backoff %s, advance %s): %w", t.Backoff, t.Advance, ErrAuthTemp)
	}
	if cm.Kind == MsgKindAuthFailed {
		return cm, fmt.Errorf("control: server rejected authentication")
	}
	return cm, nil
}
