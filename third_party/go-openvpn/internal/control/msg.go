// SPDX-License-Identifier: LGPL-2.1-or-later

// Package control reads and classifies the plaintext messages the server
// sends down the OpenVPN control channel once TLS is up: PUSH_REPLY,
// AUTH_FAILED in its plain, temporary and challenge forms, and the RESTART
// and HALT pushes that end a session.
//
// Every one of these is stock OpenVPN, present in every connection whatever
// its authentication. What a challenge body means is the authentication
// method's business — auth/saml reads a CRV1 body as a state id and an IdP
// URL — so that stays with the method, which imports this package rather than
// the other way round.
//
// Reference: openvpn-2.6.22 src/openvpn/push.c (receive_auth_failed,
// server_pushed_signal, process_incoming_push_reply).
package control

import (
	"fmt"
	"io"
	"strings"
)

// MsgKind classifies a control-channel plaintext message received from the VPN
// server after TLS negotiation.
type MsgKind int

const (
	// MsgKindUnknown is returned for messages that do not match any known pattern.
	MsgKindUnknown MsgKind = iota
	// MsgKindPushReply is a successful "PUSH_REPLY,..." tunnel configuration message.
	MsgKindPushReply
	// MsgKindAuthFailedCRV1 is an "AUTH_FAILED,CRV1:..." dynamic challenge:
	// the server wants a second exchange, with a response built from the
	// challenge body. The shape is OpenVPN's own (doc/management-notes.txt,
	// "CRV1"); what the body means belongs to the authentication method.
	MsgKindAuthFailedCRV1
	// MsgKindAuthFailed is a plain "AUTH_FAILED" rejection with no challenge.
	MsgKindAuthFailed
	// MsgKindAuthFailedTemp is an "AUTH_FAILED,TEMP..." temporary rejection.
	// The server declined this attempt and asked us to come back; it is not a
	// statement about the credentials. Reference: openvpn-2.6.22
	// src/openvpn/push.c:72-76, which raises SIGUSR1 for this and SIGTERM for
	// a plain AUTH_FAILED.
	MsgKindAuthFailedTemp
	// MsgKindRestart is a "RESTART[,...]" push: the server is ending this
	// session and expects us back.
	MsgKindRestart
	// MsgKindHalt is a "HALT[,...]" push: the server is ending this session
	// and does not.
	MsgKindHalt
)

// String returns a non-sensitive description of the control-message kind.
func (k MsgKind) String() string {
	switch k {
	case MsgKindPushReply:
		return "PUSH_REPLY"
	case MsgKindAuthFailedCRV1:
		return "AUTH_FAILED_CRV1"
	case MsgKindAuthFailed:
		return "AUTH_FAILED"
	case MsgKindAuthFailedTemp:
		return "AUTH_FAILED_TEMP"
	case MsgKindRestart:
		return "RESTART"
	case MsgKindHalt:
		return "HALT"
	default:
		return "UNKNOWN"
	}
}

// ClassifyMsg classifies the raw control-channel message msg.
// Trailing NUL bytes (OpenVPN's message terminator) are stripped before matching.
func ClassifyMsg(msg string) MsgKind {
	msg = strings.TrimRight(msg, "\x00")
	switch {
	case strings.HasPrefix(msg, "PUSH_REPLY"):
		return MsgKindPushReply
	case strings.HasPrefix(msg, "AUTH_FAILED,CRV1:"):
		return MsgKindAuthFailedCRV1
	case strings.HasPrefix(msg, "AUTH_FAILED,TEMP"):
		return MsgKindAuthFailedTemp
	case strings.HasPrefix(msg, "AUTH_FAILED"):
		return MsgKindAuthFailed
	case msg == "RESTART" || strings.HasPrefix(msg, "RESTART,"):
		return MsgKindRestart
	case msg == "HALT" || strings.HasPrefix(msg, "HALT,"):
		return MsgKindHalt
	default:
		return MsgKindUnknown
	}
}

// Message holds a classified control-channel message.
type Message struct {
	// Kind is the classified message type.
	Kind MsgKind
	// Raw is the original message text with the trailing NUL stripped. It can
	// contain authentication challenge material; never include it in logs or
	// generic errors.
	Raw string
}

// ParseControlMsg classifies a raw control-channel message. msg may include a
// trailing NUL byte.
//
// It returns no error because it has none to return: ClassifyMsg has a default
// arm, so every byte string is a Message and an unrecognised one is
// MsgKindUnknown rather than a failure.
//
// A CRV1 challenge is classified, not parsed: its body belongs to the
// authentication method that asked for it (auth/saml.ParseCRV1 for the SAML
// flow), which reads it from Raw.
func ParseControlMsg(msg string) *Message {
	stripped := strings.TrimRight(msg, "\x00")
	return &Message{Kind: ClassifyMsg(stripped), Raw: stripped}
}

// msgTerminator ends every control-channel message. OpenVPN writes it as part
// of the message — send_control_channel_string_dowork hands strlen(str)+1
// bytes to the TLS payload — so it is the only message boundary a reader has.
// The TLS record underneath is not one: nothing stops a server putting two
// messages in one record, and a reply larger than a record spans several.
//
// Reference: openvpn-2.6.22 src/openvpn/ssl.c (send_control_channel_string_dowork
// writes the NUL; key_state_read_plaintext appends whatever arrived to a buffer
// the receiver then scans, which is what makes the record boundary invisible).
const msgTerminator = 0x00

// defaultMaxMsgBytes bounds one control message when the caller names no
// bound. A PUSH_REPLY fragment is capped at PUSH_BUNDLE_SIZE, 1024 bytes
// (openvpn-2.6.22 src/openvpn/common.h), so this is 64 times that; it exists
// so a peer that never sends a terminator cannot make this grow without limit.
const defaultMaxMsgBytes = 65536

// maxEmptyReads bounds a reader that keeps returning (0, nil). io.Reader
// discourages that but does not forbid it, and without a bound it is an
// unkillable spin.
const maxEmptyReads = 100

// ReadControlMsg reads one NUL-terminated control message from r (typically a
// *tls.Conn) and returns the classified Message.
//
// It consumes the message and not one byte beyond its terminator, which is the
// whole point. Taking "whatever one Read returned" as one message is wrong in
// both directions: two messages written together fold into one, the second
// appended to Raw with its classification lost; a message split across two
// reads classifies from a prefix, "AUTH_FAI" as MsgKindUnknown. Leaving the
// bytes after the terminator in r is what lets callers reading several
// messages off one connection — joinPushContinuation, SessionMonitor — see
// each of them.
//
// The cost is one Read per byte, because a plain io.Reader offers no way to
// find a terminator without reading past it. On a *tls.Conn those are copies
// out of a record already in memory, and no data-channel traffic comes here.
//
// At most maxBytes bytes are read; pass 0 for the default (65536). Reaching
// that bound with no terminator is an error rather than a truncated Message,
// which would classify from a prefix. A stream that *ends* before the
// terminator is not an error — a server that says AUTH_FAILED and closes has
// told us why the session ended.
func ReadControlMsg(r io.Reader, maxBytes int) (*Message, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxMsgBytes
	}

	msg := make([]byte, 0, 256)
	var one [1]byte
	empties := 0
	for len(msg) < maxBytes {
		n, err := r.Read(one[:])
		switch {
		case n > 0:
			empties = 0
			if one[0] == msgTerminator {
				return ParseControlMsg(string(msg)), nil
			}
			msg = append(msg, one[0])
		case err != nil:
			if len(msg) > 0 {
				return ParseControlMsg(string(msg)), nil
			}
			return nil, fmt.Errorf("control: ReadControlMsg: %w", err)
		default:
			if empties++; empties >= maxEmptyReads {
				return nil, fmt.Errorf("control: ReadControlMsg: %w", io.ErrNoProgress)
			}
		}
	}
	return nil, fmt.Errorf("control: ReadControlMsg: no message terminator in %d bytes", maxBytes)
}

// SessionExpiredError is returned when the VPN server sends AUTH_FAILED
// mid-session (i.e. after PUSH_REPLY was already received), indicating that the
// session has expired and must be re-authenticated.
type SessionExpiredError struct {
	// Msg is the non-sensitive classification of the AUTH_FAILED message.
	Msg string
}

// Error implements the error interface.
func (e *SessionExpiredError) Error() string {
	return "control: session expired: authentication rejected"
}
