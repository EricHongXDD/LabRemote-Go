// SPDX-License-Identifier: LGPL-2.1-or-later

package control_test

import (
	"io"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/internal/control"
)

func TestClassifyMsg(t *testing.T) {
	cases := []struct {
		msg  string
		want control.MsgKind
	}{
		{"PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2\x00", control.MsgKindPushReply},
		{"PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2", control.MsgKindPushReply},
		{"AUTH_FAILED,CRV1:R:state::https://idp.example.com\x00", control.MsgKindAuthFailedCRV1},
		{"AUTH_FAILED\x00", control.MsgKindAuthFailed},
		{"AUTH_FAILED", control.MsgKindAuthFailed},
		{"", control.MsgKindUnknown},
		{"HELLO", control.MsgKindUnknown},
	}
	for _, tc := range cases {
		got := control.ClassifyMsg(tc.msg)
		if got != tc.want {
			t.Errorf("ClassifyMsg(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// TestParseControlMsgCRV1 pins that a CRV1 challenge is classified and its
// body handed on intact, NUL stripped, for the authentication method to
// parse. The classifier does not read the body itself.
func TestParseControlMsgCRV1(t *testing.T) {
	raw := "AUTH_FAILED,CRV1:R,52.1.2.3:myState::https://idp.example.com/sso"
	cm := control.ParseControlMsg(raw + "\x00")
	if cm.Kind != control.MsgKindAuthFailedCRV1 {
		t.Fatalf("Kind = %v, want MsgKindAuthFailedCRV1", cm.Kind)
	}
	if cm.Raw != raw {
		t.Errorf("Raw = %q, want the challenge line without its NUL", cm.Raw)
	}
}

func TestParseControlMsgPushReply(t *testing.T) {
	raw := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5\x00"
	cm := control.ParseControlMsg(raw)
	if cm.Kind != control.MsgKindPushReply {
		t.Fatalf("Kind = %v, want MsgKindPushReply", cm.Kind)
	}
	if strings.HasSuffix(cm.Raw, "\x00") {
		t.Error("Raw kept the NUL terminator")
	}
}

func TestReadControlMsg(t *testing.T) {
	payload := "PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5\x00"
	r := strings.NewReader(payload)
	cm, err := control.ReadControlMsg(r, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cm.Kind != control.MsgKindPushReply {
		t.Errorf("Kind = %v", cm.Kind)
	}
}

// chunkReader hands out a fixed sequence of byte slices, one Read per chunk,
// the way a *tls.Conn hands out one record per read.
type chunkReader struct{ chunks [][]byte }

func (c *chunkReader) Read(b []byte) (int, error) {
	for len(c.chunks) > 0 && len(c.chunks[0]) == 0 {
		c.chunks = c.chunks[1:]
	}
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	return n, nil
}

// TestReadControlMsgDoesNotFoldTwoMessages pins the message boundary: a server
// is free to put a PUSH_REPLY and the AUTH_FAILED that follows it into one
// write, and OpenVPN separates the two with the NUL that terminates every
// control message, not with the record boundary underneath.
func TestReadControlMsgDoesNotFoldTwoMessages(t *testing.T) {
	r := &chunkReader{chunks: [][]byte{
		[]byte("PUSH_REPLY,route 10.0.0.0 255.0.0.0\x00AUTH_FAILED\x00"),
	}}

	first, err := control.ReadControlMsg(r, 0)
	if err != nil {
		t.Fatalf("first message: %v", err)
	}
	if first.Kind != control.MsgKindPushReply {
		t.Errorf("first Kind = %v, want PUSH_REPLY", first.Kind)
	}
	if want := "PUSH_REPLY,route 10.0.0.0 255.0.0.0"; first.Raw != want {
		t.Errorf("first Raw = %q, want %q", first.Raw, want)
	}

	second, err := control.ReadControlMsg(r, 0)
	if err != nil {
		t.Fatalf("second message: %v", err)
	}
	if second.Kind != control.MsgKindAuthFailed {
		t.Errorf("second Kind = %v, want AUTH_FAILED", second.Kind)
	}
	if second.Raw != "AUTH_FAILED" {
		t.Errorf("second Raw = %q, want %q", second.Raw, "AUTH_FAILED")
	}
}

// TestReadControlMsgReassemblesASplitMessage pins the other half of the same
// contract: a message that arrives over two reads is one message, not two.
func TestReadControlMsgReassemblesASplitMessage(t *testing.T) {
	r := &chunkReader{chunks: [][]byte{[]byte("AUTH_FAI"), []byte("LED\x00")}}

	cm, err := control.ReadControlMsg(r, 0)
	if err != nil {
		t.Fatalf("ReadControlMsg: %v", err)
	}
	if cm.Kind != control.MsgKindAuthFailed {
		t.Errorf("Kind = %v, want AUTH_FAILED", cm.Kind)
	}
	if cm.Raw != "AUTH_FAILED" {
		t.Errorf("Raw = %q, want %q", cm.Raw, "AUTH_FAILED")
	}
}

// TestReadControlMsgRejectsAnUnterminatedFlood pins that maxBytes bounds the
// message rather than the scratch buffer: a peer that never sends a NUL gets
// an error, not a silently truncated and so misclassified message.
func TestReadControlMsgRejectsAnUnterminatedFlood(t *testing.T) {
	r := strings.NewReader(strings.Repeat("A", 4096) + "\x00")

	if _, err := control.ReadControlMsg(r, 64); err == nil {
		t.Fatal("a message longer than maxBytes was accepted")
	}
}

// TestReadControlMsgKeepsTheTailOfATruncatedStream pins the lenient end: a
// stream that ends without the terminator still yields what it carried, so a
// server that says AUTH_FAILED and closes has still told us why.
func TestReadControlMsgKeepsTheTailOfATruncatedStream(t *testing.T) {
	cm, err := control.ReadControlMsg(strings.NewReader("AUTH_FAILED"), 0)
	if err != nil {
		t.Fatalf("ReadControlMsg: %v", err)
	}
	if cm.Kind != control.MsgKindAuthFailed {
		t.Errorf("Kind = %v, want AUTH_FAILED", cm.Kind)
	}
}
