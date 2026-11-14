// SPDX-License-Identifier: LGPL-2.1-or-later

package control_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/internal/control"
)

// FuzzReadServerReply feeds random byte slices to ReadServerReply to verify it
// never panics regardless of the reader content.
func FuzzReadServerReply(f *testing.F) {
	// Seed: PUSH_REPLY.
	f.Add([]byte("PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5,route 10.0.0.0\x00"))
	// Seed: AUTH_FAILED,CRV1.
	f.Add([]byte("AUTH_FAILED,CRV1:R:stateid:user:https://idp.example.com/sso\x00"))
	// Seed: plain AUTH_FAILED.
	f.Add([]byte("AUTH_FAILED,Invalid username or password\x00"))
	// Seed: temporary rejection with flags.
	f.Add([]byte("AUTH_FAILED,TEMP[backoff 30,advance no]:busy\x00"))
	// Seed: empty.
	f.Add([]byte{})
	// Seed: no null terminator.
	f.Add([]byte("PUSH_REPLY,ifconfig 10.0.0.1 10.0.0.2"))
	// Seed: random garbage.
	f.Add([]byte{0xff, 0xfe, 0x00, 0x01, 0x80})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = control.ReadServerReply(bytes.NewReader(data))
	})
}

// FuzzParseControlMsg feeds random strings to ParseControlMsg.
func FuzzParseControlMsg(f *testing.F) {
	f.Add("PUSH_REPLY,ifconfig 10.0.0.6 10.0.0.5")
	f.Add("AUTH_FAILED,CRV1:R:state:user:https://example.com")
	f.Add("AUTH_FAILED")
	f.Add("")
	f.Add(strings.Repeat("A", 1024))
	f.Add("PUSH_REPLY," + strings.Repeat("x,", 500))

	f.Fuzz(func(t *testing.T, msg string) {
		_ = control.ParseControlMsg(msg)
	})
}
