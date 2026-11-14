// SPDX-License-Identifier: LGPL-2.1-or-later

package occ_test

import (
	"bytes"
	"testing"

	"github.com/buengese/go-openvpn/internal/occ"
)

// Everything here is a transcribed constant, so a typo produces a plaintext the
// peer writes to its tun device rather than acting on. The tests sit outside the
// package: asserting against the unexported occMagic proves nothing.

// TestOCCExitMessageBytes pins the exit notification's plaintext: OpenVPN
// 2.4.12 src/openvpn/occ.c occ_magic[] (line 61) then src/openvpn/occ.h
// OCC_EXIT (line 69), the order check_send_occ_msg_dowork() writes them in —
// buf_write(occ_magic) at line 227, buf_write_u8(OCC_EXIT) at line 333.
func TestOCCExitMessageBytes(t *testing.T) {
	want := []byte{
		0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
		0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
		0x06,
	}
	got := occ.ExitMessage()
	if !bytes.Equal(got, want) {
		t.Fatalf("occ.ExitMessage() = %x, want %x", got, want)
	}
	if len(got) != 17 {
		t.Fatalf("occ.ExitMessage() is %d bytes, want 17 (OCC_STRING_SIZE + one opcode)", len(got))
	}
}

// TestOCCExitMessageDoesNotAlias checks that two calls hand out independent
// slices: Manager.Encrypt frames its input in place when a compression mode is
// active, so a shared buffer would corrupt a retried notification.
func TestOCCExitMessageDoesNotAlias(t *testing.T) {
	a, b := occ.ExitMessage(), occ.ExitMessage()
	a[0] ^= 0xff
	if bytes.Equal(a, b) {
		t.Fatal("occ.ExitMessage() returns an aliased buffer: mutating one call's result changed another's")
	}
}

// TestKeepaliveMagicBytes pins the keepalive plaintext: the 16 bytes
// openvpn3-core carries as proto_context_private::keepalive_message
// (ssl/proto.hpp line 120), which are the same 16 bytes OpenVPN 2.x sends as
// src/openvpn/ping.c's ping_string[]. is_keepalive() (proto.hpp line 130)
// memcmps all 16, so one byte of drift makes a peer write the packet to its tun
// device instead of resetting its dead-link timer.
func TestKeepaliveMagicBytes(t *testing.T) {
	want := []byte{
		0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
		0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
	}
	if !bytes.Equal(occ.KeepaliveMagic, want) {
		t.Fatalf("occ.KeepaliveMagic = %x, want %x", occ.KeepaliveMagic, want)
	}
	if len(occ.KeepaliveMagic) != 16 {
		t.Fatalf("occ.KeepaliveMagic is %d bytes, want 16", len(occ.KeepaliveMagic))
	}
}

// TestIsKeepalive checks both answers. Length alone must not decide it: an
// ordinary 16-byte payload is not a keepalive, and a short prefix of the magic
// is not one either.
func TestIsKeepalive(t *testing.T) {
	if !occ.IsKeepalive(occ.KeepaliveMagic) {
		t.Error("occ.IsKeepalive(occ.KeepaliveMagic) = false, want true")
	}
	notMagic := append([]byte(nil), occ.KeepaliveMagic...)
	notMagic[len(notMagic)-1] ^= 0xff
	if occ.IsKeepalive(notMagic) {
		t.Errorf("occ.IsKeepalive(%x) = true on a payload that differs in its last byte, want false", notMagic)
	}
	if occ.IsKeepalive(occ.KeepaliveMagic[:len(occ.KeepaliveMagic)-1]) {
		t.Error("occ.IsKeepalive() = true on a 15-byte prefix of the magic, want false")
	}
}
