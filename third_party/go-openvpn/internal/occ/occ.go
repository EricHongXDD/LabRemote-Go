// SPDX-License-Identifier: LGPL-2.1-or-later

// Package occ holds the in-band control plaintexts of the OpenVPN data
// channel: the keepalive magic and the OCC (OpenVPN Configuration Control)
// messages.
//
// These are not wire framing and not ciphering but magic byte strings carried
// inside an ordinary data packet's plaintext, which is why they live neither in
// internal/framing (which owns the first byte of a wire packet) nor in
// internal/datachannel (which owns encryption). A peer recognises one by its
// prefix and acts on it instead of writing it to its tun device.
package occ

// KeepaliveMagic is the plaintext payload of an OpenVPN keepalive data packet.
//
// Reference: openvpn3-core ssl/proto.hpp:120,
// proto_context_private::keepalive_message (16 bytes):
//
//	{0x2a,0x18,0x7b,0xf3,0x64,0x1e,0xb4,0xcb,
//	 0x07,0xed,0x2d,0x0a,0x98,0x1f,0xc7,0x48}
//
// Sent as a data frame by send_keepalive() at :2541, recognised on receipt by
// is_keepalive() at :130, which memcmps all 16.
var KeepaliveMagic = []byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// IsKeepalive reports whether plaintext is an OpenVPN keepalive magic payload.
func IsKeepalive(plain []byte) bool {
	return len(plain) == len(KeepaliveMagic) && string(plain) == string(KeepaliveMagic)
}

// occMagic prefixes every OCC (OpenVPN Configuration Control) message: an
// ordinary data-channel packet whose plaintext opens with these 16 bytes and
// continues with a one-byte OCC opcode. A peer recognises one by that prefix
// and drops it rather than passing it to the tunnel.
//
// Source: OpenVPN 2.4.12 src/openvpn/occ.c occ_magic[] line 61 (16 octets):
//
//	{0x28,0x7f,0x34,0x6b,0xd4,0xef,0x7a,0x81,
//	 0x2d,0x56,0xb8,0xd3,0xaf,0xc5,0x45,0x9c}
//
// Recognised on receipt by is_occ_msg() (occ.h line 86), which compares
// OCC_STRING_SIZE = 16 bytes against the head of the decrypted buffer. The
// same bytes with OCC_EXIT appended are openvpn3-core ssl/proto.hpp:137-142,
// proto_context_private::explicit_exit_notify_message.
var occMagic = []byte{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
}

// occExit is the OCC opcode that says this end is leaving — the one byte
// explicit-exit-notify puts on the wire after occMagic.
//
// Source: OpenVPN 2.4.12 src/openvpn/occ.h line 69 (#define OCC_EXIT 6),
// unchanged in 2.6.22. Neither series guards the receive side with an option —
// process_received_occ_msg is reached from process_incoming_link for any packet
// matching the magic (forward.c line 993 in 2.4.12, line 1204 in 2.6.22) — so a
// server acts on this whether or not its own config names
// explicit-exit-notify.
//
// The two series log it differently, which any acceptance check has to match:
// 2.4.12 raises SIGTERM with signal_text "remote-exit" (occ.c line 421), logged
// as "…[soft,remote-exit] received, client-instance exiting"; 2.6.22 logs "OCC
// exit message received by peer" (occ.c line 430) and raises SIGUSR1, logged as
// "…client-instance restarting". Either way the instance closes on the spot
// rather than waiting out the server's keepalive timeout.
const occExit byte = 0x06

// ExitMessage returns the 17 plaintext bytes of an OCC_EXIT message. A fresh
// slice each call: the caller hands it to datachannel.Manager.Encrypt, and
// nothing leaving this function may alias a package-level buffer.
func ExitMessage() []byte {
	msg := make([]byte, 0, len(occMagic)+1)
	msg = append(msg, occMagic...)
	return append(msg, occExit)
}
