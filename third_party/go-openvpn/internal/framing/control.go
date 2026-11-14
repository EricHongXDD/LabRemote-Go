// SPDX-License-Identifier: LGPL-2.1-or-later
//
// control.go: the control-channel packet layer — session id, ack array and
// packet id on top of the opcode byte that opcodes.go owns.

package framing

import "encoding/binary"

// BuildHardReset builds a P_CONTROL_HARD_RESET_CLIENT_V2 packet.
func BuildHardReset(clientSID [8]byte) []byte {
	b := []byte{byte(P_CONTROL_HARD_RESET_CLIENT_V2 << 3)}
	b = append(b, clientSID[:]...)
	b = append(b, 0)          // ack_array_len = 0
	b = append(b, 0, 0, 0, 0) // packet_id = 0
	return b
}

// BuildControlV1 builds a P_CONTROL_V1 packet with an explicit key_id, for a
// renegotiated session where key_id > 0.
//
// Reference: openvpn3-core ssl/proto.hpp op_compose() at :326 — the first byte
// is (opcode << OPCODE_SHIFT) | key_id, with OPCODE_SHIFT 3.
func BuildControlV1(senderSID, remoteSID [8]byte, keyID uint8, packetID uint32, ackIDs []uint32, payload []byte) []byte {
	b := []byte{FirstByte(P_CONTROL_V1, keyID)}
	b = append(b, senderSID[:]...)
	if len(ackIDs) > 0 {
		b = append(b, byte(len(ackIDs)))
		for _, id := range ackIDs {
			b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
		}
		b = append(b, remoteSID[:]...)
	} else {
		b = append(b, 0)
	}
	b = append(b, byte(packetID>>24), byte(packetID>>16), byte(packetID>>8), byte(packetID))
	b = append(b, payload...)
	return b
}

// BuildSoftReset builds a P_CONTROL_SOFT_RESET_V1 packet for key renegotiation.
// The structure is identical to HARD_RESET but with opcode
// P_CONTROL_SOFT_RESET_V1 and the next key_id; it is the first packet of the
// renegotiated TLS session.
//
// Reference: openvpn3-core ssl/proto.hpp KeyContext::initial_op() at :3470,
//
//	if (key_id_) { return CONTROL_SOFT_RESET_V1; }
//
// and KeyContext::send_reset() at :3485, which raw_sends that opcode to start
// the new TLS handshake over the existing transport.
func BuildSoftReset(clientSID [8]byte, keyID uint8) []byte {
	b := []byte{FirstByte(P_CONTROL_SOFT_RESET_V1, keyID)}
	b = append(b, clientSID[:]...)
	b = append(b, 0)          // ack_array_len = 0
	b = append(b, 0, 0, 0, 0) // packet_id = 0 (first packet of new key epoch)
	return b
}

// BuildAck builds a P_ACK_V1 packet for keyID. ACKs are part of the control
// session and must carry the same key ID as the packet they acknowledge.
func BuildAck(senderSID, remoteSID [8]byte, keyID uint8, ackIDs []uint32) []byte {
	b := []byte{FirstByte(P_ACK_V1, keyID)}
	b = append(b, senderSID[:]...)
	b = append(b, byte(len(ackIDs)))
	for _, id := range ackIDs {
		b = append(b, byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
	}
	b = append(b, remoteSID[:]...)
	return b
}

// ParseControlV1Payload extracts the TLS payload and packet_id from
// a P_CONTROL_V1 packet.
func ParseControlV1Payload(pkt []byte) (payload []byte, packetID uint32) {
	if len(pkt) < 10 {
		return nil, 0
	}
	off := 1 + 8 // opcode + session_id
	ackLen := int(pkt[off])
	off++
	if ackLen > 0 {
		off += ackLen*4 + 8
	}
	if off+4 > len(pkt) {
		return nil, 0
	}
	packetID = binary.BigEndian.Uint32(pkt[off:])
	off += 4
	return pkt[off:], packetID
}

// ParseControlV1AckIDs returns the reliable packet IDs acknowledged by a
// P_CONTROL_V1 or P_CONTROL_SOFT_RESET_V1 packet.  Reset packets commonly
// carry the ACK for the peer's reset inline rather than as P_ACK_V1.
func ParseControlV1AckIDs(pkt []byte) []uint32 {
	if len(pkt) < 10 {
		return nil
	}
	off := 1 + 8 // opcode + session_id
	ackLen := int(pkt[off])
	off++
	if ackLen == 0 || off+ackLen*4 > len(pkt) {
		return nil
	}
	ackIDs := make([]uint32, 0, ackLen)
	for i := 0; i < ackLen; i++ {
		ackIDs = append(ackIDs, binary.BigEndian.Uint32(pkt[off:]))
		off += 4
	}
	return ackIDs
}

// ControlSrcSessionID returns the session id the sender put in a control packet
// — its own, and on the client side the server's. Every control opcode carries
// it immediately after the opcode byte, with or without an ack array.
func ControlSrcSessionID(pkt []byte) ([8]byte, bool) {
	var sid [8]byte
	if len(pkt) < 9 {
		return sid, false
	}
	copy(sid[:], pkt[1:9])
	return sid, true
}

// ControlDstSessionID returns the session id a control packet echoes back to
// its recipient, and whether it carries one at all. It is present only
// alongside an ack array: reliable_ack_read checks the echoed id against our
// own only when ack->len >= 1 (reliable.c:159-168).
func ControlDstSessionID(pkt []byte) ([8]byte, bool) {
	var sid [8]byte
	if len(pkt) < 10 {
		return sid, false
	}
	off := 1 + 8
	ackLen := int(pkt[off])
	off++
	if ackLen == 0 || off+ackLen*4+8 > len(pkt) {
		return sid, false
	}
	copy(sid[:], pkt[off+ackLen*4:])
	return sid, true
}
