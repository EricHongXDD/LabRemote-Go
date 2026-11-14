package framing_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/buengese/go-openvpn/internal/framing"
)

// TestFirstByte checks that opcode+keyid encoding round-trips.
func TestFirstByte(t *testing.T) {
	tests := []struct {
		opcode, keyID uint8
		want          byte
	}{
		{framing.P_CONTROL_HARD_RESET_CLIENT_V2, 0, 0x38},
		{framing.P_ACK_V1, 0, 0x28},
		{framing.P_CONTROL_V1, 0, 0x20},
		{framing.P_DATA_V2, 0, 0x48},
	}
	for _, tt := range tests {
		got := framing.FirstByte(tt.opcode, tt.keyID)
		if got != tt.want {
			t.Errorf("FirstByte(%#x, %d) = %#x, want %#x", tt.opcode, tt.keyID, got, tt.want)
		}
		if framing.OpcodeFromByte(got) != tt.opcode {
			t.Errorf("OpcodeFromByte(%#x) = %d, want %d", got, framing.OpcodeFromByte(got), tt.opcode)
		}
		if framing.KeyIDFromByte(got) != tt.keyID {
			t.Errorf("KeyIDFromByte(%#x) = %d, want %d", got, framing.KeyIDFromByte(got), tt.keyID)
		}
	}
}

// TestTCPRoundTrip writes a packet and reads it back.
func TestTCPRoundTrip(t *testing.T) {
	payload := []byte("hello openvpn3")
	var buf bytes.Buffer
	if err := framing.WriteTCP(&buf, payload); err != nil {
		t.Fatal(err)
	}
	// Verify wire: 2-byte big-endian length then payload
	wire := buf.Bytes()
	gotLen := binary.BigEndian.Uint16(wire[:2])
	if int(gotLen) != len(payload) {
		t.Fatalf("wire length field = %d, want %d", gotLen, len(payload))
	}
	got, err := framing.ReadTCP(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("ReadTCP returned %q, want %q", got, payload)
	}
}

// TestWriteTCPErrors checks boundary conditions.
func TestWriteTCPErrors(t *testing.T) {
	var buf bytes.Buffer
	if err := framing.WriteTCP(&buf, nil); err == nil {
		t.Error("expected error writing nil payload")
	}
	if err := framing.WriteTCP(&buf, make([]byte, 65536)); err == nil {
		t.Error("expected error writing >MaxPacketSize payload")
	}
}

// TestParseControlAck reads a P_ACK_V1 packet with one acked ID, through the
// accessors the client uses on the wire.
func TestParseControlAck(t *testing.T) {
	var raw []byte
	raw = append(raw, framing.FirstByte(framing.P_ACK_V1, 0))
	raw = append(raw, make([]byte, 8)...) // session_id
	raw = append(raw, 1)                  // ack_array_len = 1
	raw = append(raw, 0, 0, 0, 7)         // acked packet_id = 7
	raw = append(raw, make([]byte, 8)...) // remote_session_id

	if op := framing.OpcodeFromByte(raw[0]); op != framing.P_ACK_V1 {
		t.Errorf("opcode = %d, want %d", op, framing.P_ACK_V1)
	}
	if got := framing.ParseControlV1AckIDs(raw); len(got) != 1 || got[0] != 7 {
		t.Errorf("ack_ids = %v, want [7]", got)
	}
}

// TestParseControlV1AckIDs round-trips an ack array through the builder the
// client sends with, which is the half TestParseControlAck above cannot reach:
// that one hand-writes a P_ACK_V1 packet, and a P_CONTROL_V1 puts its ack array
// in front of an echoed session id and a packet id of its own.
func TestParseControlV1AckIDs(t *testing.T) {
	var sender, remote [8]byte
	pkt := framing.BuildControlV1(sender, remote, 3, 7, []uint32{0, 4}, nil)
	got := framing.ParseControlV1AckIDs(pkt)
	if len(got) != 2 || got[0] != 0 || got[1] != 4 {
		t.Fatalf("framing.ParseControlV1AckIDs = %v, want [0 4]", got)
	}
}

// TestBuildAckCarriesTheRequestedKeyID pins the first byte BuildAck composes:
// the P_ACK_V1 opcode, and the key ID it was handed rather than the 0 of the
// initial key epoch.
//
// BuildAck's contract is that an ACK carries the same key ID as the packet it
// acknowledges, which after a renegotiation is not 0. Nothing else here builds
// an ACK, so a BuildAck that dropped the parameter would pass every other test
// in this package.
func TestBuildAckCarriesTheRequestedKeyID(t *testing.T) {
	var sender, remote [8]byte
	pkt := framing.BuildAck(sender, remote, 6, []uint32{0})
	if got := framing.KeyIDFromByte(pkt[0]); got != 6 {
		t.Fatalf("ACK key ID = %d, want 6", got)
	}
	if got := framing.OpcodeFromByte(pkt[0]); got != framing.P_ACK_V1 {
		t.Fatalf("ACK opcode = %d, want P_ACK_V1", got)
	}
}

// TestReadUDPReturnsAnOwnedSlice guards the pooled read buffer: the reader
// hands a packet to the relay and reads the next while the first is in use.
func TestReadUDPReturnsAnOwnedSlice(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close() //nolint:errcheck
	defer server.Close() //nolint:errcheck
	go func() {
		server.Write([]byte{0x48, 0x01, 0x02, 0x03})       //nolint:errcheck
		server.Write([]byte{0x20, 0x09, 0x09, 0x09, 0x09}) //nolint:errcheck
	}()

	first, err := framing.ReadUDP(client)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if _, err := framing.ReadUDP(client); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if want := []byte{0x48, 0x01, 0x02, 0x03}; !bytes.Equal(first, want) {
		t.Errorf("first packet = %x after a second read, want %x", first, want)
	}
	if cap(first) == framing.MaxPacketSize {
		t.Errorf("first packet holds a %d-byte buffer for %d bytes", cap(first), len(first))
	}
}
