package framing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// MaxPacketSize is the maximum allowed size of a single OpenVPN packet.
// openvpn3-core uses 65535 as the ceiling for the 2-byte length field.
const MaxPacketSize = 65535

// ReadTCP reads one OpenVPN packet from a TCP stream.
// The wire format is: [length uint16 big-endian][payload bytes]
// where length == len(payload).
//
// Reference: openvpn3-core transport/tcplink.hpp TCPTransport::read_handler
func ReadTCP(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("framing: read length: %w", err)
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, fmt.Errorf("framing: zero-length packet")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("framing: read payload (%d bytes): %w", n, err)
	}
	return payload, nil
}

// WriteTCP writes one OpenVPN packet to a TCP stream with the 2-byte
// big-endian length prefix.
func WriteTCP(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("framing: cannot write zero-length packet")
	}
	if len(payload) > MaxPacketSize {
		return fmt.Errorf("framing: packet too large: %d > %d", len(payload), MaxPacketSize)
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("framing: write length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("framing: write payload: %w", err)
	}
	return nil
}

// udpBufs holds read buffers large enough for any datagram, so that a read
// allocates the datagram's size rather than MaxPacketSize.
var udpBufs = sync.Pool{New: func() any { return new([MaxPacketSize]byte) }}

// ReadUDP reads one OpenVPN packet from a UDP connection, into a slice the
// caller owns. UDP packets are raw (no 2-byte length prefix); each datagram is
// one packet.
//
// Reference: openvpn3-core transport/udplink.hpp
func ReadUDP(conn net.Conn) ([]byte, error) {
	buf := udpBufs.Get().(*[MaxPacketSize]byte)
	defer udpBufs.Put(buf)
	n, err := conn.Read(buf[:])
	if err != nil {
		return nil, fmt.Errorf("framing: udp read: %w", err)
	}
	return bytes.Clone(buf[:n]), nil
}

// WriteUDP writes one OpenVPN packet to a UDP connection.
// UDP packets are sent as raw datagrams (no 2-byte length prefix).
func WriteUDP(conn net.Conn, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("framing: cannot write zero-length packet")
	}
	_, err := conn.Write(payload)
	if err != nil {
		return fmt.Errorf("framing: udp write: %w", err)
	}
	return nil
}
