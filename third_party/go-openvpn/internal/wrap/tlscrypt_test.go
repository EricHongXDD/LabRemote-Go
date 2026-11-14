package wrap

import (
	"bytes"
	"testing"
)

// Unit tests for the parts of tls-crypt no captured vector reaches: the key
// slots as a rule rather than as recorded pairs, and the encryption tls-auth
// has no equivalent of.

// TestTLSCryptKeySlotsAreTheMeasuredOnes states the key-derivation rule as
// arithmetic on a known key. The two mistakes it catches are one-line ones:
// taking Ka from the 32 bytes after Ke, and putting the client on slot 0, which
// is right for the server and so would pass a server-side test.
func TestTLSCryptKeySlotsAreTheMeasuredOnes(t *testing.T) {
	key := testKey()
	for _, tc := range []struct {
		role           peerRole
		name           string
		sendKe, sendKa int
		recvKe, recvKa int
	}{
		{roleClient, "client", 128, 192, 0, 64},
		{roleServer, "server", 0, 64, 128, 192},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := newTLSCrypt(key, tc.role)
			if err != nil {
				t.Fatalf("newTLSCrypt: %v", err)
			}
			for _, f := range []struct {
				what string
				got  []byte
				off  int
			}{
				{"send Ke", w.send.ke, tc.sendKe},
				{"send Ka", w.send.ka, tc.sendKa},
				{"recv Ke", w.recv.ke, tc.recvKe},
				{"recv Ka", w.recv.ka, tc.recvKa},
			} {
				if len(f.got) != 32 {
					t.Fatalf("%s is %d bytes, want 32", f.what, len(f.got))
				}
				if want := key[f.off : f.off+32]; !bytes.Equal(f.got, want) {
					t.Errorf("%s = %x, want static_key[%d:%d] = %x", f.what, f.got, f.off, f.off+32, want)
				}
			}
			// The 32 bytes between Ke and Ka are never installed.
			if bytes.Equal(w.send.ka, key[tc.sendKe+32:tc.sendKe+64]) {
				t.Error("Ka is the 32 bytes immediately after Ke; the split follows the " +
					"64-byte fields of struct key, so 32 bytes sit unused between them")
			}
		})
	}
}

// TestTLSCryptRolesAreComplements keeps the two roles from collapsing into one:
// a wrapper that used slot 0 for everything passes every client-side assertion
// and cannot talk to a server.
func TestTLSCryptRolesAreComplements(t *testing.T) {
	key := testKey()
	client, err := newTLSCrypt(key, roleClient)
	if err != nil {
		t.Fatalf("newTLSCrypt: %v", err)
	}
	server, err := newTLSCrypt(key, roleServer)
	if err != nil {
		t.Fatalf("newTLSCrypt: %v", err)
	}
	if bytes.Equal(client.send.ka, client.recv.ka) || bytes.Equal(client.send.ke, client.recv.ke) {
		t.Fatal("the client sends and receives with the same key material")
	}
	if !bytes.Equal(client.send.ka, server.recv.ka) || !bytes.Equal(client.recv.ka, server.send.ka) {
		t.Error("the two roles' HMAC keys are not each other's complement")
	}
	if !bytes.Equal(client.send.ke, server.recv.ke) || !bytes.Equal(client.recv.ke, server.send.ke) {
		t.Error("the two roles' cipher keys are not each other's complement")
	}
}

// TestTLSCryptActuallyEncrypts pins that the payload does not appear on the wire
// in clear. It guards the shape of bug where the ciphertext is assembled from
// the wrong buffer: the wire is the right length, the tag verifies, the round
// trip passes, and the control channel is in plaintext.
func TestTLSCryptActuallyEncrypts(t *testing.T) {
	client, _ := cryptPair(t)
	plain := controlPacket(287)
	wire, err := client.Wrap(plain)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	body := plain[controlHeaderLen:]
	if bytes.Contains(wire, body) {
		t.Fatal("the plaintext payload appears verbatim on the wire")
	}
	// The 9-byte header, by contrast, must appear — it is sent in clear so the
	// peer can find the session id before it has authenticated anything.
	if !bytes.HasPrefix(wire, plain[:controlHeaderLen]) {
		t.Fatal("the wire does not open with the plain control header")
	}
}
