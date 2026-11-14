package ctls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/buengese/go-openvpn/internal/ctls"
)

// generateSelfSigned creates a self-signed CA + leaf cert for testing.
func generateSelfSigned(t *testing.T) (serverTLS *tls.Config, clientTLS *tls.Config) {
	t.Helper()

	// CA key + cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Server key + cert
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Encode to PEM for tls.X509KeyPair
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatal(err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serverTLS = &tls.Config{
		Certificates:           []tls.Certificate{srvCert},
		ClientCAs:              caPool,
		ClientAuth:             tls.NoClientCert,
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}
	clientTLS = &tls.Config{
		RootCAs:                caPool,
		ServerName:             "127.0.0.1",
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: true,
	}
	return serverTLS, clientTLS
}

// handshakePair completes one TLS handshake over an in-process pipe and returns
// both ends, closed on cleanup. The two Close calls run concurrently: net.Pipe
// is unbuffered, so a close_notify written by one side with nobody reading the
// other end blocks forever.
func handshakePair(t *testing.T) (client, server *tls.Conn) {
	t.Helper()
	serverCfg, clientCfg := generateSelfSigned(t)

	clientPipe, serverPipe := net.Pipe()

	type result struct {
		conn *tls.Conn
		err  error
	}
	serverRes := make(chan result, 1)
	go func() {
		c := tls.Server(serverPipe, serverCfg)
		serverRes <- result{c, c.Handshake()}
	}()

	client = tls.Client(clientPipe, clientCfg)
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	res := <-serverRes
	if res.err != nil {
		t.Fatalf("server handshake: %v", res.err)
	}
	t.Cleanup(func() {
		go client.Close() //nolint:errcheck
		res.conn.Close()  //nolint:errcheck
	})
	return client, res.conn
}

// TestHandshakeOverNetPipe verifies that a TLS handshake completes when both
// ends are backed by net.Pipe.
func TestHandshakeOverNetPipe(t *testing.T) {
	clientConn, _ := handshakePair(t)

	// Verify TLS version negotiated.
	cs := clientConn.ConnectionState()
	if cs.Version == 0 {
		t.Fatal("no TLS version in ConnectionState")
	}
	t.Logf("TLS version: 0x%04x cipher: 0x%04x", cs.Version, cs.CipherSuite)
}

// TestSendReceive verifies that data written on one side is readable on the other.
func TestSendReceive(t *testing.T) {
	clientConn, srvConn := handshakePair(t)

	// Client writes concurrently with server read — net.Pipe has no buffer.
	msg := []byte("hello openvpn ctls")
	type readResult struct {
		data []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buf := make([]byte, len(msg))
		if _, err := srvConn.Read(buf); err != nil {
			readDone <- readResult{err: err}
			return
		}
		readDone <- readResult{data: buf}
	}()

	if _, err := clientConn.Write(msg); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	select {
	case res := <-readDone:
		if res.err != nil {
			t.Fatalf("server Read: %v", res.err)
		}
		if string(res.data) != string(msg) {
			t.Fatalf("got %q want %q", res.data, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server Read")
	}
}

// TestControlTransportInjectDrain verifies InjectInbound / Write flow directly.
func TestControlTransportInjectDrain(t *testing.T) {
	addr := &testAddr{}
	tr := ctls.NewControlTransport(addr, addr, 8)

	want := []byte("test payload")
	if err := tr.InjectInbound(want); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	n, err := tr.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("got %q want %q", buf[:n], want)
	}

	// Write then drain.
	if _, err := tr.Write(want); err != nil {
		t.Fatal(err)
	}
	got, err := tr.DrainOutbound()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("drained %q want %q", got, want)
	}
}

type testAddr struct{}

func (testAddr) Network() string { return "test" }
func (testAddr) String() string  { return "test" }
