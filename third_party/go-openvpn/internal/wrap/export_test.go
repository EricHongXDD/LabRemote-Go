package wrap

// Seams for the known-answer tests in the external wrap_test package and for
// the shared property tests in package wrap. This file is compiled only under
// `go test`, so nothing here widens the package's real API.

// SetReplayHeaderForTest fixes the packet id and timestamp that every
// subsequent Wrap stamps, so a test can reproduce a captured packet: Wrap
// generates both itself, one a counter and the other a clock.
func SetReplayHeaderForTest(w Wrapper, packetID, timestamp uint32) {
	switch t := w.(type) {
	case *tlsAuth:
		t.send.setForTest(packetID, timestamp)
	case *tlsCrypt:
		t.sendCtr.setForTest(packetID, timestamp)
	default:
		panic("wrap: no replay-header seam on this Wrapper")
	}
}

// SendKeyForTest and RecvKeyForTest return the HMAC keys the wrapper
// installed — Ka, for tls-crypt. Asserting them separately is what tells a
// field-order bug from a key-selection one.
func SendKeyForTest(w Wrapper) []byte {
	switch t := w.(type) {
	case *tlsAuth:
		return t.sendKey
	case *tlsCrypt:
		return t.send.ka
	default:
		panic("wrap: no HMAC key seam on this Wrapper")
	}
}

// RecvKeyForTest returns the receive-direction HMAC key. See SendKeyForTest.
func RecvKeyForTest(w Wrapper) []byte {
	switch t := w.(type) {
	case *tlsAuth:
		return t.recvKey
	case *tlsCrypt:
		return t.recv.ka
	default:
		panic("wrap: no HMAC key seam on this Wrapper")
	}
}

// SendCipherKeyForTest and RecvCipherKeyForTest return tls-crypt's Ke for each
// direction; tls-auth installs no cipher. The derived keys are asserted against
// the recorded intermediates before the cipher is on trial.
func SendCipherKeyForTest(w Wrapper) []byte { return w.(*tlsCrypt).send.ke }

// RecvCipherKeyForTest returns the receive-direction Ke. See SendCipherKeyForTest.
func RecvCipherKeyForTest(w Wrapper) []byte { return w.(*tlsCrypt).recv.ke }

// NewTLSCryptServerForTest builds the tls-crypt wrapper a server runs: the
// halves of the static key the other way round. tls-crypt has no
// --key-direction, so the public API cannot ask for that role, and half the
// captured vectors are the server's outgoing packets.
func NewTLSCryptServerForTest(key *StaticKey) (Wrapper, error) {
	return newTLSCrypt(key, roleServer)
}
