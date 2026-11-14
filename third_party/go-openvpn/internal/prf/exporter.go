// RFC 5705 exported keying material for TLS 1.2, computed from captured session
// material instead of being asked of crypto/tls.
//
// Go's crypto/tls refuses RFC 5705 export on a TLS 1.2 session that negotiated
// no RFC 7627 Extended Master Secret — conn.go installs noEKMBecauseNoEMS as
// ConnectionState.ekm — while OpenSSL exports anyway. This file is the
// arithmetic and nothing else: whether running it is permissible is decided at
// its one call site in capture.go, where the material comes from.
//
// RFC 5705 §4, for a TLS version below 1.3 and no context value:
//
//	exported = PRF(master_secret, label, client_random ‖ server_random)[0:n]
//
// where PRF is RFC 5246 §5's single-digest P_hash and the digest is the one the
// negotiated cipher suite specifies. That is not TLS1PRF in prf.go, the TLS 1.0
// MD5+SHA1 split PRF OpenVPN's key expansion borrowed; the two share only
// P_hash, which is why pHash is reused here and TLS1PRF is not.
//
// An EMS session is a valid oracle for a path that only runs without EMS: RFC
// 7627 changes how master_secret is *computed* and nothing about the exporter
// above, so wherever Go will also export, this must produce the same bytes Go
// does. That is the only known-answer evidence available here, and what
// exporter_test.go checks over every suite Go will negotiate for TLS 1.2.
//
// References:
//   - RFC 5705 §4 — the exporter, and the labels §4 prohibits
//   - RFC 5246 §5 — PRF(secret, label, seed) = P_hash(secret, label ‖ seed)
//   - RFC 7627 §4 — what EMS changes, and what it does not
//   - Go crypto/tls prf.go — ekmFromMasterSecret and prfAndHashForVersion,
//     the implementation this one has to agree with byte for byte
//   - openvpn3 ssl/proto.hpp generate_datachannel_keys() — the caller's label
//     and its 256-byte length

package prf

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"hash"
	"strings"
)

// tlsRandomLen is the width of ClientHello.random and ServerHello.random
// (RFC 5246 §7.4.1.2). It matches randomLen in prf.go by coincidence: those are
// OpenVPN's own randoms, exchanged inside the control channel.
const tlsRandomLen = 32

// TLS12Session is what an RFC 5705 export needs out of a completed TLS 1.2
// session. crypto/tls exposes none of it: the master secret and the client
// random reach a caller only through a KeyLogWriter, the server random only
// from the ServerHello on the wire.
//
// Every field is a secret or binds one to a session, and the four must come
// from the *same* handshake — mismatched material derives 256 well-formed bytes
// that no peer agrees with, the one failure mode here no length check can see.
// Capture, not this type, is where that pairing is checked.
type TLS12Session struct {
	// Version is the negotiated TLS version, carried in order to be refused.
	// TLS 1.3 exports through HKDF-Expand-Label over a different secret
	// (RFC 8446 §7.5) and Go always performs that export itself, so a 1.3
	// session reaching here is a caller bug rather than something to compute.
	Version uint16
	// CipherSuite is the negotiated suite, which selects the PRF digest.
	CipherSuite uint16
	// MasterSecret is the 48-byte TLS master secret.
	MasterSecret []byte
	// ClientRandom is ClientHello.random.
	ClientRandom []byte
	// ServerRandom is ServerHello.random.
	ServerRandom []byte
}

// ExportKeyingMaterialTLS12 returns n bytes of RFC 5705 exported keying
// material for label, with no context value. It is the computation crypto/tls
// performs in ekmFromMasterSecret and declines to perform without Extended
// Master Secret. The decision to call it belongs to the caller; everything this
// function can check about the material, it checks.
func ExportKeyingMaterialTLS12(s TLS12Session, label string, n int) ([]byte, error) {
	if s.Version != tls.VersionTLS12 {
		return nil, fmt.Errorf("prf: RFC 5705 export from captured material is "+
			"for TLS 1.2 only, got %s", tls.VersionName(s.Version))
	}
	if err := checkLen("TLS master secret", s.MasterSecret, masterSecretLen); err != nil {
		return nil, err
	}
	if err := checkLen("TLS client random", s.ClientRandom, tlsRandomLen); err != nil {
		return nil, err
	}
	if err := checkLen("TLS server random", s.ServerRandom, tlsRandomLen); err != nil {
		return nil, err
	}
	if n <= 0 {
		return nil, fmt.Errorf("prf: export length must be positive, got %d", n)
	}
	// RFC 5705 §4 reserves these four labels because they are the PRF inputs TLS
	// itself uses; exporting under one would hand out the session's own
	// finished-message or key-expansion bytes. This path exists to bypass a
	// crypto/tls refusal, so the refusals worth keeping are re-stated here.
	switch label {
	case "client finished", "server finished", "master secret", "key expansion":
		return nil, fmt.Errorf("prf: %q is reserved by TLS and may not be exported", label)
	}
	newHash, err := prfHash(s.CipherSuite)
	if err != nil {
		return nil, err
	}

	// The label is part of every iteration's seed rather than a separate HMAC
	// input, so it is concatenated in front of the randoms: RFC 5246 §5's
	// PRF(secret, label, seed) is P_hash(secret, label ‖ seed).
	fullSeed := make([]byte, 0, len(label)+2*tlsRandomLen)
	fullSeed = append(fullSeed, label...)
	fullSeed = append(fullSeed, s.ClientRandom...)
	fullSeed = append(fullSeed, s.ServerRandom...)
	return pHash(newHash, s.MasterSecret, fullSeed, n), nil
}

// prfHash returns the digest the negotiated cipher suite's PRF uses.
//
// RFC 5246 §5 makes SHA-256 the default and lets a suite name its own; the
// suites that do are exactly the ones whose names end in _SHA384, which is also
// how crypto/tls decides it (the suiteSHA384 flag in cipher_suites.go), pinned
// by TestExporterAgreesWithGoOnEverySuite.
//
// A suite crypto/tls cannot name is refused rather than defaulted: defaulting
// would derive 256 plausible bytes the peer disagrees with — a dead data
// channel rather than an error at the point of the mistake.
func prfHash(suite uint16) (func() hash.Hash, error) {
	name := tls.CipherSuiteName(suite)
	switch {
	case strings.HasSuffix(name, "_SHA384"):
		return sha512.New384, nil
	case strings.HasPrefix(name, "TLS_"):
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("prf: cipher suite %s is unknown to crypto/tls, "+
			"so its PRF digest cannot be determined", name)
	}
}
