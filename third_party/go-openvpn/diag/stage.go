package diag

import (
	"fmt"
	"strconv"
)

// Stage identifies a boundary in the connection state machine. Every
// instrumented call path records the stage it is in, so a failed attempt can
// be attributed to a named point in the handshake rather than to a string.
//
// The numeric values are part of the diagnostics contract: append new stages
// at the end, never renumber. Reports serialise stages as their lowercase
// names (see MarshalText), so a renumbering does not corrupt stored data, but
// it does invalidate in-flight comparisons.
type Stage int

// The connection stages, in the order a successful attempt passes through
// them. StageRekey is the exception: it is entered repeatedly after
// StageData, once per renegotiation.
const (
	// StageParse is profile parsing and capability preflight. No socket is
	// opened during this stage.
	StageParse Stage = iota
	// StageDial is transport establishment — DNS resolution and the UDP or
	// TCP connect to the remote.
	StageDial
	// StageReset is the hard reset exchange that opens the reliable control
	// channel.
	StageReset
	// StageTLS is the TLS handshake carried inside the control channel,
	// including certificate verification.
	StageTLS
	// StageAuth is the key-method-2 exchange in both directions, carrying
	// credentials and the peer-info and options strings.
	StageAuth
	// StagePush is PUSH_REQUEST sent and PUSH_REPLY received.
	StagePush
	// StageKeys is data-channel key derivation from the TLS session.
	StageKeys
	// StageData is the first plaintext packet in each direction.
	StageData
	// StageRekey is a data-channel key renegotiation, client- or
	// server-initiated.
	StageRekey
)

// stageNames maps each Stage to the lowercase name used in reports.
var stageNames = [...]string{
	StageParse: "parse",
	StageDial:  "dial",
	StageReset: "reset",
	StageTLS:   "tls",
	StageAuth:  "auth",
	StagePush:  "push",
	StageKeys:  "keys",
	StageData:  "data",
	StageRekey: "rekey",
}

// String returns the lowercase stage name, or a "stage(N)" placeholder when
// the value is outside the defined range.
func (s Stage) String() string {
	if s < 0 || int(s) >= len(stageNames) {
		return "stage(" + strconv.Itoa(int(s)) + ")"
	}
	return stageNames[s]
}

// MarshalText implements encoding.TextMarshaler so that stages serialise as
// readable names rather than integers. It never returns an error; an
// out-of-range value marshals as its String form.
func (s Stage) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, accepting the names
// produced by String. An unrecognised name is an error.
func (s *Stage) UnmarshalText(text []byte) error {
	name := string(text)
	for i, n := range stageNames {
		if n == name {
			*s = Stage(i)
			return nil
		}
	}
	return fmt.Errorf("diag: unknown stage %q", name)
}
