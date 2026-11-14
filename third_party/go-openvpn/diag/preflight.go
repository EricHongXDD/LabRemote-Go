package diag

import (
	"fmt"
	"strconv"
)

// PreflightMode selects what the capability preflight at StageParse does when
// it finds a SeverityFatal gap.
//
// Both modes run the same preflight and record the same Gap list into
// SessionReport.Profile.Gaps; they differ only in whether a fatal gap ends the
// attempt there. The mode is recorded in SessionReport.Preflight, because the
// two produce entirely different stage histograms and an aggregate must not
// silently mix them.
//
// The numeric values are part of the diagnostics contract: append new modes at
// the end, never renumber. The zero value is PreflightFailFast, so a client
// that never sets it reads as fail-fast.
type PreflightMode int

const (
	// PreflightFailFast ends the attempt at StageParse with ClassUnsupported
	// as soon as any gap comes back SeverityFatal, naming the directive in
	// Error.Feature. It is the default and the behaviour a client wants: a
	// profile asking for something we cannot honour is told so before a
	// socket is opened.
	PreflightFailFast PreflightMode = iota
	// PreflightAdvisory records the same gaps and emits the same stage
	// event, then lets the attempt proceed so that it fails wherever it
	// really fails.
	//
	// It exists for measurement: under fail-fast a profile with a fatal gap
	// stops at StageParse, so which later stages it could reach is never
	// tested against anything. It is not a "try harder" switch — an attempt
	// that proceeds past a fatal gap is expected to fail, and the point is
	// to learn where.
	PreflightAdvisory
)

// preflightNames maps each PreflightMode to the name used in reports.
var preflightNames = [...]string{
	PreflightFailFast: "fail-fast",
	PreflightAdvisory: "advisory",
}

// String returns the lowercase mode name, or a "preflight(N)" placeholder when
// the value is outside the defined range.
func (m PreflightMode) String() string {
	if m < 0 || int(m) >= len(preflightNames) {
		return "preflight(" + strconv.Itoa(int(m)) + ")"
	}
	return preflightNames[m]
}

// MarshalText implements encoding.TextMarshaler so that the mode serialises as
// a readable name rather than an integer. It never returns an error; an
// out-of-range value marshals as its String form.
func (m PreflightMode) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, accepting the names
// produced by String. An unrecognised name is an error.
func (m *PreflightMode) UnmarshalText(text []byte) error {
	name := string(text)
	for i, n := range preflightNames {
		if n == name {
			*m = PreflightMode(i)
			return nil
		}
	}
	return fmt.Errorf("diag: unknown preflight mode %q", name)
}
