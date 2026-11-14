package diag

import (
	"fmt"
	"strconv"
)

// Severity says how badly a profile directive we cannot fully honour affects
// the connection. It is the ranking used by the capability registry and by
// the coverage matrix.
//
// The numeric values are part of the diagnostics contract: append new
// severities at the end, never renumber.
type Severity int

// The severities, ordered from harmless to fatal.
const (
	// SeveritySupported means the directive is implemented and honoured.
	SeveritySupported Severity = iota
	// SeverityIgnored means the directive is known and deliberately a
	// no-op, for example "fast-io", which has no effect in userspace.
	// This category is what lets an unrecognised directive become a loud
	// failure without drowning every config in warnings about "nobind".
	SeverityIgnored
	// SeverityDegraded means the connection can still come up, but
	// behaviour differs from what the directive asks for.
	SeverityDegraded
	// SeverityFatal means the connection cannot be made while the
	// directive is present.
	SeverityFatal
)

// severityNames maps each Severity to the lowercase name used in reports.
var severityNames = [...]string{
	SeveritySupported: "supported",
	SeverityIgnored:   "ignored",
	SeverityDegraded:  "degraded",
	SeverityFatal:     "fatal",
}

// String returns the lowercase severity name, or a "severity(N)" placeholder
// when the value is outside the defined range.
func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "severity(" + strconv.Itoa(int(s)) + ")"
	}
	return severityNames[s]
}

// MarshalText implements encoding.TextMarshaler so that severities serialise
// as readable names rather than integers. It never returns an error; an
// out-of-range value marshals as its String form.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, accepting the names
// produced by String. An unrecognised name is an error.
func (s *Severity) UnmarshalText(text []byte) error {
	name := string(text)
	for i, n := range severityNames {
		if n == name {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("diag: unknown severity %q", name)
}

// Gap is one directive in a profile that we cannot fully honour, as reported
// by the capability preflight before any socket is opened.
type Gap struct {
	// Directive is the profile directive keyword, for example "tls-crypt".
	Directive string `json:"directive"`
	// Value is the directive's argument text, when the classification
	// depends on it. It is empty when the keyword alone decides.
	Value string `json:"value,omitempty"`
	// Severity is how badly this gap affects the connection.
	Severity Severity `json:"severity"`
	// Detail is a one-line explanation of what we do instead.
	Detail string `json:"detail,omitempty"`
}
