package diag

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Class is the error taxonomy. Each class implies a different next action,
// which is the test of whether it earns its keep: a Network failure means the
// endpoint is down or filtered, an Unsupported failure means we have not built
// something the peer or the profile needs and Feature names it. The numeric
// values are part of the diagnostics contract: append new classes at the end,
// never renumber.
type Class int

// The error classes. Their order fixes the numeric values, so a new class is
// appended here and an existing one never moves.
const (
	// ClassConfig means the profile is unusable as written, for example a
	// malformed inline block. The input needs fixing.
	ClassConfig Class = iota
	// ClassUnsupported means the peer or the profile requires a feature we
	// have not built. Error.Feature names it.
	ClassUnsupported
	// ClassNetwork means the transport never came up — timeout, refused or
	// unreachable.
	ClassNetwork
	// ClassTLS means the TLS handshake or certificate verification failed.
	// This is a trust problem, not a credential problem.
	ClassTLS
	// ClassAuth means the server rejected our credentials, for example with
	// AUTH_FAILED.
	ClassAuth
	// ClassProtocol means the peer sent something we could not follow — a
	// truncated ack array, a bad opcode. Either a server quirk or a bug in
	// our parser.
	ClassProtocol
	// ClassCrypto means keys or packet authentication did not work out —
	// an HMAC mismatch or a decrypt failure. Usually a derivation mismatch.
	ClassCrypto
	// ClassLocal means our own environment is at fault, for example a
	// missing CAP_NET_ADMIN. An operator problem.
	ClassLocal
	// ClassPeerClosed means the server ended a working session on purpose,
	// by pushing RESTART or HALT. Nothing failed: the tunnel was up, the
	// credentials were accepted, and the peer decided it was over. It is its
	// own class because the alternative records a deliberate server-side
	// shutdown as a network failure, and a sweep buckets by class.
	ClassPeerClosed
	// ClassServerBusy means the server declined this attempt and said to come
	// back: an "AUTH_FAILED,TEMP" reply, optionally carrying how long to wait
	// and which remote to try next. Nothing is wrong with the profile, the
	// credentials or the link, and Error.RetryAfter carries the requested
	// wait. It is its own class for the reason ClassPeerClosed is: filed as
	// ClassProtocol it reads as "our parser could not follow the server",
	// filed as ClassAuth it records a working account as a failing one.
	//
	// Reference: openvpn-2.6.22 src/openvpn/push.c:75 raises SIGUSR1, a soft
	// restart, where a plain AUTH_FAILED raises SIGTERM.
	ClassServerBusy
)

// classNames maps each Class to the lowercase name used in reports.
var classNames = [...]string{
	ClassConfig:      "config",
	ClassUnsupported: "unsupported",
	ClassNetwork:     "network",
	ClassTLS:         "tls",
	ClassAuth:        "auth",
	ClassProtocol:    "protocol",
	ClassCrypto:      "crypto",
	ClassLocal:       "local",
	ClassPeerClosed:  "peer-closed",
	ClassServerBusy:  "server-busy",
}

// String returns the lowercase class name, or a "class(N)" placeholder when
// the value is outside the defined range.
func (c Class) String() string {
	if c < 0 || int(c) >= len(classNames) {
		return "class(" + strconv.Itoa(int(c)) + ")"
	}
	return classNames[c]
}

// MarshalText implements encoding.TextMarshaler so that classes serialise as
// readable names rather than integers. It never returns an error; an
// out-of-range value marshals as its String form.
func (c Class) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, accepting the names
// produced by String. An unrecognised name is an error.
func (c *Class) UnmarshalText(text []byte) error {
	name := string(text)
	for i, n := range classNames {
		if n == name {
			*c = Class(i)
			return nil
		}
	}
	return fmt.Errorf("diag: unknown class %q", name)
}

// Error is the typed error returned by every instrumented call path. Interior
// helpers may keep using fmt.Errorf, provided the stage boundary wraps their
// result in an *Error.
//
// Recover it with errors.As, never by matching on the message text:
//
//	var derr *diag.Error
//	if errors.As(err, &derr) && derr.Class == diag.ClassAuth { ... }
type Error struct {
	// Class is the taxonomy bucket this failure falls into.
	Class Class
	// Stage is the connection stage the failure occurred in.
	Stage Stage
	// Feature names the missing capability. It is set when Class is
	// ClassUnsupported and empty otherwise.
	Feature string
	// Detail is a short human-readable explanation. It must not contain
	// credentials: SessionReport.Redacted scrubs secret values out of error
	// text, but only values registered with AddSecret.
	Detail string
	// RetryAfter is how long the peer asked us to wait before trying again.
	// Set only when the peer said so — an "AUTH_FAILED,TEMP" carrying a
	// backoff, which is ClassServerBusy — and zero everywhere else.
	RetryAfter time.Duration
	// Err is the wrapped cause, if any.
	Err error

	// report is the redacted report for the attempt this error ended. It is
	// unexported so that logging the error does not serialise the report.
	report *SessionReport
}

// Error implements the error interface. The message is
// "<stage>: <class>[ (<feature>)][: <detail>][: <cause>]".
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	b.WriteString(e.Stage.String())
	b.WriteString(": ")
	b.WriteString(e.Class.String())
	if e.Feature != "" {
		b.WriteString(" (")
		b.WriteString(e.Feature)
		b.WriteString(")")
	}
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

// Unwrap returns the wrapped cause so that errors.Is and errors.As reach it.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Wrap returns an *Error carrying cause. It returns a non-nil *Error even when
// cause is nil, because a stage boundary always has a class and a stage to
// report, so a causeless error is Wrap's business too.
func Wrap(class Class, stage Stage, cause error, detail string) *Error {
	return &Error{Class: class, Stage: stage, Detail: detail, Err: cause}
}

// Unsupported returns an *Error of Class ClassUnsupported naming the feature
// we have not built. feature should be the directive or protocol element as
// it appears on the wire or in the profile, for example "tls-crypt".
func Unsupported(stage Stage, feature, detail string) *Error {
	return &Error{Class: ClassUnsupported, Stage: stage, Feature: feature, Detail: detail}
}

// SetReport attaches r.Redacted() to the error, so the diagnosis survives %w
// wrapping. What survives redaction still reaches every log line that prints
// the error: endpoints, certificate subjects (which can name the user),
// pushed routes and resolvers, and directive names.
//
// A nil r clears the report. Safe on a nil receiver.
func (e *Error) SetReport(r *SessionReport) {
	if e == nil {
		return
	}
	e.report = r.Redacted()
}

// Report returns the redacted report for the attempt this error ended, or nil
// when none was attached. Safe on a nil receiver.
//
//	if derr := diag.AsError(err); derr != nil {
//	    if rep := derr.Report(); rep != nil { store(rep) }
//	}
func (e *Error) Report() *SessionReport {
	if e == nil {
		return nil
	}
	return e.report
}

// AsError returns the first *Error in err's unwrap chain, or nil when there
// is none. It is a convenience wrapper around errors.As.
func AsError(err error) *Error {
	var derr *Error
	if errors.As(err, &derr) {
		return derr
	}
	return nil
}

// maxErrorChainDepth bounds ErrorChain against a cyclic or pathological
// unwrap chain.
const maxErrorChainDepth = 64

// ErrorChain flattens err into the message of every error in its unwrap chain,
// outermost first. It follows both the single-error and the multi-error
// (Unwrap() []error) forms and returns nil for a nil error. The result is what
// SessionReport.Outcome.ErrorChain holds: strings rather than errors, so that a
// report is serialisable and its free text can be scrubbed by Redacted.
func ErrorChain(err error) []string {
	var out []string
	var walk func(error, int)
	walk = func(e error, depth int) {
		for e != nil && depth < maxErrorChainDepth {
			out = append(out, e.Error())
			if multi, ok := e.(interface{ Unwrap() []error }); ok {
				for _, sub := range multi.Unwrap() {
					walk(sub, depth+1)
				}
				return
			}
			e = errors.Unwrap(e)
			depth++
		}
	}
	walk(err, 0)
	return out
}
