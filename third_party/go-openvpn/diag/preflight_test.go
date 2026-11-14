package diag_test

import (
	"encoding/json"
	"testing"

	"github.com/buengese/go-openvpn/diag"
)

// TestPreflightModeZeroValueIsFailFast pins that a zero value — a report with
// the field absent, a client that never sets it — reads as fail-fast.
func TestPreflightModeZeroValueIsFailFast(t *testing.T) {
	var m diag.PreflightMode
	if m != diag.PreflightFailFast {
		t.Errorf("zero value = %v, want fail-fast", m)
	}
	if got := (&diag.SessionReport{}).Redacted().Preflight; got != diag.PreflightFailFast {
		t.Errorf("zero report redacts to preflight %v, want fail-fast", got)
	}
}

// TestPreflightModeNames covers the strings a report is read by.
func TestPreflightModeNames(t *testing.T) {
	tests := []struct {
		mode diag.PreflightMode
		want string
	}{
		{diag.PreflightFailFast, "fail-fast"},
		{diag.PreflightAdvisory, "advisory"},
		{diag.PreflightMode(42), "preflight(42)"},
		{diag.PreflightMode(-1), "preflight(-1)"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("PreflightMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
		text, err := tt.mode.MarshalText()
		if err != nil || string(text) != tt.want {
			t.Errorf("MarshalText = %q, %v; want %q, nil", text, err, tt.want)
		}
	}
}

// TestPreflightModeRoundTrips checks that a serialised report reads back as the
// mode it was produced under, so an aggregator cannot mix advisory and
// fail-fast runs.
func TestPreflightModeRoundTrips(t *testing.T) {
	for _, mode := range []diag.PreflightMode{diag.PreflightFailFast, diag.PreflightAdvisory} {
		blob, err := json.Marshal((&diag.SessionReport{Preflight: mode}).Redacted())
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back diag.SessionReport
		if err := json.Unmarshal(blob, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if back.Preflight != mode {
			t.Errorf("round trip: got %v, want %v", back.Preflight, mode)
		}
	}
	var m diag.PreflightMode
	if err := m.UnmarshalText([]byte("neither")); err == nil {
		t.Error("UnmarshalText accepted an unknown mode name")
	}
}
