package diag_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/diag"
)

func TestStageString(t *testing.T) {
	cases := []struct {
		stage diag.Stage
		want  string
	}{
		{diag.StageParse, "parse"},
		{diag.StageDial, "dial"},
		{diag.StageReset, "reset"},
		{diag.StageTLS, "tls"},
		{diag.StageAuth, "auth"},
		{diag.StagePush, "push"},
		{diag.StageKeys, "keys"},
		{diag.StageData, "data"},
		{diag.StageRekey, "rekey"},
		{diag.Stage(42), "stage(42)"},
		{diag.Stage(-1), "stage(-1)"},
	}
	for _, tc := range cases {
		if got := tc.stage.String(); got != tc.want {
			t.Errorf("Stage(%d).String() = %q, want %q", int(tc.stage), got, tc.want)
		}
	}
}

func TestClassString(t *testing.T) {
	cases := []struct {
		class diag.Class
		want  string
	}{
		{diag.ClassConfig, "config"},
		{diag.ClassUnsupported, "unsupported"},
		{diag.ClassNetwork, "network"},
		{diag.ClassTLS, "tls"},
		{diag.ClassAuth, "auth"},
		{diag.ClassProtocol, "protocol"},
		{diag.ClassCrypto, "crypto"},
		{diag.ClassLocal, "local"},
		{diag.ClassPeerClosed, "peer-closed"},
		{diag.ClassServerBusy, "server-busy"},
		{diag.Class(99), "class(99)"},
		{diag.Class(-1), "class(-1)"},
	}
	for _, tc := range cases {
		if got := tc.class.String(); got != tc.want {
			t.Errorf("Class(%d).String() = %q, want %q", int(tc.class), got, tc.want)
		}
	}
}

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  diag.Severity
		want string
	}{
		{diag.SeveritySupported, "supported"},
		{diag.SeverityIgnored, "ignored"},
		{diag.SeverityDegraded, "degraded"},
		{diag.SeverityFatal, "fatal"},
		{diag.Severity(7), "severity(7)"},
		{diag.Severity(-1), "severity(-1)"},
	}
	for _, tc := range cases {
		if got := tc.sev.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(tc.sev), got, tc.want)
		}
	}
}

// TestConstantOrdering pins the integer values. The ordering is a contract:
// stored reports and everything written to compare against them depend on
// these numbers, and a renumbering silently invalidates them.
func TestConstantOrdering(t *testing.T) {
	stages := []diag.Stage{
		diag.StageParse, diag.StageDial, diag.StageReset, diag.StageTLS,
		diag.StageAuth, diag.StagePush, diag.StageKeys, diag.StageData,
		diag.StageRekey,
	}
	for i, s := range stages {
		if int(s) != i {
			t.Errorf("stage %s = %d, want %d", s, int(s), i)
		}
	}
	classes := []diag.Class{
		diag.ClassConfig, diag.ClassUnsupported, diag.ClassNetwork,
		diag.ClassTLS, diag.ClassAuth, diag.ClassProtocol, diag.ClassCrypto,
		diag.ClassLocal, diag.ClassPeerClosed, diag.ClassServerBusy,
	}
	for i, c := range classes {
		if int(c) != i {
			t.Errorf("class %s = %d, want %d", c, int(c), i)
		}
	}
	// And the list is all of them. Without this the enumeration silently
	// stops covering the taxonomy the moment a class is appended.
	if got := diag.Class(len(classes)).String(); !strings.HasPrefix(got, "class(") {
		t.Errorf("Class(%d).String() = %q: a class was appended and this list "+
			"was not, so the numbering above no longer covers the taxonomy",
			len(classes), got)
	}
	severities := []diag.Severity{
		diag.SeveritySupported, diag.SeverityIgnored, diag.SeverityDegraded,
		diag.SeverityFatal,
	}
	for i, s := range severities {
		if int(s) != i {
			t.Errorf("severity %s = %d, want %d", s, int(s), i)
		}
	}
}

// TestTextRoundTrip checks that the vocabulary serialises as readable strings
// and parses back to the same constant.
func TestTextRoundTrip(t *testing.T) {
	type wrapper struct {
		Stage    diag.Stage    `json:"stage"`
		Class    diag.Class    `json:"class"`
		Severity diag.Severity `json:"severity"`
	}
	in := wrapper{diag.StageKeys, diag.ClassCrypto, diag.SeverityFatal}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"stage":"keys","class":"crypto","severity":"fatal"}`
	if string(raw) != want {
		t.Fatalf("Marshal = %s, want %s", raw, want)
	}
	var out wrapper
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
}

func TestUnmarshalTextRejectsUnknown(t *testing.T) {
	var s diag.Stage
	if err := s.UnmarshalText([]byte("nonesuch")); err == nil {
		t.Error("Stage.UnmarshalText accepted an unknown name")
	}
	var c diag.Class
	if err := c.UnmarshalText([]byte("nonesuch")); err == nil {
		t.Error("Class.UnmarshalText accepted an unknown name")
	}
	var sev diag.Severity
	if err := sev.UnmarshalText([]byte("nonesuch")); err == nil {
		t.Error("Severity.UnmarshalText accepted an unknown name")
	}
}
