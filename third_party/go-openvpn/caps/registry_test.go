package caps_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/caps"
	"github.com/buengese/go-openvpn/diag"
)

func TestLookupIsCaseInsensitive(t *testing.T) {
	lower, ok := caps.Lookup("fast-io")
	if !ok {
		t.Fatal("fast-io not in registry")
	}
	upper, ok := caps.Lookup("FAST-IO")
	if !ok {
		t.Fatal("FAST-IO not found; lookup is case sensitive")
	}
	if lower != upper {
		t.Errorf("case changed the verdict: %+v vs %+v", lower, upper)
	}
	if _, ok := caps.LookupBlock("TLS-AUTH"); !ok {
		t.Error("block lookup is case sensitive")
	}
}

func TestLookupRejectsUnknown(t *testing.T) {
	if _, ok := caps.Lookup("no-such-directive"); ok {
		t.Error("unknown directive resolved")
	}
	if _, ok := caps.LookupBlock("no-such-block"); ok {
		t.Error("unknown block resolved")
	}
}

func TestEveryRowHasAOneLineDetail(t *testing.T) {
	check := func(kind, name, detail string, sev diag.Severity) {
		t.Helper()
		switch {
		case detail == "":
			t.Errorf("%s %q has no detail", kind, name)
		case strings.ContainsAny(detail, "\n\r"):
			t.Errorf("%s %q detail is not one line: %q", kind, name, detail)
		case len(detail) > 120:
			t.Errorf("%s %q detail is %d chars, keep it to one line", kind, name, len(detail))
		}
		if sev < diag.SeveritySupported || sev > diag.SeverityFatal {
			t.Errorf("%s %q has severity %d, outside the defined range", kind, name, sev)
		}
	}
	for _, name := range caps.Known() {
		s, _ := caps.Lookup(name)
		check("directive", name, s.Detail, s.Severity)
	}
	for _, tag := range caps.KnownBlocks() {
		s, _ := caps.LookupBlock(tag)
		check("block", tag, s.Detail, s.Severity)
	}
}

func TestKnownIsSortedAndNormalised(t *testing.T) {
	for _, list := range [][]string{caps.Known(), caps.KnownBlocks()} {
		if !sort.StringsAreSorted(list) {
			t.Errorf("not sorted: %v", list)
		}
		for _, name := range list {
			if name != strings.ToLower(name) {
				t.Errorf("registry key %q is not lowercase", name)
			}
			if strings.ContainsAny(name, " \t<>") {
				t.Errorf("registry key %q contains markup or whitespace", name)
			}
		}
	}
}

// TestRegistrySeverityForKeyDirectives pins one directive per severity band, so
// that a change to any of the three is deliberate rather than incidental.
// tls-crypt-v2 is the fatal example because it needs a per-client wrapped key
// the measurement system has no way to obtain; tls-crypt is implemented, and an
// illustration of a fatal gap has to be something that stays fatal.
func TestRegistrySeverityForKeyDirectives(t *testing.T) {
	cases := []struct {
		directive string
		want      diag.Severity
	}{
		{"tls-crypt-v2", diag.SeverityFatal},
		{"comp-lzo", diag.SeveritySupported},
		{"fast-io", diag.SeverityIgnored},
	}
	for _, tc := range cases {
		s, ok := caps.Lookup(tc.directive)
		if !ok {
			t.Errorf("%s missing from registry", tc.directive)
			continue
		}
		if s.Severity != tc.want {
			t.Errorf("%s = %v, want %v", tc.directive, s.Severity, tc.want)
		}
	}
}
