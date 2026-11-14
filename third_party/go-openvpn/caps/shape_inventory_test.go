// SPDX-License-Identifier: LGPL-2.1-or-later

package caps_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// inventoryPath is the committed list of what the fixtures exercise.
const inventoryPath = "testdata/shape-inventory.txt"

// inventoryDims is the order the inventory is written in.
var inventoryDims = []string{"directive", "argument shape", "lexical shape"}

// inventoryHeader opens the committed file, so a reader who finds it without
// the test knows what it is for.
const inventoryHeader = `# shapes the fixtures exercise — go-openvpn
#
# Written from caps/fixtures_test.go. It is the published claim about what the
# fixtures cover: a consumer holding a corpus of real profiles checks its own
# against this list, and anything that corpus exercises and this list does not
# name is a shape the fixtures do not reach.
#
# Regenerate after adding or changing a shape:
#   go test ./caps -run TestShapeInventory -update
`

// renderInventory writes the surveyed sets as sorted, stable text.
func renderInventory(sets map[string]map[string]bool) string {
	var b strings.Builder
	b.WriteString(inventoryHeader)
	for _, dim := range inventoryDims {
		fmt.Fprintf(&b, "\n%s\n", dim)
		names := make([]string, 0, len(sets[dim]))
		for name := range sets[dim] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(&b, "  %s\n", name)
		}
	}
	return b.String()
}

// TestShapeInventoryIsCurrent holds the committed inventory to what the
// generator actually writes. It is the half of the coverage claim that survives
// without a corpus of real profiles: the list cannot quietly shrink, so a
// consumer comparing one against it is comparing against something true.
func TestShapeInventoryIsCurrent(t *testing.T) {
	written := fixtures(t)
	got := renderInventory(surveyFixtures(t, written))

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(inventoryPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write inventory: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", inventoryPath, len(got))
		return
	}

	want, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatalf("read inventory: %v\nregenerate with:\n  go test ./caps -run TestShapeInventory -update", err)
	}
	if got != string(want) {
		t.Errorf("the fixtures no longer match %s.\n"+
			"If a shape was added or changed deliberately, regenerate with:\n"+
			"  go test ./caps -run TestShapeInventory -update\n\n"+
			"missing from the file: %v\nextra in the file:     %v",
			inventoryPath,
			missingFrom(surveyFixtures(t, written), inventorySets(t, string(want))),
			missingFrom(inventorySets(t, string(want)), surveyFixtures(t, written)))
	}
}

// inventorySets parses a rendered inventory back into the surveyed sets.
func inventorySets(t *testing.T, text string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, dim := range inventoryDims {
		out[dim] = map[string]bool{}
	}
	dim := ""
	for _, ln := range strings.Split(text, "\n") {
		switch {
		case ln == "" || strings.HasPrefix(ln, "#"):
			continue
		case !strings.HasPrefix(ln, "  "):
			dim = strings.TrimSpace(ln)
		case out[dim] != nil:
			out[dim][strings.TrimSpace(ln)] = true
		}
	}
	return out
}

// missingFromSet returns the members of want that are absent from got, sorted.
func missingFromSet(want, got map[string]bool) []string {
	var out []string
	for k := range want {
		if !got[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// missingFrom is missingFromSet across every dimension, each entry prefixed
// with the dimension it belongs to.
func missingFrom(want, got map[string]map[string]bool) []string {
	var out []string
	for _, dim := range inventoryDims {
		for _, name := range missingFromSet(want[dim], got[dim]) {
			out = append(out, dim+": "+name)
		}
	}
	return out
}

// surveyFixtures reduces the fixtures to the sets of things they exercise. Values
// of arguments are never recorded — only which class of shape each falls into.
func surveyFixtures(t *testing.T, written []fixtureFile) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{
		"directive":      {},
		"argument shape": {},
		"lexical shape":  {},
	}
	for _, f := range written {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatalf("read %s: %v", f.id(), err)
		}
		body := string(raw)
		if strings.Contains(body, "\r\n") {
			out["lexical shape"]["crlf line endings"] = true
		}
		if strings.HasPrefix(body, "\ufeff") {
			out["lexical shape"]["byte order mark"] = true
		}
		if strings.Contains(body, "\t") {
			out["lexical shape"]["tab separator"] = true
		}

		inBlock := false
		for _, ln := range strings.Split(body, "\n") {
			line := strings.TrimSpace(ln)
			switch {
			case strings.HasPrefix(line, "</"):
				inBlock = false
				continue
			case strings.HasPrefix(line, "<"):
				out["directive"][strings.ToLower(line)] = true
				inBlock = true
				continue
			}
			if inBlock {
				switch {
				case strings.HasPrefix(line, "#"), strings.HasPrefix(line, ";"):
					out["lexical shape"]["comment inside an inline block"] = true
				case line == "":
					out["lexical shape"]["blank line inside an inline block"] = true
				}
				continue
			}
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				out["lexical shape"]["comment line"] = true
				continue
			}
			if strings.ContainsAny(line, `"'`) {
				out["lexical shape"]["quoted argument"] = true
			}

			fields := strings.Fields(line)
			name := strings.ToLower(fields[0])
			out["directive"][name] = true
			if len(fields) == 1 {
				out["argument shape"][name+": none"] = true
				continue
			}
			for _, arg := range fields[1:] {
				out["argument shape"][name+": "+argShape(arg)] = true
			}
		}
	}
	return out
}

// argShape names the class an argument falls into. The classes are the ones a
// parser treats differently: a path is resolved, an address is not resolved, a
// value carrying upper case is matched case-sensitively by OpenVPN and not by
// this client, and a bare number is a count.
func argShape(a string) string {
	switch {
	case strings.ContainsAny(a, `/\`):
		return "path"
	case strings.ContainsRune(a, '.') && !strings.ContainsFunc(a, isLetter):
		return "address literal"
	case strings.ContainsRune(a, '.'):
		return "dotted name"
	case strings.ToLower(a) != a:
		return "carries upper case"
	case !strings.ContainsFunc(a, func(r rune) bool { return r < '0' || r > '9' }):
		return "number"
	default:
		return "lower-case word"
	}
}

// isLetter reports whether r is an ASCII letter.
func isLetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }
