// SPDX-License-Identifier: LGPL-2.1-or-later

// Acceptance for the capability registry, over the generated profile fixtures.
//
// caps.Inspect runs over every fixture and the result is aggregated into a
// feature matrix — how many configs, how many gaps, the severity split per
// directive — which is committed as testdata/registry-matrix.golden.
//
// The fixtures instantiate every registry row, so a regrade of any directive
// moves a cell here and the diff is the review's evidence. That is the whole
// point of generating them: a set of real provider profiles graded 58 of the
// 91 rows, and the other 33 could be regraded without moving a number.
//
// Regenerate after a deliberate registry change:
//
//	go test ./caps -run TestRegistryMatrix -update
package caps_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/caps"
	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/profile"
)

// updateGolden rewrites this package's committed artifacts — the registry
// matrix and the shape inventory — instead of asserting against them.
var updateGolden = flag.Bool("update", false,
	"rewrite caps/testdata/*.golden and shape-inventory.txt from the fixtures")

const (
	// goldenPath is the committed matrix over the fixtures.
	goldenPath = "testdata/registry-matrix.golden"
	// regenCmd is quoted verbatim in failure output and in the golden header.
	regenCmd = "go test ./caps -run TestRegistryMatrix -update"
	// nameCol and numCol are fixed column widths. They are deliberately not
	// derived from the data: a width that grew with the longest name would
	// re-align every line of the file whenever one row changed.
	nameCol = 28
	numCol  = 10
)

// severities is the severity order used for every column set in the matrix.
var severities = [...]diag.Severity{
	diag.SeveritySupported,
	diag.SeverityIgnored,
	diag.SeverityDegraded,
	diag.SeverityFatal,
}

// severityCols are the column headings for a tally, in severities order.
var severityCols = []string{"supported", "ignored", "degraded", "fatal"}

// tally counts gaps by severity, indexed as severities is ordered.
type tally [len(severities)]int

// add records one observation at severity s. An out-of-range severity is
// dropped rather than panicking; the totals row would show the discrepancy.
func (t *tally) add(s diag.Severity) {
	if int(s) >= 0 && int(s) < len(t) {
		t[s]++
	}
}

// total is the number of observations across all severities.
func (t tally) total() int {
	sum := 0
	for _, v := range t {
		sum += v
	}
	return sum
}

// counts returns the tally as a column slice, in severities order.
func (t tally) counts() []int {
	out := make([]int, len(t))
	copy(out, t[:])
	return out
}

// row is one line of a table: a name, the number of configs it was seen in,
// and its gap tally.
type row struct {
	name    string
	configs int
	gaps    tally
}

// matrix is the whole aggregate.
type matrix struct {
	configs        int
	directiveLines int
	inlineBlocks   int
	gaps           int
	// impliedGaps are gaps Inspect reports for something the profile does
	// *not* say — today only the SHA1 digest a CBC profile inherits by
	// omitting auth. Counted generically as the excess of gaps over recorded
	// directive lines and inline blocks, so another implied gap is picked up
	// without naming it here.
	impliedGaps    int
	impliedConfigs int
	unrecognisedD  int
	unrecognisedB  int
	// refused counts configs the parser declined outright. It is a row rather
	// than a tolerance: the fixtures gaining or losing a refusal is a change
	// worth seeing.
	refused int

	severity   tally
	worst      tally
	groups     []row
	directives []row
}

// buildMatrix parses and inspects every file exactly once, reporting any parse
// failure without echoing config content.
func buildMatrix(t *testing.T, fixtures []fixtureFile) *matrix {
	t.Helper()
	m := &matrix{}
	perGroup := map[string]*row{}
	perDirective := map[string]*row{}

	for _, f := range fixtures {
		p, err := parseFixture(f.path)
		if err != nil {
			m.refused++
			t.Logf("parse refused: provider=%s file=%s: %s", f.group, f.id(), err)
			continue
		}
		gaps := caps.Inspect(p)

		m.configs++
		m.directiveLines += len(p.Directives)
		m.inlineBlocks += len(p.InlineBlocks)
		m.gaps += len(gaps)
		if implied := len(gaps) - len(p.Directives) - len(p.InlineBlocks); implied > 0 {
			m.impliedGaps += implied
			m.impliedConfigs++
		}
		m.worst.add(caps.Worst(gaps))

		prov := perGroup[f.group]
		if prov == nil {
			prov = &row{name: f.group}
			perGroup[f.group] = prov
		}
		prov.configs++

		seen := map[string]bool{}
		for _, g := range gaps {
			name := g.Directive
			d := perDirective[name]
			if d == nil {
				d = &row{name: name}
				perDirective[name] = d
			}
			if !seen[name] {
				seen[name] = true
				d.configs++
			}
			d.gaps.add(g.Severity)
			prov.gaps.add(g.Severity)
			m.severity.add(g.Severity)
			if !recognised(g) {
				if isBlockGap(g) {
					m.unrecognisedB++
				} else {
					m.unrecognisedD++
				}
			}
		}
	}

	m.groups = sortedRows(perGroup)
	m.directives = sortedRows(perDirective)
	return m
}

// parseFixture parses one fixture. It opens the file itself rather than
// calling profile.ParsePath, so that a parse error never carries the path, and
// still hands the parser the profile's directory: a config naming its CA in a
// file beside it would otherwise be refused for want of a directory rather
// than misgraded on its merits.
func parseFixture(path string) (*profile.Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return profile.ParseFileIn(f, filepath.Dir(path))
}

// sortedRows flattens a row map into a name-sorted slice.
func sortedRows(byName map[string]*row) []row {
	out := make([]row, 0, len(byName))
	for _, r := range byName {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// isBlockGap reports whether a gap came from an inline <tag> block.
func isBlockGap(g diag.Gap) bool {
	return strings.HasPrefix(g.Directive, "<") && strings.HasSuffix(g.Directive, ">")
}

// recognised reports whether the registry has a row for the gap's directive.
// A false here is a registry fall-through, which
// TestRegistryHasNoFallThrough asserts must not happen.
func recognised(g diag.Gap) bool {
	if isBlockGap(g) {
		_, ok := caps.LookupBlock(strings.Trim(g.Directive, "<>"))
		return ok
	}
	_, ok := caps.Lookup(g.Directive)
	return ok
}

// ---- Rendering -------------------------------------------------------

// goldenHeader opens the committed matrix. It is part of the file so a reader
// who opens it without the test knows what it is and how to regenerate it.
const goldenHeader = `# capability matrix over the generated fixtures — go-openvpn
#
# Aggregate of caps.Inspect over the fixtures in caps/fixtures_test.go, which
# instantiate every registry row. A change here is a change in how a directive
# is graded.
#
# Regenerate after a deliberate registry change:
#   ` + regenCmd + `
#
# Table columns are gap counts by severity. "configs" is how many profiles the
# row was seen in at all.
`

// item writes a single name/value line, aligned with the tables.
func item(b *strings.Builder, name string, value int) {
	fmt.Fprintf(b, "  %-*s %*d\n", nameCol, name, numCol, value)
}

// heading writes a table heading aligned with the rows beneath it.
func heading(b *strings.Builder, name string, cols ...string) {
	fmt.Fprintf(b, "  %-*s", nameCol, name)
	for _, c := range cols {
		fmt.Fprintf(b, " %*s", numCol, c)
	}
	b.WriteByte('\n')
}

// line writes one table row.
func line(b *strings.Builder, name string, values ...int) {
	fmt.Fprintf(b, "  %-*s", nameCol, name)
	for _, v := range values {
		fmt.Fprintf(b, " %*d", numCol, v)
	}
	b.WriteByte('\n')
}

// render produces the matrix text under the given header.
func (m *matrix) render(header string) string {
	var b strings.Builder
	b.WriteString(header)

	b.WriteString("\nfixtures\n")
	item(&b, "groups", len(m.groups))
	item(&b, "configs", m.configs)
	item(&b, "refused", m.refused)
	item(&b, "directive lines", m.directiveLines)
	item(&b, "inline blocks", m.inlineBlocks)
	item(&b, "gaps", m.gaps)
	item(&b, "implied gaps", m.impliedGaps)
	item(&b, "configs with implied gaps", m.impliedConfigs)
	item(&b, "unrecognised directives", m.unrecognisedD)
	item(&b, "unrecognised blocks", m.unrecognisedB)

	b.WriteString("\nseverity totals\n")
	for i, name := range severityCols {
		item(&b, name, m.severity[i])
	}

	b.WriteString("\nconfigs by worst severity\n")
	for i, name := range severityCols {
		item(&b, name, m.worst[i])
	}

	b.WriteString("\nper group\n")
	heading(&b, "group", append([]string{"configs", "gaps"}, severityCols...)...)
	for _, r := range m.groups {
		line(&b, r.name, append([]int{r.configs, r.gaps.total()}, r.gaps.counts()...)...)
	}

	b.WriteString("\nper directive\n")
	heading(&b, "directive", append([]string{"configs", "gaps"}, severityCols...)...)
	for _, r := range m.directives {
		line(&b, r.name, append([]int{r.configs, r.gaps.total()}, r.gaps.counts()...)...)
	}

	return b.String()
}

// ---- Tests -----------------------------------------------------------

// fixtures writes the profile fixtures and returns them.
func fixtures(t *testing.T) []fixtureFile {
	t.Helper()
	return writeFixtures(t, t.TempDir())
}

func TestRegistryMatrix(t *testing.T) {
	fixtures := fixtures(t)
	m := buildMatrix(t, fixtures)
	if m.configs+m.refused != len(fixtures) {
		t.Errorf("accounted for %d of %d configs (%d parsed, %d refused)",
			m.configs+m.refused, len(fixtures), m.configs, m.refused)
	}
	t.Logf("%d of %d fixtures across %d groups (%d refused); %d gaps, %d unrecognised",
		m.configs, len(fixtures), len(m.groups), m.refused, m.gaps,
		m.unrecognisedD+m.unrecognisedB)

	assertGolden(t, m)
}

// assertGolden holds the fixtures to the committed matrix.
func assertGolden(t *testing.T, m *matrix) {
	t.Helper()
	got := m.render(goldenHeader)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d bytes)", goldenPath, len(got))
		return
	}
	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v\nregenerate with:\n  %s", err, regenCmd)
	}
	if want := string(wantBytes); got != want {
		t.Errorf("the capability matrix differs from %s\n"+
			"if the change is intended, regenerate with:\n  %s\n\n%s",
			goldenPath, regenCmd, diffLines(strings.Split(want, "\n"), strings.Split(got, "\n")))
	}
}

// TestRegistryHasNoFallThrough asserts that every directive the fixtures
// carry classifies: none of them reaches the unrecognised catch-all.
func TestRegistryHasNoFallThrough(t *testing.T) {
	fixtures := fixtures(t)
	unrecognised := map[string]int{}
	for _, f := range fixtures {
		p, err := parseFixture(f.path)
		if err != nil {
			continue // TestRegistryMatrix reports parse failures.
		}
		for _, g := range caps.Inspect(p) {
			if !recognised(g) {
				unrecognised[g.Directive]++
			}
		}
	}
	for name, n := range unrecognised {
		t.Errorf("directive %q falls through the registry in %d places", name, n)
	}
}

// TestGoldenIsCountsAndNamesOnly is the standing guard on the committed matrix:
// it stays a table of counts and directive keywords, whatever the renderer is
// later asked to add.
//
// The grammar is written out here rather than shared. It used to come from a
// package the provider sweep and this file both used, back when the sweep
// committed documents measured from a corpus of real profiles and the rule was
// about what may be written down. The sweep and that rule left together; what
// survives is narrower and local — an aggregate is counts and names, and a
// renderer that started emitting argument values would be a bug either way.
func TestGoldenIsCountsAndNamesOnly(t *testing.T) {
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if len(data) > 64*1024 {
		t.Fatalf("golden is %d bytes; an aggregate matrix has no business being that large", len(data))
	}
	text := string(data)

	// The whole file, comments included: the field check below never sees the
	// header.
	for _, marker := range []string{"-----BEGIN", "-----END", "@", "://"} {
		if strings.Contains(text, marker) {
			t.Errorf("golden contains %q, which no aggregate count needs", marker)
		}
	}

	// Every data line is counts and names. Nothing but lowercase words and
	// decimal integers gets through, which rules out paths, file names, PEM
	// fragments and argument values by construction.
	for i, ln := range strings.Split(text, "\n") {
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		for _, field := range strings.Fields(ln) {
			if _, err := strconv.Atoi(field); err == nil {
				continue
			}
			if !isPlainName(field) {
				t.Errorf("golden line %d: field %q is neither a count nor a plain name", i+1, field)
			}
		}
	}
}

// isPlainName reports whether a field is a directive keyword or a group name:
// lowercase ASCII, digits, hyphen and underscore, optionally wrapped in angle
// brackets for an inline block tag. No dot, slash, colon or upper case, so a
// path or an argument value cannot pass it.
func isPlainName(s string) bool {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "<"), ">")
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// TestGoldenIsSelfConsistent catches a hand-edited matrix: the per directive
// table accounts for every gap, so its columns must sum to the severity
// totals. It reads only the committed file.
func TestGoldenIsSelfConsistent(t *testing.T) {
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	var section string
	totals := map[string]int{}
	summed := map[string]int{}
	totalGaps := -1
	for _, ln := range strings.Split(string(data), "\n") {
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if !strings.HasPrefix(ln, "  ") {
			section = strings.TrimSpace(ln)
			continue
		}
		fields := strings.Fields(ln)
		switch section {
		case "fixtures":
			if len(fields) == 2 && fields[0] == "gaps" {
				totalGaps, _ = strconv.Atoi(fields[1])
			}
		case "severity totals":
			if len(fields) == 2 {
				if n, err := strconv.Atoi(fields[1]); err == nil {
					totals[fields[0]] = n
				}
			}
		case "per directive":
			// name configs gaps supported ignored degraded fatal
			if len(fields) != 3+len(severityCols) || fields[1] == "configs" {
				continue
			}
			for i, name := range severityCols {
				n, err := strconv.Atoi(fields[3+i])
				if err != nil {
					t.Fatalf("per directive row %q: column %s is not a number", fields[0], name)
				}
				summed[name] += n
			}
		}
	}

	sum := 0
	for _, name := range severityCols {
		if totals[name] != summed[name] {
			t.Errorf("severity totals say %s=%d, per directive rows sum to %d", name, totals[name], summed[name])
		}
		sum += summed[name]
	}
	if totalGaps != sum {
		t.Errorf("the fixtures section says %d gaps, per directive rows sum to %d", totalGaps, sum)
	}
}

// ---- Diff ------------------------------------------------------------

// op is one line of a rendered diff: kept, removed or added. line is the
// 1-based line number in the file being compared against, and is 0 for an
// added line.
type op struct {
	kind byte // ' ', '-' or '+'
	text string
	line int
}

// diffContext is how many unchanged lines are shown around each hunk.
const diffContext = 2

// maxDiffLines bounds the failure output. A diff longer than this is a
// wholesale regeneration, not something a reviewer reads line by line.
const maxDiffLines = 200

// diffLines renders a unified-style diff of want against got. The matrix is a
// stable, sorted, one-row-per-directive table, so a registry change shows up as
// a handful of ± pairs on the rows that moved rather than a re-flowed wall of
// numbers. Nothing here can print config content: both inputs are the
// aggregate.
func diffLines(want, got []string) string {
	n, m := len(want), len(got)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if want[i] == got[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
				continue
			}
			if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case want[i] == got[j]:
			ops = append(ops, op{' ', want[i], i + 1})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, op{'-', want[i], i + 1})
			i++
		default:
			ops = append(ops, op{'+', got[j], 0})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{'-', want[i], i + 1})
	}
	for ; j < m; j++ {
		ops = append(ops, op{'+', got[j], 0})
	}

	// Keep only changed lines plus a little context around them.
	keep := make([]bool, len(ops))
	for k, o := range ops {
		if o.kind == ' ' {
			continue
		}
		lo, hi := k-diffContext, k+diffContext
		if lo < 0 {
			lo = 0
		}
		if hi >= len(ops) {
			hi = len(ops) - 1
		}
		for x := lo; x <= hi; x++ {
			keep[x] = true
		}
	}

	var b strings.Builder
	b.WriteString("--- recorded\n+++ caps.Inspect over the fixtures\n")
	shown, gap := 0, true
	for k, o := range ops {
		if !keep[k] {
			gap = true
			continue
		}
		if shown >= maxDiffLines {
			fmt.Fprintf(&b, "... diff truncated at %d lines\n", maxDiffLines)
			break
		}
		if gap {
			fmt.Fprintf(&b, "@@ line %d @@\n", hunkStart(ops, k))
			gap = false
		}
		fmt.Fprintf(&b, "%c %s\n", o.kind, o.text)
		shown++
	}
	return b.String()
}

// hunkStart is the line number a hunk beginning at ops[k] refers to. An
// addition has no line of its own, so the nearest following one is used,
// falling back to the end of the file.
func hunkStart(ops []op, k int) int {
	for _, o := range ops[k:] {
		if o.line > 0 {
			return o.line
		}
	}
	return 0
}
