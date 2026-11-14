// SPDX-License-Identifier: LGPL-2.1-or-later

// Acceptance for the parser, over the generated profile fixtures.
package profile_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/buengese/go-openvpn/profile"
)

// fixtures writes the profile fixtures and returns them.
func fixtures(t *testing.T) []fixtureFile {
	t.Helper()
	return writeFixtures(t, t.TempDir())
}

// parseFixture parses one fixture from its bytes and directory, so no error
// can carry the path.
func parseFixture(path string) (*profile.Profile, []byte, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, nil, err
	}
	p, err := profile.ParseFileIn(bytes.NewReader(raw), filepath.Dir(path))
	return p, raw, err
}

// countBlocks returns how many inline blocks with the given tag, case-folded,
// a profile recorded.
func countBlocks(p *profile.Profile, tag string) int {
	n := 0
	for _, b := range p.InlineBlocks {
		if strings.EqualFold(b.Tag, tag) {
			n++
		}
	}
	return n
}

// hasDirective reports whether the profile recorded a directive by name.
func hasDirective(p *profile.Profile, name string) bool {
	for _, d := range p.Directives {
		if d.Name == name {
			return true
		}
	}
	return false
}

// TestWrapKeyFileReferenceLoadsNoKey pins that "tls-auth ta.key" loads
// nothing: file references resolve ca, cert and key only.
func TestWrapKeyFileReferenceLoadsNoKey(t *testing.T) {
	fixtures := fixtures(t)
	seen := 0
	for _, f := range fixtures {
		p, _, err := parseFixture(f.path)
		if err != nil {
			continue
		}
		for _, name := range []string{"tls-auth", "tls-crypt"} {
			if !hasDirective(p, name) {
				continue
			}
			seen++
			if countBlocks(p, name) > 0 {
				continue // The block is what loaded the key.
			}
			if (name == "tls-auth" && p.TLSAuth != nil) || (name == "tls-crypt" && p.TLSCrypt != nil) {
				t.Errorf("%s: %q named a file and a key was loaded anyway", f.id(), name)
			}
			for _, ref := range p.FileRefs {
				if ref.Tag == name {
					t.Errorf("%s: %q was recorded as a file reference; only ca, cert "+
						"and key are resolved", f.id(), name)
				}
			}
		}
	}
	requireSome(t, map[string]int{"wrap directives naming a file": seen})
	t.Logf("%d wrap directives naming a file", seen)
}

// TestFileReferencedCA pins that each file reference is read or superseded,
// a read CA builds a pool, and only configs that read a file need a directory.
func TestFileReferencedCA(t *testing.T) {
	fixtures := fixtures(t)
	var refs, loaded, superseded, pools, readers, noDir int
	for _, f := range fixtures {
		p, raw, err := parseFixture(f.path)
		if err != nil {
			continue
		}

		readsAFile := false
		for _, ref := range p.FileRefs {
			refs++
			switch ref.Tag {
			case "ca", "cert", "key":
			default:
				t.Errorf("%s: a %q file reference; only ca, cert and key are resolved",
					f.id(), ref.Tag)
			}
			switch {
			case ref.Loaded && ref.Superseded:
				t.Errorf("%s: a file reference is both read and superseded", f.id())
			case ref.Loaded:
				loaded++
				readsAFile = true
			case ref.Superseded:
				superseded++
			default:
				t.Errorf("%s: a file reference was neither read nor superseded", f.id())
			}
		}

		if readsAFile {
			readers++
		}
		if readsAFile && len(p.CA) > 0 {
			if pool := x509.NewCertPool(); !pool.AppendCertsFromPEM(p.CA) {
				t.Errorf("%s: the CA read from a file builds no certificate pool", f.id())
			} else {
				pools++
			}
		}

		_, err = profile.ParseFile(bytes.NewReader(raw))
		switch {
		case err == nil && readsAFile:
			t.Errorf("%s: parsed from bytes alone, with no directory to read its CA from", f.id())
		case errors.Is(err, profile.ErrNoProfileDir):
			noDir++
			if !readsAFile {
				t.Errorf("%s: refused for want of a directory it does not need", f.id())
			}
		}
	}
	if noDir != readers {
		t.Errorf("%d configs read a file and %d were refused without a directory; "+
			"they are the same configs", readers, noDir)
	}
	requireSome(t, map[string]int{
		"file references": refs, "read": loaded, "superseded": superseded, "pools built": pools,
	})
	t.Logf("%d file references: %d read, %d superseded by an inline block; %d pools built",
		refs, loaded, superseded, pools)
}

func TestLineEndingsDoNotChangeMeaning(t *testing.T) {
	fixtures := fixtures(t)
	flipped := 0
	for _, f := range fixtures {
		raw, err := os.ReadFile(filepath.Clean(f.path))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		lf := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
		crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
		if !bytes.Equal(lf, crlf) {
			flipped++
		}

		dir := filepath.Dir(f.path)
		a, errA := profile.ParseFileIn(bytes.NewReader(lf), dir)
		b, errB := profile.ParseFileIn(bytes.NewReader(crlf), dir)
		if (errA == nil) != (errB == nil) {
			t.Errorf("%s: parses with LF=%v and with CRLF=%v", f.id(), errA == nil, errB == nil)
			continue
		}
		if errA != nil {
			continue
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: the same profile parses differently with CRLF line endings", f.id())
		}
	}
	requireSome(t, map[string]int{"configs compared in both line endings": flipped})
	t.Logf("%d configs compared in both line endings", flipped)
}

// TestParseErrorsNameNoPath pins that a parse error never quotes the path; a
// config's name carries location labels.
func TestParseErrorsNameNoPath(t *testing.T) {
	fixtures := fixtures(t)
	checked := 0
	for _, f := range fixtures {
		_, _, err := parseFixture(f.path)
		if err == nil {
			continue
		}
		checked++
		for _, leak := range []string{f.path, filepath.Base(f.path)} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: a parse error names the file it was reading", f.id())
				break
			}
		}
	}
	requireSome(t, map[string]int{"refusals": checked})
	t.Logf("%d refusals checked", checked)
}

// requireSome fails when a count this suite ranges over is zero, since a
// property over an empty set holds vacuously.
func requireSome(t *testing.T, counts map[string]int) {
	t.Helper()
	for what, n := range counts {
		if n == 0 {
			t.Errorf("no fixture produced any %s; this test asserts nothing", what)
		}
	}
}

// profileDiff reports the fields two profiles disagree on, or "" if none.
// Directives, InlineBlocks and FileRefs record source text and are skipped.
func profileDiff(a, b *profile.Profile) string {
	excluded := map[string]bool{"Directives": true, "InlineBlocks": true, "FileRefs": true}

	va, vb := reflect.ValueOf(*a), reflect.ValueOf(*b)
	var d []string
	for i := range va.NumField() {
		f := va.Type().Field(i)
		if !f.IsExported() || excluded[f.Name] {
			continue
		}
		x, y := va.Field(i).Interface(), vb.Field(i).Interface()

		// Spec does not keep ProtoSet.
		if ra, ok := x.([]profile.Remote); ok {
			x, y = clearProtoSet(ra), clearProtoSet(y.([]profile.Remote))
		}

		// Spec cannot tell a nil byte slice from an empty one.
		if ba, ok := x.([]byte); ok {
			bb, _ := y.([]byte)
			if len(ba) == 0 && len(bb) == 0 {
				continue
			}
		}

		// Compare *StaticKey by value.
		if ka, ok := x.(*profile.StaticKey); ok {
			kb, _ := y.(*profile.StaticKey)
			switch {
			case ka == nil && kb == nil:
			case ka == nil || kb == nil:
				d = append(d, "  "+f.Name+": presence differs")
			case *ka != *kb:
				d = append(d, "  "+f.Name+": key bytes differ")
			}
			continue
		}

		if !reflect.DeepEqual(x, y) {
			d = append(d, fmt.Sprintf("  %s: %v -> %v", f.Name, x, y))
		}
	}
	return strings.Join(d, "\n")
}

func clearProtoSet(rs []profile.Remote) []profile.Remote {
	out := make([]profile.Remote, len(rs))
	for i, r := range rs {
		r.ProtoSet = false
		out[i] = r
	}
	return out
}
