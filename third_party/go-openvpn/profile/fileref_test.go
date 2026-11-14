package profile_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/buengese/go-openvpn/diag"
	"github.com/buengese/go-openvpn/profile"
)

// caPEM is a plausible CA body; the parser only has to deliver the bytes.
const caPEM = "-----BEGIN CERTIFICATE-----\nMIIBfixture\n-----END CERTIFICATE-----\n"

// writeProfile writes body to dir as a .ovpn file and returns its path.
func writeProfile(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "profile.ovpn")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	return path
}

// writeFile writes content to name under dir, creating parent directories.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("create directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// configErr asserts that err is a ClassConfig failure at StageParse.
func configErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	var derr *diag.Error
	if !errors.As(err, &derr) {
		t.Fatalf("error is not a *diag.Error: %v", err)
	}
	if derr.Class != diag.ClassConfig {
		t.Errorf("class = %s, want %s", derr.Class, diag.ClassConfig)
	}
	if derr.Stage != diag.StageParse {
		t.Errorf("stage = %s, want %s", derr.Stage, diag.StageParse)
	}
}

// TestParsePathReadsAllThreeAtOnce uses names that differ from the tags so a
// mix-up cannot pass.
func TestParsePathReadsAllThreeAtOnce(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "authority.pem", "CA-BODY\n")
	writeFile(t, dir, "me.pem", "CERT-BODY\n")
	writeFile(t, dir, "me.key", "KEY-BODY\n")
	path := writeProfile(t, dir, "remote vpn.example.test 443\n"+
		"ca authority.pem\ncert me.pem\nkey me.key\n")

	p, err := profile.ParsePath(path)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if string(p.CA) != "CA-BODY\n" || string(p.Cert) != "CERT-BODY\n" || string(p.Key) != "KEY-BODY\n" {
		t.Errorf("material landed in the wrong fields: ca=%q cert=%q key=%q", p.CA, p.Cert, p.Key)
	}
	want := []profile.FileRef{
		{Tag: "ca", Line: 2, Loaded: true},
		{Tag: "cert", Line: 3, Loaded: true},
		{Tag: "key", Line: 4, Loaded: true},
	}
	if !slices.Equal(p.FileRefs, want) {
		t.Errorf("FileRefs = %+v, want %+v", p.FileRefs, want)
	}
}

func TestParsePathResolvesASubdirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join("keys", "ca.crt"), caPEM)
	path := writeProfile(t, dir, "remote vpn.example.test 443\nca keys/ca.crt\n")

	p, err := profile.ParsePath(path)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if string(p.CA) != caPEM {
		t.Errorf("CA = %q, want the file's contents", p.CA)
	}
}

// TestParseStringRefusesAFileReference pins ClassConfig and a message naming
// the call to make instead.
func TestParseStringRefusesAFileReference(t *testing.T) {
	for _, directive := range []string{"ca", "cert", "key"} {
		t.Run(directive, func(t *testing.T) {
			_, err := profile.ParseString("remote vpn.example.test 443\n" +
				directive + " material.pem\n")
			configErr(t, err)
			if !errors.Is(err, profile.ErrNoProfileDir) {
				t.Errorf("error does not wrap ErrNoProfileDir: %v", err)
			}
			if !strings.Contains(err.Error(), "ParsePath") {
				t.Errorf("error does not name the entry point that works: %q", err)
			}
			if !strings.Contains(err.Error(), directive+" file reference") {
				t.Errorf("error does not name the directive: %q", err)
			}
		})
	}
}

// TestInlineBlockWinsWithNoDirectoryAtAll: a superseded reference needs no
// directory.
func TestInlineBlockWinsWithNoDirectoryAtAll(t *testing.T) {
	p, err := profile.ParseString("remote vpn.example.test 443\nca ca.crt\n" +
		"<ca>\n" + caPEM + "</ca>\n")
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if string(p.CA) != caPEM {
		t.Errorf("CA = %q, want the inline block's body", p.CA)
	}
	if len(p.FileRefs) != 1 || !p.FileRefs[0].Superseded {
		t.Errorf("FileRefs = %+v, want one superseded entry", p.FileRefs)
	}
}

// TestInlineBlockWinsOverAFileReference uses a decoy file to prove it is
// never read, whatever the tag's case and wherever the block sits.
func TestInlineBlockWinsOverAFileReference(t *testing.T) {
	for _, tc := range []struct{ tag, order string }{
		{"ca", "ref first"}, {"ca", "block first"},
		{"CA", "ref first"}, {"Ca", "ref first"}, {"cA", "block first"},
	} {
		t.Run(tc.tag+" "+tc.order, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "ca.crt", "DECOY: the file must not be read\n")
			block := "<" + tc.tag + ">\n" + caPEM + "</" + tc.tag + ">\n"
			body := "ca ca.crt\n" + block
			if tc.order == "block first" {
				body = block + "ca ca.crt\n"
			}
			p, err := profile.ParsePath(writeProfile(t, dir, "remote vpn.example.test 443\n"+body))
			if err != nil {
				t.Fatalf("ParsePath: %v", err)
			}
			if string(p.CA) != caPEM {
				t.Errorf("CA = %q, want the inline block's body", p.CA)
			}
			if len(p.FileRefs) != 1 || !p.FileRefs[0].Superseded || p.FileRefs[0].Loaded {
				t.Errorf("FileRefs = %+v, want one superseded, unloaded entry", p.FileRefs)
			}
		})
	}
}

// TestFileReferenceEscapesAreRefused pins ErrFileRefEscapes before anything
// is opened. The secret sits where each escape points.
func TestFileReferenceEscapesAreRefused(t *testing.T) {
	const secret = "SECRET-OUTSIDE-THE-PROFILE-DIRECTORY"

	for _, tc := range []struct {
		name string
		ref  string
	}{
		{"parent, and the file is there", "../secret.txt"},
		{"grandparent", "../../secret.txt"},
		{"a path that does not exist outside the tree", "../../etc/shadow"},
		{"down and back out", "keys/../../secret.txt"},
		{"absolute", "/etc/shadow"},
		{"out of the tree entirely", "../../../../../../etc/passwd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "outer", "profiles")
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatalf("create directory: %v", err)
			}
			writeFile(t, root, "secret.txt", secret)
			writeFile(t, filepath.Join(root, "outer"), "secret.txt", secret)
			path := writeProfile(t, dir, "remote vpn.example.test 443\nca "+tc.ref+"\n")

			p, err := profile.ParsePath(path)
			if p != nil {
				t.Fatalf("a profile pointing outside its directory parsed: CA = %q", p.CA)
			}
			configErr(t, err)
			if !errors.Is(err, profile.ErrFileRefEscapes) {
				t.Errorf("error does not wrap ErrFileRefEscapes: %v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Error("the contents of the escaped file reached the error")
			}
		})
	}
}

// TestFileReferenceWalkingBackInsideIsAllowed: where the name lands is what
// counts, not whether it contains "..".
func TestFileReferenceWalkingBackInsideIsAllowed(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "profiles")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create directory: %v", err)
	}
	writeFile(t, dir, "ca.crt", caPEM)
	path := writeProfile(t, dir, "remote vpn.example.test 443\nca ../profiles/ca.crt\n")

	p, err := profile.ParsePath(path)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if string(p.CA) != caPEM {
		t.Errorf("CA = %q, want the file's contents", p.CA)
	}
}

// TestFileReferenceSymlinkEscapeIsRefused pins that containment is tested
// after EvalSymlinks.
func TestFileReferenceSymlinkEscapeIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege this test will not ask for")
	}
	const secret = "SECRET-BEHIND-A-SYMLINK"

	root := t.TempDir()
	dir := filepath.Join(root, "profiles")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create directory: %v", err)
	}
	outside := writeFile(t, root, "secret.txt", secret)
	if err := os.Symlink(outside, filepath.Join(dir, "ca.crt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	path := writeProfile(t, dir, "remote vpn.example.test 443\nca ca.crt\n")

	p, err := profile.ParsePath(path)
	if p != nil {
		t.Fatalf("a symlink out of the directory was followed: CA = %q", p.CA)
	}
	configErr(t, err)
	if !errors.Is(err, profile.ErrFileRefEscapes) {
		t.Errorf("error does not wrap ErrFileRefEscapes: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("the contents of the linked file reached the error")
	}
}

func TestFileReferenceSymlinkInsideIsAllowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege this test will not ask for")
	}
	dir := t.TempDir()
	real := writeFile(t, dir, "real-ca.crt", caPEM)
	if err := os.Symlink(real, filepath.Join(dir, "ca.crt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	path := writeProfile(t, dir, "remote vpn.example.test 443\nca ca.crt\n")

	p, err := profile.ParsePath(path)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if string(p.CA) != caPEM {
		t.Errorf("CA = %q, want the linked file's contents", p.CA)
	}
}

// TestFileReferenceFailuresAreConfigErrors covers unreadable names inside
// the directory.
func TestFileReferenceFailuresAreConfigErrors(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		dir := t.TempDir()
		path := writeProfile(t, dir, "remote vpn.example.test 443\nca absent.crt\n")
		_, err := profile.ParsePath(path)
		configErr(t, err)
		if strings.Contains(err.Error(), dir) {
			t.Errorf("the resolved path reached the error, which the sweep logs: %q", err)
		}
		if !strings.Contains(err.Error(), `"absent.crt"`) {
			t.Errorf("the error does not quote the name as written: %q", err)
		}
	})

	t.Run("a directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "ca.crt"), 0o750); err != nil {
			t.Fatalf("create directory: %v", err)
		}
		path := writeProfile(t, dir, "remote vpn.example.test 443\nca ca.crt\n")
		_, err := profile.ParsePath(path)
		configErr(t, err)
	})

	t.Run("empty", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "ca.crt", "")
		path := writeProfile(t, dir, "remote vpn.example.test 443\nca ca.crt\n")
		_, err := profile.ParsePath(path)
		configErr(t, err)
	})

	t.Run("oversize", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "ca.crt", strings.Repeat("A", (1<<20)+1))
		path := writeProfile(t, dir, "remote vpn.example.test 443\nca ca.crt\n")
		_, err := profile.ParsePath(path)
		configErr(t, err)
	})

	t.Run("no name at all", func(t *testing.T) {
		dir := t.TempDir()
		path := writeProfile(t, dir, "remote vpn.example.test 443\nca\n")
		if _, err := profile.ParsePath(path); err == nil {
			t.Error("a ca directive naming no file parsed")
		}
	})
}

func TestFileReferenceToleratesTrailingWhitespace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ca.crt", caPEM)
	path := writeProfile(t, dir, "remote vpn.example.test 443\n   ca   ca.crt   \t\n")

	p, err := profile.ParsePath(path)
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if string(p.CA) != caPEM {
		t.Errorf("CA = %q, want the file's contents", p.CA)
	}
}

// TestEntryPointsAgree pins that ParsePath, ParseFileIn and ParseFileInFS
// resolve the same references to the same profile.
func TestEntryPointsAgree(t *testing.T) {
	const src = "remote vpn.example.test 443\nca ca.crt\ncert keys/client.crt\nkey keys/client.key\n"
	files := map[string]string{"ca.crt": caPEM, "keys/client.crt": caPEM, "keys/client.key": inertKey}

	dir := t.TempDir()
	mapFS := fstest.MapFS{}
	for name, body := range files {
		writeFile(t, dir, name, body)
		mapFS[name] = &fstest.MapFile{Data: []byte(body)}
	}

	fromPath, err := profile.ParsePath(writeProfile(t, dir, src))
	if err != nil {
		t.Fatalf("ParsePath: %v", err)
	}
	if string(fromPath.CA) != caPEM || string(fromPath.Key) != inertKey || len(fromPath.FileRefs) != 3 {
		t.Fatalf("ParsePath did not read all three files: %+v", fromPath.FileRefs)
	}
	fromDir, err := profile.ParseFileIn(strings.NewReader(src), dir)
	if err != nil {
		t.Fatalf("ParseFileIn: %v", err)
	}
	fromFS, err := profile.ParseFileInFS(strings.NewReader(src), mapFS)
	if err != nil {
		t.Fatalf("ParseFileInFS: %v", err)
	}
	for name, p := range map[string]*profile.Profile{"ParseFileIn": fromDir, "ParseFileInFS": fromFS} {
		if diff := profileDiff(fromPath, p); diff != "" {
			t.Errorf("%s disagrees with ParsePath:\n%s", name, diff)
		}
		if !slices.Equal(p.FileRefs, fromPath.FileRefs) {
			t.Errorf("%s FileRefs = %+v, want %+v", name, p.FileRefs, fromPath.FileRefs)
		}
	}

	if _, err := profile.ParseFileIn(strings.NewReader(src), ""); !errors.Is(err, profile.ErrNoProfileDir) {
		t.Errorf("ParseFileIn with no directory: %v, want ErrNoProfileDir", err)
	}
}

// TestParseFileInFSRefusesEscapes is the FS parallel of
// TestFileReferenceEscapesAreRefused.
func TestParseFileInFSRefusesEscapes(t *testing.T) {
	const secret = "SECRET-OUTSIDE-THE-ARCHIVE"

	for _, tc := range []struct {
		name string
		ref  string
	}{
		{"parent", "../secret.txt"},
		{"grandparent", "../../secret.txt"},
		{"down and back out", "keys/../../secret.txt"},
		{"absolute", "/etc/shadow"},
		{"out of the tree entirely", "../../../../../../etc/passwd"},
		{"a bare parent", ".."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Present under both spellings, so a refusal is the guard working.
			fsys := fstest.MapFS{
				"secret.txt":    {Data: []byte(secret)},
				"../secret.txt": {Data: []byte(secret)},
				"etc/shadow":    {Data: []byte(secret)},
				"/etc/shadow":   {Data: []byte(secret)},
				"etc/passwd":    {Data: []byte(secret)},
			}
			src := "remote vpn.example.test 443\nca " + tc.ref + "\n"

			p, err := profile.ParseFileInFS(strings.NewReader(src), fsys)
			if p != nil {
				t.Fatalf("a profile pointing outside the FS parsed: CA = %q", p.CA)
			}
			if err == nil {
				t.Fatal("no error")
			}
			if !errors.Is(err, profile.ErrFileRefEscapes) {
				t.Errorf("error does not wrap ErrFileRefEscapes: %v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Error("the contents of the escaped file reached the error")
			}
		})
	}
}

// TestParseFileInFSIsStricterAboutNames pins that fs.ValidPath refuses any
// "..", even one that lands back inside.
func TestParseFileInFSIsStricterAboutNames(t *testing.T) {
	const src = "remote vpn.example.test 443\nca ../profiles/ca.crt\n"

	root := t.TempDir()
	dir := filepath.Join(root, "profiles")
	writeFile(t, dir, "ca.crt", caPEM)
	if _, err := profile.ParseFileIn(strings.NewReader(src), dir); err != nil {
		t.Fatalf("ParseFileIn refused a walk back inside: %v", err)
	}

	fsys := fstest.MapFS{"profiles/ca.crt": {Data: []byte(caPEM)}}
	_, err := profile.ParseFileInFS(strings.NewReader(src), fsys)
	if err == nil {
		t.Fatal("ParseFileInFS accepted a name with a .. element")
	}
	if !errors.Is(err, profile.ErrFileRefEscapes) {
		t.Errorf("error does not wrap ErrFileRefEscapes: %v", err)
	}
}

func TestParseFileInFSRefusesNonRegularAndOversized(t *testing.T) {
	t.Run("a directory is not a file", func(t *testing.T) {
		fsys := fstest.MapFS{"ca.crt/inner": {Data: []byte(caPEM)}}
		if _, err := profile.ParseFileInFS(
			strings.NewReader("remote a.test 443\nca ca.crt\n"), fsys); err == nil {
			t.Error("a directory was read as a CA")
		}
	})

	t.Run("an empty file is refused", func(t *testing.T) {
		fsys := fstest.MapFS{"ca.crt": {Data: []byte{}}}
		_, err := profile.ParseFileInFS(
			strings.NewReader("remote a.test 443\nca ca.crt\n"), fsys)
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Errorf("error = %v, want it to name the file as empty", err)
		}
	})

	t.Run("an oversized file is refused", func(t *testing.T) {
		fsys := fstest.MapFS{"ca.crt": {Data: make([]byte, (1<<20)+1)}}
		_, err := profile.ParseFileInFS(
			strings.NewReader("remote a.test 443\nca ca.crt\n"), fsys)
		if err == nil || !strings.Contains(err.Error(), "limit") {
			t.Errorf("error = %v, want it to name the size limit", err)
		}
	})
}

// TestParseFileInFSWithNoFSRefusesAReference pins that a nil fsys behaves
// as ParseFile does.
func TestParseFileInFSWithNoFSRefusesAReference(t *testing.T) {
	_, err := profile.ParseFileInFS(strings.NewReader("remote a.test 443\nca ca.crt\n"), nil)
	if !errors.Is(err, profile.ErrNoProfileDir) {
		t.Errorf("error = %v, want ErrNoProfileDir", err)
	}
	p, err := profile.ParseFileInFS(
		strings.NewReader("remote a.test 443\n<ca>\n"+caPEM+"</ca>\n"), nil)
	if err != nil {
		t.Fatalf("a profile with no reference failed: %v", err)
	}
	if string(p.CA) != caPEM {
		t.Error("the inline CA did not survive")
	}
}

// TestOpenRootFSRefusesASymlinkEscapeAndDirFSDoesNot backs the warning in
// ParseFileInFS's doc comment.
func TestOpenRootFSRefusesASymlinkEscapeAndDirFSDoesNot(t *testing.T) {
	const secret = "SECRET-REACHED-THROUGH-A-SYMLINK"

	root := t.TempDir()
	dir := filepath.Join(root, "profiles")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("create directory: %v", err)
	}
	writeFile(t, root, "secret.txt", secret)
	if err := os.Symlink(filepath.Join(root, "secret.txt"), filepath.Join(dir, "ca.crt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	src := "remote vpn.example.test 443\nca ca.crt\n"

	// ParseFileIn refuses: containment is tested after EvalSymlinks.
	if _, err := profile.ParseFileIn(strings.NewReader(src), dir); err == nil {
		t.Error("ParseFileIn followed a symlink out of the profile's directory")
	} else if !errors.Is(err, profile.ErrFileRefEscapes) {
		t.Errorf("ParseFileIn error does not wrap ErrFileRefEscapes: %v", err)
	}

	p, err := profile.ParseFileInFS(strings.NewReader(src), os.DirFS(dir))
	if err == nil && string(p.CA) == secret {
		t.Log("confirmed: os.DirFS followed the symlink, as its documentation says it does — " +
			"this is why ParseFileIn is not defined in terms of it")
	} else {
		t.Logf("os.DirFS refused it on this platform (err=%v); the warning is still right "+
			"for the platforms where it does not", err)
	}

	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("os.OpenRoot: %v", err)
	}
	defer func() { _ = r.Close() }()
	got, err := profile.ParseFileInFS(strings.NewReader(src), r.FS())
	if err == nil {
		t.Errorf("os.OpenRoot(dir).FS() followed the symlink: CA = %q", got.CA)
	}
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Error("the escaped file's contents reached the error")
	}
}

// FuzzParseFileInFS fuzzes the resolver path, which FuzzParseString cannot
// reach.
func FuzzParseFileInFS(f *testing.F) {
	f.Add("remote vpn.example.test 443\nca ca.crt\n", "ca.crt", caPEM)
	f.Add("remote vpn.example.test 443\nca ../escape\n", "escape", "SECRET")
	f.Add("remote vpn.example.test 443\nca /absolute\n", "absolute", "SECRET")
	f.Add("remote vpn.example.test 443\ncert c\nkey k\n", "c", caPEM)
	f.Add("remote vpn.example.test 443\nca .\n", "ca.crt", "")
	f.Add("remote vpn.example.test 443\nca a/b/c\n", "a/b/c", caPEM)
	f.Add("remote vpn.example.test 443\nca ca.crt\n<ca>\n"+caPEM+"</ca>\n", "ca.crt", "SECRET")

	f.Fuzz(func(t *testing.T, src, name, body string) {
		fsys := fstest.MapFS{name: {Data: []byte(body)}}

		p, err := profile.ParseFileInFS(strings.NewReader(src), fsys)
		if err != nil {
			// The error must not carry the file's body.
			if len(body) > 8 && strings.Contains(err.Error(), body) {
				t.Fatalf("a file's contents reached the error: %v", err)
			}
			return
		}
		if p == nil {
			t.Fatal("no profile and no error")
		}
		for _, ref := range p.FileRefs {
			if ref.Loaded && !fs.ValidPath(name) {
				t.Fatalf("%s loaded from %q, which is not a valid FS path", ref.Tag, name)
			}
		}
	})
}

// hostileFS is an fs.FS that implements no Stat and returns a nil file, a
// nil FileInfo, or a Read that makes no progress.
type hostileFS struct{ mode hostileMode }

type hostileMode int

const (
	hostileNilFile hostileMode = iota
	hostileStatErrors
	hostileNilInfo
	hostileNoProgress
	hostilePathInError
)

func (h hostileFS) Open(name string) (fs.File, error) {
	switch h.mode {
	case hostileNilFile:
		return nil, nil
	case hostilePathInError:
		return nil, errors.New("could not open /home/victim/secrets/" + name + ": permission denied")
	default:
		return &hostileFile{mode: h.mode}, nil
	}
}

type hostileFile struct{ mode hostileMode }

func (f *hostileFile) Stat() (fs.FileInfo, error) {
	switch f.mode {
	case hostileStatErrors:
		return nil, errors.New("stat says /home/victim/secrets is off limits")
	case hostileNilInfo:
		return nil, nil
	default:
		return nil, errors.New("no stat")
	}
}
func (f *hostileFile) Read([]byte) (int, error) { return 0, nil } // never progresses
func (f *hostileFile) Close() error             { return nil }

// TestParseFileInFSSurvivesAHostileFS pins that the resolver refuses rather
// than panicking or hanging, and leaks nothing the FS wrote.
func TestParseFileInFSSurvivesAHostileFS(t *testing.T) {
	const src = "remote vpn.example.test 443\nca ca.crt\n"

	for name, mode := range map[string]hostileMode{
		"Open returns a nil file": hostileNilFile,
		"Stat errors":             hostileStatErrors,
		"Stat returns a nil info": hostileNilInfo,
		"Read never progresses":   hostileNoProgress,
		"the error names a path":  hostilePathInError,
	} {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				_, err := profile.ParseFileInFS(strings.NewReader(src), hostileFS{mode})
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a hostile FS was accepted")
				}
				if strings.Contains(err.Error(), "/home/victim") {
					t.Errorf("the FS's own path reached the error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the parser did not return; a non-regular file hung the read")
			}
		})
	}
}
