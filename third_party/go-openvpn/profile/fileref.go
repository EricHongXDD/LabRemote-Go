package profile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/buengese/go-openvpn/diag"
)

// ErrNoProfileDir reports a ca, cert or key file reference in a profile parsed
// without a directory to resolve it against.
var ErrNoProfileDir = errors.New(
	"a file reference needs the profile's directory: parse with ParsePath, or with ParseFileIn when the bytes are already read")

// ErrFileRefEscapes reports a ca, cert or key reference that resolves outside
// the profile's own directory.
var ErrFileRefEscapes = errors.New("resolves outside the profile's own directory")

// maxFileRefBytes bounds a file a profile names.
const maxFileRefBytes = 1 << 20

// pendingFileRef is a file reference awaiting resolveFileRefs. Unlike FileRef
// it carries the name.
type pendingFileRef struct {
	tag  string
	name string
	line int
}

// resolveFileRefs reads the files a profile named and records each on
// FileRefs. An inline block of the same tag wins, as in OpenVPN, and the file
// is not opened. Failures are diag.ClassConfig at diag.StageParse and quote the
// name, never the resolved path.
func (p *Profile) resolveFileRefs(refs []pendingFileRef, res fileResolver) error {
	for _, ref := range refs {
		rec := FileRef{Tag: ref.tag, Line: ref.line}
		if p.hasInlineBlock(ref.tag) {
			rec.Superseded = true
			p.FileRefs = append(p.FileRefs, rec)
			continue
		}
		if res == nil {
			return configError(ErrNoProfileDir, ref.tag+" file reference")
		}
		data, err := res.read(ref.name)
		if err != nil {
			return configError(err, ref.tag+" file reference")
		}
		switch ref.tag {
		case "ca":
			p.CA = data
		case "cert":
			p.Cert = data
		case "key":
			p.Key = data
		}
		rec.Loaded = true
		p.FileRefs = append(p.FileRefs, rec)
	}
	return nil
}

// configError wraps a file-reference failure in the diag taxonomy.
func configError(cause error, detail string) error {
	return diag.Wrap(diag.ClassConfig, diag.StageParse, cause, detail)
}

// hasInlineBlock reports whether the profile carried an inline block with the
// given tag, empty or not.
func (p *Profile) hasInlineBlock(tag string) bool {
	for _, b := range p.InlineBlocks {
		if strings.EqualFold(b.Tag, tag) {
			return true
		}
	}
	return false
}

// fileResolver reads a file a profile named. A nil fileResolver means
// references cannot be resolved (ErrNoProfileDir).
type fileResolver interface {
	// read returns the named file's contents. Errors may quote the name but
	// must not contain the resolved path.
	read(name string) ([]byte, error)
}

// dirResolver resolves against a real directory, confined to it.
type dirResolver struct{ dir string }

func (d dirResolver) read(name string) ([]byte, error) { return readConfined(d.dir, name) }

// fsResolver resolves against an fs.FS. Names must pass fs.ValidPath; symlink
// confinement is up to the FS (see ParseFileInFS).
type fsResolver struct{ fsys fs.FS }

func (r fsResolver) read(name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("names no file")
	}
	if !fs.ValidPath(name) {
		return nil, fmt.Errorf("%q %w", name, ErrFileRefEscapes)
	}

	f, err := r.fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, fsErr(err))
	}
	if f == nil {
		// The FS is caller-supplied; nothing below trusts it.
		return nil, fmt.Errorf("%q: the filesystem returned no file", name)
	}
	defer func() { _ = f.Close() }()

	// Anything but a regular file is refused: io.ReadAll caps bytes, not
	// time, and a Read returning (0, nil) forever would never finish.
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, fsErr(err))
	}
	if info == nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}

	// Enforced on the read, not from the stat, which may disagree.
	data, err := io.ReadAll(io.LimitReader(f, maxFileRefBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, fsErr(err))
	}
	if len(data) > maxFileRefBytes {
		return nil, fmt.Errorf("%q is larger than the %d-byte limit on a file a profile names",
			name, maxFileRefBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%q is empty", name)
	}
	return data, nil
}

// fsErr reduces an error from a caller-supplied fs.FS to an fs sentinel, so
// nothing the FS wrote, such as a host path, reaches the error.
func fsErr(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fs.ErrNotExist
	case errors.Is(err, fs.ErrPermission):
		return fs.ErrPermission
	case errors.Is(err, fs.ErrInvalid):
		return fs.ErrInvalid
	default:
		return errors.New("could not be read")
	}
}

// readConfined reads name relative to dir, refusing an absolute name, a walk
// or symlink out of dir, and anything that is not a regular file. Containment
// is tested lexically first and again after resolving symlinks.
func readConfined(dir, name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("names no file")
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) || filepath.IsAbs(name) {
		return nil, fmt.Errorf("%q is an absolute path and %w", name, ErrFileRefEscapes)
	}
	base, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("the profile's own directory is unusable: %w", bareErr(err))
	}
	named := filepath.Join(base, name)
	if !within(base, named) {
		return nil, fmt.Errorf("%q %w", name, ErrFileRefEscapes)
	}

	// Both sides, so a symlinked base directory (macOS temp) compares equal.
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, fmt.Errorf("the profile's own directory is unusable: %w", bareErr(err))
	}
	target, err := filepath.EvalSymlinks(named)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, bareErr(err))
	}
	if !within(realBase, target) {
		return nil, fmt.Errorf("%q %w", name, ErrFileRefEscapes)
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, bareErr(err))
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}

	f, err := os.Open(target)
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, bareErr(err))
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxFileRefBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%q: %w", name, bareErr(err))
	}
	if len(data) > maxFileRefBytes {
		return nil, fmt.Errorf("%q is larger than the %d-byte limit on a file a profile names",
			name, maxFileRefBytes)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%q is empty", name)
	}
	return data, nil
}

// within reports whether target, an absolute cleaned path, is strictly inside
// base.
func within(base, target string) bool {
	if target == base {
		return false
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// bareErr strips the path out of a filesystem error, keeping the reason.
func bareErr(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		return pe.Err
	}
	return err
}
