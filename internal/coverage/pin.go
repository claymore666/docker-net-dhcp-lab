package coverage

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	tagRE      = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.]+)?$`)
	testFuncRE = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\(`)
	testDirs   = []string{"test/integration", "pkg/plugin"}
)

// Pin copies reference.md of the plugin tree at tag into outDir and
// writes tests.txt beside it. It refuses a tree whose HEAD is not the
// tag, or whose working tree is dirty, so the pinned copy is the
// tagged one.
func Pin(treeDir, tag, outDir string) error {
	if !tagRE.MatchString(tag) {
		return fmt.Errorf("tag %q is not vX.Y.Z", tag)
	}
	gitRaw := func(args ...string) ([]byte, error) {
		cmd := exec.Command("git", append([]string{"-C", treeDir}, args...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return out, nil
	}
	git := func(args ...string) (string, error) {
		out, err := gitRaw(args...)
		return strings.TrimSpace(string(out)), err
	}
	head, err := git("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	tagged, err := git("rev-parse", tag+"^{commit}")
	if err != nil {
		return fmt.Errorf("the tree has no tag %s: %w", tag, err)
	}
	if head != tagged {
		return fmt.Errorf("the tree's HEAD %s is not %s (%s): check the tag out first", head[:12], tag, tagged[:12])
	}
	if dirty, err := git("status", "--porcelain", "--untracked-files=no"); err != nil {
		return err
	} else if dirty != "" {
		return fmt.Errorf("the tree has uncommitted changes; pin a clean checkout of %s", tag)
	}
	// Both files are read from the tagged commit, never the working
	// tree: an untracked test file must not land in tests.txt.
	ref, err := gitRaw("show", "HEAD:docs/reference.md")
	if err != nil {
		return err
	}
	tests, err := scanTests(git, gitRaw)
	if err != nil {
		return err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# tag: %s\n# sha: %s\n", tag, head)
	for _, t := range tests {
		sb.WriteString(t + "\n")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "reference.md"), ref, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "tests.txt"), []byte(sb.String()), 0o644)
}

// scanTests lists every top-level Test function of the plugin's
// integration and unit tests as file:TestName, sorted, from the files
// the tagged commit tracks.
func scanTests(git func(...string) (string, error), gitRaw func(...string) ([]byte, error)) ([]string, error) {
	var out []string
	for _, d := range testDirs {
		listing, err := git("ls-tree", "--name-only", "HEAD", d+"/")
		if err != nil {
			return nil, err
		}
		for _, f := range strings.Split(listing, "\n") {
			if path.Dir(f) != d || !strings.HasSuffix(f, "_test.go") {
				continue
			}
			data, err := gitRaw("show", "HEAD:"+f)
			if err != nil {
				return nil, err
			}
			for _, m := range testFuncRE.FindAllSubmatch(data, -1) {
				out = append(out, f+":"+string(m[1]))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// Pinned is one pinned plugin release.
type Pinned struct {
	Tag       string
	SHA       string
	Reference string
	Tests     map[string]bool
}

// LoadPinned reads pinned/<tag> from fsys (rooted at the data
// directory). It refuses a tests.txt whose header names another tag.
func LoadPinned(fsys fs.FS, tag string) (*Pinned, error) {
	ref, err := fs.ReadFile(fsys, path.Join("pinned", tag, "reference.md"))
	if err != nil {
		return nil, err
	}
	txt, err := fs.ReadFile(fsys, path.Join("pinned", tag, "tests.txt"))
	if err != nil {
		return nil, err
	}
	p := &Pinned{Tag: tag, Reference: string(ref), Tests: map[string]bool{}}
	var headerTag string
	sc := bufio.NewScanner(bytes.NewReader(txt))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "# tag: "):
			headerTag = strings.TrimPrefix(line, "# tag: ")
		case strings.HasPrefix(line, "# sha: "):
			p.SHA = strings.TrimPrefix(line, "# sha: ")
		case line == "" || strings.HasPrefix(line, "#"):
		default:
			p.Tests[line] = true
		}
	}
	if headerTag != tag {
		return nil, fmt.Errorf("pinned/%s/tests.txt says tag %q: the directory and the file disagree", tag, headerTag)
	}
	if p.SHA == "" {
		return nil, fmt.Errorf("pinned/%s/tests.txt has no sha line", tag)
	}
	return p, nil
}

// LatestPinned returns the highest tag directory under pinned/.
func LatestPinned(fsys fs.FS) (string, error) {
	entries, err := fs.ReadDir(fsys, "pinned")
	if err != nil {
		return "", err
	}
	var tags []string
	for _, e := range entries {
		if e.IsDir() && tagRE.MatchString(e.Name()) {
			tags = append(tags, e.Name())
		}
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no pinned release under pinned/")
	}
	sort.Slice(tags, func(i, j int) bool { return tagLess(tags[i], tags[j]) })
	return tags[len(tags)-1], nil
}

func tagLess(a, b string) bool {
	am, bm := tagRE.FindStringSubmatch(a), tagRE.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(am[i])
		y, _ := strconv.Atoi(bm[i])
		if x != y {
			return x < y
		}
	}
	// A release outranks its own release candidates.
	if (am[4] == "") != (bm[4] == "") {
		return am[4] != ""
	}
	// rc2 before rc10: compare the number, not the text.
	ar, br := rcNumber(am[4]), rcNumber(bm[4])
	if ar != br {
		return ar < br
	}
	return am[4] < bm[4]
}

func rcNumber(suffix string) int {
	n, _ := strconv.Atoi(strings.TrimLeft(suffix, "-rc"))
	return n
}

// CompareFetched returns "" when the fetched reference.md is the pinned
// one and a one-line difference otherwise.
func CompareFetched(fetched, pinned string) string {
	if fetched == pinned {
		return ""
	}
	fl, pl := strings.Split(fetched, "\n"), strings.Split(pinned, "\n")
	for i := 0; i < len(fl) && i < len(pl); i++ {
		if fl[i] != pl[i] {
			return fmt.Sprintf("the fetched copy and the pinned copy differ at line %d", i+1)
		}
	}
	return fmt.Sprintf("the fetched copy has %d lines, the pinned copy %d", len(fl), len(pl))
}
