package coverage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// gitIn runs git in dir with a fixed identity, so the tests depend on no
// global configuration.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)
	out, err := exec.Command("git", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// pluginTree builds a tiny git repository shaped like the plugin: a
// docs/reference.md and test files in the two scanned directories, with
// one commit tagged v9.9.9.
func pluginTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	writeFile(t, filepath.Join(dir, "docs", "reference.md"), miniMD)
	writeFile(t, filepath.Join(dir, "pkg", "plugin", "a_test.go"), "package plugin\n\nfunc TestB(t *testing.T) {}\nfunc TestA(t *testing.T) {}\nfunc helper() {}\nfunc benchmarkX() {}\n")
	writeFile(t, filepath.Join(dir, "test", "integration", "i_test.go"), "package integration\n\nfunc TestI(t *testing.T) {}\n")
	writeFile(t, filepath.Join(dir, "pkg", "plugin", "notatest.go"), "package plugin\n\nfunc TestNotInATestFile() {}\n")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "tree")
	gitIn(t, dir, "tag", "v9.9.9")
	return dir
}

func TestPin_WritesReferenceAndSortedTests(t *testing.T) {
	tree := pluginTree(t)
	out := filepath.Join(t.TempDir(), "pinned", "v9.9.9")
	if err := Pin(tree, "v9.9.9", out); err != nil {
		t.Fatal(err)
	}
	ref, err := os.ReadFile(filepath.Join(out, "reference.md"))
	if err != nil || string(ref) != miniMD {
		t.Fatalf("reference.md is not the tree's copy: %v", err)
	}
	txt, err := os.ReadFile(filepath.Join(out, "tests.txt"))
	if err != nil {
		t.Fatal(err)
	}
	sha := gitIn(t, tree, "rev-parse", "HEAD")
	want := "# tag: v9.9.9\n# sha: " + sha + "\n" +
		"pkg/plugin/a_test.go:TestA\npkg/plugin/a_test.go:TestB\ntest/integration/i_test.go:TestI\n"
	if string(txt) != want {
		t.Errorf("tests.txt =\n%s\nwant\n%s", txt, want)
	}
}

func TestPin_RefusesATreeWhoseHeadIsNotTheTag(t *testing.T) {
	tree := pluginTree(t)
	writeFile(t, filepath.Join(tree, "docs", "reference.md"), miniMD+"\nmore\n")
	gitIn(t, tree, "commit", "-q", "-a", "-m", "after the tag")
	out := filepath.Join(t.TempDir(), "o")
	err := Pin(tree, "v9.9.9", out)
	if err == nil || !strings.Contains(err.Error(), "is not v9.9.9") {
		t.Fatalf("a tree past the tag must be refused, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(out, "reference.md")); serr == nil {
		t.Error("nothing may be written for a refused tree")
	}
}

func TestPin_RefusesATagTheTreeDoesNotHave(t *testing.T) {
	tree := pluginTree(t)
	if err := Pin(tree, "v1.2.3", filepath.Join(t.TempDir(), "o")); err == nil || !strings.Contains(err.Error(), "no tag v1.2.3") {
		t.Fatalf("an unknown tag must be refused, got %v", err)
	}
}

func TestPin_RefusesADirtyTree(t *testing.T) {
	tree := pluginTree(t)
	writeFile(t, filepath.Join(tree, "docs", "reference.md"), miniMD+"\nlocal edit\n")
	err := Pin(tree, "v9.9.9", filepath.Join(t.TempDir(), "o"))
	if err == nil || !strings.Contains(err.Error(), "uncommitted changes") {
		t.Fatalf("a dirty tree must be refused, got %v", err)
	}
}

func TestPin_RefusesATagThatIsNotAVersion(t *testing.T) {
	tree := pluginTree(t)
	for _, tag := range []string{"main", "9.9.9", "v9.9", "../x"} {
		if err := Pin(tree, tag, filepath.Join(t.TempDir(), "o")); err == nil || !strings.Contains(err.Error(), "not vX.Y.Z") {
			t.Errorf("tag %q must be refused, got %v", tag, err)
		}
	}
}

func TestLoadPinned_RoundTripsWhatPinWrote(t *testing.T) {
	tree := pluginTree(t)
	root := t.TempDir()
	if err := Pin(tree, "v9.9.9", filepath.Join(root, "pinned", "v9.9.9")); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPinned(os.DirFS(root), "v9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if p.SHA != gitIn(t, tree, "rev-parse", "HEAD") || !p.Tests["pkg/plugin/a_test.go:TestA"] || len(p.Tests) != 3 || p.Reference != miniMD {
		t.Errorf("round trip lost something: %+v", p)
	}
}

func TestLoadPinned_RefusesAMismatchedTag(t *testing.T) {
	fsys := fstest.MapFS{
		"pinned/v1.0.0/reference.md": {Data: []byte("x")},
		"pinned/v1.0.0/tests.txt":    {Data: []byte("# tag: v2.0.0\n# sha: abc\na:TestA\n")},
	}
	if _, err := LoadPinned(fsys, "v1.0.0"); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("a header tag that differs from the directory must be refused, got %v", err)
	}
	fsys["pinned/v1.0.0/tests.txt"] = &fstest.MapFile{Data: []byte("# tag: v1.0.0\na:TestA\n")}
	if _, err := LoadPinned(fsys, "v1.0.0"); err == nil || !strings.Contains(err.Error(), "no sha line") {
		t.Fatalf("a missing sha line must be refused, got %v", err)
	}
}

func TestLatestPinned_OrdersBySemverAndReleaseOverRC(t *testing.T) {
	mk := func(names ...string) fstest.MapFS {
		f := fstest.MapFS{}
		for _, n := range names {
			f["pinned/"+n+"/reference.md"] = &fstest.MapFile{Data: []byte("x")}
		}
		return f
	}
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"v2.5.0", "v2.10.0", "v2.9.0"}, "v2.10.0"},
		{[]string{"v2.5.0-rc1", "v2.5.0"}, "v2.5.0"},
		{[]string{"v2.5.0-rc2", "v2.5.0-rc10", "v2.4.9"}, "v2.5.0-rc10"},
		{[]string{"v1.9.9", "v2.0.0-rc1"}, "v2.0.0-rc1"},
	}
	for _, c := range cases {
		got, err := LatestPinned(mk(c.names...))
		if err != nil || got != c.want {
			t.Errorf("%v: got %q (%v), want %q", c.names, got, err, c.want)
		}
	}
	if _, err := LatestPinned(mk()); err == nil {
		// An empty pinned dir does not exist in MapFS: still an error.
		t.Error("no pinned release must be an error")
	}
}

func TestCompareFetchedWithPinned(t *testing.T) {
	if d := CompareFetched("a\nb\n", "a\nb\n"); d != "" {
		t.Errorf("identical copies reported %q", d)
	}
	if d := CompareFetched("a\nX\n", "a\nb\n"); !strings.Contains(d, "line 2") {
		t.Errorf("a changed line must be located: %q", d)
	}
	if d := CompareFetched("a\nb", "a\nb\nc"); !strings.Contains(d, "lines") {
		t.Errorf("a length difference must be reported: %q", d)
	}
}

func TestPin_ListsOnlyTestsTheTagTracks(t *testing.T) {
	tree := pluginTree(t)
	// Untracked files do not make a tree dirty, and must not reach
	// tests.txt: the pinned list names tests that exist at the tag.
	writeFile(t, filepath.Join(tree, "pkg", "plugin", "u_test.go"), "package plugin\n\nfunc TestUntracked(t *testing.T) {}\n")
	out := filepath.Join(t.TempDir(), "pinned", "v9.9.9")
	if err := Pin(tree, "v9.9.9", out); err != nil {
		t.Fatal(err)
	}
	txt, err := os.ReadFile(filepath.Join(out, "tests.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(txt), "TestUntracked") {
		t.Errorf("an untracked test file landed in tests.txt:\n%s", txt)
	}
	// Control: the tracked tests are all there.
	for _, want := range []string{"a_test.go:TestA", "a_test.go:TestB", "i_test.go:TestI"} {
		if !strings.Contains(string(txt), want) {
			t.Errorf("tests.txt lost %s:\n%s", want, txt)
		}
	}
}
