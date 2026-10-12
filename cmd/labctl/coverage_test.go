package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/coverage"
)

// runCoverage runs cmdCoverage with stdout and stderr captured.
func runCoverage(t *testing.T, args ...string) (int, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	code := cmdCoverage(args)
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return code, <-done
}

const pinnedReference = "../../internal/coverage/data/pinned/v2.5.0/reference.md"

func TestCoverageUsageErrorsExitTwo(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--tag", "v2.5.0", "--file", pinnedReference},
		{"--file", pinnedReference, "--regen"},
		{"--pinned", "v2.5.0", "extra"},
		{"--nonsense"},
		{"pin", "--tag", "v2.5.0"},
	} {
		if code, out := runCoverage(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2\n%s", args, code, out)
		}
	}
}

func TestCoverageFileOfThePinnedReferenceExitsZero(t *testing.T) {
	code, out := runCoverage(t, "--file", pinnedReference)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "43 option(s)") {
		t.Errorf("the summary should count the 43 rows:\n%s", out)
	}
}

func TestCoverageFileWithAnUnreviewedRowExitsOne(t *testing.T) {
	data, err := os.ReadFile(pinnedReference)
	if err != nil {
		t.Fatal(err)
	}
	reworded := strings.Replace(string(data), "Attachment strategy", "Attachment strategy (reworded)", 1)
	if reworded == string(data) {
		t.Fatal("the edit did not apply")
	}
	f := filepath.Join(t.TempDir(), "reference.md")
	if err := os.WriteFile(f, []byte(reworded), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCoverage(t, "--file", f)
	if code != 1 || !strings.Contains(out, "changed since it was reviewed") {
		t.Fatalf("a reworded row must fail with the changed-row notice, exit %d\n%s", code, out)
	}
}

func TestCoveragePinnedExitsOneUntilPlacementsExist(t *testing.T) {
	code, out := runCoverage(t, "--pinned", "v2.5.0")
	if code != 1 {
		t.Fatalf("exit %d, want 1 (no placements yet)\n%s", code, out)
	}
	if !strings.Contains(out, "has no placement") || strings.Contains(out, "matrix.tsv is stale") {
		t.Errorf("want unplaced variants named and a current matrix:\n%s", out[:min(len(out), 600)])
	}
	l, err := coverage.LoadPinnedMatrix(coverage.Data(), "v2.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "has no placement"); n != len(l.Variants) {
		t.Errorf("%d unplaced variants named, want all %d", n, len(l.Variants))
	}
}

func TestCoveragePinnedRegenWritesTheSameMatrix(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.CopyFS(dir, coverage.Data()); err != nil {
		t.Fatal(err)
	}
	m := filepath.Join(dir, "matrix.tsv")
	want, _ := os.ReadFile(m)
	if err := os.WriteFile(m, []byte("# variants: 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := runCoverage(t, "--pinned", "v2.5.0", "--data-dir", dir); code != 1 || !strings.Contains(out, "matrix.tsv is stale") {
		t.Fatalf("a stale matrix must be reported, exit %d", code)
	}
	runCoverage(t, "--pinned", "v2.5.0", "--regen", "--data-dir", dir)
	got, _ := os.ReadFile(m)
	if !bytes.Equal(got, want) {
		t.Error("--regen did not reproduce the checked-in matrix")
	}
}

func TestCoveragePinUnknownTagExitsOne(t *testing.T) {
	tree := t.TempDir()
	if code, _ := runCoverage(t, "pin", "--plugin-tree", tree, "--tag", "v9.9.9", "--data-dir", t.TempDir()); code != 1 {
		t.Errorf("pin on a non-repository must exit 1, got %d", code)
	}
}

// withFetch replaces the network fetch for one test.
func withFetch(t *testing.T, f func(ctx context.Context, tag string) (string, error)) {
	t.Helper()
	old := fetchReference
	fetchReference = f
	t.Cleanup(func() { fetchReference = old })
}

func pinnedReferenceText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(pinnedReference)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCoverageTagOfflineExitsThreeNotOne(t *testing.T) {
	withFetch(t, func(context.Context, string) (string, error) { return "", errors.New("dial tcp: no route to host") })
	code, out := runCoverage(t, "--tag", "v2.5.0")
	if code != 3 {
		t.Fatalf("exit %d, want 3 (1 means the docs disagree)\n%s", code, out)
	}
	if !strings.Contains(out, "no route to host") {
		t.Errorf("the fetch error should be shown:\n%s", out)
	}
	if code, _ := runCoverage(t, "--file", filepath.Join(t.TempDir(), "absent.md")); code != 3 {
		t.Errorf("an unreadable --file is also exit 3, got %d", code)
	}
}

func TestCoverageTagComparesTheFetchedDocsWithThePin(t *testing.T) {
	ref := pinnedReferenceText(t)
	withFetch(t, func(context.Context, string) (string, error) { return ref, nil })
	if code, out := runCoverage(t, "--tag", "v2.5.0"); code != 0 {
		t.Fatalf("identical fetched docs: exit %d, want 0\n%s", code, out)
	}
	// Control: a fetched copy that differs from the pin must fail.
	withFetch(t, func(context.Context, string) (string, error) { return ref + "\nextra text\n", nil })
	code, out := runCoverage(t, "--tag", "v2.5.0")
	if code != 1 || !strings.Contains(out, "pinned v2.5.0") {
		t.Fatalf("a fetched copy that differs from the pin: exit %d, want 1 with the pinned diff\n%s", code, out)
	}
}

func TestCoverageTagMalformedPinIsAProblemNotASkip(t *testing.T) {
	ref := pinnedReferenceText(t)
	withFetch(t, func(context.Context, string) (string, error) { return ref, nil })
	dir := t.TempDir()
	copyTree(t, "../../internal/coverage/data", dir)
	tests := filepath.Join(dir, "pinned", "v2.5.0", "tests.txt")
	if err := os.WriteFile(tests, []byte("# tag: v9.9.9\n# sha: abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCoverage(t, "--tag", "v2.5.0", "--data-dir", dir)
	if code != 1 || !strings.Contains(out, "cannot be compared") {
		t.Fatalf("a malformed pin must be reported, got exit %d\n%s", code, out)
	}
	// An unpinned tag is a notice, not a failure.
	if err := os.RemoveAll(filepath.Join(dir, "pinned")); err != nil {
		t.Fatal(err)
	}
	code, out = runCoverage(t, "--tag", "v2.5.0", "--data-dir", dir)
	if code != 0 || strings.Contains(out, "cannot be compared") || !strings.Contains(out, "is not pinned") {
		t.Errorf("an unpinned tag is a notice, got exit %d\n%s", code, out)
	}
}

// copyTree copies the data directory so a test can edit its copy.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
