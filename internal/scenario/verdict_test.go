package scenario

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestReadVerdictRoundTripsWrite guards the exact bug ReadVerdict exists
// to avoid (issue #4): a shape or scenario name with its own internal
// hyphens must never be recovered by splitting the file name, so this
// writes with both an IPAM shape and A5b's hyphenated name and checks
// every field comes back unchanged from content alone.
func TestReadVerdictRoundTripsWrite(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "ev.txt")
	if err := os.WriteFile(evPath, []byte("evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := Verdict{
		Scenario:        NameA5b,
		Cell:            "kea",
		Shape:           ShapeBridgeIPAM,
		Result:          PASS,
		Reason:          "lease confirmed",
		Evidence:        map[string]string{"lease_after": evPath},
		GitSHA:          "abc123",
		IsolationMethod: "network recreated between scenarios",
		Timestamp:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := Write(dir, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := ReadVerdict(filepath.Join(dir, want.FileName()))
	if err != nil {
		t.Fatalf("ReadVerdict: %v", err)
	}
	if got.Scenario != want.Scenario || got.Cell != want.Cell || got.Shape != want.Shape ||
		got.Result != want.Result || got.Reason != want.Reason || got.GitSHA != want.GitSHA ||
		got.IsolationMethod != want.IsolationMethod || !got.Timestamp.Equal(want.Timestamp) {
		t.Fatalf("ReadVerdict round trip mismatch: got %+v, want %+v", got, want)
	}
	if got.Evidence["lease_after"] != evPath {
		t.Fatalf("evidence not preserved: got %q", got.Evidence["lease_after"])
	}
}

// TestReadVerdictOmitsIsolationWhenEmpty guards Write's own "only when
// non-empty" rule for the isolation line: a null-IPAM verdict (no
// isolation step ever ran) must read back with an empty
// IsolationMethod, never an error for a missing line.
func TestReadVerdictOmitsIsolationWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	v := Verdict{Scenario: NameA1, Cell: "kea", Shape: ShapeBridge, Result: NA, Reason: "no capability", Timestamp: time.Now()}
	if err := Write(dir, v); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := ReadVerdict(filepath.Join(dir, v.FileName()))
	if err != nil {
		t.Fatalf("ReadVerdict: %v", err)
	}
	if got.IsolationMethod != "" {
		t.Fatalf("expected empty IsolationMethod, got %q", got.IsolationMethod)
	}
}

// TestReadVerdictRejectsUnrecognisedField is the mutant this test was
// written to catch: a results page silently ignoring an unknown field
// would misread a future verdict format instead of failing loudly
// (issue #4).
func TestReadVerdictRejectsUnrecognisedField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.verdict")
	content := "scenario: A1-first-lease\ncell: kea\nshape: bridge\nresult: PASS\nreason: x\ngit_sha: x\ntimestamp: 2026-01-01T00:00:00Z\nfuture_field: surprise\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVerdict(path); err == nil {
		t.Fatal("expected an error for an unrecognised field, got nil")
	}
}

// TestReadVerdictRejectsMissingRequiredField catches a truncated or
// corrupted verdict file (e.g. written by an interrupted run) instead
// of silently building a Verdict with a blank Scenario or Shape, which
// a matrix renderer could otherwise attribute to the wrong cell.
func TestReadVerdictRejectsMissingRequiredField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.verdict")
	content := "cell: kea\nshape: bridge\nresult: PASS\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVerdict(path); err == nil {
		t.Fatal("expected an error for a missing scenario field, got nil")
	}
}
