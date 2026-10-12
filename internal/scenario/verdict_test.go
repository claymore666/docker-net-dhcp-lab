package scenario

import (
	"os"
	"path/filepath"
	"strings"
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
	if got.Evidence["lease_after"] != "ev.txt" {
		t.Fatalf("evidence not stored relative to dir: got %q", got.Evidence["lease_after"])
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

// TestReadVerdictRoundTripsHost guards the same discipline as the
// isolation field, for the host axis (issue #8): all three host.* lines
// present must come back unchanged.
func TestReadVerdictRoundTripsHost(t *testing.T) {
	dir := t.TempDir()
	want := Verdict{
		Scenario:  NameA1,
		Cell:      "host-ubuntu2404",
		Shape:     ShapeBridge,
		Result:    NA,
		Reason:    "no capability",
		Host:      HostInfo{Distro: "Ubuntu 24.04.1 LTS", Kernel: "6.8.0-45-generic", DockerVersion: "27.3.1"},
		Timestamp: time.Now(),
	}
	if err := Write(dir, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := ReadVerdict(filepath.Join(dir, want.FileName()))
	if err != nil {
		t.Fatalf("ReadVerdict: %v", err)
	}
	if got.Host != want.Host {
		t.Fatalf("Host round trip mismatch: got %+v, want %+v", got.Host, want.Host)
	}
}

// TestReadVerdictOmitsHostWhenEmpty guards Write's "only when non-empty"
// rule for the host.* lines: a verdict from before issue #8 (or one
// whose host read failed) must read back with a zero HostInfo, never an
// error for the missing lines.
func TestReadVerdictOmitsHostWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	v := Verdict{Scenario: NameA1, Cell: "kea", Shape: ShapeBridge, Result: NA, Reason: "no capability", Timestamp: time.Now()}
	if err := Write(dir, v); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := ReadVerdict(filepath.Join(dir, v.FileName()))
	if err != nil {
		t.Fatalf("ReadVerdict: %v", err)
	}
	if got.Host != (HostInfo{}) {
		t.Fatalf("expected zero HostInfo, got %+v", got.Host)
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

// The reasons the #38 -j 6 run wrote across several lines: ssh's own
// "\r\n" inside the reason, and a nested reason ending in "\n)".
func TestWriteKeepsAReasonWithLineBreaksOnOneLine(t *testing.T) {
	for _, reason := range []string{
		"plugin not installed under alias net-dhcp-under-test: ssh lab@10.200.255.20: exit status 255: Connection timed out during banner exchange\r\nConnection to 10.200.255.20 port 22 timed out\r\n",
		"plugin never became ready: (plugin log capture also failed: ssh lab@10.200.255.40: exit status 255: Connection refused\n)",
		"bare\rcarriage return",
	} {
		dir := t.TempDir()
		v := Verdict{Scenario: NameA10, Cell: "kea", Shape: ShapeBridge, Result: BLOCKED,
			Reason: reason, GitSHA: "abc123", Timestamp: time.Date(2026, 10, 9, 12, 38, 10, 0, time.UTC),
			Host: HostInfo{Distro: "Debian GNU/Linux 13 (trixie)\n", Kernel: "6.12\r\n", DockerVersion: "29.9.0"}}
		if err := Write(dir, v); err != nil {
			t.Fatalf("Write: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(dir, v.FileName()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "\r") {
			t.Fatalf("verdict file still carries a CR: %q", data)
		}
		got, err := ReadVerdict(filepath.Join(dir, v.FileName()))
		if err != nil {
			t.Fatalf("ReadVerdict on a reason with line breaks: %v", err)
		}
		first, rest, _ := strings.Cut(strings.NewReplacer("\r", "\n").Replace(reason), "\n")
		rest = strings.Trim(strings.TrimLeft(rest, "\n"), "\n")
		if !strings.Contains(got.Reason, first) || !strings.Contains(got.Reason, rest) {
			t.Fatalf("folded reason lost text: got %q from %q", got.Reason, reason)
		}
	}
}

// The reader stays strict: a continuation line is still refused.
func TestReadVerdictRejectsAReasonSplitAcrossLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-bridge-A10-kill-restart-policy.verdict")
	body := "scenario: A10-kill-restart-policy\ncell: kea\nshape: bridge\nresult: BLOCKED\n" +
		"reason: ssh lab@10.200.255.20: exit status 255: Connection timed out during banner exchange\r\n" +
		"Connection to 10.200.255.20 port 22 timed out\r\n" +
		"git_sha: abc123\ntimestamp: 2026-10-09T12:38:10Z\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ReadVerdict(path)
	if err == nil || !strings.Contains(err.Error(), ":6:") {
		t.Fatalf("expected the continuation at line 6 to be refused, got %v", err)
	}
}
