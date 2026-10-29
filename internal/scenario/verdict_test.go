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

// #94: files written before the writer folded its values carry the
// value's own line break. The reader joins the broken-off text instead of
// refusing the file, so labctl remaining and labctl matrix read them.
func TestReadVerdictJoinsAContinuationLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host-macvlan-ipam-A5-host-reboot.verdict")
	body := "scenario: A5-host-reboot\ncell: host\nshape: macvlan-ipam\nresult: PASS\nreason: ok\ngit_sha: abc123\n" +
		"isolation: network recreated between scenarios (docker network rm failed: ssh lab@10.200.255.40: exit status 255: Connection refused\r\n" +
		")\n" +
		"timestamp: 2026-10-13T12:38:10Z\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := ReadVerdict(path)
	if err != nil {
		t.Fatalf("ReadVerdict on a value with a continuation line: %v", err)
	}
	want := "network recreated between scenarios (docker network rm failed: ssh lab@10.200.255.40: exit status 255: Connection refused )"
	if v.IsolationMethod != want {
		t.Fatalf("isolation = %q, want %q", v.IsolationMethod, want)
	}
	if v.Timestamp.IsZero() || v.GitSHA != "abc123" {
		t.Fatalf("fields after the continuation lost: %+v", v)
	}
}

// A broken-off line may itself hold ": " (ssh prints "port 22: timed
// out"); its prefix is not a key, so it still joins the value (#94).
func TestReadVerdictJoinsAContinuationLineHoldingAColon(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.verdict")
	body := "scenario: A5-host-reboot\ncell: host\nshape: bridge\nresult: BLOCKED\nreason: ssh failed\r\nConnection to 10.200.255.40 port 22: timed out\r\ngit_sha: abc123\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := ReadVerdict(path)
	if err != nil {
		t.Fatalf("ReadVerdict: %v", err)
	}
	if want := "ssh failed Connection to 10.200.255.40 port 22: timed out"; v.Reason != want || v.GitSHA != "abc123" {
		t.Fatalf("reason = %q (git_sha %q), want %q", v.Reason, v.GitSHA, want)
	}
}

// A continuation joins only a value; one with no field before it, or a
// key-shaped unknown field after it, is still refused loudly (#94).
func TestReadVerdictStaysStrictAroundContinuations(t *testing.T) {
	for name, body := range map[string]string{
		"continuation first":               ")\nscenario: A1-first-lease\ncell: k\nshape: bridge\nresult: PASS\n",
		"unknown key after a continuation": "scenario: A1-first-lease\ncell: k\nshape: bridge\nresult: PASS\nreason: x\n)\nfuture_field: surprise\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.verdict")
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadVerdict(path); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// #94: every value Write prints stays on its own line, whatever the
// whitespace it carries, and reads back folded to single spaces.
func TestWriteKeepsEveryFieldOnOneLine(t *testing.T) {
	dir := t.TempDir()
	ev := filepath.Join(dir, "lease.txt")
	if err := os.WriteFile(ev, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	v := Verdict{Scenario: "A5\nhost", Cell: "ce\tll", Shape: ShapeBridge, Result: PASS,
		Reason: "r\r\n\r\nx", GitSHA: "ab\ncd",
		IsolationMethod: "recreated (ssh: exit status 255: Connection refused\n)",
		Host:            HostInfo{Distro: "d\n1", Kernel: "k\r2", DockerVersion: "v\t3\n"},
		Evidence:        map[string]string{"lease": ev},
		Timestamp:       time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	if err := Write(dir, v); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, v.FileName()))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != 12 || strings.ContainsAny(string(data), "\r\t") {
		t.Fatalf("want 12 lines and no CR or tab, got %d:\n%q", len(lines), data)
	}
	got, err := ReadVerdict(filepath.Join(dir, v.FileName()))
	if err != nil {
		t.Fatalf("ReadVerdict: %v", err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"scenario", got.Scenario, "A5 host"}, {"cell", got.Cell, "ce ll"}, {"reason", got.Reason, "r x"},
		{"git_sha", got.GitSHA, "ab cd"}, {"isolation", got.IsolationMethod, "recreated (ssh: exit status 255: Connection refused )"},
		{"distro", got.Host.Distro, "d 1"}, {"kernel", got.Host.Kernel, "k 2"}, {"docker", got.Host.DockerVersion, "v 3"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// An evidence label or path is a pointer, so Write refuses a line break
// in one rather than folding the pointer into a different name (#94).
func TestWriteRefusesALineBreakInAnEvidenceLabelOrPath(t *testing.T) {
	dir := t.TempDir()
	ev := filepath.Join(dir, "lease.txt")
	if err := os.WriteFile(ev, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	odd := filepath.Join(dir, "a\nb.txt")
	if err := os.WriteFile(odd, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, evidence := range map[string]map[string]string{
		"label": {"lease\nafter": ev},
		"path":  {"lease": odd},
	} {
		v := Verdict{Scenario: NameA1, Cell: "kea", Shape: ShapeBridge, Result: PASS, Reason: "x",
			Evidence: evidence, Timestamp: time.Now()}
		if err := Write(dir, v); err == nil || !strings.Contains(err.Error(), "line break") {
			t.Fatalf("%s: expected a line-break refusal, got %v", name, err)
		}
	}
}
