package matrix

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
)

// linkTargetRE matches a markdown link target, "(...)", so the leaked-id
// check below can look only at visible prose, not at the file names
// links legitimately carry (issue #4's own rule permits ids in file
// names).
var linkTargetRE = regexp.MustCompile(`\([^)]*\)`)

// writeResolvedLab writes the minimal resolved-lab.json shape
// `labctl resolve` produces (cmd/labctl's cmdResolve), just enough for
// LoadBundle to read plugin_tag/previous_plugin_tag back out.
func writeResolvedLab(t *testing.T, dir, cell, pluginTag, previousTag string) {
	t.Helper()
	content := `{"cell":{"name":"` + cell + `","docker_host":{"plugin_tag":"` + pluginTag + `","previous_plugin_tag":"` + previousTag + `"}}}`
	path := filepath.Join(dir, cell+"-resolved-lab.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeVerdict(t *testing.T, dir string, v scenario.Verdict) {
	t.Helper()
	if v.Timestamp.IsZero() {
		v.Timestamp = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if v.GitSHA == "" {
		v.GitSHA = "abc123"
	}
	if err := scenario.Write(dir, v); err != nil {
		t.Fatalf("write verdict %s/%s/%s: %v", v.Cell, v.Shape, v.Scenario, err)
	}
}

// TestLoadBundleAndRenderBasicTable is the golden-output check: two
// scenarios under two shapes of one cell, rendered against a root one
// level up, so the links exercise the "relative to a shared root" rule
// the packed-tarball layout depends on (issue #4).
func TestLoadBundleAndRenderBasicTable(t *testing.T) {
	root := t.TempDir()
	bundleDir := filepath.Join(root, "evidence-abc123-kea")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeResolvedLab(t, bundleDir, "kea", "ghcr.io/claymore666/docker-net-dhcp:v2.2.2", "ghcr.io/claymore666/docker-net-dhcp:v2.2.1")

	writeVerdict(t, bundleDir, scenario.Verdict{
		Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeBridge,
		Result: scenario.PASS, Reason: "lease confirmed",
		Evidence: map[string]string{"lease_after": mustFile(t, bundleDir, "lease.txt")},
	})
	writeVerdict(t, bundleDir, scenario.Verdict{
		Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeMacvlan,
		Result: scenario.FAIL, Reason: "no lease seen",
	})
	writeVerdict(t, bundleDir, scenario.Verdict{
		Scenario: scenario.NameA2, Cell: "kea", Shape: scenario.ShapeBridge,
		Result: scenario.NA, Reason: "source does not declare capability",
	})
	// A2/macvlan is intentionally never written, to exercise "(missing)".

	b, err := LoadBundle(bundleDir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if b.PluginTag != "ghcr.io/claymore666/docker-net-dhcp:v2.2.2" {
		t.Fatalf("PluginTag: got %q", b.PluginTag)
	}
	if b.PreviousPluginTag != "ghcr.io/claymore666/docker-net-dhcp:v2.2.1" {
		t.Fatalf("PreviousPluginTag: got %q", b.PreviousPluginTag)
	}

	page, err := Render(root, "", []Bundle{b})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// The rendered prose must carry the plain-word names, never the
	// scenario ids (issue #4's own rule): ids belong only in a verdict
	// file name, which is fine inside a link target, so link targets are
	// stripped before this check -- a raw id in the visible table text
	// still fails it.
	prose := linkTargetRE.ReplaceAllString(page, "")
	if strings.Contains(prose, "A1-first-lease") || strings.Contains(prose, "A2-container-restart") {
		t.Fatalf("rendered page leaks a scenario id into prose:\n%s", page)
	}
	if !strings.Contains(page, "first lease") || !strings.Contains(page, "container restart") {
		t.Fatalf("rendered page missing plain-word scenario names:\n%s", page)
	}
	if !strings.Contains(page, "kea / bridge") || !strings.Contains(page, "kea / macvlan") {
		t.Fatalf("rendered page missing expected columns:\n%s", page)
	}
	if !strings.Contains(page, "[PASS](evidence-abc123-kea/kea-bridge-A1-first-lease.verdict)") {
		t.Fatalf("rendered page missing the expected PASS link, root-relative:\n%s", page)
	}
	if !strings.Contains(page, "[FAIL](evidence-abc123-kea/kea-macvlan-A1-first-lease.verdict)") {
		t.Fatalf("rendered page missing the expected FAIL link:\n%s", page)
	}
	if !strings.Contains(page, "(missing)") {
		t.Fatalf("rendered page did not mark the dropped A2/macvlan verdict as missing:\n%s", page)
	}
	if !strings.Contains(page, "v2.2.2") || !strings.Contains(page, "v2.2.1") {
		t.Fatalf("rendered header missing plugin tag or previous tag:\n%s", page)
	}
}

// TestRenderRejectsUnknownScenarioID is the "an option maps to no
// scenario" sibling for the matrix side: a verdict naming a scenario id
// PlainNames does not carry must fail Render outright rather than
// printing the raw id (issue #4).
func TestRenderRejectsUnknownScenarioID(t *testing.T) {
	b := Bundle{
		Dir:  "irrelevant",
		Cell: "kea",
		Verdicts: []scenario.Verdict{
			{Scenario: "Z9-not-a-real-scenario", Cell: "kea", Shape: scenario.ShapeBridge, Result: scenario.FAIL, Reason: "x"},
		},
	}
	if _, err := Render("root", "", []Bundle{b}); err == nil {
		t.Fatal("expected Render to reject an unmapped scenario id, got nil error")
	}
}

// TestRenderRejectsDuplicateCell is the "a cell is misplaced" guard:
// two bundles both claiming the same cell/shape/scenario cell must
// never let one silently overwrite the other (map iteration order
// would otherwise make the outcome non-deterministic).
func TestRenderRejectsDuplicateCell(t *testing.T) {
	v := scenario.Verdict{Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeBridge, Result: scenario.PASS, Reason: "x", Evidence: map[string]string{"e": "irrelevant"}}
	b1 := Bundle{Dir: "bundle-one", Cell: "kea", Verdicts: []scenario.Verdict{v}}
	b2 := Bundle{Dir: "bundle-two", Cell: "kea", Verdicts: []scenario.Verdict{v}}
	if _, err := Render("root", "", []Bundle{b1, b2}); err == nil {
		t.Fatal("expected Render to reject two bundles covering the same cell, got nil error")
	}
}

// TestRenderRejectsUnrecognisedResult guards the legitimate-result rule
// directly: a verdict carrying anything other than PASS/FAIL/N/A/BLOCKED
// must fail Render outright rather than render it as if it were real.
func TestRenderRejectsUnrecognisedResult(t *testing.T) {
	b := Bundle{
		Dir:  "irrelevant",
		Cell: "kea",
		Verdicts: []scenario.Verdict{
			{Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeBridge, Result: "PASSISH", Reason: "x"},
		},
	}
	if _, err := Render("root", "", []Bundle{b}); err == nil {
		t.Fatal("expected Render to reject a result other than PASS/FAIL/N/A/BLOCKED, got nil error")
	}
}

// TestRenderRejectsNAWithEmptyReason guards the other half of the same
// rule: a scenario that never ran must always say why, never render as
// a bare N/A with nothing behind it.
func TestRenderRejectsNAWithEmptyReason(t *testing.T) {
	b := Bundle{
		Dir:  "irrelevant",
		Cell: "kea",
		Verdicts: []scenario.Verdict{
			{Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeBridge, Result: scenario.NA, Reason: ""},
		},
	}
	if _, err := Render("root", "", []Bundle{b}); err == nil {
		t.Fatal("expected Render to reject an N/A verdict with an empty reason, got nil error")
	}
}

// TestVerdictLinkRejectsNonAncestorRoot guards N4: a --root that is not
// actually an ancestor of the bundle directory must refuse the link
// rather than write one carrying "../" or this machine's own absolute
// path into a page meant to be portable.
func TestVerdictLinkRejectsNonAncestorRoot(t *testing.T) {
	dir := t.TempDir()
	if _, err := verdictLink("/no/such/unrelated/root", dir, "kea-bridge-A1-first-lease.verdict"); err == nil {
		t.Fatal("expected verdictLink to reject a root that is not an ancestor of the bundle, got nil error")
	}
}

// TestRenderHeaderNamesAsset guards N5: passing --asset must name the
// release asset the page's relative links live inside, in the header;
// leaving it empty must change nothing.
func TestRenderHeaderNamesAsset(t *testing.T) {
	root := t.TempDir()
	bundleDir := filepath.Join(root, "evidence-abc123-kea")
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeResolvedLab(t, bundleDir, "kea", "ghcr.io/claymore666/docker-net-dhcp:v2.2.2", "")
	writeVerdict(t, bundleDir, scenario.Verdict{
		Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeBridge,
		Result: scenario.NA, Reason: "source does not declare capability",
	})
	b, err := LoadBundle(bundleDir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	page, err := Render(root, "results-v2.2.2.tar.gz", []Bundle{b})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(page, "results-v2.2.2.tar.gz") {
		t.Fatalf("rendered header does not name the release asset:\n%s", page)
	}
}

// TestLoadBundleRejectsMixedCells catches a bundle directory that
// somehow ended up with verdicts from two different cells (a copy-paste
// mistake assembling a bundle by hand) instead of silently reporting
// whichever cell the first verdict alphabetically happened to name.
func TestLoadBundleRejectsMixedCells(t *testing.T) {
	dir := t.TempDir()
	writeVerdict(t, dir, scenario.Verdict{Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeBridge, Result: scenario.NA, Reason: "x"})
	writeVerdict(t, dir, scenario.Verdict{Scenario: scenario.NameA1, Cell: "dnsmasq", Shape: scenario.ShapeBridge, Result: scenario.NA, Reason: "x"})
	if _, err := LoadBundle(dir); err == nil {
		t.Fatal("expected LoadBundle to reject a bundle mixing two cells, got nil error")
	}
}

// TestLoadBundleRequiresResolvedLab guards the header's plugin tag: a
// bundle with no <cell>-resolved-lab.json must fail loudly rather than
// render a page with a blank plugin tag (issue #4's header requirement).
func TestLoadBundleRequiresResolvedLab(t *testing.T) {
	dir := t.TempDir()
	writeVerdict(t, dir, scenario.Verdict{Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeBridge, Result: scenario.NA, Reason: "x"})
	if _, err := LoadBundle(dir); err == nil {
		t.Fatal("expected LoadBundle to reject a bundle with no resolved-lab.json, got nil error")
	}
}

func mustFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("evidence"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadBundleCapturesHostFromFirstVerdict guards issue #8's
// permissive read: Bundle.Host comes from the first verdict carrying a
// non-zero HostInfo, not from an exact match requirement the way
// Cell/GitSHA already enforce.
func TestLoadBundleCapturesHostFromFirstVerdict(t *testing.T) {
	dir := t.TempDir()
	writeResolvedLab(t, dir, "host-ubuntu2404", "ghcr.io/claymore666/docker-net-dhcp:v2.2.2", "")
	writeVerdict(t, dir, scenario.Verdict{
		Scenario: scenario.NameA1, Cell: "host-ubuntu2404", Shape: scenario.ShapeBridge,
		Result: scenario.NA, Reason: "x",
		Host: scenario.HostInfo{Distro: "Ubuntu 24.04.1 LTS", Kernel: "6.8.0-45-generic", DockerVersion: "27.3.1"},
	})
	writeVerdict(t, dir, scenario.Verdict{
		Scenario: scenario.NameA2, Cell: "host-ubuntu2404", Shape: scenario.ShapeBridge,
		Result: scenario.NA, Reason: "x",
	})

	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if b.Host.Distro != "Ubuntu 24.04.1 LTS" || b.Host.Kernel != "6.8.0-45-generic" || b.Host.DockerVersion != "27.3.1" {
		t.Fatalf("Bundle.Host = %+v, want the first verdict's non-zero HostInfo", b.Host)
	}
}

// TestRenderShowsHostPerColumnAndInHeader guards deliverable 2 of issue
// #8: the matrix renderer must show the host per column, and the
// per-bundle summary line must carry it too.
func TestRenderShowsHostPerColumnAndInHeader(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "evidence-host")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeResolvedLab(t, dir, "host-debian11-docker2010", "ghcr.io/claymore666/docker-net-dhcp:v2.2.2", "")
	writeVerdict(t, dir, scenario.Verdict{
		Scenario: scenario.NameA1, Cell: "host-debian11-docker2010", Shape: scenario.ShapeBridge,
		Result: scenario.NA, Reason: "x",
		Host: scenario.HostInfo{Distro: "Debian GNU/Linux 11 (bullseye)", Kernel: "5.10.0-30-amd64", DockerVersion: "20.10.24"},
	})

	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	page, err := Render(root, "", []Bundle{b})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(page, "Debian GNU/Linux 11 (bullseye)") {
		t.Fatalf("rendered page does not show the host distro anywhere:\n%s", page)
	}
	if !strings.Contains(page, "host-debian11-docker2010 / bridge (Debian GNU/Linux 11 (bullseye))") {
		t.Fatalf("rendered column header does not carry the host distro:\n%s", page)
	}
	if !strings.Contains(page, "20.10.24") {
		t.Fatalf("rendered header line does not carry the docker engine version:\n%s", page)
	}
	if !strings.Contains(page, "5.10.0-30-amd64") {
		t.Fatalf("rendered header line does not carry the kernel:\n%s", page)
	}
}

// TestRenderKeaHAColumnsCarryTheC5Rows: the failover pair cell renders
// as its own "kea-ha / <shape>" columns with C5 to C5d in plain words (#12).
func TestRenderKeaHAColumnsCarryTheC5Rows(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "evidence-abc123-kea-ha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeResolvedLab(t, dir, "kea-ha", "ghcr.io/claymore666/docker-net-dhcp:v2.5.0", "ghcr.io/claymore666/docker-net-dhcp:v2.4.0")
	for _, s := range []scenario.Shape{scenario.ShapeMacvlan, scenario.ShapeBridge} {
		for _, id := range []string{scenario.NameC5, scenario.NameC5b, scenario.NameC5c, scenario.NameC5d} {
			writeVerdict(t, dir, scenario.Verdict{Scenario: id, Cell: "kea-ha", Shape: s, Result: scenario.FAIL, Reason: "probe"})
		}
	}
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	page, err := Render(root, "", []Bundle{b})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kea-ha / macvlan", "kea-ha / bridge", "failover, granting peer stopped", "failover, primary down at create", "failover, primary returns", "failover, no address given twice"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

// writeBlocked writes the marker run-cells.sh leaves for a skipped-image
// cell (lab #14).
func writeBlocked(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BlockedFile), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const blockedWindows = `{"cell":"windows","reason":"image not built","detail":"built image windows-2025-eval is not on this host","date":"2026-10-28T09:30:00Z"}`

// A cell without a result bundle is one BLOCKED column, not a dropped or
// empty one (lab #14). Cell and reason come from the marker's content:
// the directory is named for a different cell on purpose.
func TestBlockedBundleRendersOneBlockedColumn(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "evidence", "not-the-cell")
	writeBlocked(t, dir, blockedWindows)

	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if b.Cell != "windows" || b.Blocked == nil || b.Blocked.Reason != "image not built" {
		t.Fatalf("marker not read from content: %+v", b)
	}
	page, err := Render(root, "", []Bundle{b})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(page, "| scenario | windows |") {
		t.Fatalf("expected a single column labelled with the cell only:\n%s", page)
	}
	if !strings.Contains(page, "- **windows**: not run, image not built, 2026-10-28") {
		t.Fatalf("header does not say why the cell did not run:\n%s", page)
	}
	rows := 0
	for _, line := range strings.Split(page, "\n") {
		if strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "| scenario") && !strings.HasPrefix(line, "| ---") {
			rows++
			if !strings.HasSuffix(line, " [BLOCKED](evidence/not-the-cell/image-not-built.json) |") {
				t.Fatalf("catalog row is not a linked BLOCKED: %q", line)
			}
		}
	}
	if rows != len(Order()) {
		t.Fatalf("got %d catalog rows, want %d:\n%s", rows, len(Order()), page)
	}
	if strings.Contains(page, "(missing)") {
		t.Fatalf("a blocked cell must not render (missing):\n%s", page)
	}
}

// It sits next to a real bundle without disturbing it.
func TestBlockedBundleBesideARunBundle(t *testing.T) {
	root := t.TempDir()
	kdir := filepath.Join(root, "kea")
	writeResolvedLab(t, mkdir(t, kdir), "kea", "tag", "")
	writeVerdict(t, kdir, scenario.Verdict{
		Scenario: scenario.NameA1, Cell: "kea", Shape: scenario.ShapeBridge,
		Result: scenario.PASS, Reason: "ok", Evidence: map[string]string{"e": mustFile(t, kdir, "e.txt")},
	})
	wdir := filepath.Join(root, "windows")
	writeBlocked(t, wdir, blockedWindows)
	kb, err := LoadBundle(kdir)
	if err != nil {
		t.Fatal(err)
	}
	wb, err := LoadBundle(wdir)
	if err != nil {
		t.Fatal(err)
	}
	page, err := Render(root, "", []Bundle{kb, wb})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| scenario | kea / bridge | windows |", "[PASS](kea/kea-bridge-A1-first-lease.verdict)", "[BLOCKED](windows/image-not-built.json)"} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %q:\n%s", want, page)
		}
	}
}

func TestLoadBundleRefusesBadMarkers(t *testing.T) {
	for name, body := range map[string]string{
		"empty reason": `{"cell":"windows","reason":"","date":"2026-10-28T09:30:00Z"}`,
		"no cell":      `{"reason":"image not built","date":"2026-10-28T09:30:00Z"}`,
		"no date":      `{"cell":"windows","reason":"image not built"}`,
		"not json":     `image not built`,
	} {
		dir := filepath.Join(t.TempDir(), "w")
		writeBlocked(t, dir, body)
		if _, err := LoadBundle(dir); err == nil {
			t.Errorf("%s: marker accepted", name)
		}
	}
}

// run-cells.sh never leaves both; if both are there one is stale and
// rendering either would mislead.
func TestLoadBundleRefusesMarkerBesideVerdicts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "windows")
	writeResolvedLab(t, mkdir(t, dir), "windows", "tag", "")
	writeVerdict(t, dir, scenario.Verdict{
		Scenario: scenario.NameA1, Cell: "windows", Shape: scenario.ShapeBridge,
		Result: scenario.FAIL, Reason: "x",
	})
	writeBlocked(t, dir, blockedWindows)
	if _, err := LoadBundle(dir); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("marker plus verdicts: %v", err)
	}
}

func TestRenderRefusesBlockedCellAlsoInARunBundle(t *testing.T) {
	blocked := Bundle{Dir: "b1", Cell: "windows", Blocked: &Blocked{Cell: "windows", Reason: "image not built"}}
	run := Bundle{Dir: "b2", Cell: "windows", Verdicts: []scenario.Verdict{
		{Scenario: scenario.NameA1, Cell: "windows", Shape: scenario.ShapeBridge, Result: scenario.PASS, Reason: "x", Evidence: map[string]string{"e": "x"}},
	}}
	for name, bs := range map[string][]Bundle{"blocked first": {blocked, run}, "run first": {run, blocked}, "twice": {blocked, blocked}} {
		if _, err := Render("", "", bs); err == nil {
			t.Errorf("%s: rendered one cell twice", name)
		}
	}
}

func TestRenderRefusesBlockedWithoutReason(t *testing.T) {
	b := Bundle{Dir: "b", Cell: "windows", Blocked: &Blocked{Cell: "windows"}}
	if _, err := Render("", "", []Bundle{b}); err == nil {
		t.Fatal("blocked bundle with no reason rendered")
	}
}

func mkdir(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}
