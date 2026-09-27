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
