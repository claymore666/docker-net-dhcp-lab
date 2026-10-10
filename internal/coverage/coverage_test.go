package coverage

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

const fixtureMD = `# Reference

## At a glance

| option | modes | default |
| ------ | ----- | ------- |
| ` + "`mode`" + ` | n/a | ` + "`bridge`" + ` |

Some prose in between.

## Driver options (network-level)

Passed as ` + "`-o key=value`" + `.

| option | modes | default | since | description |
| ------ | ----- | ------- | ----- | ----------- |
| ` + "`mode`" + ` | n/a | ` + "`bridge`" + ` | upstream | Attachment strategy. |
| ` + "`bridge`" + ` | bridge | *(required)* | upstream | Existing Linux bridge. |
| ` + "`gateway`" + ` | all | from DHCP | v0.3.0 | Override the gateway. |

### DHCP classless static routes (option 121)

Some prose that must not be mistaken for a table row.

#### A worked example, not an option

| container | host-side link |
| --------- | -------------- |
| ` + "`web`" + ` | ` + "`web`" + ` |

## Driver options (per-endpoint)

| option | description |
| ------ | ----------- |
| ` + "`ip`" + ` | Request a specific IPv4 address. |

## Plugin settings

| name | default | meaning |
| ---- | ------- | ------- |
| ` + "`LOG_LEVEL`" + ` | ` + "`info`" + ` | logrus level. |

## Behaviour

| option | should not | be counted |
| ------ | ----------- | --------- |
| ` + "`bogus`" + ` | this table | is past the last known heading |
`

// TestParseRowsFindsEveryTableRowOnceEach is the "a cell is
// misplaced" guard for the coverage side: the At-a-glance table (before
// the first known heading) and the trailing Behaviour table (after the
// last one) must both be ignored, the ### subsection inside the
// network-level table must not reset its prefix, a worked-example table
// further down the same section (the real docs/reference.md shape that
// once leaked a "web" pseudo-option into this package's own output)
// must not be read as more option rows, and each real row is namespaced
// by the table it came from.
func TestParseRowsFindsEveryTableRowOnceEach(t *testing.T) {
	rows, err := ParseRows(fixtureMD)
	if err != nil {
		t.Fatalf("ParseRows: %v", err)
	}
	got := Keys(rows)
	want := []string{"network:mode", "network:bridge", "network:gateway", "endpoint:ip", "setting:LOG_LEVEL"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRows: got %v, want %v", got, want)
	}
}

// TestParseRowsFailsOnNoKnownHeadings guards against a silent,
// empty, all-green coverage report when docs/reference.md's headings
// have all changed out from under this package.
func TestParseRowsFailsOnNoKnownHeadings(t *testing.T) {
	if _, err := ParseRows("# Reference\n\nnothing recognisable here\n"); err == nil {
		t.Fatal("expected an error when no known heading is present, got nil")
	}
}

// TestParseRowsFailsWhenOneHeadingIsRenamed is the B6 guard: one
// table's heading changing under it (docs/reference.md renaming a
// section) must fail ParseRows outright, never just drop that
// table's options from the count as though nothing were missing.
func TestParseRowsFailsWhenOneHeadingIsRenamed(t *testing.T) {
	renamed := strings.Replace(fixtureMD, "## Plugin settings", "## Plugin configuration", 1)
	if _, err := ParseRows(renamed); err == nil {
		t.Fatal("expected an error when a known heading is renamed, got nil")
	}
}

// TestParseRowsFailsWhenAHeaderRowGainsAColumn is B6's other shape:
// the heading survives but its header row picks up an extra column, so
// that table's own rows never start being captured either.
func TestParseRowsFailsWhenAHeaderRowGainsAColumn(t *testing.T) {
	changed := strings.Replace(fixtureMD,
		"| name | default | meaning |\n| ---- | ------- | ------- |",
		"| name | default | meaning | notes |\n| ---- | ------- | ------- | ----- |", 1)
	if _, err := ParseRows(changed); err == nil {
		t.Fatal("expected an error when a header row gains a column, got nil")
	}
}

// withMapping temporarily swaps the package-level Mapping for m and
// restores it after the test, so Check can be exercised against a
// controlled fixture without ever touching the real, reviewed mapping.
func withMapping(t *testing.T, m map[string]Entry) {
	t.Helper()
	orig := Mapping
	Mapping = m
	t.Cleanup(func() { Mapping = orig })
}

// TestCheckClassifiesCoveredReasonedAndUnmapped is the mutant this
// package's own mapping-review rule guards against: an option present
// with neither a scenario nor a reason (the shape a copy-paste half of
// an Entry produces) must land in Unmapped, exactly like an option
// missing from the map entirely -- the option->scenario/reason rule
// issue #4 asks for, without needing to hit the real reference.md at
// all.
func TestCheckClassifiesCoveredReasonedAndUnmapped(t *testing.T) {
	withMapping(t, map[string]Entry{
		"network:mode":    {Scenario: "A1-first-lease"},
		"network:gateway": {Reason: "not covered yet, planned"},
		"network:empty":   {},
	})
	r := Check([]string{"network:mode", "network:gateway", "network:empty", "network:absent"})
	if r.Total != 4 {
		t.Fatalf("Total: got %d, want 4", r.Total)
	}
	if r.Covered != 1 {
		t.Fatalf("Covered: got %d, want 1", r.Covered)
	}
	if r.Reasoned != 1 {
		t.Fatalf("Reasoned: got %d, want 1", r.Reasoned)
	}
	if len(r.Unmapped) != 2 {
		t.Fatalf("Unmapped: got %v, want 2 entries", r.Unmapped)
	}
}

// TestCheckDeduplicatesRepeatedOptionNames guards against double-
// counting an option docs/reference.md happens to list twice under one
// heading.
func TestCheckDeduplicatesRepeatedOptionNames(t *testing.T) {
	withMapping(t, map[string]Entry{"network:mode": {Scenario: "A1-first-lease"}})
	r := Check([]string{"network:mode", "network:mode"})
	if r.Total != 1 || r.Covered != 1 {
		t.Fatalf("expected one deduplicated, covered option; got Total=%d Covered=%d", r.Total, r.Covered)
	}
}

// TestRealMappingHasNoUnmappedEntries is the coverage check's own
// self-test against the file it ships: every option this package's own
// Mapping names must resolve to either a scenario or a reason, so a
// future edit that adds a row with neither breaks this test locally,
// with no network access needed to catch it.
func TestRealMappingHasNoUnmappedEntries(t *testing.T) {
	names := make([]string, 0, len(Mapping))
	for name := range Mapping {
		names = append(names, name)
	}
	r := Check(names)
	if len(r.Unmapped) != 0 {
		t.Fatalf("real Mapping has unmapped entries: %v", r.Unmapped)
	}
}
