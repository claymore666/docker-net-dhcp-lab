package scenario

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Result is one of the readings issue #3 asks a verdict to carry: a
// scenario this source cannot run is N/A with a reason, never PASS or
// FAIL. BLOCKED is the same discipline for a scenario that never reached
// a known plugin state to begin with: one failure must never cascade
// into FAILs for the
// scenarios after it, so a scenario whose precondition could not be
// established, or restored after a previous failure, is recorded as
// BLOCKED with the reason, not run at all.
type Result string

const (
	PASS    Result = "PASS"
	FAIL    Result = "FAIL"
	NA      Result = "N/A"
	BLOCKED Result = "BLOCKED"
)

// Verdict is the interface issue #4's results matrix reads. Evidence
// maps a short label to a file path inside the run's evidence bundle;
// Write refuses to write a PASS with none (issue #3 defeat list: a PASS
// must never claim more than the files beside it back up) and refuses
// an N/A carrying any, since a scenario that never ran has nothing to
// point at but its own reason.
type Verdict struct {
	Scenario  string
	Cell      string
	Shape     Shape
	Result    Result
	Reason    string
	Evidence  map[string]string
	GitSHA    string
	Timestamp time.Time
}

// FileName is deterministic per scenario x cell x shape (issue #3): a
// re-run overwrites its own prior verdict instead of accumulating stale
// ones beside it.
func (v Verdict) FileName() string {
	return fmt.Sprintf("%s-%s-%s.verdict", v.Cell, v.Shape, v.Scenario)
}

// Write is documented briefly in README.md ("Scenario runner"), since
// this format is the interface issue #4 reads.
func Write(dir string, v Verdict) error {
	if v.Result == PASS && len(v.Evidence) == 0 {
		return fmt.Errorf("verdict %s/%s/%s: a PASS must carry at least one evidence file", v.Cell, v.Shape, v.Scenario)
	}
	if v.Result == NA && len(v.Evidence) != 0 {
		return fmt.Errorf("verdict %s/%s/%s: an N/A result carries evidence %v; a scenario that did not run has only its reason", v.Cell, v.Shape, v.Scenario, v.Evidence)
	}
	if v.Result == BLOCKED && len(v.Evidence) != 0 {
		return fmt.Errorf("verdict %s/%s/%s: a BLOCKED result carries evidence %v; a scenario that never reached a known starting state has only its reason", v.Cell, v.Shape, v.Scenario, v.Evidence)
	}
	for label, path := range v.Evidence {
		fi, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("verdict %s/%s/%s: evidence %q (%s) is not readable: %w", v.Cell, v.Shape, v.Scenario, label, path, err)
		}
		if fi.Size() == 0 {
			return fmt.Errorf("verdict %s/%s/%s: evidence %q (%s) is empty", v.Cell, v.Shape, v.Scenario, label, path)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "scenario: %s\n", v.Scenario)
	fmt.Fprintf(&b, "cell: %s\n", v.Cell)
	fmt.Fprintf(&b, "shape: %s\n", v.Shape)
	fmt.Fprintf(&b, "result: %s\n", v.Result)
	fmt.Fprintf(&b, "reason: %s\n", v.Reason)
	fmt.Fprintf(&b, "git_sha: %s\n", v.GitSHA)
	fmt.Fprintf(&b, "timestamp: %s\n", v.Timestamp.UTC().Format(time.RFC3339))
	labels := make([]string, 0, len(v.Evidence))
	for label := range v.Evidence {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		fmt.Fprintf(&b, "evidence.%s: %s\n", label, v.Evidence[label])
	}
	return os.WriteFile(dir+"/"+v.FileName(), []byte(b.String()), 0o644)
}
