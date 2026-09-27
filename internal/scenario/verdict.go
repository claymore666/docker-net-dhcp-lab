package scenario

import (
	"fmt"
	"os"
	"path/filepath"
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
	Scenario string
	Cell     string
	Shape    Shape
	Result   Result
	Reason   string
	Evidence map[string]string
	GitSHA   string
	// IsolationMethod is which of IsolateIPAMNetwork's two paths ran
	// right before this scenario, for the IPAM shapes only ("network
	// recreated between scenarios" or the wait-out fallback's own
	// message). Empty for a scenario that ran with no isolation step
	// before it (the shape's first scenario, or a null-IPAM shape).
	// Carried here, not only in isolation.log, so a verdict read on its
	// own says how the network it ran against was isolated (issue #3).
	IsolationMethod string
	// Host is the docker host this scenario ran against (issue #8, host
	// axis): distro, kernel and docker engine version, read once per
	// shape and copied onto every verdict by RunOne. Zero value (every
	// field empty) for a verdict from before this field existed, or when
	// the read itself failed -- a verdict never blocks on it.
	Host      HostInfo
	Timestamp time.Time
}

// HostInfo is the docker host's own identity, per issue #8: which
// distro/kernel/engine a verdict ran against, so a difference between
// two hosts running the same scenario has one recorded cause.
type HostInfo struct {
	Distro        string
	Kernel        string
	DockerVersion string
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
	if v.IsolationMethod != "" {
		fmt.Fprintf(&b, "isolation: %s\n", v.IsolationMethod)
	}
	if v.Host.Distro != "" {
		fmt.Fprintf(&b, "host.distro: %s\n", v.Host.Distro)
	}
	if v.Host.Kernel != "" {
		fmt.Fprintf(&b, "host.kernel: %s\n", v.Host.Kernel)
	}
	if v.Host.DockerVersion != "" {
		fmt.Fprintf(&b, "host.docker_version: %s\n", v.Host.DockerVersion)
	}
	fmt.Fprintf(&b, "timestamp: %s\n", v.Timestamp.UTC().Format(time.RFC3339))
	labels := make([]string, 0, len(v.Evidence))
	for label := range v.Evidence {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		// Stored relative to dir, never the absolute path Write was
		// called with: the run's own machine layout is not evidence and
		// must never leak into a bundle another host later reads or
		// packs (issue #4).
		rel, err := filepath.Rel(dir, v.Evidence[label])
		if err != nil {
			return fmt.Errorf("verdict %s/%s/%s: evidence %q (%s): %w", v.Cell, v.Shape, v.Scenario, label, v.Evidence[label], err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("verdict %s/%s/%s: evidence %q (%s) is outside %s", v.Cell, v.Shape, v.Scenario, label, v.Evidence[label], dir)
		}
		fmt.Fprintf(&b, "evidence.%s: %s\n", label, filepath.ToSlash(rel))
	}
	return os.WriteFile(dir+"/"+v.FileName(), []byte(b.String()), 0o644)
}

// ReadVerdict parses one file Write produced. It never looks at path's
// own name for scenario/cell/shape (issue #4): both a shape and a
// scenario name can carry internal hyphens of their own
// ("bridge-ipam", or a scenario's own multi-word name), so the only
// field boundary that can never be ambiguous is the "key: value" line
// Write already wrote.
// isolation is optional, matching Write's own "only when non-empty"
// rule; every other key is required, and an unrecognised key fails
// loudly rather than being silently dropped, the same discipline a
// results page reading this file depends on (issue #4).
func ReadVerdict(path string) (Verdict, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Verdict{}, fmt.Errorf("read verdict %s: %w", path, err)
	}
	v := Verdict{Evidence: map[string]string{}}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			return Verdict{}, fmt.Errorf("%s:%d: line %q is not a \"key: value\" pair", path, i+1, line)
		}
		switch {
		case key == "scenario":
			v.Scenario = val
		case key == "cell":
			v.Cell = val
		case key == "shape":
			v.Shape = Shape(val)
		case key == "result":
			v.Result = Result(val)
		case key == "reason":
			v.Reason = val
		case key == "git_sha":
			v.GitSHA = val
		case key == "isolation":
			v.IsolationMethod = val
		case key == "host.distro":
			v.Host.Distro = val
		case key == "host.kernel":
			v.Host.Kernel = val
		case key == "host.docker_version":
			v.Host.DockerVersion = val
		case key == "timestamp":
			t, err := time.Parse(time.RFC3339, val)
			if err != nil {
				return Verdict{}, fmt.Errorf("%s:%d: timestamp %q: %w", path, i+1, val, err)
			}
			v.Timestamp = t
		case strings.HasPrefix(key, "evidence."):
			v.Evidence[strings.TrimPrefix(key, "evidence.")] = val
		default:
			return Verdict{}, fmt.Errorf("%s:%d: unrecognised field %q", path, i+1, key)
		}
	}
	if v.Scenario == "" || v.Cell == "" || v.Shape == "" || v.Result == "" {
		return Verdict{}, fmt.Errorf("%s: missing one of scenario/cell/shape/result", path)
	}
	return v, nil
}
