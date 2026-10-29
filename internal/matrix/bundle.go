package matrix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
)

// Bundle is one run-cell.sh evidence directory: one cell, every
// shape it ran, read back through scenario.ReadVerdict rather than
// anything a caller reconstructs from file names (issue #4).
type Bundle struct {
	Dir               string
	Cell              string
	PluginTag         string
	PreviousPluginTag string
	// LabCommit is the git_sha every verdict in this bundle carries --
	// the lab repo's own commit the run used, not the plugin's.
	LabCommit string
	// Date is the latest Timestamp among this bundle's verdicts.
	Date time.Time
	// Host is the docker host this bundle's cell ran on (issue #8): the
	// first non-zero scenario.HostInfo found among its verdicts.
	// Deliberately permissive, unlike Cell/LabCommit above -- a verdict
	// written before this field existed, or one whose host read failed,
	// carries a zero HostInfo, and that alone must never fail a whole
	// bundle's load the way a real cell or git_sha mismatch does.
	Host     scenario.HostInfo
	Verdicts []scenario.Verdict
	// Blocked is set instead of Verdicts when run-cells.sh did not start
	// the cell because its built base image is not on the host (lab #14).
	Blocked *Blocked
}

// BlockedFile is the marker run-cells.sh writes into a cell's evidence
// directory when it records skipped-image (lab #14): JSON with cell,
// reason, detail and date (RFC 3339, UTC).
const BlockedFile = "image-not-built.json"

// Blocked is that marker, read back. Cell and Reason come from its
// content, never from the directory name, like every other bundle field.
type Blocked struct {
	Cell   string    `json:"cell"`
	Reason string    `json:"reason"`
	Detail string    `json:"detail"`
	Date   time.Time `json:"date"`
}

// resolvedLab mirrors only the fields `labctl resolve`'s JSON output
// carries that a results page needs (cmd/labctl's cmdResolve): reusing
// labyaml.Cell's own tags instead of a second, hand-kept field list
// means a field rename there is a compile error here, not a silent
// empty header cell.
type resolvedLab struct {
	Cell *labyaml.Cell `json:"cell"`
}

// LoadBundle reads every *.verdict file directly under dir plus its
// <cell>-resolved-lab.json, exactly what run-cell.sh leaves behind
// (README.md's scenario-runner section). It never looks at dir's own
// path or a verdict file's name for any field: every value it returns
// came from a verdict's own content or from resolved-lab.json (issue
// #4).
func LoadBundle(dir string) (Bundle, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.verdict"))
	if err != nil {
		return Bundle{}, fmt.Errorf("list verdicts in %s: %w", dir, err)
	}
	markerPath := filepath.Join(dir, BlockedFile)
	_, markerErr := os.Stat(markerPath)
	hasMarker := markerErr == nil
	if hasMarker && len(matches) > 0 {
		return Bundle{}, fmt.Errorf("bundle %s: holds both %s and %d verdict(s); run-cells.sh never leaves both, so one of them is stale",
			dir, BlockedFile, len(matches))
	}
	if hasMarker {
		return loadBlocked(dir, markerPath)
	}
	if len(matches) == 0 {
		return Bundle{}, fmt.Errorf("bundle %s: no *.verdict files found", dir)
	}
	sort.Strings(matches)

	b := Bundle{Dir: dir}
	for _, path := range matches {
		v, err := scenario.ReadVerdict(path)
		if err != nil {
			return Bundle{}, fmt.Errorf("bundle %s: %w", dir, err)
		}
		if b.Cell == "" {
			b.Cell = v.Cell
			b.LabCommit = v.GitSHA
		} else if v.Cell != b.Cell {
			return Bundle{}, fmt.Errorf("bundle %s: mixes cell %q (%s) with cell %q (%s); one bundle is one cell",
				dir, b.Cell, matches[0], v.Cell, path)
		} else if v.GitSHA != b.LabCommit {
			return Bundle{}, fmt.Errorf("bundle %s: verdict %s carries git_sha %q, others carry %q; one bundle is one run",
				dir, path, v.GitSHA, b.LabCommit)
		}
		if v.Timestamp.After(b.Date) {
			b.Date = v.Timestamp
		}
		if b.Host == (scenario.HostInfo{}) && v.Host != (scenario.HostInfo{}) {
			b.Host = v.Host
		}
		b.Verdicts = append(b.Verdicts, v)
	}

	resolvedPath := filepath.Join(dir, b.Cell+"-resolved-lab.json")
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return Bundle{}, fmt.Errorf("bundle %s: read %s: %w", dir, resolvedPath, err)
	}
	var rl resolvedLab
	if err := json.Unmarshal(data, &rl); err != nil {
		return Bundle{}, fmt.Errorf("bundle %s: parse %s: %w", dir, resolvedPath, err)
	}
	if rl.Cell == nil {
		return Bundle{}, fmt.Errorf("bundle %s: %s carries no \"cell\" object", dir, resolvedPath)
	}
	b.PluginTag = rl.Cell.DockerHost.PluginTag
	b.PreviousPluginTag = rl.Cell.DockerHost.PreviousPluginTag
	if b.PluginTag == "" {
		return Bundle{}, fmt.Errorf("bundle %s: %s carries no plugin_tag", dir, resolvedPath)
	}
	return b, nil
}

// loadBlocked reads the image-not-built marker (lab #14). A marker with
// no cell, no reason or no date is refused: a BLOCKED column that cannot
// say why or when is the empty column this exists to replace.
func loadBlocked(dir, path string) (Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("bundle %s: read %s: %w", dir, path, err)
	}
	var m Blocked
	if err := json.Unmarshal(data, &m); err != nil {
		return Bundle{}, fmt.Errorf("bundle %s: parse %s: %w", dir, path, err)
	}
	switch {
	case m.Cell == "":
		return Bundle{}, fmt.Errorf("bundle %s: %s carries no cell", dir, path)
	case m.Reason == "":
		return Bundle{}, fmt.Errorf("bundle %s: %s carries no reason", dir, path)
	case m.Date.IsZero():
		return Bundle{}, fmt.Errorf("bundle %s: %s carries no date", dir, path)
	}
	return Bundle{Dir: dir, Cell: m.Cell, Date: m.Date, Blocked: &m}, nil
}
