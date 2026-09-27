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

// Bundle is one run-group-a.sh evidence directory: one cell, every
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
	Date     time.Time
	Verdicts []scenario.Verdict
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
// <cell>-resolved-lab.json, exactly what run-group-a.sh leaves behind
// (README.md's scenario-runner section). It never looks at dir's own
// path or a verdict file's name for any field: every value it returns
// came from a verdict's own content or from resolved-lab.json (issue
// #4).
func LoadBundle(dir string) (Bundle, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.verdict"))
	if err != nil {
		return Bundle{}, fmt.Errorf("list verdicts in %s: %w", dir, err)
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
