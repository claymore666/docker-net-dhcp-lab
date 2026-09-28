package matrix

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
)

// column is one cell (source) x shape pairing, one results-page column.
type column struct {
	cell  string
	shape scenario.Shape
}

func (c column) label() string { return fmt.Sprintf("%s / %s", c.cell, c.shape) }

type cellKey struct {
	scenarioID string
	col        column
}

// placed is a verdict plus the bundle directory it came from, which
// scenario.Verdict itself does not carry -- the link Render writes
// needs it, and looking it up by column/scenario is cheaper than
// storing it a second time inside Verdict.
type placed struct {
	verdict scenario.Verdict
	dir     string
}

// Render builds the markdown results page for one or more bundles.
// root is the directory every evidence link is written relative to
// (issue #4's "a bundle root given as a flag"): the same links resolve
// once a bundle's own directory becomes a release tarball's extracted
// root, because packing changes nothing about a bundle's internal
// layout (labctl pack).
//
// Render fails outright, rather than printing a raw id, the moment a
// verdict names a scenario matrix.PlainNames does not carry -- issue
// #4's own rule that a scenario id never reaches rendered prose
// unmapped -- the moment a verdict's own Result is not one of the
// legitimate readings scenario.Write ever produces, the moment an N/A
// or BLOCKED verdict carries no reason, and the moment two bundles both
// cover the same cell/shape/scenario cell, which would otherwise
// silently render whichever one Go's map iteration happened to keep.
// asset, when non-empty, names the release asset the page's relative
// links resolve inside (issue #4); an empty asset leaves the existing
// header unchanged.
func Render(root, asset string, bundles []Bundle) (string, error) {
	if len(bundles) == 0 {
		return "", fmt.Errorf("render: no bundles given")
	}

	placedAt := map[cellKey]placed{}
	cols := map[column]bool{}

	for _, b := range bundles {
		for _, v := range b.Verdicts {
			if _, ok := PlainName(v.Scenario); !ok {
				return "", fmt.Errorf("render: bundle %s: verdict %s names scenario %q, which matrix.PlainNames does not carry",
					b.Dir, v.FileName(), v.Scenario)
			}
			switch v.Result {
			case scenario.PASS, scenario.FAIL, scenario.NA, scenario.BLOCKED:
			default:
				return "", fmt.Errorf("render: bundle %s: verdict %s carries result %q, not one of PASS/FAIL/N/A/BLOCKED",
					b.Dir, v.FileName(), v.Result)
			}
			if (v.Result == scenario.NA || v.Result == scenario.BLOCKED) && v.Reason == "" {
				return "", fmt.Errorf("render: bundle %s: verdict %s is %s with no reason",
					b.Dir, v.FileName(), v.Result)
			}
			col := column{cell: v.Cell, shape: v.Shape}
			cols[col] = true
			key := cellKey{scenarioID: v.Scenario, col: col}
			if prior, ok := placedAt[key]; ok {
				return "", fmt.Errorf("render: %s/%s/%s is covered by both %s and %s; pass one bundle per cell/run",
					v.Cell, v.Shape, v.Scenario, prior.dir, b.Dir)
			}
			placedAt[key] = placed{verdict: v, dir: b.Dir}
		}
	}

	colList := make([]column, 0, len(cols))
	for c := range cols {
		colList = append(colList, c)
	}
	sort.Slice(colList, func(i, j int) bool {
		if colList[i].cell != colList[j].cell {
			return colList[i].cell < colList[j].cell
		}
		return colList[i].shape < colList[j].shape
	})

	var out strings.Builder
	writeHeader(&out, asset, bundles)

	// cellHost backs each column header's host tag (issue #8): keyed by
	// cell rather than carried on column itself, since column is also a
	// map key (cellKey.col) and must stay just cell+shape for that.
	cellHost := map[string]scenario.HostInfo{}
	for _, b := range bundles {
		if b.Host != (scenario.HostInfo{}) {
			cellHost[b.Cell] = b.Host
		}
	}

	out.WriteString("| scenario |")
	for _, c := range colList {
		label := c.label()
		if h, ok := cellHost[c.cell]; ok && h.Distro != "" {
			label = fmt.Sprintf("%s (%s)", label, h.Distro)
		}
		fmt.Fprintf(&out, " %s |", label)
	}
	out.WriteString("\n| --- |")
	for range colList {
		out.WriteString(" --- |")
	}
	out.WriteString("\n")

	for _, id := range Order() {
		name, ok := PlainName(id)
		if !ok {
			// Order() is built straight from scenario.Catalog and
			// PlainNames is keyed on the same constants (names.go), so
			// this is a programming error in this package, not
			// something a bundle could ever trigger.
			return "", fmt.Errorf("render: catalog scenario %q has no entry in PlainNames", id)
		}
		fmt.Fprintf(&out, "| %s |", name)
		for _, c := range colList {
			p, ok := placedAt[cellKey{scenarioID: id, col: c}]
			if !ok {
				out.WriteString(" (missing) |")
				continue
			}
			link, err := verdictLink(root, p.dir, p.verdict.FileName())
			if err != nil {
				return "", err
			}
			fmt.Fprintf(&out, " [%s](%s) |", p.verdict.Result, link)
		}
		out.WriteString("\n")
	}

	return out.String(), nil
}

func writeHeader(out *strings.Builder, asset string, bundles []Bundle) {
	out.WriteString("# Results\n\n")
	if asset != "" {
		fmt.Fprintf(out, "Links below are relative to `%s`.\n\n", asset)
	}
	for _, b := range bundles {
		fmt.Fprintf(out, "- **%s**: plugin `%s`", b.Cell, b.PluginTag)
		if b.PreviousPluginTag != "" {
			fmt.Fprintf(out, " (previous `%s`)", b.PreviousPluginTag)
		}
		fmt.Fprintf(out, ", %s, lab commit `%s`", b.Date.UTC().Format("2006-01-02"), b.LabCommit)
		if b.Host.Distro != "" || b.Host.Kernel != "" || b.Host.DockerVersion != "" {
			fmt.Fprintf(out, ", host %s (kernel %s, docker %s)", orDash(b.Host.Distro), orDash(b.Host.Kernel), orDash(b.Host.DockerVersion))
		}
		out.WriteString("\n")
	}
	out.WriteString("\n")
}

// orDash prints a placeholder for one of writeHeader's three host
// fields when only some of them came back from the read (#8).
func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// verdictLink is the path a cell links to, relative to root, so the
// same page resolves once root's own directory becomes a packed
// tarball's extracted root (issue #4). A PASS/FAIL/N/A/BLOCKED result
// links straight at the verdict file, which always carries the reason
// -- there is no separate "reason" column to keep in step with it.
func verdictLink(root, dir, fileName string) (string, error) {
	abs := filepath.Join(dir, fileName)
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", fmt.Errorf("render: relative path from root %s to %s: %w", root, abs, err)
	}
	// A link may never climb out of root or fall back to an absolute
	// path (issue #4): either shape means --root was not actually an
	// ancestor of this bundle, so the page would carry this machine's
	// own layout instead of a portable, packable link.
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("render: %s is not an ancestor of %s; refusing a link that would leave it", root, abs)
	}
	return filepath.ToSlash(rel), nil
}
