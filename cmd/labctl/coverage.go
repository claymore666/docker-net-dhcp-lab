package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/coverage"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

const coverageUsage = `usage: labctl coverage (--tag vX.Y.Z | --file reference.md | --pinned vX.Y.Z) [--regen] [--data-dir DIR]
       labctl coverage pin --plugin-tree DIR --tag vX.Y.Z [--data-dir DIR]`

// exitUnreadable is the exit code when the docs could not be fetched
// or read at all (offline, a bad path). It is not 1, which says the
// docs and the inventory disagree, so a CI step can tell a network
// outage from a real finding.
const exitUnreadable = 3

// defaultDataDir is read when the command runs from the repo root, so
// an edit to the inventory is seen without a rebuild; anywhere else
// the copy compiled into labctl is used.
const defaultDataDir = "internal/coverage/data"

// undeclared are the capabilities no adapter declares yet (scenario's
// capabilityNAReason lists the same three): a lab scenario needing one
// runs nowhere, so it cannot count as coverage.
var undeclared = map[string]bool{
	string(sourceadapter.CapV6):           true,
	string(sourceadapter.CapRelay):        true,
	string(sourceadapter.CapFailoverPair): true,
}

// cmdCoverage is issue #4's coverage check, widened by issue #35: the
// docs' option tables against the hand-kept inventory, the reviewed
// option-to-scenario mapping and, for a pinned release, the generated
// variant matrix against its placements.
func cmdCoverage(args []string) int {
	if len(args) > 0 && args[0] == "pin" {
		return cmdCoveragePin(args[1:])
	}
	fs_ := flag.NewFlagSet("labctl coverage", flag.ContinueOnError)
	fs_.SetOutput(os.Stderr)
	tag := fs_.String("tag", "", "docker-net-dhcp tag to fetch docs/reference.md from, e.g. v2.5.0")
	file := fs_.String("file", "", "local docs/reference.md to read instead of fetching")
	pinned := fs_.String("pinned", "", "pinned release under "+defaultDataDir+"/pinned to check in full")
	regen := fs_.Bool("regen", false, "with --pinned: write matrix.tsv instead of comparing with it")
	dataDir := fs_.String("data-dir", "", "data directory (default "+defaultDataDir+" when present, else the compiled-in copy)")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	n := 0
	for _, s := range []string{*tag, *file, *pinned} {
		if s != "" {
			n++
		}
	}
	if n != 1 || fs_.NArg() != 0 || (*regen && *pinned == "") {
		fmt.Fprintln(os.Stderr, coverageUsage)
		return 2
	}
	dir, fsys := openData(*dataDir)
	if *pinned != "" {
		return coveragePinned(fsys, dir, *pinned, *regen)
	}
	return coverageRows(fsys, *tag, *file)
}

func openData(flagDir string) (string, fs.FS) {
	dir := flagDir
	if dir == "" {
		dir = defaultDataDir
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return "", coverage.Data()
		}
	}
	return dir, os.DirFS(dir)
}

func report(problems []string) {
	for _, p := range problems {
		fmt.Println("  -", p)
	}
}

// coverageRows is --tag and --file: the docs rows against the inventory
// and the mapping. There is no matrix to place, so it can exit 0.
func coverageRows(fsys fs.FS, tag, file string) int {
	md, err := loadReferenceMD(tag, file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl coverage:", err)
		return exitUnreadable
	}
	rows, err := coverage.ParseRows(md)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl coverage:", err)
		return 1
	}
	var problems []string
	if tag != "" {
		switch p, perr := coverage.LoadPinned(fsys, tag); {
		case perr == nil:
			if d := coverage.CompareFetched(md, p.Reference); d != "" {
				problems = append(problems, "pinned "+tag+": "+d)
			}
		case errors.Is(perr, fs.ErrNotExist):
			fmt.Printf("labctl coverage: %s is not pinned, so the fetched docs are not compared with a pinned copy\n", tag)
		default:
			problems = append(problems, "pinned "+tag+" cannot be compared: "+perr.Error())
		}
	}
	inv, _, err := coverage.LoadData(fsys)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl coverage:", err)
		return 1
	}
	problems = append(problems, inv.Validate(rows)...)
	m := coverage.Check(coverage.Keys(rows))
	fmt.Printf("labctl coverage: %d option(s), %d covered by a scenario, %d carry a recorded reason\n", m.Total, m.Covered, m.Reasoned)
	problems = append(problems, m.Unmapped...)
	if len(problems) == 0 {
		return 0
	}
	fmt.Println("labctl coverage: problem(s):")
	report(problems)
	return 1
}

// coveragePinned is --pinned: the whole check on the pinned copy.
func coveragePinned(fsys fs.FS, dir, tag string, regen bool) int {
	l, err := coverage.LoadPinnedMatrix(fsys, tag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl coverage:", err)
		return 1
	}
	var problems []string
	m := coverage.Check(coverage.Keys(l.Rows))
	fmt.Printf("labctl coverage: %s: %d option(s), %d covered by a scenario, %d carry a recorded reason, %d variant(s)\n",
		tag, m.Total, m.Covered, m.Reasoned, len(l.Variants))
	problems = append(problems, m.Unmapped...)
	if regen {
		if dir == "" {
			fmt.Fprintln(os.Stderr, "labctl coverage: --regen writes to the data directory: run from the repo root or pass --data-dir")
			return 2
		}
		out := filepath.Join(dir, "matrix.tsv")
		if err := os.WriteFile(out, []byte(coverage.FormatMatrix(l.Variants)), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "labctl coverage:", err)
			return 1
		}
		fmt.Printf("labctl coverage: wrote %s (%d variants)\n", out, len(l.Variants))
	} else if d := coverage.MatrixDiff(fsys, l.Variants); d != "" {
		problems = append(problems, d)
	}
	res := coverage.CheckVariants(coverage.Input{
		Variants:   l.Variants,
		Placements: l.Placements,
		Tests:      l.Pinned.Tests,
		Lab:        labScenarios(),
		Undeclared: undeclared,
		ModePath:   l.Inventory.ModePaths(l.Rows),
	})
	problems = append(problems, res.Problems...)
	keys := make([]string, 0, len(res.Counts))
	for k := range res.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("labctl coverage: %-22s %d\n", k, res.Counts[k])
	}
	if len(problems) == 0 {
		return 0
	}
	fmt.Printf("labctl coverage: %d problem(s):\n", len(problems))
	report(problems)
	return 1
}

func labScenarios() []coverage.LabScenario {
	out := make([]coverage.LabScenario, 0, len(scenario.Catalog))
	for _, s := range scenario.Catalog {
		ls := coverage.LabScenario{Name: s.Name}
		for _, n := range s.Needs {
			ls.Needs = append(ls.Needs, string(n))
		}
		out = append(out, ls)
	}
	return out
}

func cmdCoveragePin(args []string) int {
	fs_ := flag.NewFlagSet("labctl coverage pin", flag.ContinueOnError)
	fs_.SetOutput(os.Stderr)
	tree := fs_.String("plugin-tree", "", "a checkout of docker-net-dhcp at the tag")
	tag := fs_.String("tag", "", "the tag, e.g. v2.5.0")
	dataDir := fs_.String("data-dir", defaultDataDir, "data directory to write pinned/<tag> under")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	if *tree == "" || *tag == "" || fs_.NArg() != 0 {
		fmt.Fprintln(os.Stderr, coverageUsage)
		return 2
	}
	out := filepath.Join(*dataDir, "pinned", *tag)
	if err := coverage.Pin(*tree, *tag, out); err != nil {
		fmt.Fprintln(os.Stderr, "labctl coverage pin:", err)
		return 1
	}
	fmt.Printf("labctl coverage pin: wrote %s\n", out)
	return 0
}

func loadReferenceMD(tag, file string) (string, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	if !strings.HasPrefix(tag, "v") {
		return "", fmt.Errorf("tag %q is not vX.Y.Z", tag)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return fetchReference(ctx, tag)
}

// fetchReference fetches the tag's docs/reference.md; tests replace it.
var fetchReference = func(ctx context.Context, tag string) (string, error) {
	return coverage.FetchURL(ctx, http.DefaultClient, coverage.RawURL(tag))
}
