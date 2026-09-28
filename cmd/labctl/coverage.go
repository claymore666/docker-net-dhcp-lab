package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/coverage"
)

// cmdCoverage is issue #4's coverage check: docs/reference.md's option
// tables, at a tag or from a local file, against internal/coverage's
// one reviewed option->scenario/reason mapping. It is a labctl
// subcommand and not a verify.sh step: the --tag path fetches a live
// URL every time, and verify.sh is deliberately network-free by design
// (verify.sh's own header comment) with no pinned local copy of
// reference.md to run this against instead -- README.md documents this
// choice, so it is not a decision only this file knows about.
func cmdCoverage(args []string) int {
	fs := flag.NewFlagSet("labctl coverage", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	tag := fs.String("tag", "", "docker-net-dhcp tag to fetch docs/reference.md from, e.g. v2.2.2")
	file := fs.String("file", "", "local docs/reference.md to read instead of fetching (tests, or a pinned copy)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*tag == "") == (*file == "") {
		fmt.Fprintln(os.Stderr, "usage: labctl coverage (--tag vX.Y.Z | --file path/to/reference.md)")
		return 2
	}

	md, err := loadReferenceMD(*tag, *file)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl coverage:", err)
		return 1
	}

	options, err := coverage.ParseOptions(md)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl coverage:", err)
		return 1
	}
	result := coverage.Check(options)
	fmt.Printf("labctl coverage: %d option(s), %d covered by a scenario, %d carry a recorded reason\n",
		result.Total, result.Covered, result.Reasoned)
	if len(result.Unmapped) == 0 {
		return 0
	}
	fmt.Println("labctl coverage: unmapped option(s), with no recorded scenario or reason:")
	for _, o := range result.Unmapped {
		fmt.Println("  -", o)
	}
	return 1
}

func loadReferenceMD(tag, file string) (string, error) {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return coverage.FetchURL(ctx, http.DefaultClient, coverage.RawURL(tag))
}
