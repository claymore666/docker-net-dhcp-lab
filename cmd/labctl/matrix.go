package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/claymore666/docker-net-dhcp-lab/internal/matrix"
)

// cmdMatrix is issue #4's results-page renderer: one or more evidence
// bundle directories in, one markdown results page out. Every evidence
// link is written relative to --root, so the page still resolves once
// root's own directory becomes a packed release tarball's extracted
// root (labctl pack); the caller decides root, this never guesses it.
func cmdMatrix(args []string) int {
	fs := flag.NewFlagSet("labctl matrix", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	root := fs.String("root", "", "bundle root every evidence link is written relative to (required)")
	out := fs.String("out", "", "path to write the results page to (default: stdout)")
	asset := fs.String("asset", "", "release asset name the page's relative links resolve inside (default: unnamed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bundleDirs := fs.Args()
	if *root == "" || len(bundleDirs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: labctl matrix --root <bundle-root> [--out <path>] [--asset <name>] <bundle-dir> [<bundle-dir> ...]")
		return 2
	}

	bundles := make([]matrix.Bundle, 0, len(bundleDirs))
	for _, dir := range bundleDirs {
		b, err := matrix.LoadBundle(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "labctl matrix:", err)
			return 1
		}
		bundles = append(bundles, b)
	}

	page, err := matrix.Render(*root, *asset, bundles)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl matrix:", err)
		return 1
	}

	if *out == "" {
		fmt.Print(page)
		return 0
	}
	if err := os.WriteFile(*out, []byte(page), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "labctl matrix:", err)
		return 1
	}
	return 0
}
