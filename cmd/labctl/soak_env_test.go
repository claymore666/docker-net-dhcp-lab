package main

import (
	"path/filepath"
	"testing"
)

// Row 11 (#15 soak): a soak value that does not parse stops labctl run
// with a usage error before it reads lab.yaml, never running the default.
func TestCmdRunRefusesABadSoakValue(t *testing.T) {
	dir := t.TempDir()
	args := []string{filepath.Join(dir, "missing-lab.yaml"), dir, "dnsmasq", "bridge", dir, dir, "-"}
	for _, kv := range [][2]string{{"LAB_SOAK_DURATION", "an hour"}, {"LAB_SOAK_LEASE", "40s"}, {"LAB_SOAK_DURATION", "30s"}} {
		t.Run(kv[0]+"="+kv[1], func(t *testing.T) {
			t.Setenv(kv[0], kv[1])
			if got := cmdRun(args); got != 2 {
				t.Fatalf("cmdRun = %d, want 2", got)
			}
		})
	}
	t.Setenv("LAB_SOAK_DURATION", "1h")
	if got := cmdRun(args); got != 1 {
		t.Fatalf("a valid soak value went on to read lab.yaml: cmdRun = %d, want 1 for the missing file", got)
	}
}
