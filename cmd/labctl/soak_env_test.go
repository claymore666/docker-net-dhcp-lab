package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
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

// Row 11 (#15 soak): the soak parameters cmdRun read from the
// environment are in the Env E5 runs with. The call site in cmdRun
// passing them is not exercised here: it needs a live ssh dial.
func TestCellEnvCarriesTheSoakParameters(t *testing.T) {
	cfg, err := labyaml.Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cell, err := cfg.CellByName("kea")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LAB_SOAK_DURATION", "1h")
	t.Setenv("LAB_SOAK_LEASE", "60")
	soak, err := scenario.SoakFromEnv(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]*fakeHost{hostPart(cell.Source.MgmtAddress): {}}
	env, err := cellEnv(context.Background(), cell, "kea", "/repo", t.TempDir(), soak, dialFakes(hosts))
	if err != nil {
		t.Fatal(err)
	}
	want := scenario.SoakParams{Window: time.Hour, Lease: 60}
	if env.Soak != want {
		t.Fatalf("Env.Soak = %+v, want %+v", env.Soak, want)
	}
}
