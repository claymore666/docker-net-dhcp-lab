package main

import (
	"context"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Lab #10: the Env cellEnv hands a run for the pihole cell still carries
// the adapter's own N/A reasoning, so a lease-time or v6 scenario reads as
// "the lab does not edit the toml" and "DHCPv4 only", never a bare
// capability name.
func TestCellEnvKeepsThePiholeNAReasoning(t *testing.T) {
	cfg, err := labyaml.Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cell, err := cfg.CellByName("pihole")
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]*fakeHost{hostPart(cell.Source.MgmtAddress): {}}
	env, err := cellEnv(context.Background(), cell, "pihole", "/repo", t.TempDir(), dialFakes(hosts))
	if err != nil {
		t.Fatal(err)
	}
	for c, frag := range map[sourceadapter.Capability]string{
		sourceadapter.CapShortLease: "does not edit the toml",
		sourceadapter.CapV6:         "DHCPv4 only",
	} {
		need := scenario.Scenario{Name: "needs-" + string(c), Needs: []sourceadapter.Capability{c}}
		if ok, why := scenario.Applicable(need, env.Source); ok || !strings.Contains(why, frag) {
			t.Errorf("%s on pihole: applicable=%v reason %q, want N/A naming %q", c, ok, why, frag)
		}
	}
}
