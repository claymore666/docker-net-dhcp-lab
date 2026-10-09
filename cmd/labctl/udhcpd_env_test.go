package main

import (
	"context"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Lab #10, #11: the Env cellEnv hands a run for the udhcpd cell still
// carries the adapter's own N/A reasoning, so an ipvlan run or a client-id
// scenario reads as the server's MAC-only leasing, never a bare capability
// name or a FAIL.
func TestCellEnvKeepsTheUdhcpdNAReasoning(t *testing.T) {
	cfg, err := labyaml.Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cell, err := cfg.CellByName("udhcpd")
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]*fakeHost{hostPart(cell.Source.MgmtAddress): {}}
	env, err := cellEnv(context.Background(), cell, "udhcpd", "/repo", t.TempDir(), dialFakes(hosts))
	if err != nil {
		t.Fatal(err)
	}
	sr, ok := env.Source.(sourceadapter.ShapeNAReasoner)
	if !ok || !strings.Contains(sr.NAShapeReason("ipvlan", "A1-first-lease"), "not a plugin fault") {
		t.Errorf("the udhcpd Env lost its shape reasoning (ok=%v)", ok)
	}
	need := scenario.Scenario{Name: "needs-client-id", Needs: []sourceadapter.Capability{sourceadapter.CapReserveClientID}}
	if ok, why := scenario.Applicable(need, env.Source); ok || !strings.Contains(why, "not a plugin fault") {
		t.Errorf("client-id scenario on udhcpd: applicable=%v reason %q, want N/A naming the server", ok, why)
	}
}
