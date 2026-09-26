package scenario

import (
	"context"
	"fmt"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Env is everything one scenario run needs, resolved once by the caller
// (labctl's run subcommand) and passed to every scenario unchanged.
// Scenarios never touch the network or libvirt directly (cmd/labctl's
// own rule); every action here goes through Host (the docker host's own
// SSH runner) or Source (the source's own adapter).
type Env struct {
	Host        sourceadapter.Runner
	Source      sourceadapter.Adapter
	Cell        string
	Shape       Shape
	Network     string
	PCAP        string // whole-cell capture, spans every scenario x shape
	RepoRoot    string // this clone's root, for dhcp-exchange-check.sh
	WorkDir     string
	EvidenceDir string
	PluginTag   string // e.g. ghcr.io/claymore666/docker-net-dhcp:v2.2.2
	// PreviousPluginTag is the release A6 upgrades FROM, carried
	// explicitly from lab.yaml rather than derived by decrementing
	// PluginTag's patch number (issue #3, lead directive 2026-09-26): the
	// real previous release is not always PluginTag's patch predecessor.
	// Empty means A6 has nothing to upgrade from and reports N/A.
	PreviousPluginTag string
	GitSHA            string
}

// Scenario is one entry in the catalog. Run returns the finished
// Verdict; Run is never called directly when Applicable says otherwise
// -- the runner checks Applicable itself first, so a scenario body never
// has to guard against running on a source it cannot.
type Scenario struct {
	Name  string
	Needs []sourceadapter.Capability
	Run   func(ctx context.Context, e Env) Verdict
}

// Applicable reports whether source declares every capability Name
// needs. A scenario whose capability is missing never reaches its Run
// body at all (issue #3 defeat list): the N/A path is enforced here,
// once, not repeated in every scenario.
func Applicable(s Scenario, source sourceadapter.Adapter) (bool, string) {
	have := map[sourceadapter.Capability]bool{}
	for _, c := range source.Capabilities() {
		have[c] = true
	}
	for _, need := range s.Needs {
		if !have[need] {
			return false, fmt.Sprintf("source does not declare capability %q", need)
		}
	}
	return true, ""
}

// Scenario name constants: the single source of truth for both Catalog
// and each runA* body, so a verdict's Scenario field can never drift
// from the name Catalog registered it under.
const (
	NameA1 = "A1-first-lease"
	NameA2 = "A2-container-restart"
	NameA3 = "A3-compose-down-up"
	NameA4 = "A4-daemon-restart"
	NameA5 = "A5-host-reboot"
	NameA6 = "A6-plugin-upgrade"
	NameA7 = "A7-plugin-killed"
	NameA8 = "A8-fleet-burst"
)

// RunOne checks Applicable itself, so a caller (labctl's run subcommand)
// never has to duplicate that check: a scenario whose capability is
// missing comes back N/A with a reason and never reaches s.Run at all.
//
// It also checks the plugin is in a known state -- installed, enabled,
// its process alive -- before every scenario, including the one right
// after a previous scenario's failure (issue #3, lead directive
// 2026-09-26): this one check simultaneously satisfies "known state
// before each scenario," "restore after a failure," and "BLOCKED, never
// a cascading FAIL, when it cannot be restored," with no separate
// before/after hooks and no change to the caller's loop.
func RunOne(ctx context.Context, s Scenario, e Env) Verdict {
	if err := ensurePluginKnownState(ctx, e.Host); err != nil {
		return blocked(s.Name, e.Cell, e.Shape,
			fmt.Sprintf("plugin not in a known state before this scenario: %v", err), e.GitSHA)
	}
	// The shape's own bridge, for bridge shape, must actually be present
	// before this scenario runs, not assumed from an earlier bring-up in
	// the same run (issue #3, lead directive 2026-09-26, item 1): a
	// missing or broken bridge is rebuilt here, or this scenario is
	// BLOCKED rather than left to cascade into a FAIL that reads like a
	// plugin defect. A no-op for macvlan/ipvlan.
	if err := ensureBridgePresent(ctx, e.Host, e.Cell, e.Shape); err != nil {
		return blocked(s.Name, e.Cell, e.Shape,
			fmt.Sprintf("shape's bridge not in a known state before this scenario: %v", err), e.GitSHA)
	}
	if ok, reason := Applicable(s, e.Source); !ok {
		return na(s.Name, e.Cell, e.Shape, reason, e.GitSHA)
	}
	return s.Run(ctx, e)
}

// Catalog is group A: first lease, container restart, compose down/up,
// daemon restart, host reboot, plugin upgrade, plugin killed, fleet
// burst (issue #3). Groups B, C, D are later PRs, per the issue.
var Catalog = []Scenario{
	{Name: NameA1, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA1},
	{Name: NameA2, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA2},
	{Name: NameA3, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA3},
	{Name: NameA4, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA4},
	{Name: NameA5, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA5},
	{Name: NameA6, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA6},
	{Name: NameA7, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA7},
	{Name: NameA8, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA8},
}
