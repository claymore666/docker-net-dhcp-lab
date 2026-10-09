package scenario

import (
	"context"
	"fmt"
	"time"

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
	// PluginTag's patch number (issue #3): the real previous release is
	// not always PluginTag's patch predecessor.
	// Empty means A6 has nothing to upgrade from and reports N/A.
	PreviousPluginTag string
	GitSHA            string
	// SegGateway is the address the segment's DHCP server hands out as
	// the router option, cell.source.seg_address stripped of its CIDR
	// suffix (issue #3, A13 redesign): A13 checks the container's own
	// default route against this, not against a hardcoded address.
	SegGateway string
	// SourceAddr is the source's own segment address; it equals SegGateway
	// on every cell without a relay (#11, #23).
	SourceAddr string
	// SegSubnet, PoolStart and PoolEnd are the cell's /24 and the source's
	// main pool from lab.yaml (group B, #23): the reservation, class-pool
	// and DNS-option addresses are chosen from SegSubnet and refused
	// when they fall inside the pool.
	SegSubnet string
	PoolStart string
	PoolEnd   string
	// HostInfo is the docker host this Env's scenarios run against
	// (issue #8): copied onto every Verdict by RunOne, once, so no
	// scenario body has to carry it. Zero value when the read failed;
	// never blocks a run.
	HostInfo HostInfo
	// Capture reads the live observer capture (group C, #23); nil
	// leaves a group C scenario BLOCKED, never judged without it.
	Capture CaptureReader
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
			reason := fmt.Sprintf("source does not declare capability %q", need)
			if why, ok := capabilityNAReason[need]; ok {
				reason += ": " + why
			}
			return false, reason
		}
	}
	return true, ""
}

// capabilityNAReason names, for a capability no adapter declares yet,
// the lab issue that builds the cell it needs (C5, C12; #23).
var capabilityNAReason = map[sourceadapter.Capability]string{
	sourceadapter.CapFailoverPair: "needs a failover pair cell, claymore666/docker-net-dhcp-lab#12",
	sourceadapter.CapRelay:        "needs a relay cell, claymore666/docker-net-dhcp-lab#11",
	sourceadapter.CapV6:           "needs the IPv6 segment, #23 group D",
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
	// NameA5b tests the documented promise A5 itself cannot (a plain
	// container may legitimately get a new mac/address on a reboot,
	// #3): a container with a fixed mac_address must keep both across a
	// host reboot.
	NameA5b = "A5b-host-reboot-fixed-mac"
	NameA6  = "A6-plugin-upgrade"
	NameA7  = "A7-plugin-killed"
	NameA8  = "A8-fleet-burst"
	NameA9  = "A9-stop-wait-start"
	NameA10 = "A10-kill-restart-policy"
	NameA11 = "A11-pause-unpause"
	NameA12 = "A12-network-disconnect-reconnect"
	// NameA13 runs under every shape (#3 part 2, redesigned 2026-09-27):
	// one plugin network plus one ordinary Docker bridge network, never
	// two plugin networks on the one segment (runA13's own doc comment).
	NameA13 = "A13-two-networks-one-container"
	NameA14 = "A14-short-lease-renewal"
	NameA15 = "A15-compose-scale"
	NameA16 = "A16-forced-remove-running"

	NameB1 = "B1-reservation-by-mac"
	NameB2 = "B2-reservation-by-client-id"
	NameB3 = "B3-dns-registration"
	NameB4 = "B4-requested-address-kept"
	NameB5 = "B5-vendor-class-pool"
	NameB6 = "B6-option-change-on-renewal"
	NameB7 = "B7-lease-release"
	NameB8 = "B8-three-at-once"

	NameC1  = "C1-source-down-at-start"
	NameC2  = "C2-source-down-past-t1"
	NameC3  = "C3-source-down-past-expiry"
	NameC4  = "C4-restart-without-lease-db"
	NameC5  = "C5-failover-primary-killed"
	NameC6  = "C6-early-squatter"
	NameC6b = "C6b-late-squatter"
	NameC7  = "C7-rogue-server"
	NameC8  = "C8-pool-exhausted"
	NameC9  = "C9-subnet-renumbered"
	NameC10 = "C10-loss-and-latency"
	NameC11 = "C11-validate-dhcp-create"
	NameC12 = "C12-relay"

	NameF1  = "F1-user-class-pool"
	NameF2a = "F2a-option-108-not-asked"
	NameF2b = "F2b-option-108-forced"
	NameF3  = "F3-rapid-commit-v4"
	NameF4  = "F4-rapid-commit-v6"
	NameF5  = "F5-temporary-address"
	NameF6  = "F6-prefix-delegation"
	NameF7  = "F7-pref64"
	NameF8  = "F8-forcerenew"
)

// MinPoolAddresses is the most pool addresses one full pass under one
// shape could hold onto, worst case (issue #3 part 2, #23). The plugin's
// own default is release_lease=never (docs/reference.md): nothing frees
// a lease on its own, so every fresh MAC/client-id a scenario mints
// keeps its address until the source's lease database is reset
// (sourceadapter.Adapter.ResetLeases, called once before every shape).
// Counted straight from the catalog, one fresh address for every
// container start an event could mint in the worst case, even though
// most of the time it reuses the same one: A1(1) + A2(2) + A3(2) +
// A4(2) + A5(2) + A5b(2) + A6(1, persists across the upgrade) +
// A7(1, persists across the kill) + A8(10, fleet burst) + A9(2) +
// A10(2) + A11(1, pause/unpause mints nothing new) + A12(2) + A13(1,
// its own second network is Docker's default IPAM, never this pool) +
// A14(1) + A15(5, peak replica count) + A16(1) = 38, plus group B's 11
// (poolDemand, counted as if every reservation and the class pool missed),
// plus group C's 17: C1(2, if a failed run still kept a lease) + C2(1) +
// C3(2, a new address after expiry) + C4(2, the reset may hand out a
// second) + C6(1, the squatted address is reserved outside the pool) +
// C6b(2) + C7(2, the rogue's pool is its own) + C8(1, the fills sit on
// the narrowed range outside the pool) + C9(1, the renumbered lease is
// reset) + C10(2) + C11(1, the validate_dhcp probe); C5 and C12 never run,
// plus group F's 7: one each for the user class, 108 not asked and rapid commit, two each
// for 108 forced and FORCERENEW (their control clients, #21); the IPv6 rows never run (#20).
// The pre-shape check in cmd/labctl compares a pool's free addresses
// against this and aborts the cell as a lab error, never as a scenario
// FAIL. TestPoolDemandSumsToMinPoolAddresses pins the sum (#23).
const MinPoolAddresses = 73

// poolDemand is the per-scenario worst case MinPoolAddresses is the sum
// of; a scenario added to Catalog without a row here fails the test.
var poolDemand = map[string]int{
	NameA1: 1, NameA2: 2, NameA3: 2, NameA4: 2, NameA5: 2, NameA5b: 2,
	NameA6: 1, NameA7: 1, NameA8: 10, NameA9: 2, NameA10: 2, NameA11: 1,
	NameA12: 2, NameA13: 1, NameA14: 1, NameA15: 5, NameA16: 1,
	NameB1: 1, NameB2: 1, NameB3: 1, NameB4: 2, NameB5: 1, NameB6: 1,
	NameB7: 1, NameB8: 3,
	NameC1: 2, NameC2: 1, NameC3: 2, NameC4: 2, NameC5: 0, NameC6: 1,
	NameC6b: 2, NameC7: 2, NameC8: 1, NameC9: 1, NameC10: 2,
	NameC11: 1, NameC12: 0,
	NameF1: 1, NameF2a: 1, NameF2b: 2, NameF3: 1,
	NameF4: 0, NameF5: 0, NameF6: 0, NameF7: 0, NameF8: 2,
}

// RunOne checks Applicable itself, so a caller (labctl's run subcommand)
// never has to duplicate that check: a scenario whose capability is
// missing comes back N/A with a reason and never reaches s.Run at all.
//
// It also checks the plugin is in a known state -- installed, enabled,
// its process alive -- before every scenario, including the one right
// after a previous scenario's failure (issue #3): this one check
// simultaneously satisfies "known state
// before each scenario," "restore after a failure," and "BLOCKED, never
// a cascading FAIL, when it cannot be restored," with no separate
// before/after hooks and no change to the caller's loop.
func RunOne(ctx context.Context, s Scenario, e Env) Verdict {
	// Every return path below funnels through here (#8): a verdict picks
	// up which host it ran on regardless of which check produced it,
	// without any of the checks below or the scenario bodies themselves
	// having to set it.
	v := runOneInner(ctx, s, e)
	v.Host = e.HostInfo
	return v
}

func runOneInner(ctx context.Context, s Scenario, e Env) Verdict {
	if err := ensurePluginKnownState(ctx, e.Host); err != nil {
		return blocked(s.Name, e.Cell, e.Shape,
			fmt.Sprintf("plugin not in a known state before this scenario: %v", err), e.GitSHA)
	}
	// The shape's own bridge, for bridge shape, must actually be present
	// before this scenario runs, not assumed from an earlier bring-up in
	// the same run (#3): a missing or broken bridge is rebuilt here, or
	// this scenario is BLOCKED rather than left to cascade into a FAIL
	// that reads like a plugin defect. A no-op for macvlan/ipvlan.
	if err := ensureBridgePresent(ctx, e.Host, e.Cell, e.Shape); err != nil {
		return blocked(s.Name, e.Cell, e.Shape,
			fmt.Sprintf("shape's bridge not in a known state before this scenario: %v", err), e.GitSHA)
	}
	if ok, reason := Applicable(s, e.Source); !ok {
		return na(s.Name, e.Cell, e.Shape, reason, e.GitSHA)
	}
	recovered, err := ensureSourceReady(ctx, e.Source)
	if err != nil {
		return blocked(s.Name, e.Cell, e.Shape,
			fmt.Sprintf("source not in a known state before this scenario: %v", err), e.GitSHA)
	}
	v := s.Run(ctx, e)
	if recovered != "" {
		v.Reason += "; the source was recovered before this scenario from: " + recovered
	}
	return v
}

// sourceReadyTries and sourceReadyGap bound the wait for Ready after a
// Recover: a restarted Kea answers its control API a few seconds late
// (group C defeat A7, #23). Variables so tests run without the wait.
var (
	sourceReadyTries = 6
	sourceReadyGap   = 5 * time.Second
)

// ensureSourceReady is the group C gate (#23 defeat 1): Ready, else
// Recover once and poll Ready; still not ready is an error the caller
// turns into BLOCKED, never a FAIL of the next scenario. recovered names
// what the first Ready found when Recover fixed it.
func ensureSourceReady(ctx context.Context, src sourceadapter.Adapter) (recovered string, err error) {
	first := src.Ready(ctx)
	if first == nil {
		return "", nil
	}
	if err := src.Recover(ctx); err != nil {
		return "", fmt.Errorf("%v; recover failed: %w", first, err)
	}
	var last error
	for i := 0; i < sourceReadyTries; i++ {
		if last = src.Ready(ctx); last == nil {
			return first.Error(), nil
		}
		if err := sleepCtx(ctx, sourceReadyGap); err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("%v; still not ready after recover: %w", first, last)
}

// Catalog is the scenario list: first lease, container restart, compose down/up,
// daemon restart, host reboot, plugin upgrade, plugin killed, fleet
// burst (issue #3), then groups B and C (#23). Group C's C6-C9 and
// group D are later PRs.
var Catalog = []Scenario{
	{Name: NameA1, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA1},
	{Name: NameA2, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA2},
	{Name: NameA3, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA3},
	{Name: NameA4, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA4},
	{Name: NameA5, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA5},
	{Name: NameA5b, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA5b},
	{Name: NameA6, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA6},
	{Name: NameA7, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA7},
	{Name: NameA8, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA8},
	{Name: NameA9, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA9},
	{Name: NameA10, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA10},
	{Name: NameA11, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA11},
	{Name: NameA12, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA12},
	{Name: NameA13, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA13},
	{Name: NameA14, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease}, Run: runA14},
	{Name: NameA15, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA15},
	{Name: NameA16, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runA16},
	{Name: NameB1, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapReserveMAC}, Run: runB1},
	{Name: NameB2, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapReserveClientID}, Run: runB2},
	{Name: NameB3, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapDNSRegistration}, Run: runB3},
	{Name: NameB4, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runB4},
	{Name: NameB5, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapVendorClassPool}, Run: runB5},
	{Name: NameB6, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapOptionChange}, Run: runB6},
	{Name: NameB7, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runB7},
	{Name: NameB8, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runB8},
	{Name: NameC1, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapRestart}, Run: runC1},
	{Name: NameC2, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapRestart}, Run: runC2},
	{Name: NameC3, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapRestart}, Run: runC3},
	{Name: NameC4, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease}, Run: runC4},
	{Name: NameC5, Needs: []sourceadapter.Capability{sourceadapter.CapFailoverPair}, Run: runNeverReached},
	{Name: NameC6, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapReserveClientID, sourceadapter.CapSquatter}, Run: runC6},
	{Name: NameC6b, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapSquatter}, Run: runC6b},
	{Name: NameC7, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapRogueServer}, Run: runC7},
	{Name: NameC8, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapNarrowPool}, Run: runC8},
	{Name: NameC9, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapRenumber}, Run: runC9},
	{Name: NameC10, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapImpair}, Run: runC10},
	{Name: NameC11, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapRestart}, Run: runC11},
	{Name: NameC12, Needs: []sourceadapter.Capability{sourceadapter.CapRelay}, Run: runNeverReached},
	{Name: NameF1, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapUserClassPool}, Run: runF1},
	{Name: NameF2a, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapOption108}, Run: runF2a},
	{Name: NameF2b, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapOption108}, Run: runF2b},
	{Name: NameF3, Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: runF3},
	{Name: NameF4, Needs: []sourceadapter.Capability{sourceadapter.CapV6}, Run: runNeverReached},
	{Name: NameF5, Needs: []sourceadapter.Capability{sourceadapter.CapV6}, Run: runNeverReached},
	{Name: NameF6, Needs: []sourceadapter.Capability{sourceadapter.CapV6}, Run: runNeverReached},
	{Name: NameF7, Needs: []sourceadapter.Capability{sourceadapter.CapV6}, Run: runNeverReached},
	{Name: NameF8, Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapForceRenewNonce}, Run: runF8},
}
