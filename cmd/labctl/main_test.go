package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// The pre-shape pool capacity check exists because the plugin's own
// default is release_lease=never (docs/reference.md) -- nothing frees
// a lease between shapes on its own, so a run only stays sound if the
// pool the cell's source hands out can actually cover one shape's
// worst case (#3). These two functions are the pure core of that
// check; the rest of cmdRun is the plumbing that calls them and cannot
// run without a real source VM.

func TestPoolCapacityCountsInclusive(t *testing.T) {
	cases := []struct {
		name, start, end string
		want             int
	}{
		{"kea pool", "10.200.1.100", "10.200.1.200", 101},
		{"isc-dhcp pool", "10.200.2.100", "10.200.2.200", 101},
		{"dnsmasq pool", "10.200.3.100", "10.200.3.200", 101},
		{"single address", "10.200.1.100", "10.200.1.100", 1},
		{"crosses a byte boundary", "10.200.1.250", "10.200.2.5", 12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := poolCapacity(c.start, c.end)
			if err != nil {
				t.Fatalf("poolCapacity(%q, %q): %v", c.start, c.end, err)
			}
			if got != c.want {
				t.Fatalf("poolCapacity(%q, %q) = %d, want %d", c.start, c.end, got, c.want)
			}
		})
	}
}

func TestPoolCapacityRejectsBadInput(t *testing.T) {
	cases := []struct {
		name, start, end string
	}{
		{"not an address", "not-an-ip", "10.200.1.200"},
		{"end before start", "10.200.1.200", "10.200.1.100"},
		{"ipv6", "fe80::1", "fe80::2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := poolCapacity(c.start, c.end); err == nil {
				t.Fatalf("poolCapacity(%q, %q): want an error, got none", c.start, c.end)
			}
		})
	}
}

// TestPoolHasCapacityForMatchesMinPoolAddresses pins the check against
// scenario.MinPoolAddresses's own value (catalog.go) rather than a
// number restated here: a pool exhausted by four prior shapes' worth of
// held leases must abort the fifth, and a fresh 101-address pool must
// clear every shape (five shapes x the requirement is exactly the case that
// exhausted the pool on A15/A16 before this fix, #3).
func TestPoolHasCapacityForMatchesMinPoolAddresses(t *testing.T) {
	const need = scenario.MinPoolAddresses

	if ok, reason := poolHasCapacityFor(101, 0, need); !ok {
		t.Fatalf("a fresh 101-address pool must cover one shape's run: %s", reason)
	}
	if ok, _ := poolHasCapacityFor(101, 4*need, need); ok {
		t.Fatalf("a pool already holding four shapes' worth of leases must not clear a fifth")
	}
	if ok, _ := poolHasCapacityFor(101, 101-need+1, need); ok {
		t.Fatalf("one address short of the requirement must not pass")
	}
	if ok, reason := poolHasCapacityFor(101, 101-need, need); !ok {
		t.Fatalf("exactly enough free addresses must pass: %s", reason)
	}
}

func TestPoolHasCapacityForReasonNamesTheShortfall(t *testing.T) {
	ok, reason := poolHasCapacityFor(101, 70, 38)
	if ok {
		t.Fatalf("101 capacity, 70 held, need 38: want insufficient, got ok")
	}
	if reason == "" {
		t.Fatal("want a non-empty reason describing the shortfall")
	}
}

// selectScenarios is the debug-logging evidence pass's own filter
// (#3): the main run always passes an empty filterArg and must see
// every scenario, in catalog order; a named pass narrows to just the
// scenarios it asks for, still in catalog order.
func TestSelectScenariosEmptyFilterReturnsWholeCatalog(t *testing.T) {
	catalog := []scenario.Scenario{{Name: "A1"}, {Name: "A2"}, {Name: "A3"}}
	got := selectScenarios(catalog, "")
	if len(got) != len(catalog) {
		t.Fatalf("empty filter dropped scenarios: got %d, want %d", len(got), len(catalog))
	}
}

func TestSelectScenariosNarrowsAndKeepsCatalogOrder(t *testing.T) {
	catalog := []scenario.Scenario{
		{Name: "A1"}, {Name: "A5b-host-reboot-fixed-mac"}, {Name: "A9"}, {Name: "A10-kill-restart-policy"},
	}
	// Named in the reverse of catalog order, on purpose.
	got := selectScenarios(catalog, "A10-kill-restart-policy,A5b-host-reboot-fixed-mac")
	if len(got) != 2 {
		t.Fatalf("want 2 scenarios selected, got %d: %v", len(got), got)
	}
	if got[0].Name != "A5b-host-reboot-fixed-mac" || got[1].Name != "A10-kill-restart-policy" {
		t.Fatalf("want catalog order (A5b then A10) regardless of filter order, got %v", got)
	}
}

func TestSelectScenariosDropsUnknownNames(t *testing.T) {
	catalog := []scenario.Scenario{{Name: "A1"}, {Name: "A2"}}
	got := selectScenarios(catalog, "A1, A404 ,")
	if len(got) != 1 || got[0].Name != "A1" {
		t.Fatalf("want only the known name A1 kept, got %v", got)
	}
}

// TestRemainingScenarioNamesKeepsCatalogOrderAndDropsDone guards #8's
// resume support: the result must exclude every name already in done
// and keep catalog's own order, so it feeds straight back into
// selectScenarios unchanged.
func TestRemainingScenarioNamesKeepsCatalogOrderAndDropsDone(t *testing.T) {
	catalog := []scenario.Scenario{
		{Name: "A1"}, {Name: "A5b-host-reboot-fixed-mac"}, {Name: "A9"}, {Name: "A10-kill-restart-policy"},
	}
	done := map[string]bool{"A9": true, "A1": true}
	got := remainingScenarioNames(catalog, done)
	want := []string{"A5b-host-reboot-fixed-mac", "A10-kill-restart-policy"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestRemainingScenarioNamesEmptyDoneReturnsWholeCatalog: a fresh
// evidence dir with no verdicts yet must not skip anything.
func TestRemainingScenarioNamesEmptyDoneReturnsWholeCatalog(t *testing.T) {
	catalog := []scenario.Scenario{{Name: "A1"}, {Name: "A2"}}
	got := remainingScenarioNames(catalog, map[string]bool{})
	if len(got) != 2 || got[0] != "A1" || got[1] != "A2" {
		t.Fatalf("got %v, want the whole catalog in order", got)
	}
}

// TestRemainingScenarioNamesAllDoneReturnsEmpty: once every catalog
// scenario has a verdict, resuming this shape must be a no-op, not an
// error and not a re-run of everything.
func TestRemainingScenarioNamesAllDoneReturnsEmpty(t *testing.T) {
	catalog := []scenario.Scenario{{Name: "A1"}, {Name: "A2"}}
	got := remainingScenarioNames(catalog, map[string]bool{"A1": true, "A2": true})
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// Every lab.yaml cell has no relay yet, so its router and its source are
// the same seg_address without the CIDR suffix (#11, #23).
func TestSegAddressesAreEqualWithoutARelay(t *testing.T) {
	cfg, err := labyaml.Load(filepath.Join("..", "..", "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for name, c := range cfg.Cells {
		if c.Source == nil {
			continue
		}
		seen++
		gw, src := segAddresses(c.Source)
		p, err := netip.ParsePrefix(c.Source.SegAddress)
		if err != nil || gw != p.Addr().String() || gw != src {
			t.Errorf("%v: router %q, source %q from seg_address %q", name, gw, src, c.Source.SegAddress)
		}
	}
	if seen == 0 {
		t.Fatal("lab.yaml holds no cell with a source")
	}
}

type mgmtRunner string

func (r mgmtRunner) Run(context.Context, string) (string, error) { return "", nil }

// A source with a partner (lab #12) gets one PairAdapter whose peers
// each run on their own mgmt address and carry their seg address as
// the server-id; without one, the single adapter as before.
func TestNewCellSourceAdapterPair(t *testing.T) {
	runnerFor := func(m string) sourceadapter.Runner { return mgmtRunner(m) }
	src := &labyaml.Source{Type: "kea", MgmtAddress: "10.200.255.91/24", SegAddress: "10.200.8.2/24"}
	a, err := newCellSourceAdapter(src, runnerFor)
	if k, ok := a.(*sourceadapter.KeaAdapter); err != nil || !ok || k.Runner != mgmtRunner("10.200.255.91/24") {
		t.Fatalf("single source: %#v, %v", a, err)
	}
	src.Partner = &labyaml.Peer{MgmtAddress: "10.200.255.92/24", SegAddress: "10.200.8.3/24"}
	a, err = newCellSourceAdapter(src, runnerFor)
	p, ok := a.(*sourceadapter.PairAdapter)
	if err != nil || !ok {
		t.Fatalf("pair: %#v, %v", a, err)
	}
	want := [2][3]string{{"primary", "10.200.255.91/24", "10.200.8.2"}, {"partner", "10.200.255.92/24", "10.200.8.3"}}
	for i, w := range want {
		peer := p.Peers[i]
		k, _ := peer.Adapter.(*sourceadapter.KeaAdapter)
		if peer.Name != w[0] || k == nil || k.Runner != mgmtRunner(w[1]) || peer.ServerID != w[2] {
			t.Errorf("peer %d = %s runner %v id %s, want %v", i, peer.Name, k, peer.ServerID, w)
		}
	}
	src.Type = "isc-dhcp"
	if _, err := newCellSourceAdapter(src, runnerFor); err == nil || !strings.Contains(err.Error(), "PR 2") {
		t.Errorf("isc-dhcp pair: %v, want the PR 2 error", err)
	}
	src.Type = "dnsmasq"
	if _, err := newCellSourceAdapter(src, runnerFor); err == nil {
		t.Error("a dnsmasq pair built an adapter")
	}
}
