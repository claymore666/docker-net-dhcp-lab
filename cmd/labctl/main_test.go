package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// Every lab.yaml cell's fresh pool must cover one shape's run of what its
// own source can run (scenario.PoolDemand, #3); the C5 family counts only
// on the failover pair, where it fits beside the rest (lab #12).
func TestPoolHasCapacityForEveryLabCell(t *testing.T) {
	cfg, err := labyaml.Load(filepath.Join("..", "..", "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	runnerFor := func(m string) sourceadapter.Runner { return mgmtRunner(m) }
	need, pairs := 0, 0
	for _, c := range cfg.Cells {
		if c.Source == nil {
			continue
		}
		src, err := newCellSourceAdapter(c.Source, runnerFor)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if slices.Contains(src.Capabilities(), sourceadapter.CapFailoverPair) {
			pairs++
		}
		capacity, err := poolCapacity(c.Source.PoolStart, c.Source.PoolEnd)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		demand := scenario.PoolDemand(scenario.Catalog, src)
		need = max(need, demand)
		if ok, reason := poolHasCapacityFor(capacity, 0, demand); !ok {
			t.Errorf("%s: a fresh pool must cover one shape's run: %s", c.Name, reason)
		}
	}
	if pairs == 0 {
		t.Fatal("lab.yaml holds no failover pair, so the C5 family's demand went unchecked")
	}

	// The edges, at the largest demand any cell has.
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

// Every lab.yaml cell without a relay has its router and its source on
// the same seg_address without the CIDR suffix (#11, #23).
func TestSegAddressesAreEqualWithoutARelay(t *testing.T) {
	cfg, err := labyaml.Load(filepath.Join("..", "..", "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for name, c := range cfg.Cells {
		if c.Source == nil || c.Relay != nil {
			continue
		}
		seen++
		gw, src := segAddresses(&c)
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
	a, err = newCellSourceAdapter(src, runnerFor)
	p, ok = a.(*sourceadapter.PairAdapter)
	if err != nil || !ok {
		t.Fatalf("isc-dhcp pair: %#v, %v", a, err)
	}
	for i, w := range want {
		peer := p.Peers[i]
		d, _ := peer.Adapter.(*sourceadapter.ISCDHCPAdapter)
		if peer.Name != w[0] || d == nil || d.Runner != mgmtRunner(w[1]) || peer.ServerID != w[2] || d.V4Only != (i == 1) || !d.Failover {
			t.Errorf("isc peer %d = %s adapter %+v id %s, want %v", i, peer.Name, d, peer.ServerID, w)
		}
	}
	src.Type = "dnsmasq"
	if _, err := newCellSourceAdapter(src, runnerFor); err == nil {
		t.Error("a dnsmasq pair built an adapter")
	}
}

// The shipped fritzbox cell reaches an adapter through the same mapping as
// every other source type (lab #13).
func TestNewSourceAdapterFritzbox(t *testing.T) {
	a, err := newSourceAdapter("fritzbox", mgmtRunner("10.200.255.171/24"))
	if f, ok := a.(*sourceadapter.FritzboxAdapter); err != nil || !ok || f.Runner != mgmtRunner("10.200.255.171/24") {
		t.Fatalf("fritzbox: %#v, %v", a, err)
	}
}

// The per-scenario wrapper (plugin and bridge checks, source readiness,
// and on the ipam shapes a fresh network before every scenario after the
// first) runs once per scenario the shape does not already answer (#79).
// The counts are for a source declaring every capability: the catalog
// size on the null-IPAM shapes, and the catalog minus the shape-static
// N/A rows on the two ipam shapes.
func TestStaticNAForCountsTheWrapperCallsPerShape(t *testing.T) {
	src := &sourceadapter.KeaAdapter{}
	static := 0
	for _, shape := range scenario.Shapes {
		env := scenario.Env{Source: src, Cell: "kea", Shape: shape, GitSHA: "abc1234"}
		na := staticNAFor(scenario.Catalog, env)
		calls := len(scenario.Catalog) - len(na)
		ipam := shape == scenario.ShapeBridgeIPAM || shape == scenario.ShapeMacvlanIPAM
		switch {
		case !ipam && len(na) != 0:
			t.Errorf("%s: %d scenarios skipped on a shape without the ipam refusal", shape, len(na))
		case ipam && len(na) == 0:
			t.Errorf("%s: no scenario skipped", shape)
		}
		if ipam {
			static = len(na)
		}
		t.Logf("%s: %d scenarios, %d wrapper calls, %d answered statically", shape, len(scenario.Catalog), calls, len(na))
		for name, v := range na {
			if v.Result != scenario.NA || v.Scenario != name || v.Shape != shape || v.Cell != "kea" {
				t.Errorf("%s/%s: skipped verdict %+v", shape, name, v)
			}
		}
	}
	if static == 0 {
		t.Fatal("no ipam shape was counted")
	}
}

// A scenario answered without the wrapper leaves no identity behind on
// the network, so the first scenario that does run starts on the network
// NetworkUp made and each later one gets a fresh one.
func TestNeedsIsolationKeysOnScenariosThatRan(t *testing.T) {
	for ran, want := range []bool{false, true, true} {
		if got := needsIsolation(ran); got != want {
			t.Errorf("needsIsolation(%d) = %v, want %v", ran, got, want)
		}
	}
}

// The loop cmdRun runs, driven with fake steps on every shape: the ipam
// shapes send only the scenarios the shape does not answer through the
// wrapper, isolate before each of them but the first, and write the rest
// without either; the other shapes send the whole catalog through (#79).
func TestRunScenariosCountsWrapperAndIsolationCallsPerShape(t *testing.T) {
	src := &sourceadapter.KeaAdapter{}
	for _, shape := range scenario.Shapes {
		env := scenario.Env{Source: src, Cell: "kea", Shape: shape, GitSHA: "abc1234"}
		na := staticNAFor(scenario.Catalog, env)
		isolating := shape == scenario.ShapeBridgeIPAM || shape == scenario.ShapeMacvlanIPAM
		var ran, isolated, written []string
		failed, err := runScenarios(scenario.Catalog, na, isolating, scenarioSteps{
			static: func(v scenario.Verdict) error { written = append(written, v.Scenario); return nil },
			isolate: func(s scenario.Scenario) error {
				isolated = append(isolated, s.Name)
				return nil
			},
			run: func(s scenario.Scenario) (scenario.Verdict, error) {
				ran = append(ran, s.Name)
				return scenario.Verdict{Scenario: s.Name, Result: scenario.PASS}, nil
			},
		})
		if err != nil || failed != 0 {
			t.Fatalf("%s: failed=%d err=%v", shape, failed, err)
		}
		if len(ran) != len(scenario.Catalog)-len(na) || len(written) != len(na) {
			t.Errorf("%s: %d wrapper runs, %d static writes; want %d and %d", shape, len(ran), len(written), len(scenario.Catalog)-len(na), len(na))
		}
		wantIso := 0
		if isolating && len(ran) > 0 {
			wantIso = len(ran) - 1
		}
		if len(isolated) != wantIso {
			t.Errorf("%s: %d isolations for %d wrapper runs, want %d", shape, len(isolated), len(ran), wantIso)
		}
		if isolating && len(ran) > 1 && isolated[0] != ran[1] {
			t.Errorf("%s: first isolation is before %s, want before %s", shape, isolated[0], ran[1])
		}
		t.Logf("%s: %d wrapper runs, %d isolations, %d static writes", shape, len(ran), len(isolated), len(written))
	}
}

// A step error ends the loop: nothing behind it is written or run, and a
// FAIL verdict counts.
func TestRunScenariosStopsOnAStepErrorAndCountsFails(t *testing.T) {
	list := []scenario.Scenario{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	var ran []string
	failed, err := runScenarios(list, nil, false, scenarioSteps{
		run: func(s scenario.Scenario) (scenario.Verdict, error) {
			ran = append(ran, s.Name)
			if s.Name == "b" {
				return scenario.Verdict{}, errors.New("disk")
			}
			return scenario.Verdict{Result: scenario.FAIL}, nil
		},
	})
	if err == nil || failed != 1 || len(ran) != 2 {
		t.Fatalf("failed=%d err=%v ran=%v", failed, err, ran)
	}
}

// A resumed run can start its list with a scenario the shape answers: the
// first scenario that really runs still starts on the network NetworkUp
// made and gets no isolation (#79).
func TestRunScenariosListStartingWithAStaticRowIsolatesLater(t *testing.T) {
	list := []scenario.Scenario{{Name: "s"}, {Name: "a"}, {Name: "b"}}
	na := map[string]scenario.Verdict{"s": {Scenario: "s", Result: scenario.NA}}
	var isolated []string
	_, err := runScenarios(list, na, true, scenarioSteps{
		static:  func(scenario.Verdict) error { return nil },
		isolate: func(s scenario.Scenario) error { isolated = append(isolated, s.Name); return nil },
		run: func(s scenario.Scenario) (scenario.Verdict, error) {
			return scenario.Verdict{Scenario: s.Name, Result: scenario.PASS}, nil
		},
	})
	if err != nil || len(isolated) != 1 || isolated[0] != "b" {
		t.Fatalf("isolated before %v (err %v), want only b", isolated, err)
	}
}

// #101: an infrastructure abort leaves BLOCKED rows with the abort reason
// for the shape's scenarios that have no verdict, and touches no other.
func TestWriteAbortRowsFillsOnlyTheMissingScenarios(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	first, second := scenario.Catalog[0].Name, scenario.Catalog[1].Name
	existing := []scenario.Verdict{
		{Scenario: first, Cell: "dnsmasq", Shape: scenario.ShapeBridgeIPAM, Result: scenario.NA, Reason: "kept", GitSHA: "aaa", Timestamp: at},
		{Scenario: second, Cell: "dnsmasq", Shape: scenario.ShapeBridgeIPAM, Result: scenario.FAIL, Reason: "kept too", GitSHA: "aaa", Timestamp: at},
		{Scenario: first, Cell: "dnsmasq", Shape: scenario.ShapeMacvlan, Result: scenario.NA, Reason: "other shape", GitSHA: "aaa", Timestamp: at},
		{Scenario: first, Cell: "kea", Shape: scenario.ShapeBridgeIPAM, Result: scenario.NA, Reason: "other cell", GitSHA: "aaa", Timestamp: at},
	}
	before := map[string]string{}
	for _, v := range existing {
		if err := scenario.Write(dir, v); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, v.FileName()))
		if err != nil {
			t.Fatal(err)
		}
		before[v.FileName()] = string(b)
	}

	names, err := writeAbortRows(dir, "dnsmasq", scenario.ShapeBridgeIPAM, "bbb", "network recreate failed\r\nsecond line", at)
	if err != nil {
		t.Fatal(err)
	}
	if want := len(scenario.Catalog) - 2; len(names) != want {
		t.Fatalf("wrote %d rows, want %d (catalog minus the two that had verdicts)", len(names), want)
	}
	for name, content := range before {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != content {
			t.Fatalf("%s changed or vanished: err=%v", name, err)
		}
	}
	for _, s := range scenario.Catalog[2:] {
		v, err := scenario.ReadVerdict(filepath.Join(dir, fmt.Sprintf("dnsmasq-%s-%s.verdict", scenario.ShapeBridgeIPAM, s.Name)))
		if err != nil {
			t.Fatalf("%s has no row: %v", s.Name, err)
		}
		if v.Result != scenario.BLOCKED || !strings.HasPrefix(v.Reason, abortReasonPrefix) || !strings.Contains(v.Reason, "network recreate failed second line") {
			t.Fatalf("%s: result %s reason %q", s.Name, v.Result, v.Reason)
		}
	}
	if left, err := scenariosWithVerdict(dir, "dnsmasq", string(scenario.ShapeBridgeIPAM)); err != nil || len(left) != 2 {
		t.Fatalf("after the abort %d scenarios count as done, want only the 2 real verdicts, err %v", len(left), err)
	}
}

// #101: an abort row is not a verdict. A second pass over the same
// evidence directory (a resume, or run-cells.sh's retry pass) must still
// list the scenarios the abort covered, and the real verdict it writes
// replaces the row.
func TestAbortRowsDoNotStopASecondPassFromRunningTheScenarios(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	first := scenario.Catalog[0].Name
	if err := scenario.Write(dir, scenario.Verdict{Scenario: first, Cell: "dnsmasq", Shape: scenario.ShapeBridgeIPAM, Result: scenario.NA, Reason: "ran before the abort", GitSHA: "a", Timestamp: at}); err != nil {
		t.Fatal(err)
	}
	aborted, err := writeAbortRows(dir, "dnsmasq", scenario.ShapeBridgeIPAM, "b", "boom", at)
	if err != nil || len(aborted) != len(scenario.Catalog)-1 {
		t.Fatalf("abort wrote %d rows, err %v", len(aborted), err)
	}

	done, err := scenariosWithVerdict(dir, "dnsmasq", string(scenario.ShapeBridgeIPAM))
	if err != nil {
		t.Fatal(err)
	}
	again := remainingScenarioNames(scenario.Catalog, done)
	if len(again) != len(aborted) || again[0] != aborted[0] {
		t.Fatalf("second pass would run %d scenarios, want the %d the abort covered", len(again), len(aborted))
	}

	real := scenario.Verdict{Scenario: again[0], Cell: "dnsmasq", Shape: scenario.ShapeBridgeIPAM, Result: scenario.FAIL, Reason: "ran on the second pass", GitSHA: "c", Timestamp: at}
	if err := scenario.Write(dir, real); err != nil {
		t.Fatal(err)
	}
	v, err := scenario.ReadVerdict(filepath.Join(dir, real.FileName()))
	if err != nil || v.Result != scenario.FAIL || isAbortRow(v) {
		t.Fatalf("after the second pass %s reads %s %q (err %v), want the real verdict", again[0], v.Result, v.Reason, err)
	}

	rows, err := writeAbortRows(dir, "dnsmasq", scenario.ShapeBridgeIPAM, "d", "boom again", at)
	if err != nil || len(rows) != len(aborted)-1 {
		t.Fatalf("a second abort rewrote %d rows, want %d, err %v", len(rows), len(aborted)-1, err)
	}
	v, err = scenario.ReadVerdict(filepath.Join(dir, real.FileName()))
	if err != nil || v.Result != scenario.FAIL {
		t.Fatalf("a second abort replaced a real verdict: %s (err %v)", v.Result, err)
	}
}

// #101: only an abort row is non-final. A BLOCKED verdict from the plugin
// side (parent busy, plugin not ready, pool capacity) still counts as done,
// is not listed by remaining and is never rewritten by an abort, even when
// its reason mentions an abort.
func TestNonAbortBlockedVerdictsStayFinal(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	reasons := []string{
		"the parent interface is busy",
		"the plugin was not ready",
		"the run was aborted by the operator before this scenario ran",
	}
	before := map[string]string{}
	for i, reason := range reasons {
		v := scenario.Verdict{Scenario: scenario.Catalog[i].Name, Cell: "dnsmasq", Shape: scenario.ShapeBridgeIPAM, Result: scenario.BLOCKED, Reason: reason, GitSHA: "a", Timestamp: at}
		if err := scenario.Write(dir, v); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, v.FileName()))
		if err != nil {
			t.Fatal(err)
		}
		before[v.FileName()] = string(b)
	}
	done, err := scenariosWithVerdict(dir, "dnsmasq", string(scenario.ShapeBridgeIPAM))
	if err != nil {
		t.Fatal(err)
	}
	for i := range reasons {
		if !done[scenario.Catalog[i].Name] {
			t.Fatalf("%s: a non-abort BLOCKED verdict does not count as done", scenario.Catalog[i].Name)
		}
	}
	names, err := writeAbortRows(dir, "dnsmasq", scenario.ShapeBridgeIPAM, "b", "boom", at)
	if err != nil || len(names) != len(scenario.Catalog)-len(reasons) {
		t.Fatalf("abort wrote %d rows, want %d, err %v", len(names), len(scenario.Catalog)-len(reasons), err)
	}
	for name, content := range before {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != content {
			t.Fatalf("%s changed by the abort: err=%v", name, err)
		}
	}
}

func TestWriteAbortRowsOnACompleteShapeWritesNothing(t *testing.T) {
	dir := t.TempDir()
	at := time.Now()
	for _, s := range scenario.Catalog {
		if err := scenario.Write(dir, scenario.Verdict{Scenario: s.Name, Cell: "kea", Shape: scenario.ShapeBridge, Result: scenario.NA, Reason: "r", GitSHA: "a", Timestamp: at}); err != nil {
			t.Fatal(err)
		}
	}
	names, err := writeAbortRows(dir, "kea", scenario.ShapeBridge, "b", "x", at)
	if err != nil || len(names) != 0 {
		t.Fatalf("names %v err %v, want none", names, err)
	}
}

func TestCmdAbortBlockedRefusesAnUnknownShape(t *testing.T) {
	if rc := cmdAbortBlocked([]string{"lab.yaml", ".", "kea", "tunnel", t.TempDir(), "x"}); rc != 2 {
		t.Fatalf("rc %d, want 2", rc)
	}
}
