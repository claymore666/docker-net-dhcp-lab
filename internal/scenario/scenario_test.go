package scenario

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// fakeAdapter is the same no-network pattern
// internal/sourceadapter/adapter_test.go already uses for its fakeRunner:
// every scenario-package test below runs with no real source VM at all.
type fakeAdapter struct {
	caps     []sourceadapter.Capability
	leases   []sourceadapter.Lease
	err      error
	reachErr error
}

func (f *fakeAdapter) Capabilities() []sourceadapter.Capability { return f.caps }
func (f *fakeAdapter) Leases(_ context.Context) ([]sourceadapter.Lease, error) {
	return f.leases, f.err
}
func (f *fakeAdapter) ReserveMAC(_ context.Context, _, _ string) error { return nil }
func (f *fakeAdapter) Restart(_ context.Context) error                 { return nil }
func (f *fakeAdapter) Stop(_ context.Context) error                    { return nil }
func (f *fakeAdapter) Start(_ context.Context) error                   { return nil }
func (f *fakeAdapter) Reachable(_ context.Context, _ string) error     { return f.reachErr }

func TestNetworkNameAndBridgeNameAreDeterministic(t *testing.T) {
	n1 := NetworkName("dnsmasq", ShapeBridge)
	n2 := NetworkName("dnsmasq", ShapeBridge)
	if n1 != n2 {
		t.Fatalf("NetworkName is not deterministic: %q vs %q", n1, n2)
	}
	if NetworkName("dnsmasq", ShapeBridge) == NetworkName("dnsmasq", ShapeMacvlan) {
		t.Fatalf("two different shapes produced the same network name")
	}
	if hostBridgeName(n1) == n1 {
		t.Fatalf("hostBridgeName must not equal the network name it derives from")
	}
	// IFNAMSIZ is 16 bytes including the terminator, 15 usable; a real
	// bridge-shape run against kea hit exactly this (issue #3).
	if got := len(hostBridgeName(n1)); got > 15 {
		t.Fatalf("hostBridgeName exceeds IFNAMSIZ (15 usable bytes): %q (%d bytes)", hostBridgeName(n1), got)
	}
	if hostBridgeName(n1) != hostBridgeName(n2) {
		t.Fatalf("hostBridgeName is not deterministic: %q vs %q", hostBridgeName(n1), hostBridgeName(n2))
	}
	if other := NetworkName("kea", ShapeBridge); hostBridgeName(n1) == hostBridgeName(other) {
		t.Fatalf("hostBridgeName collided for two different network names: %q", hostBridgeName(n1))
	}
}

// fakeRunOneHostRunner is a minimal sourceadapter.Runner for RunOne's
// own precondition check (issue #3, lead directive 2026-09-26): scripted
// independently of fakeAdapter, since Env.Host and Env.Source are two
// different interfaces.
type fakeRunOneHostRunner struct {
	installed bool
	pgrepOK   bool
}

func (f *fakeRunOneHostRunner) Run(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "PluginReference"):
		if !f.installed {
			return "", context.DeadlineExceeded
		}
		return "ghcr.io/claymore666/docker-net-dhcp:v2.3.0-rc1", nil
	case strings.Contains(cmd, "pgrep"):
		if f.pgrepOK {
			return "1234", nil
		}
		return "", context.DeadlineExceeded
	default:
		return "", context.DeadlineExceeded // e.g. "plugin enable": no self-heal available here
	}
}

// A scenario whose plugin precondition cannot be established (or
// restored) comes back BLOCKED and never reaches Scenario.Run at all --
// the one check that keeps a single failure from cascading into FAILs
// for every scenario after it.
func TestRunOneReturnsBlockedWhenPluginPreconditionFails(t *testing.T) {
	ran := false
	s := Scenario{Name: "probe", Run: func(_ context.Context, _ Env) Verdict {
		ran = true
		return pass("probe", "dnsmasq", ShapeBridge, "should never run", map[string]string{"x": "y"}, "sha")
	}}
	e := Env{Host: &fakeRunOneHostRunner{installed: false}, Source: &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}}, Cell: "dnsmasq", Shape: ShapeBridge}
	v := RunOne(context.Background(), s, e)
	if v.Result != BLOCKED {
		t.Fatalf("want BLOCKED, got %s", v.Result)
	}
	if v.Reason == "" {
		t.Fatal("a BLOCKED verdict must carry a reason")
	}
	if ran {
		t.Fatal("Scenario.Run was called despite a failed plugin precondition")
	}
}

// Preservation: a healthy precondition still reaches Scenario.Run.
// Shape is macvlan, not bridge: ensureBridgePresent no-ops for
// macvlan/ipvlan (issue #3, lead directive 2026-09-26, item 1), so this
// test stays about the plugin precondition alone; the bridge-specific
// readiness gate has its own tests below.
func TestRunOneRunsScenarioWhenPluginPreconditionHolds(t *testing.T) {
	ran := false
	s := Scenario{Name: "probe", Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: func(_ context.Context, _ Env) Verdict {
		ran = true
		return pass("probe", "dnsmasq", ShapeMacvlan, "ran", map[string]string{"x": "y"}, "sha")
	}}
	e := Env{Host: &fakeRunOneHostRunner{installed: true, pgrepOK: true}, Source: &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}}, Cell: "dnsmasq", Shape: ShapeMacvlan}
	v := RunOne(context.Background(), s, e)
	if !ran {
		t.Fatalf("Scenario.Run was never called; verdict: %+v", v)
	}
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s", v.Result)
	}
}

// fakeBridgeReadyRunner answers both RunOne's plugin-precondition check
// and its bridge-readiness gate (issue #3, lead directive 2026-09-26,
// item 1): bridgeUp controls whether the three bridgeReady checks (`ip
// link show`, the segment NIC's master symlink, the FORWARD -C check)
// succeed. When bridgeUp is false, NetworkUp's own forwardRuleCheck step
// fails too -- the same command, the same behaviour NetworkUp already
// has -- so a rebuild attempt fails cleanly rather than needing a second
// canned failure point.
type fakeBridgeReadyRunner struct {
	bridgeUp bool
	calls    []string
}

func (f *fakeBridgeReadyRunner) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	switch {
	case strings.Contains(cmd, "PluginReference"):
		return "ghcr.io/claymore666/docker-net-dhcp:v2.3.0-rc1", nil
	case strings.Contains(cmd, "pgrep"):
		return "1234", nil
	case strings.HasPrefix(cmd, "ip link show"), strings.HasPrefix(cmd, "readlink -f"), strings.Contains(cmd, "iptables -C FORWARD"):
		if f.bridgeUp {
			return "", nil
		}
		return "", context.DeadlineExceeded
	default:
		return "", nil
	}
}

// The bridge is already present and passes every bridgeReady check:
// RunOne must not rebuild it (no docker network create among the
// calls) and must still reach Scenario.Run.
func TestRunOneRunsBridgeScenarioWhenBridgeAlreadyReady(t *testing.T) {
	ran := false
	s := Scenario{Name: "probe", Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: func(_ context.Context, _ Env) Verdict {
		ran = true
		return pass("probe", "dnsmasq", ShapeBridge, "ran", map[string]string{"x": "y"}, "sha")
	}}
	r := &fakeBridgeReadyRunner{bridgeUp: true}
	e := Env{Host: r, Source: &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}}, Cell: "dnsmasq", Shape: ShapeBridge}
	v := RunOne(context.Background(), s, e)
	if !ran {
		t.Fatalf("Scenario.Run was never called; verdict: %+v", v)
	}
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s", v.Result)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "docker network create") {
			t.Fatalf("RunOne rebuilt an already-ready bridge: %q", c)
		}
	}
}

// The bridge is missing and NetworkUp cannot bring it back (the same
// FORWARD-rule-missing failure NetworkUp already reports by name):
// RunOne must BLOCK, carry a reason, and never reach Scenario.Run --
// never a cascading FAIL that reads like a plugin defect (issue #3,
// lead directive 2026-09-26, item 1).
func TestRunOneBlocksWhenBridgeMissingAndUnrebuildable(t *testing.T) {
	ran := false
	s := Scenario{Name: "probe", Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: func(_ context.Context, _ Env) Verdict {
		ran = true
		return pass("probe", "dnsmasq", ShapeBridge, "should never run", map[string]string{"x": "y"}, "sha")
	}}
	r := &fakeBridgeReadyRunner{bridgeUp: false}
	e := Env{Host: r, Source: &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}}, Cell: "dnsmasq", Shape: ShapeBridge}
	v := RunOne(context.Background(), s, e)
	if v.Result != BLOCKED {
		t.Fatalf("want BLOCKED, got %s (reason %q)", v.Result, v.Reason)
	}
	if v.Reason == "" {
		t.Fatal("a BLOCKED verdict must carry a reason")
	}
	if ran {
		t.Fatal("Scenario.Run was called despite an unrebuildable bridge")
	}
}

// runA6 must never guess a previous tag on its own (issue #3, lead
// directive 2026-09-26): an empty Env.PreviousPluginTag is N/A with a
// reason, and Run is never reached far enough to touch the host at all.
func TestRunA6IsNAWithNoPreviousPluginTag(t *testing.T) {
	e := Env{Cell: "dnsmasq", Shape: ShapeBridge, PreviousPluginTag: ""}
	v := runA6(context.Background(), e)
	if v.Result != NA {
		t.Fatalf("want NA, got %s (reason %q)", v.Result, v.Reason)
	}
	if v.Reason == "" {
		t.Fatal("an N/A verdict must carry a reason")
	}
}

func TestApplicableRequiresEveryCapability(t *testing.T) {
	s := Scenario{Name: "needs-v4-and-restart",
		Needs: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapRestart}}

	full := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapRestart}}
	if ok, reason := Applicable(s, full); !ok {
		t.Fatalf("source declaring every needed capability was rejected: %s", reason)
	}

	partial := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}}
	ok, reason := Applicable(s, partial)
	if ok {
		t.Fatal("source missing a needed capability was accepted as applicable")
	}
	if reason == "" {
		t.Fatal("an N/A applicability check must carry a reason")
	}
}

func TestFindLeaseMatchesMACAndAddressTogether(t *testing.T) {
	leases := []sourceadapter.Lease{
		{MAC: "AA:BB:CC:DD:EE:FF", Address: "10.200.1.100", Hostname: "box1"},
		{MAC: "aa:bb:cc:dd:ee:00", Address: "10.200.1.101", Hostname: "box2"},
	}
	l, ok := findLease(leases, "aa:bb:cc:dd:ee:ff", "10.200.1.100")
	if !ok || l.Hostname != "box1" {
		t.Fatalf("want box1 (case-insensitive MAC match), got ok=%v l=%+v", ok, l)
	}
	if _, ok := findLease(leases, "aa:bb:cc:dd:ee:ff", "10.200.1.101"); ok {
		t.Fatal("matched a MAC with the wrong address")
	}
}

// ipvlan slaves share the parent's MAC: two leases with the same MAC but
// different addresses must resolve to different rows when matched by
// address alone (issue #3 defeat list's ipvlan bullet).
func TestFindLeaseByAddrResolvesIpvlanSharedMACCollision(t *testing.T) {
	sharedMAC := "aa:bb:cc:dd:ee:ff"
	leases := []sourceadapter.Lease{
		{MAC: sharedMAC, Address: "10.200.1.100", Hostname: "slave1"},
		{MAC: sharedMAC, Address: "10.200.1.101", Hostname: "slave2"},
	}
	l1, ok1 := findLeaseByAddr(leases, "10.200.1.100")
	l2, ok2 := findLeaseByAddr(leases, "10.200.1.101")
	if !ok1 || !ok2 {
		t.Fatalf("both addresses should resolve: ok1=%v ok2=%v", ok1, ok2)
	}
	if l1.Hostname == l2.Hostname {
		t.Fatalf("two distinct ipvlan slaves with a shared MAC resolved to the same row: %+v vs %+v", l1, l2)
	}
	if l1.Hostname != "slave1" || l2.Hostname != "slave2" {
		t.Fatalf("resolved to the wrong rows: l1=%+v l2=%+v", l1, l2)
	}
}

func TestWriteRefusesPASSWithNoEvidence(t *testing.T) {
	dir := t.TempDir()
	v := Verdict{Scenario: "A1", Cell: "dnsmasq", Shape: ShapeBridge, Result: PASS, Timestamp: time.Now()}
	if err := Write(dir, v); err == nil {
		t.Fatal("a PASS with no evidence was written")
	}
}

func TestWriteRefusesNAWithEvidence(t *testing.T) {
	dir := t.TempDir()
	ev := filepath.Join(dir, "x.txt")
	if err := os.WriteFile(ev, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	v := Verdict{Scenario: "A1", Cell: "dnsmasq", Shape: ShapeBridge, Result: NA,
		Evidence: map[string]string{"x": ev}, Timestamp: time.Now()}
	if err := Write(dir, v); err == nil {
		t.Fatal("an N/A carrying evidence was written")
	}
}

func TestWriteRefusesMissingOrEmptyEvidenceFile(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.txt")
	v := Verdict{Scenario: "A1", Cell: "dnsmasq", Shape: ShapeBridge, Result: PASS,
		Evidence: map[string]string{"x": missing}, Timestamp: time.Now()}
	if err := Write(dir, v); err == nil {
		t.Fatal("a PASS pointing at a missing evidence file was written")
	}

	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	v.Evidence = map[string]string{"x": empty}
	if err := Write(dir, v); err == nil {
		t.Fatal("a PASS pointing at an empty evidence file was written")
	}
}

// Preservation: a well-formed PASS with real, non-empty evidence still
// writes, and a re-run overwrites the same deterministic filename rather
// than accumulating a stale one beside it.
func TestWriteAcceptsWellFormedVerdictAndFileNameIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	ev := filepath.Join(dir, "leases-after.txt")
	if err := os.WriteFile(ev, []byte("aa:bb:cc:dd:ee:ff 10.200.1.100 box1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v := Verdict{Scenario: NameA1, Cell: "dnsmasq", Shape: ShapeBridge, Result: PASS,
		Reason: "ok", Evidence: map[string]string{"leases-after": ev}, GitSHA: "deadbeef", Timestamp: time.Now()}
	if err := Write(dir, v); err != nil {
		t.Fatalf("well-formed verdict was rejected: %v", err)
	}
	want := filepath.Join(dir, v.FileName())
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("verdict file not written at the expected deterministic path: %v", err)
	}

	// A second write to the same scenario/cell/shape must overwrite, not
	// accumulate: only one file for this triple exists afterwards.
	if err := Write(dir, v); err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".verdict" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want 1 verdict file after two writes, got %d", count)
	}
}

func TestLookupLeaseUsesAddressOnlyMatchForIpvlan(t *testing.T) {
	dir := t.TempDir()
	sharedMAC := "aa:bb:cc:dd:ee:ff"
	a := &fakeAdapter{leases: []sourceadapter.Lease{
		{MAC: sharedMAC, Address: "10.200.1.100", Hostname: "slave1"},
		{MAC: sharedMAC, Address: "10.200.1.101", Hostname: "slave2"},
	}}
	snap := filepath.Join(dir, "snap.txt")
	lease, _, ok, err := lookupLease(context.Background(), a, ShapeIpvlan, sharedMAC, "10.200.1.101", snap)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || lease.Hostname != "slave2" {
		t.Fatalf("want slave2 via address-only match, got ok=%v lease=%+v", ok, lease)
	}
	if fi, statErr := os.Stat(snap); statErr != nil || fi.Size() == 0 {
		t.Fatalf("lease snapshot was not written or is empty: %v", statErr)
	}
}

func TestLookupLeasePropagatesAdapterError(t *testing.T) {
	dir := t.TempDir()
	a := &fakeAdapter{err: context.DeadlineExceeded}
	snap := filepath.Join(dir, "snap.txt")
	if _, _, _, err := lookupLease(context.Background(), a, ShapeBridge, "aa:bb:cc:dd:ee:ff", "10.200.1.100", snap); err == nil {
		t.Fatal("an adapter error was silently swallowed instead of propagated")
	}
}
