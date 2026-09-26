package scenario

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// b9StopWait and b14Wait are the near-zero durations these tests pass to
// runA9Tuned/runA14Tuned in place of the real 5s/25s waits (issue #3 part
// 2): the real waits are the point of A9 and A14 themselves, not
// something a unit test should have to sit through, the same reasoning
// waitHostRebootedTuned's own tests already apply.
const (
	b9StopWait = 10 * time.Millisecond
	b14Wait    = 10 * time.Millisecond
)

// simpleContainerRunner backs A9, A11 and A14's happy-path tests: one
// container whose mac/address/endpoint id never change, with just enough
// state (running, paused) for waitContainerRunning/waitContainerPaused to
// observe the stop/start or pause/unpause it drives.
type simpleContainerRunner struct {
	mac, addr, endpointID string
	running               bool
	paused                bool
}

func (f *simpleContainerRunner) Run(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "State.Paused"):
		if f.paused {
			return "true", nil
		}
		return "false", nil
	case strings.Contains(cmd, "State.Running"):
		if f.running {
			return "true", nil
		}
		return "false", nil
	case strings.Contains(cmd, "MacAddress"):
		return f.mac, nil
	case strings.Contains(cmd, "IPAddress"):
		return f.addr, nil
	case strings.Contains(cmd, "EndpointID"):
		return f.endpointID, nil
	case strings.Contains(cmd, "docker stop"):
		f.running = false
		return "", nil
	case strings.Contains(cmd, "docker pause"):
		f.paused = true
		return "", nil
	case strings.Contains(cmd, "docker unpause"):
		f.paused = false
		f.running = true
		return "", nil
	case strings.Contains(cmd, "docker start"):
		f.running = true
		return "", nil
	default:
		return "", nil
	}
}

func newSimpleContainerRunner() *simpleContainerRunner {
	return &simpleContainerRunner{mac: "aa:bb:cc:dd:ee:01", addr: "10.200.1.101", endpointID: "ep-9", running: true}
}

// TestRunA9TunedPassesOnStopWaitStart covers A9's ordinary path: stopped,
// waited, started again, same address, still leased and reachable.
func TestRunA9TunedPassesOnStopWaitStart(t *testing.T) {
	host := newSimpleContainerRunner()
	source := &fakeAdapter{leases: []sourceadapter.Lease{{MAC: host.mac, Address: host.addr}}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA9Tuned(context.Background(), e, b9StopWait)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
	if !strings.Contains(v.Reason, "kept address") {
		t.Fatalf("want the reason to note the address was kept, got %q", v.Reason)
	}
}

// TestRunA11PassesAcrossPauseUnpause covers A11's ordinary path: the
// lease must read identically before and after, and the container must
// answer again once unpaused.
func TestRunA11PassesAcrossPauseUnpause(t *testing.T) {
	host := newSimpleContainerRunner()
	source := &fakeAdapter{leases: []sourceadapter.Lease{{MAC: host.mac, Address: host.addr}}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA11(context.Background(), e)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
}

// TestRunA14TunedPassesPastT1 covers A14's ordinary path: with a shortened
// lease, the same lease is still confirmed and reachable once the (here,
// near-instant) wait past T1 elapses.
func TestRunA14TunedPassesPastT1(t *testing.T) {
	host := newSimpleContainerRunner()
	source := &fakeAdapter{
		caps:   []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease},
		leases: []sourceadapter.Lease{{MAC: host.mac, Address: host.addr}},
	}
	e := Env{Host: host, Source: source, Cell: "kea", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA14Tuned(context.Background(), e, 1, b14Wait)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
	if !source.shortened || !source.restored {
		t.Fatalf("want ShortenLeaseTime called and its restore func called, got shortened=%v restored=%v", source.shortened, source.restored)
	}
}

// TestRunA14FailsWhenShortenLeaseTimeErrors preserves the plain
// error-propagation path: a source that cannot shorten its own lease
// time must FAIL before ever starting a container.
func TestRunA14FailsWhenShortenLeaseTimeErrors(t *testing.T) {
	source := &fakeAdapter{shortenErr: fmt.Errorf("kea-shell: no such command")}
	e := Env{Host: newSimpleContainerRunner(), Source: source, Cell: "kea", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA14Tuned(context.Background(), e, 1, b14Wait)
	if v.Result != FAIL {
		t.Fatalf("want FAIL, got %s", v.Result)
	}
}

// a10Runner backs A10's tests: crashContainer's own kill -9 (reached via
// a fake Pid read, never `docker kill` -- issue #3, measured 2026-09-26/
// 27, dockerd's restart-manager skips a container `docker kill` stops,
// so it cannot exercise restart-policy recovery at all) is answered by
// an instant restart-policy recovery -- Running true again, with a
// StartedAt that has actually changed -- the one thing
// waitContainerRestarted requires before A10 ever reads the lease table
// again.
type a10Runner struct {
	mac, addr, endpointID string
	running               bool
	startedAt             string
	killed                bool
}

func (f *a10Runner) Run(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "State.Running") && strings.Contains(cmd, "State.StartedAt"):
		startedAt := f.startedAt
		if f.killed {
			startedAt = f.startedAt + "-recovered"
		}
		return "true " + startedAt, nil
	case strings.Contains(cmd, "State.StartedAt"):
		return f.startedAt, nil
	case strings.Contains(cmd, "State.Pid"):
		return "4242", nil
	case strings.Contains(cmd, "MacAddress"):
		return f.mac, nil
	case strings.Contains(cmd, "IPAddress"):
		return f.addr, nil
	case strings.Contains(cmd, "EndpointID"):
		return f.endpointID, nil
	case strings.Contains(cmd, "kill -9"):
		f.killed = true
		return "", nil
	default:
		return "", nil
	}
}

func newA10Runner() *a10Runner {
	return &a10Runner{mac: "aa:bb:cc:dd:ee:02", addr: "10.200.1.102", endpointID: "ep-10", running: true, startedAt: "2026-09-26T00:00:00Z"}
}

// TestRunA10PassesOnKillAndRestartPolicyRecovery covers A10's ordinary
// path: killed, the restart policy brings it back on a confirmed new
// StartedAt, exactly one lease for the recovered address.
func TestRunA10PassesOnKillAndRestartPolicyRecovery(t *testing.T) {
	host := newA10Runner()
	source := &fakeAdapter{leases: []sourceadapter.Lease{{MAC: host.mac, Address: host.addr, Hostname: "box"}}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA10(context.Background(), e)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
}

// TestRunA10FailsOnDuplicateLeaseAfterKill is the edge case the issue
// asked for by name: a kill+restart-policy recovery that leaves TWO
// lease rows for the same address is a real defect (a second lease
// minted instead of the endpoint's own one reused), never a PASS, however
// reachable the address still is.
func TestRunA10FailsOnDuplicateLeaseAfterKill(t *testing.T) {
	host := newA10Runner()
	source := &fakeAdapter{leases: []sourceadapter.Lease{
		{MAC: host.mac, Address: host.addr, Hostname: "box-1"},
		{MAC: host.mac, Address: host.addr, Hostname: "box-2"},
	}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA10(context.Background(), e)
	if v.Result != FAIL {
		t.Fatalf("want FAIL on a duplicated lease row, got %s (reason %q)", v.Result, v.Reason)
	}
	if !strings.Contains(v.Reason, "duplicate") {
		t.Fatalf("want the reason to name the duplicate, got %q", v.Reason)
	}
}

// a12Runner backs A12's tests: disconnect/connect never change the
// container's own inspected mac/address/endpoint id in this lab's
// networks.
type a12Runner struct {
	mac, addr, endpointID string
}

func (f *a12Runner) Run(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "MacAddress"):
		return f.mac, nil
	case strings.Contains(cmd, "IPAddress"):
		return f.addr, nil
	case strings.Contains(cmd, "EndpointID"):
		return f.endpointID, nil
	default:
		return "", nil
	}
}

// sequencedLeaseAdapter answers Leases with the next slice in sequence on
// each call, holding the last one once the sequence is exhausted: the
// tool A12 and A16's tests need to script a lease that is present at one
// read and gone (or back) at the next, something fakeAdapter's single
// static slice cannot express.
type sequencedLeaseAdapter struct {
	sequence [][]sourceadapter.Lease
	call     int
	reachErr error
}

func (a *sequencedLeaseAdapter) Capabilities() []sourceadapter.Capability { return nil }
func (a *sequencedLeaseAdapter) Leases(_ context.Context) ([]sourceadapter.Lease, error) {
	i := a.call
	if i >= len(a.sequence) {
		i = len(a.sequence) - 1
	}
	a.call++
	return a.sequence[i], nil
}
func (a *sequencedLeaseAdapter) ReserveMAC(_ context.Context, _, _ string) error { return nil }
func (a *sequencedLeaseAdapter) Restart(_ context.Context) error                 { return nil }
func (a *sequencedLeaseAdapter) Stop(_ context.Context) error                    { return nil }
func (a *sequencedLeaseAdapter) Start(_ context.Context) error                   { return nil }
func (a *sequencedLeaseAdapter) Reachable(_ context.Context, _ string) error     { return a.reachErr }
func (a *sequencedLeaseAdapter) ShortenLeaseTime(_ context.Context, _ int) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}

// TestRunA12NotesLeaseHeldAtDisconnect covers this lab's actual
// configuration -- every network left at release_lease's own default,
// never -- where the lease is still held at the disconnect-time read.
func TestRunA12NotesLeaseHeldAtDisconnect(t *testing.T) {
	host := &a12Runner{mac: "aa:bb:cc:dd:ee:03", addr: "10.200.1.103", endpointID: "ep-12"}
	source := &fakeAdapter{leases: []sourceadapter.Lease{{MAC: host.mac, Address: host.addr}}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA12(context.Background(), e)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
	if !strings.Contains(v.Reason, "held at disconnect") {
		t.Fatalf("want the reason to note the lease was held at disconnect, got %q", v.Reason)
	}
}

// TestRunA12NotesLeaseReleasedAtDisconnect is A12's other reported
// branch: a source that DID drop the lease at the disconnect-time read
// (never this lab's own configuration, but a real DHCP server's own
// choice on a network configured differently) is still reported, and
// this scenario's PASS bar -- lease and reachability after reconnect --
// is unaffected by which branch fired.
func TestRunA12NotesLeaseReleasedAtDisconnect(t *testing.T) {
	host := &a12Runner{mac: "aa:bb:cc:dd:ee:04", addr: "10.200.1.104", endpointID: "ep-13"}
	held := []sourceadapter.Lease{{MAC: host.mac, Address: host.addr}}
	source := &sequencedLeaseAdapter{sequence: [][]sourceadapter.Lease{
		held, // leases-before
		nil,  // leases-at-disconnect: released
		held, // leases-after-reconnect
	}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA12(context.Background(), e)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
	if !strings.Contains(v.Reason, "released at disconnect") {
		t.Fatalf("want the reason to note the lease was released at disconnect, got %q", v.Reason)
	}
}

// TestRunA13IsNAOnBothHostBridgeShapes is the edge case the issue asked
// for by name: A13 must never attempt a second bridge on the one NIC a
// host-bridge shape's own NetworkUp already enslaved, on EITHER
// host-bridge shape.
func TestRunA13IsNAOnBothHostBridgeShapes(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeBridgeIPAM} {
		e := Env{Cell: "dnsmasq", Shape: shape, Network: "net1", GitSHA: "sha"}
		v := runA13(context.Background(), e)
		if v.Result != NA {
			t.Fatalf("shape %s: want NA, got %s (reason %q)", shape, v.Result, v.Reason)
		}
		if v.Reason == "" {
			t.Fatalf("shape %s: an N/A verdict must carry a reason", shape)
		}
	}
}

// a13Runner backs A13's happy-path test on a parent-attached shape: one
// container joins two networks, and inspectContainerNetwork's
// index-by-name template must resolve the SECOND network's own
// mac/address/endpoint id, distinct from the first.
type a13Runner struct {
	net2Name                 string
	mac1, addr1, endpointID1 string
	mac2, addr2, endpointID2 string
}

func (f *a13Runner) Run(_ context.Context, cmd string) (string, error) {
	onNet2 := f.net2Name != "" && strings.Contains(cmd, fmt.Sprintf("%q", f.net2Name))
	switch {
	case onNet2 && strings.Contains(cmd, "MacAddress"):
		return f.mac2, nil
	case onNet2 && strings.Contains(cmd, "IPAddress"):
		return f.addr2, nil
	case onNet2 && strings.Contains(cmd, "EndpointID"):
		return f.endpointID2, nil
	case strings.Contains(cmd, "MacAddress"):
		return f.mac1, nil
	case strings.Contains(cmd, "IPAddress"):
		return f.addr1, nil
	case strings.Contains(cmd, "EndpointID"):
		return f.endpointID1, nil
	default:
		return "", nil
	}
}

// TestRunA13PassesWithTwoDistinctLeasesOnMacvlan covers A13's ordinary
// path on a parent-attached shape: two independent networks on one
// container, each with its own confirmed, reachable lease.
func TestRunA13PassesWithTwoDistinctLeasesOnMacvlan(t *testing.T) {
	cell, shape := "dnsmasq", ShapeMacvlan
	net2 := NetworkName(cell, shape) + "-a13b"
	host := &a13Runner{
		net2Name: net2,
		mac1:     "aa:bb:cc:dd:ee:05", addr1: "10.200.1.105", endpointID1: "ep-13a",
		mac2: "aa:bb:cc:dd:ee:06", addr2: "10.200.1.106", endpointID2: "ep-13b",
	}
	source := &fakeAdapter{leases: []sourceadapter.Lease{
		{MAC: host.mac1, Address: host.addr1},
		{MAC: host.mac2, Address: host.addr2},
	}}
	e := Env{Host: host, Source: source, Cell: cell, Shape: shape, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA13(context.Background(), e)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
}

// TestRunA13FailsWhenBothNetworksReportTheSameAddress preserves A13's own
// duplicate-address guard: two networks that somehow reported the same
// address for one container is a defect, not two independent leases.
func TestRunA13FailsWhenBothNetworksReportTheSameAddress(t *testing.T) {
	cell, shape := "dnsmasq", ShapeMacvlan
	net2 := NetworkName(cell, shape) + "-a13b"
	host := &a13Runner{
		net2Name: net2,
		mac1:     "aa:bb:cc:dd:ee:05", addr1: "10.200.1.105", endpointID1: "ep-13a",
		mac2: "aa:bb:cc:dd:ee:06", addr2: "10.200.1.105", endpointID2: "ep-13b",
	}
	source := &fakeAdapter{leases: []sourceadapter.Lease{
		{MAC: host.mac1, Address: host.addr1},
		{MAC: host.mac2, Address: host.addr2},
	}}
	e := Env{Host: host, Source: source, Cell: cell, Shape: shape, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA13(context.Background(), e)
	if v.Result != FAIL {
		t.Fatalf("want FAIL when both networks report the same address, got %s", v.Result)
	}
}

// a15Runner backs A15's test: it derives each replica's own
// mac/address/endpoint id from the trailing numeric suffix runA15's own
// nameAt(i) always appends, and tracks which replica names are currently
// attached (created by `docker run -d`, not yet `docker rm -f`'d) so
// `docker network inspect`'s Containers listing reflects only those --
// exactly what networkContainsEndpoint reads for A15's own stranded-state
// check.
type a15Runner struct {
	attached map[string]bool
}

func newA15Runner() *a15Runner { return &a15Runner{attached: map[string]bool{}} }

func a15ExtractName(cmd string) string {
	if idx := strings.Index(cmd, "--name "); idx >= 0 {
		rest := strings.Fields(cmd[idx+len("--name "):])
		if len(rest) > 0 {
			return rest[0]
		}
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

func a15ReplicaIndex(name string) int {
	parts := strings.Split(name, "-")
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return -1
	}
	return n
}

func a15Identity(idx int) (mac, addr, endpointID string) {
	return fmt.Sprintf("aa:bb:cc:dd:ee:%02x", idx), fmt.Sprintf("10.200.1.%d", 150+idx), fmt.Sprintf("ep-15-%d", idx)
}

func (f *a15Runner) Run(_ context.Context, cmd string) (string, error) {
	name := a15ExtractName(cmd)
	idx := a15ReplicaIndex(name)
	switch {
	case strings.Contains(cmd, "docker network inspect"):
		var attached []string
		for n, ok := range f.attached {
			if ok {
				_, _, ep := a15Identity(a15ReplicaIndex(n))
				attached = append(attached, ep)
			}
		}
		return strings.Join(attached, ","), nil
	case strings.Contains(cmd, "docker run -d"):
		f.attached[name] = true
		return "", nil
	case strings.Contains(cmd, "docker rm -f"):
		f.attached[name] = false
		return "", nil
	}
	if idx < 0 {
		return "", nil
	}
	mac, addr, endpointID := a15Identity(idx)
	switch {
	case strings.Contains(cmd, "MacAddress"):
		return mac, nil
	case strings.Contains(cmd, "IPAddress"):
		return addr, nil
	case strings.Contains(cmd, "EndpointID"):
		return endpointID, nil
	default:
		return "", nil
	}
}

// TestRunA15PassesAcrossScaleUpAndDown covers A15's ordinary path: base
// replicas up, scaled up with new distinct leases, scaled back down with
// no stranded endpoint left behind for the removed ones.
func TestRunA15PassesAcrossScaleUpAndDown(t *testing.T) {
	host := newA15Runner()
	var leases []sourceadapter.Lease
	for i := 0; i < 5; i++ {
		mac, addr, _ := a15Identity(i)
		leases = append(leases, sourceadapter.Lease{MAC: mac, Address: addr})
	}
	source := &fakeAdapter{leases: leases}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA15(context.Background(), e)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
}

// a16Runner backs A16's tests: the container's own mac/address/endpoint
// id, and whether the network's own inspect output still lists that
// endpoint after the forced remove.
type a16Runner struct {
	mac, addr, endpointID  string
	hasEndpointAfterRemove bool
}

func (f *a16Runner) Run(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "MacAddress"):
		return f.mac, nil
	case strings.Contains(cmd, "IPAddress"):
		return f.addr, nil
	case strings.Contains(cmd, "EndpointID"):
		return f.endpointID, nil
	case strings.Contains(cmd, "docker network inspect"):
		if f.hasEndpointAfterRemove {
			return fmt.Sprintf(`{"c":{"EndpointID":"%s"}}`, f.endpointID), nil
		}
		return "{}", nil
	default:
		return "", nil
	}
}

// TestRunA16PassesWhenLeaseHeldAndEndpointGoneAfterForceRemove covers
// A16's ordinary, documented path: release_lease's own default (never)
// means the lease stays held after a forced remove of a running
// container, while the network's own bookkeeping no longer lists its
// endpoint.
func TestRunA16PassesWhenLeaseHeldAndEndpointGoneAfterForceRemove(t *testing.T) {
	host := &a16Runner{mac: "aa:bb:cc:dd:ee:07", addr: "10.200.1.107", endpointID: "ep-16", hasEndpointAfterRemove: false}
	source := &fakeAdapter{leases: []sourceadapter.Lease{{MAC: host.mac, Address: host.addr, Hostname: "box"}}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA16(context.Background(), e)
	if v.Result != PASS {
		t.Fatalf("want PASS, got %s (reason %q)", v.Result, v.Reason)
	}
}

// TestRunA16FailsWhenNetworkStillListsEndpointAfterForceRemove is A16's
// first FAIL branch: Docker's own bookkeeping, not the plugin's, still
// naming the removed container's endpoint is stranded state.
func TestRunA16FailsWhenNetworkStillListsEndpointAfterForceRemove(t *testing.T) {
	host := &a16Runner{mac: "aa:bb:cc:dd:ee:08", addr: "10.200.1.108", endpointID: "ep-17", hasEndpointAfterRemove: true}
	source := &fakeAdapter{leases: []sourceadapter.Lease{{MAC: host.mac, Address: host.addr}}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA16(context.Background(), e)
	if v.Result != FAIL {
		t.Fatalf("want FAIL, got %s", v.Result)
	}
	if !strings.Contains(v.Reason, "still lists endpoint") {
		t.Fatalf("want the reason to name the stranded endpoint, got %q", v.Reason)
	}
}

// TestRunA16FailsWhenLeaseIsGoneAfterForceRemove is the edge case the
// issue asked for by name: this lab's networks are all left at
// release_lease's own default, never, so a lease that vanished from the
// source's table after a forced remove means the plugin released it
// anyway -- a real defect, asserted with the source's own table as the
// outside evidence, never the plugin's own counters.
func TestRunA16FailsWhenLeaseIsGoneAfterForceRemove(t *testing.T) {
	host := &a16Runner{mac: "aa:bb:cc:dd:ee:09", addr: "10.200.1.109", endpointID: "ep-18", hasEndpointAfterRemove: false}
	held := []sourceadapter.Lease{{MAC: host.mac, Address: host.addr}}
	source := &sequencedLeaseAdapter{sequence: [][]sourceadapter.Lease{
		held, // leases-before
		nil,  // leases-after: gone, an unwanted release
	}}
	e := Env{Host: host, Source: source, Cell: "dnsmasq", Shape: ShapeBridge, Network: "net1", EvidenceDir: t.TempDir(), GitSHA: "sha"}
	v := runA16(context.Background(), e)
	if v.Result != FAIL {
		t.Fatalf("want FAIL, got %s", v.Result)
	}
	if !strings.Contains(v.Reason, "nothing should have released it") {
		t.Fatalf("want the reason to name the unwanted release, got %q", v.Reason)
	}
}
