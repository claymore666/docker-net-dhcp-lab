package scenario

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// eHost scripts the docker host for the group E runner tests: the
// plugin's /Plugin.Health and /metrics, its settings, the ledger files,
// and the stop that moves the counters from "before" to "after".
type eHost struct {
	*bRunner
	stopped       bool
	active        int
	before, after map[string]int64
	instBefore    string
	instAfter     string
	settings      string
	ledger        *string
	metricsErr    error
	healthErr     error
	healthDrift   bool
	healthReads   int
}

func newEHost() *eHost {
	h := &eHost{
		bRunner:    newBRunner(),
		before:     map[string]int64{"leases_obtained": 7, "leases_renewed": 3, "releases_sent": 2},
		after:      map[string]int64{"leases_obtained": 8, "leases_renewed": 4, "releases_sent": 3},
		instBefore: "i1", instAfter: "i1",
	}
	h.forceMAC = eMAC
	h.addrFn = func(string, string) string { return eIP }
	return h
}

func (h *eHost) counters() (map[string]int64, string) {
	if h.stopped {
		return eCounters(h.after), h.instAfter
	}
	return eCounters(h.before), h.instBefore
}

func (h *eHost) Run(ctx context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "docker stop"):
		h.cmds = append(h.cmds, cmd)
		h.stopped = true
		return "", nil
	case strings.Contains(cmd, "/Plugin.Health"):
		h.cmds = append(h.cmds, cmd)
		if h.healthErr != nil {
			return "", h.healthErr
		}
		h.healthReads++
		c, inst := h.counters()
		active := h.active
		if h.stopped {
			active = 0
		}
		var b strings.Builder
		fmt.Fprintf(&b, `{"instance_id":%q,"active_endpoints":%d`, inst, active)
		for k, v := range c {
			if h.healthDrift && h.stopped && h.healthReads%2 == 0 && k == "leases_obtained_v4" {
				v++
			}
			fmt.Fprintf(&b, `,%q:%d`, k, v)
		}
		b.WriteString("}")
		return b.String(), nil
	case strings.Contains(cmd, "/metrics"):
		h.cmds = append(h.cmds, cmd)
		if h.metricsErr != nil {
			return "", h.metricsErr
		}
		c, inst := h.counters()
		var b strings.Builder
		fmt.Fprintf(&b, "net_dhcp_build_info{instance_id=%q,version=\"v\"} 1\n", inst)
		for _, n := range e2Names {
			fmt.Fprintf(&b, "net_dhcp_%s_total{family=\"ipv4\"} %d\n", n, c[n+"_v4"])
			fmt.Fprintf(&b, "net_dhcp_%s_total{family=\"ipv6\"} %d\n", n, c[n+"_v6"])
		}
		return b.String(), nil
	case strings.Contains(cmd, "docker plugin inspect") && strings.Contains(cmd, "Settings.Env"):
		h.cmds = append(h.cmds, cmd)
		return h.settings, nil
	case strings.Contains(cmd, "leases.jsonl.1"):
		h.cmds = append(h.cmds, cmd)
		return ledgerAbsentMarker + "\n", nil
	case strings.Contains(cmd, "leases.jsonl"):
		h.cmds = append(h.cmds, cmd)
		return fileOrMarker(h.ledger), nil
	}
	return h.bRunner.Run(ctx, cmd)
}

// eLedger renders ledger lines for the endpoint the runner's first
// container gets, stamped now so the since filter keeps them.
func eLedger(endpoint string, kinds ...string) *string {
	var b strings.Builder
	ts := time.Now().UTC().Format(time.RFC3339)
	for _, k := range kinds {
		fmt.Fprintf(&b, `{"ts":%q,"kind":%q,"network":"n","endpoint":%q,"ip":%q,"mac":%q}`+"\n", ts, k, endpoint, eIP, eMAC)
	}
	s := b.String()
	return &s
}

var eEndpoint = fmt.Sprintf("%016x%048x", 1, 0)

// eAdapter serves the source journal: pre before the stop, pre+fresh
// after it, or an error.
type eAdapter struct {
	*fakeAdapter
	host  *eHost
	pre   []sourceadapter.ServerEvent
	fresh []sourceadapter.ServerEvent
	err   error
	calls int
	// mutatePre rewrites the baseline lines once the stop happened.
	mutatePre func([]sourceadapter.ServerEvent) []sourceadapter.ServerEvent
}

func (a *eAdapter) ServerEvents(_ context.Context, _ time.Time, _ string) ([]sourceadapter.ServerEvent, error) {
	a.calls++
	if a.err != nil {
		return nil, a.err
	}
	pre := append([]sourceadapter.ServerEvent(nil), a.pre...)
	if !a.host.stopped {
		return pre, nil
	}
	if a.mutatePre != nil {
		pre = a.mutatePre(pre)
	}
	return append(pre, a.fresh...), nil
}

type eRig struct {
	h   *eHost
	src *eAdapter
	cap *cCapture
	e   Env
}

func eSetup(t *testing.T, shape Shape) *eRig {
	t.Helper()
	h := newEHost()
	fa := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapServerEvents}}
	src := &eAdapter{
		fakeAdapter: fa, host: h,
		fresh: []sourceadapter.ServerEvent{srvEv("ACK", eIP, 0), srvEv("ACK", eIP, 20), srvEv("RELEASE", eIP, 31)},
	}
	c := &cCapture{fn: func(string) []DHCPMsg { return cat(boundWire("a1", eIP, 0), renewWire("b2", eIP, 20)) }}
	e := bEnv(t, h, &eLeaseAdapter{eAdapter: src}, shape)
	e.Capture = c
	h.ledger = eLedger(eEndpoint, "bound", "renew", "stopped")
	return &eRig{h: h, src: src, cap: c, e: e}
}

// eLeaseAdapter holds the container's lease in the table; the journal
// and the table come from one adapter.
type eLeaseAdapter struct{ *eAdapter }

func (a *eLeaseAdapter) Leases(context.Context) ([]sourceadapter.Lease, error) {
	cid, _ := ipvlanClientID(eEndpoint)
	return []sourceadapter.Lease{{MAC: eMAC, Address: eIP, ClientID: cid, Expires: time.Now().Add(time.Hour)}}, nil
}

var eFast = eTune{lease: 40, wait: 0, idle: 30 * time.Millisecond, release: 30 * time.Millisecond, tail: 0, poll: time.Millisecond}

func runBoth(t *testing.T, r *eRig) map[string]Verdict {
	t.Helper()
	return map[string]Verdict{NameE1: runE1Tuned(context.Background(), r.e, eFast), NameE2: runE2Tuned(context.Background(), r.e, eFast)}
}

var eShapes = []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan}

func TestRunE1AndE2PassOnEveryShape(t *testing.T) {
	for _, shape := range eShapes {
		for name, run := range map[string]func(context.Context, Env, eTune) Verdict{NameE1: runE1Tuned, NameE2: runE2Tuned} {
			t.Run(string(shape)+"/"+name, func(t *testing.T) {
				r := eSetup(t, shape)
				v := run(context.Background(), r.e, eFast)
				needResult(t, v, PASS)
				if !r.h.has("audit_log=true") || !r.h.has("release_lease=on_stop") {
					t.Errorf("the network was created without the ledger options: %v", r.h.cmds)
				}
				if !r.h.has("docker stop") {
					t.Error("the container was never stopped")
				}
				if !r.src.shortened || !r.src.restored {
					t.Errorf("lease time shortened=%v restored=%v", r.src.shortened, r.src.restored)
				}
				suffix := map[string]string{NameE1: "e1", NameE2: "e2"}[name]
				needCleanup(t, r.h.bRunner, suffix, containerName(r.e, name))
				for _, label := range []string{"server-events", "ledger", "capture", "health-before", "health-after"} {
					if p := v.Evidence[label]; p == "" {
						t.Errorf("no %s evidence", label)
					} else if _, err := os.Stat(p); err != nil {
						t.Errorf("%s evidence unreadable: %v", label, err)
					}
				}
			})
		}
	}
}

func TestRunE1AndE2AreNotApplicableOnIPAMShapes(t *testing.T) {
	for _, shape := range []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		r := eSetup(t, shape)
		for name, v := range runBoth(t, r) {
			needResult(t, v, NA)
			if len(r.h.cmds) != 0 {
				t.Errorf("%s/%s touched the host: %v", shape, name, r.h.cmds)
			}
		}
	}
}

// Defeat rows 1 and 2: an absent ledger, or one the plugin keeps inside
// its own rootfs, never reads as "no entries".
func TestRunE1LedgerAbsentBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.ledger = nil
	v := runE1Tuned(context.Background(), r.e, eFast)
	needResult(t, v, BLOCKED)
	if !strings.Contains(v.Reason, "absent") {
		t.Errorf("reason: %q", v.Reason)
	}
}

func TestRunE1RepointedStateDirBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.settings = "STATE_DIR=/elsewhere\n"
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), BLOCKED)
}

// Defeat row 3: a suppressed journal reads as "cannot judge", never as
// an empty log that matches an empty ledger.
func TestRunE1SuppressedJournalBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.src.err = sourceadapter.ErrJournalSuppressed
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), BLOCKED)
}

func TestRunE2SuppressedJournalBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.src.err = sourceadapter.ErrJournalSuppressed
	needResult(t, runE2Tuned(context.Background(), r.e, eFast), BLOCKED)
}

// Defeat row 7: another endpoint alive on the plugin moves the
// plugin-wide counters, so the run does not start.
func TestRunE2OtherEndpointsLiveBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.active = 2
	v := runE2Tuned(context.Background(), r.e, eFast)
	needResult(t, v, BLOCKED)
	if r.h.has("docker run") {
		t.Error("a container started beside another live endpoint")
	}
}

func TestRunE1OtherEndpointsLiveBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.active = 1
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), BLOCKED)
}

// A ledger that holds other endpoints' lines (an earlier run, another
// network) must not count against this endpoint.
func TestRunE1IgnoresOtherEndpointsLedgerLines(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	other := *eLedger(strings.Repeat("f", 64), "bound", "bound", "renew", "stopped")
	r.h.ledger = func() *string { s := other + *eLedger(eEndpoint, "bound", "renew", "stopped"); return &s }()
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), PASS)
}

// Defeat row 3: lines the journal already held before the run are
// excluded by position, so an old RELEASE for the same MAC is not this
// run's release.
func TestRunE1OnlyNewServerEventsCount(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.src.pre = []sourceadapter.ServerEvent{srvEv("ACK", eIP, -3600), srvEv("RELEASE", eIP, -3500), srvEv("DECLINE", eIP, -3400)}
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), PASS)
}

func TestRunE1BaselinePrefixChangeIsBlocked(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.src.pre = []sourceadapter.ServerEvent{srvEv("ACK", eIP, -3600), srvEv("ACK", eIP, -3500)}
	// The line count stays, one line's content changes: only the prefix
	// compare can see it.
	r.src.mutatePre = func(p []sourceadapter.ServerEvent) []sourceadapter.ServerEvent {
		p[0].IP = "10.200.1.199"
		return p
	}
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), BLOCKED)
}

// Another client's journal lines (same source, same window) are not
// this container's.
func TestRunE1IgnoresOtherClientsJournalLines(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	other := sourceadapter.ServerEvent{At: eAt(5).Truncate(time.Second), Type: "DECLINE", MAC: "02:aa:bb:cc:dd:99", IP: "10.200.1.160"}
	otherRel := sourceadapter.ServerEvent{At: eAt(6).Truncate(time.Second), Type: "RELEASE", MAC: "02:aa:bb:cc:dd:99", IP: "10.200.1.160"}
	r.src.fresh = append([]sourceadapter.ServerEvent{other, otherRel}, r.src.fresh...)
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), PASS)
}

func TestRunE1PluginRestartBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.instAfter = "i2"
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), BLOCKED)
}

func TestRunE1ReleaseCounterGoingDownBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.after["releases_sent"] = 1
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), BLOCKED)
}

func TestRunE2ScrapeFailureBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.metricsErr = errors.New("connection refused")
	needResult(t, runE2Tuned(context.Background(), r.e, eFast), BLOCKED)
}

func TestRunE2PluginRestartBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.instAfter = "i2"
	needResult(t, runE2Tuned(context.Background(), r.e, eFast), BLOCKED)
}

func TestRunE1HealthStillMovingBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.healthDrift = true
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), BLOCKED)
}

func TestRunE1NoCaptureBlocks(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.e.Capture = nil
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), BLOCKED)
	if len(r.h.cmds) != 0 {
		t.Errorf("touched the host without a capture: %v", r.h.cmds)
	}
}

// A ledger without the renew the wire and the source both show is a
// plugin finding, not a lab problem.
func TestRunE1MissingRenewLedgerEntryFails(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.ledger = eLedger(eEndpoint, "bound", "stopped")
	needResult(t, runE1Tuned(context.Background(), r.e, eFast), FAIL)
}

func TestRunE2ReleaseCounterNotMovingFails(t *testing.T) {
	r := eSetup(t, ShapeBridge)
	r.h.after["releases_sent"] = 2
	needResult(t, runE2Tuned(context.Background(), r.e, eFast), FAIL)
}

// The README table and the catalog agree for group E (lab #15).
func TestReadmeGroupETableMatchesTheCatalog(t *testing.T) { readmeGroupMatchesCatalog(t, "E") }
