package scenario

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// The ISC failover pair through the C5 family (lab #12 PR 2): its
// PairProfile drives C5b's half-pool rule and C5d's premise, and its
// state reader feeds waitPeerStates.

// iscProfile is NewISCPair's own profile, so a test fails when the
// pair's constructor changes what the scenarios are told.
func iscProfile() sourceadapter.PairProfile {
	return sourceadapter.NewISCPair(nil, nil, "10.200.9.2", "10.200.9.3").Profile()
}

// fixtureRunner answers every command with one file of
// internal/sourceadapter/testdata/isc-failover.
type fixtureRunner string

func (f fixtureRunner) Run(context.Context, string) (string, error) {
	b, err := os.ReadFile(filepath.Join("..", "sourceadapter", "testdata", "isc-failover", string(f)))
	return string(b), err
}

func TestISCPairProfileIsLoadBalancedAndSplit(t *testing.T) {
	p := iscProfile()
	if p.Normal != "normal" || p.Survivor != "communications-interrupted" || p.StandbySilent || !p.SplitPool {
		t.Fatalf("isc pair profile = %+v", p)
	}
}

// Defeat 5 (lab #12): a load-balanced pair answered from one peer did
// not exercise the split, however the profile came about.
func TestRunC5dOnTheISCProfile(t *testing.T) {
	for _, tc := range []struct {
		name      string
		alternate bool
		result    Result
		reason    string
	}{
		{"one server-id answers all eighteen", false, BLOCKED, "split was not exercised"},
		{"both server-ids answer", true, PASS, "18 distinct"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newC5dRig(t)
			r.p.prof, r.alternate = iscProfile(), tc.alternate
			v := runC5dTuned(context.Background(), r.e, cFast)
			needResult(t, v, tc.result)
			needReason(t, v, tc.reason)
		})
	}
}

// Defeat 3 (lab #12): the survivor's lease is the MCLT's 60 s, not the
// cell's 120 s, so T1, T2 and the expiry come from the ACK's option 51.
func TestC5WindowsFollowOption51(t *testing.T) {
	bind := time.Unix(5000, 0)
	for _, tc := range []struct {
		lease          time.Duration
		t1, t2, expiry time.Duration
	}{
		{60 * time.Second, 30 * time.Second, 52500 * time.Millisecond, 60 * time.Second},
		{120 * time.Second, 60 * time.Second, 105 * time.Second, 120 * time.Second},
	} {
		t1, t2, exp := c5Windows(bind, tc.lease)
		if t1.Sub(bind) != tc.t1 || t2.Sub(bind) != tc.t2 || exp.Sub(bind) != tc.expiry {
			t.Errorf("lease %s: T1 %s T2 %s expiry %s", tc.lease, t1.Sub(bind), t2.Sub(bind), exp.Sub(bind))
		}
	}
	// A rebind inside the 60 s lease's window is outside the 120 s one.
	rb := []DHCPMsg{req(bind.Add(55*time.Second), "x", "10.0.0.5", "255.255.255.255"), ack(bind.Add(56*time.Second), "x", "10.0.0.5", "S", time.Minute)}
	_, t2, exp := c5Windows(bind, 60*time.Second)
	if _, _, ok := c5Rebind(rb, "10.0.0.5", "S", t2, exp); !ok {
		t.Error("the 55 s rebind was not found in the 60 s lease's window")
	}
	_, t2, exp = c5Windows(bind, 120*time.Second)
	if _, _, ok := c5Rebind(rb, "10.0.0.5", "S", t2, exp); ok {
		t.Error("the 55 s rebind was found in the 120 s lease's window")
	}
}

// splitPair adds the partner's own backup-half read to a fake pair and
// records which peer was asked and whether the primary was stopped then.
type splitPair struct {
	*fakePair
	half        []string
	err         error
	asked       []string
	primaryDown []bool
}

func (s *splitPair) PeerBackupAddrs(_ context.Context, name string) ([]string, error) {
	s.asked = append(s.asked, name)
	s.primaryDown = append(s.primaryDown, s.fakePair.down["primary"])
	return s.half, s.err
}

func TestRunC5bHalfPoolRule(t *testing.T) {
	const outage = "10.200.1.121"
	for _, tc := range []struct {
		name   string
		half   []string
		err    error
		plain  bool
		result Result
		reason string
	}{
		{"the outage address was the partner's half", []string{"10.200.1.120", outage}, nil, false, PASS, "by 10.200.1.3"},
		{"the outage address was the primary's own", []string{"10.200.1.120"}, nil, false, BLOCKED, "did not serve its own half"},
		{"the partner lists no backup address", nil, nil, false, BLOCKED, "names no backup"},
		{"the partner's table cannot be read", nil, errors.New("ssh down"), false, BLOCKED, "ssh down"},
		{"the pair offers no read of the half", nil, nil, true, BLOCKED, "offers no read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newC5bRig(t, NameC5b)
			r.p.prof = iscProfile()
			r.h.addrFn = func(string, string) string { return outage }
			sp := &splitPair{fakePair: r.p, half: tc.half, err: tc.err}
			if tc.plain {
				r.e.Source = r.p
			} else {
				r.e.Source = sp
			}
			v := runC5bTuned(context.Background(), r.e, cFast)
			needResult(t, v, tc.result)
			needReason(t, v, tc.reason)
			if r.p.down["primary"] {
				t.Error("the primary was left stopped")
			}
		})
	}
}

// Lab #129: the half is the partner's own table, read after the takeover
// (the primary stopped), not the primary's list from before the stop.
func TestRunC5bReadsTheHalfFromThePartnerAfterTheStop(t *testing.T) {
	r := newC5bRig(t, NameC5b)
	r.p.prof = iscProfile()
	r.h.addrFn = func(string, string) string { return "10.200.1.121" }
	sp := &splitPair{fakePair: r.p, half: []string{"10.200.1.121"}}
	r.e.Source = sp
	needResult(t, runC5bTuned(context.Background(), r.e, cFast), PASS)
	if len(sp.asked) != 1 || sp.asked[0] != "partner" {
		t.Errorf("the half was read from %v, want the partner only", sp.asked)
	}
	if len(sp.primaryDown) != 1 || !sp.primaryDown[0] {
		t.Error("the half was read before the primary was stopped")
	}
}

// Lab #129, run 4 (bridge and macvlan): the plugin's tombstone gave C5b
// C5's MAC and address, so ISC re-offered the first container's lease
// (.142, the primary's half) instead of leasing from the partner's half.
// The fake server does the same for any container started without a MAC
// of its own.
func TestRunC5bAndC5cLeaseUnderAFreshMAC(t *testing.T) {
	const reoffered, fresh = "10.200.1.142", "10.200.1.121"
	for _, name := range []string{NameC5b, NameC5c} {
		t.Run(name, func(t *testing.T) {
			r := newC5bRig(t, name)
			r.p.prof = iscProfile()
			r.h.addrFn = func(_, mac string) string {
				if strings.HasPrefix(mac, "aa:bb:cc:") {
					return reoffered
				}
				return fresh
			}
			r.e.Source = &splitPair{fakePair: r.p, half: []string{fresh}}
			var v Verdict
			if name == NameC5b {
				v = runC5bTuned(context.Background(), r.e, cFast)
			} else {
				v = runC5cTuned(context.Background(), r.e, cFast)
			}
			if v.Result == BLOCKED && strings.Contains(v.Reason, reoffered) {
				t.Fatalf("the container reused an earlier identity: %s", v.Reason)
			}
			if !r.h.has("--mac-address 02:42:") {
				t.Error("the outage container was started without a MAC of its own")
			}
		})
	}
}

func TestC5FreshMAC(t *testing.T) {
	e := Env{Cell: "isc-failover", Shape: ShapeBridge}
	a, b := c5FreshMAC(e, NameC5b), c5FreshMAC(e, NameC5c)
	time.Sleep(time.Millisecond)
	a2 := c5FreshMAC(e, NameC5b)
	if _, err := net.ParseMAC(a); err != nil || !strings.HasPrefix(a, "02:42:") {
		t.Errorf("%q is not a locally administered unicast MAC: %v", a, err)
	}
	if a == b || a == a2 {
		t.Errorf("MACs repeat: %s %s %s", a, b, a2)
	}
	e.Shape = ShapeIpvlan
	if m := c5FreshMAC(e, NameC5b); m != "" {
		t.Errorf("ipvlan got %q, but --mac-address is invalid there", m)
	}
}

// A Kea pair has no split pool: C5b reads no half and judges as before.
func TestRunC5bWithoutSplitPoolReadsNoHalf(t *testing.T) {
	r := newC5bRig(t, NameC5b)
	r.e.Source = &splitPair{fakePair: r.p, err: errors.New("must not be read")}
	needResult(t, runC5bTuned(context.Background(), r.e, cFast), PASS)
}

// Defeat 9 (lab #12): waitPeerStates on the measured files. The
// survivor's last block says communications-interrupted after a history
// of recover and normal blocks; the primary's says normal.
func TestWaitPeerStatesOnTheMeasuredFiles(t *testing.T) {
	pair := sourceadapter.NewISCPair(fixtureRunner("primary-normal.leases"), fixtureRunner("partner-comm-interrupted.leases"), "10.200.9.2", "10.200.9.3")
	ctx := context.Background()
	prof := pair.Profile()
	if _, err := waitPeerStates(ctx, pair, prof.Survivor, 20*ms, 5*ms, "partner"); err != nil {
		t.Errorf("the survivor was not seen in %q: %v", prof.Survivor, err)
	}
	if _, err := waitPeerStates(ctx, pair, prof.Normal, 20*ms, 5*ms, "primary"); err != nil {
		t.Errorf("the primary was not seen normal: %v", err)
	}
	if _, err := waitPeerStates(ctx, pair, prof.Normal, 20*ms, 5*ms, "primary", "partner"); err == nil || !strings.Contains(err.Error(), "partner: communications-interrupted") {
		t.Errorf("a pair with a survivor passed as normal: %v", err)
	}
	if _, err := waitPeerStates(ctx, pair, prof.Survivor, 20*ms, 5*ms, "primary", "partner"); err == nil || !strings.Contains(err.Error(), "primary: normal") {
		t.Errorf("a normal primary passed as a survivor: %v", err)
	}
}

// Defeat 3 (lab #12): runC5Tuned times T1, T2 and the expiry from the
// bound ACK's option 51 (800 ms here), never from the cell's lease time
// (cFast.lease, 120 s). Timing from the cell lease waits out T2 at 105 s,
// so the bounded context turns that into a BLOCKED in seconds, not a hang.
func TestRunC5TimesFromOption51NotTheCellLease(t *testing.T) {
	r := newC5Rig(t, ShapeMacvlan, "primary")
	if cFast.lease <= 100 || r.lease >= time.Second {
		t.Fatalf("premise: cell lease %d s must dwarf option 51 %s", cFast.lease, r.lease)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	v := runC5Tuned(ctx, r.e, cFast)
	needResult(t, v, PASS)
	needReason(t, v, "for "+r.lease.String())
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("took %s: the windows came from the cell's lease", d)
	}
}
