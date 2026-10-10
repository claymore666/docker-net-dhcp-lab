package scenario

import (
	"context"
	"errors"
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

// splitPair adds the primary's backup-half read to a fake pair.
type splitPair struct {
	*fakePair
	half []string
	err  error
}

func (s splitPair) PeerBackupAddrs(context.Context, string) ([]string, error) { return s.half, s.err }

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
		{"the primary lists no backup address", nil, nil, false, BLOCKED, "names no backup"},
		{"the primary's table cannot be read", nil, errors.New("ssh down"), false, BLOCKED, "ssh down"},
		{"the pair offers no read of the half", nil, nil, true, BLOCKED, "offers no read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newC5bRig(t, NameC5b)
			r.p.prof = iscProfile()
			r.h.addrFn = func(string, string) string { return outage }
			if tc.plain {
				r.e.Source = r.p
			} else {
				r.e.Source = splitPair{fakePair: r.p, half: tc.half, err: tc.err}
			}
			v := runC5bTuned(context.Background(), r.e, cFast)
			needResult(t, v, tc.result)
			needReason(t, v, tc.reason)
			if r.p.down["primary"] {
				t.Error("the primary was left stopped")
			}
			// the half is read before the stop, so a BLOCKED read stops nothing
			if tc.result == BLOCKED && strings.Contains(tc.reason, "names no backup") {
				for _, op := range r.p.ops {
					if op == "stop primary" {
						t.Error("the primary was stopped before the half was read")
					}
				}
			}
		})
	}
}

// A Kea pair has no split pool: C5b reads no half and judges as before.
func TestRunC5bWithoutSplitPoolReadsNoHalf(t *testing.T) {
	r := newC5bRig(t, NameC5b)
	r.e.Source = splitPair{fakePair: r.p, err: errors.New("must not be read")}
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
