package scenario

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// fakePair is a bAdapter with per-peer control: a stopped peer's state
// read fails, the other reports the profile's survivor state.
type fakePair struct {
	*bAdapter
	ids     map[string]string
	down    map[string]bool
	startAt map[string]time.Time
	ops     []string
	stopErr error
	peerFn  func(name string) []sourceadapter.Lease
	stateFn func(name string) (sourceadapter.HAState, error)
	prof    sourceadapter.PairProfile
}

var _ sourceadapter.PairControl = (*fakePair)(nil)

func newFakePair(src *bAdapter) *fakePair {
	return &fakePair{bAdapter: src, ids: map[string]string{"primary": "10.200.1.2", "partner": "10.200.1.3"},
		down: map[string]bool{}, startAt: map[string]time.Time{},
		prof: sourceadapter.PairProfile{Normal: "hot-standby", Survivor: "partner-down", StandbySilent: true}}
}

func (p *fakePair) other(n string) string {
	if n == "primary" {
		return "partner"
	}
	return "primary"
}

func (p *fakePair) PeerNames() []string { return []string{"primary", "partner"} }

func (p *fakePair) PeerServerID(n string) (string, error) {
	if id, ok := p.ids[n]; ok {
		return id, nil
	}
	return "", errors.New("no such peer")
}

func (p *fakePair) StopPeer(_ context.Context, n string) error {
	p.ops = append(p.ops, "stop "+n)
	if p.stopErr != nil {
		return p.stopErr
	}
	p.down[n] = true
	return nil
}

func (p *fakePair) StartPeer(_ context.Context, n string) error {
	p.ops = append(p.ops, "start "+n)
	p.down[n] = false
	p.startAt[n] = time.Now()
	return nil
}

func (p *fakePair) PeerLeases(ctx context.Context, n string) ([]sourceadapter.Lease, error) {
	if p.down[n] {
		return nil, errors.New(n + " is stopped")
	}
	if p.peerFn == nil {
		return p.bAdapter.Leases(ctx)
	}
	return p.peerFn(n), nil
}

func (p *fakePair) PeerState(_ context.Context, n string) (sourceadapter.HAState, error) {
	if p.stateFn != nil {
		return p.stateFn(n)
	}
	return p.defaultState(n)
}

func (p *fakePair) defaultState(n string) (sourceadapter.HAState, error) {
	switch {
	case p.down[n]:
		return sourceadapter.HAState{}, errors.New("connection refused")
	case p.down[p.other(n)]:
		return sourceadapter.HAState{State: p.prof.Survivor, Clock: time.Now()}, nil
	}
	return sourceadapter.HAState{State: p.prof.Normal, Clock: time.Now()}, nil
}

func (p *fakePair) Profile() sourceadapter.PairProfile { return p.prof }

// ShortenLeaseTime records its restore in ops, so a test sees the order.
func (p *fakePair) ShortenLeaseTime(ctx context.Context, s int) (func(context.Context) error, error) {
	r, err := p.bAdapter.ShortenLeaseTime(ctx, s)
	if err != nil {
		return nil, err
	}
	return func(c context.Context) error { p.ops = append(p.ops, "restore"); return r(c) }, nil
}

// seen drops what the observer could not have captured yet.
func seen(msgs []DHCPMsg) []DHCPMsg {
	now := time.Now()
	var out []DHCPMsg
	for _, m := range msgs {
		if !m.At.After(now) {
			out = append(out, m)
		}
	}
	return out
}

func needOps(t *testing.T, p *fakePair, want ...string) {
	t.Helper()
	if strings.Join(p.ops, ",") != strings.Join(want, ",") {
		t.Fatalf("ops %v, want %v", p.ops, want)
	}
}

const c5Lease = 800 * ms

func ack(at time.Time, xid, yi, server string, lease time.Duration) DHCPMsg {
	return DHCPMsg{At: at, Type: "ACK", XID: xid, YIAddr: yi, Server: server, LeaseTime: lease, Src: server, Dst: yi}
}

func req(at time.Time, xid, addr, dst string) DHCPMsg {
	return DHCPMsg{At: at, Type: "REQUEST", XID: xid, CIAddr: addr, Src: addr, Dst: dst}
}

// ---- C5 ---------------------------------------------------------------

// c5Rig: the granting peer's renewal goes unanswered at T1 + 10 ms, the
// rebind broadcast at T2 + 10 ms is ACKed by the survivor 10 ms later,
// whose table then shows the extended lease.
type c5Rig struct {
	*cBoundRig
	p                                   *fakePair
	grant                               string
	no51, noRenewal, noUnicast, deadACK bool
	lateRenewal, noRebind, rebindByDead bool
	noSurvivorRenew, renewToSurvivor    bool
	earlyRenewal                        bool
	bindServer                          string
	lease                               time.Duration
}

func newC5Rig(t *testing.T, shape Shape, grant string) *c5Rig {
	b := cBoundSetup(t, shape, NameC5)
	r := &c5Rig{cBoundRig: b, p: newFakePair(b.src), grant: grant, lease: c5Lease}
	b.e.Source = r.p
	addr := "10.200.1.101"
	b.src.fn = func(int) []sourceadapter.Lease { return []sourceadapter.Lease{b.lease(addr, b.bind.Add(r.lease))} }
	r.p.peerFn = func(n string) []sourceadapter.Lease {
		if n != r.p.other(r.grant) || r.noSurvivorRenew || time.Now().Before(b.bind.Add(r.lease*7/8+20*ms)) {
			return []sourceadapter.Lease{b.lease(addr, b.bind.Add(r.lease))}
		}
		return []sourceadapter.Lease{b.lease(addr, b.bind.Add(time.Hour))}
	}
	b.cap.fn = func(ident string) []DHCPMsg {
		if b.bind.IsZero() {
			b.bind = time.Now()
		}
		gid, sid := r.p.ids[r.grant], r.p.ids[r.p.other(r.grant)]
		lease := r.lease
		if r.no51 {
			lease = 0
		}
		bs := gid
		if r.bindServer != "" {
			bs = r.bindServer
		}
		out := []DHCPMsg{ack(b.bind, "b", addr, bs, lease)}
		t1, t2 := b.bind.Add(r.lease/2), b.bind.Add(r.lease*7/8)
		switch {
		case r.noRenewal:
		case r.earlyRenewal:
			out = append(out, req(b.bind.Add(100*ms), "r", addr, gid))
		case r.lateRenewal:
			out = append(out, req(t2.Add(5*ms), "r", addr, gid))
		case r.renewToSurvivor:
			out = append(out, req(t1.Add(10*ms), "r", addr, sid))
		default:
			out = append(out, req(t1.Add(10*ms), "r", addr, gid))
		}
		if r.deadACK {
			out = append(out, ack(b.bind.Add(r.lease/4), "r", addr, gid, r.lease))
		}
		if !r.noRebind {
			by := sid
			if r.rebindByDead {
				by = gid
			}
			out = append(out, req(t2.Add(10*ms), "x", addr, "255.255.255.255"), ack(t2.Add(20*ms), "x", addr, by, r.lease))
		}
		if ident == "*" && !r.noUnicast {
			out = append(out, req(b.bind.Add(ms), "o", "10.200.1.150", "10.200.1.2"))
		}
		return seen(out)
	}
	return r
}

func TestRunC5PassesWhenTheSurvivorAnswersTheRebind(t *testing.T) {
	for _, tc := range []struct {
		shape Shape
		grant string
	}{{ShapeMacvlan, "primary"}, {ShapeIpvlan, "primary"}, {ShapeBridge, "partner"}} {
		t.Run(string(tc.shape)+"-"+tc.grant, func(t *testing.T) {
			r := newC5Rig(t, tc.shape, tc.grant)
			v := runC5Tuned(context.Background(), r.e, cFast)
			needResult(t, v, PASS)
			needWritten(t, r.e, v)
			needReason(t, v, "ACKed by "+r.p.ids[r.p.other(tc.grant)])
			needReason(t, v, "(secs 0)")
			needOps(t, r.p, "stop "+tc.grant, "start "+tc.grant, "restore")
			if v.Evidence["survivor-leases"] == "" {
				t.Error("no survivor table in the evidence")
			}
			needCleanup(t, r.h.bRunner, "", r.name)
		})
	}
}

func TestRunC5Judges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		set    func(*c5Rig)
		result Result
		reason string
	}{
		{"no option 51", func(r *c5Rig) { r.no51 = true }, BLOCKED, "no option 51"},
		{"unknown server-id", func(r *c5Rig) { r.bindServer = "10.200.1.9" }, BLOCKED, "neither peer's"},
		{"the stop fails", func(r *c5Rig) { r.p.stopErr = errors.New("virsh says no") }, BLOCKED, "could not stop the granting peer"},
		{"the stopped peer ACKs", func(r *c5Rig) { r.deadACK = true }, BLOCKED, "the stop did not land"},
		{"no renewal and no unicast seen", func(r *c5Rig) { r.noRenewal, r.noUnicast = true, true }, BLOCKED, "absence is not judged"},
		{"no renewal", func(r *c5Rig) { r.noRenewal = true }, FAIL, "no REQUEST from"},
		{"renewal only after T2", func(r *c5Rig) { r.lateRenewal = true }, FAIL, "between T1"},
		// T1 less the 1 s jitter must fall after bind + 100 ms, so this lease is 2.4 s (#12).
		{"renewal only before T1", func(r *c5Rig) { r.earlyRenewal, r.lease = true, 2400*ms }, FAIL, "between T1"},
		{"renewal unicast to the survivor", func(r *c5Rig) { r.renewToSurvivor = true }, FAIL, "no REQUEST from"},
		{"no rebind", func(r *c5Rig) { r.noRebind = true }, FAIL, "no broadcast REQUEST"},
		{"rebind ACKed by the stopped peer", func(r *c5Rig) { r.rebindByDead, r.deadACK = true, false }, BLOCKED, "the stop did not land"},
		{"the survivor never extends", func(r *c5Rig) { r.noSurvivorRenew = true }, FAIL, "shows no renewed lease"},
		{"the address goes", func(r *c5Rig) { r.h.setAddrs(r.name) }, FAIL, "no longer carries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newC5Rig(t, ShapeMacvlan, "primary")
			tc.set(r)
			v := runC5Tuned(context.Background(), r.e, cFast)
			needResult(t, v, tc.result)
			needReason(t, v, tc.reason)
			needWritten(t, r.e, v)
			if r.p.down["primary"] {
				t.Error("the granting peer was left stopped")
			}
			if !r.src.restored {
				t.Error("the lease time was not restored")
			}
		})
	}
}

func TestRunC5BlocksOnASourceWithoutPairControl(t *testing.T) {
	b := cBoundSetup(t, ShapeMacvlan, NameC5)
	v := runC5Tuned(context.Background(), b.e, cFast)
	needResult(t, v, BLOCKED)
	needReason(t, v, "no control of its two peers")
}

func TestC5RebindWindow(t *testing.T) {
	t0 := time.Unix(1000, 0)
	from, until := t0.Add(100*time.Second), t0.Add(120*time.Second)
	base := []DHCPMsg{req(t0.Add(110*time.Second), "x", "10.0.0.5", "255.255.255.255"), ack(t0.Add(111*time.Second), "x", "10.0.0.5", "S", time.Minute)}
	if _, _, ok := c5Rebind(base, "10.0.0.5", "S", from, until); !ok {
		t.Fatal("the in-window rebind was not found")
	}
	for name, msgs := range map[string][]DHCPMsg{
		"request before the window": {req(t0.Add(99*time.Second), "x", "10.0.0.5", "255.255.255.255"), base[1]},
		"ack at the expiry":         {base[0], ack(until, "x", "10.0.0.5", "S", time.Minute)},
		"unicast request":           {req(t0.Add(110*time.Second), "x", "10.0.0.5", "10.0.0.2"), base[1]},
		"other xid":                 {base[0], ack(t0.Add(111*time.Second), "y", "10.0.0.5", "S", time.Minute)},
		"other server":              {base[0], ack(t0.Add(111*time.Second), "x", "10.0.0.5", "T", time.Minute)},
		"other yiaddr":              {base[0], ack(t0.Add(111*time.Second), "x", "10.0.0.6", "S", time.Minute)},
		"other address":             {req(t0.Add(110*time.Second), "x", "10.0.0.7", "255.255.255.255"), base[1]},
	} {
		if _, _, ok := c5Rebind(msgs, "10.0.0.5", "S", from, until); ok {
			t.Errorf("%s: judged a rebind", name)
		}
	}
	byOpt50 := []DHCPMsg{{At: t0.Add(110 * time.Second), Type: "REQUEST", XID: "x", Requested: "10.0.0.5", Dst: "255.255.255.255"}, base[1]}
	if _, _, ok := c5Rebind(byOpt50, "10.0.0.5", "S", from, until); !ok {
		t.Error("a rebind naming the address in option 50 was not found")
	}
}

// ---- C5b and C5c ------------------------------------------------------

// c5bRig: the outage container is ACKed by the partner at its first
// capture read; after the primary's start its renewal goes unicast to
// the partner, its rebind is ACKed by the primary 30 ms after the start,
// and a second container is ACKed by the primary at once.
type c5bRig struct {
	*cRig
	p                                  *fakePair
	name                               string
	outageAt                           time.Time
	outageServer                       string
	noPartnerLease, noPrimaryLease     bool
	noPrimaryACK, standbyACK, newByPtn bool
	renewToPrimary, noStandbyRenewal   bool
	noRebind, noUnicast, outageRenewal bool
}

func newC5bRig(t *testing.T, scenario string) *c5bRig {
	c := cSetup(t, ShapeMacvlan)
	r := &c5bRig{cRig: c, p: newFakePair(c.src), name: containerName(c.e, scenario)}
	c.e.Source = r.p
	r.outageServer = r.p.ids["partner"]
	lease := func(name string) []sourceadapter.Lease {
		ct, _, ok := c.h.container(name)
		if !ok {
			return nil
		}
		return []sourceadapter.Lease{{MAC: ct.mac, Address: ct.addr, Expires: time.Now().Add(time.Hour)}}
	}
	r.p.peerFn = func(n string) []sourceadapter.Lease {
		if (n == "partner" && r.noPartnerLease) || (n == "primary" && r.noPrimaryLease) {
			return nil
		}
		return lease(r.name)
	}
	c.cap.fn = func(ident string) []DHCPMsg {
		ct, _, ok := c.h.container(r.name)
		if !ok {
			return nil
		}
		if r.outageAt.IsZero() {
			r.outageAt = time.Now()
		}
		out := []DHCPMsg{ack(r.outageAt, "b", ct.addr, r.outageServer, c5Lease)}
		if st := r.p.startAt["primary"]; !st.IsZero() {
			if r.standbyACK && time.Now().After(st) {
				out = append(out, ack(st.Add(ms), "s", ct.addr, r.p.ids["partner"], c5Lease))
			}
			if r.outageRenewal {
				out = append(out, req(st.Add(-ms), "u", ct.addr, r.p.ids["partner"]))
			}
			if !r.noStandbyRenewal {
				out = append(out, req(st.Add(15*ms), "t", ct.addr, r.p.ids["partner"]))
			}
			dst := "255.255.255.255"
			if r.renewToPrimary {
				dst = r.p.ids["primary"]
			}
			if !r.noRebind {
				out = append(out, req(st.Add(25*ms), "r", ct.addr, dst))
			}
			if !r.noPrimaryACK {
				out = append(out, ack(st.Add(30*ms), "r", ct.addr, r.p.ids["primary"], c5Lease))
			}
		}
		if n, _, ok := c.h.container(r.name + "-new"); ok {
			by := r.p.ids["primary"]
			if r.newByPtn {
				by = r.p.ids["partner"]
			}
			out = append(out, ack(time.Now(), "n", n.addr, by, c5Lease))
		}
		if ident == "*" && !r.noUnicast {
			out = append(out, req(r.outageAt.Add(ms), "o", "10.200.1.150", "10.200.1.2"))
		}
		return seen(out)
	}
	return r
}

func TestRunC5bPassesWhenThePartnerLeasesWithThePrimaryDown(t *testing.T) {
	r := newC5bRig(t, NameC5b)
	v := runC5bTuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, r.e, v)
	needReason(t, v, "by 10.200.1.3")
	needOps(t, r.p, "stop primary", "start primary")
	needCleanup(t, r.h.bRunner, "", r.name)
}

func TestRunC5bJudges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		set    func(*c5bRig)
		result Result
		reason string
	}{
		{"the partner never takes over", func(r *c5bRig) {
			r.p.stateFn = func(string) (sourceadapter.HAState, error) { return sourceadapter.HAState{State: "hot-standby"}, nil }
		}, BLOCKED, "did not take over"},
		{"docker run fails", func(r *c5bRig) { r.h.rc[r.name] = 125 }, FAIL, "exited 125"},
		{"over C1's bound", func(r *c5bRig) { r.h.wall[r.name] = c1WallMax + ms }, FAIL, "over C1's"},
		{"the stopped primary ACKs", func(r *c5bRig) { r.outageServer = r.p.ids["primary"] }, BLOCKED, "the stop did not land"},
		{"an unknown server ACKs", func(r *c5bRig) { r.outageServer = "10.200.1.9" }, BLOCKED, "neither peer's"},
		{"the partner's table lacks it", func(r *c5bRig) { r.noPartnerLease = true }, FAIL, "partner ACKed but its table lacks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newC5bRig(t, NameC5b)
			tc.set(r)
			v := runC5bTuned(context.Background(), r.e, cFast)
			needResult(t, v, tc.result)
			needReason(t, v, tc.reason)
			needWritten(t, r.e, v)
			if r.p.down["primary"] {
				t.Error("the primary was left stopped")
			}
		})
	}
}

func TestC1WallMaxBoundIsInclusiveForC5b(t *testing.T) {
	r := newC5bRig(t, NameC5b)
	r.h.wall[r.name] = c1WallMax
	needResult(t, runC5bTuned(context.Background(), r.e, cFast), PASS)
}

func TestRunC5cPassesWhenThePrimaryReturnsAndTakesTheRebind(t *testing.T) {
	r := newC5bRig(t, NameC5c)
	v := runC5cTuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, r.e, v)
	needReason(t, v, "the primary ACKed it")
	needReason(t, v, "1 renewal(s) unicast to the standby 10.200.1.3 went unanswered")
	needOps(t, r.p, "stop primary", "start primary", "start primary", "restore")
	needCleanup(t, r.h.bRunner, "", r.name)
	needCleanup(t, r.h.bRunner, "", r.name+"-new")
}

func TestRunC5cJudges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		set    func(*c5bRig)
		result Result
		reason string
	}{
		{"the returning primary lacks the outage lease", func(r *c5bRig) { r.noPrimaryLease = true }, FAIL, "returning primary's table lacks"},
		{"the standby answers", func(r *c5bRig) { r.standbyACK = true }, BLOCKED, "broke the premise"},
		{"the primary never ACKs", func(r *c5bRig) { r.noPrimaryACK = true }, FAIL, "no ACK of"},
		{"the new container goes to the standby", func(r *c5bRig) { r.newByPtn = true }, FAIL, "not the primary"},
		{"renewal unicast to the returned primary", func(r *c5bRig) { r.renewToPrimary = true }, FAIL, "unicast to the returned primary"},
		{"the primary ACKs with no rebind seen", func(r *c5bRig) { r.noRebind = true }, FAIL, "answers no broadcast REQUEST"},
		{"no renewal to the standby", func(r *c5bRig) { r.noStandbyRenewal = true }, FAIL, "unicast to the granting standby"},
		{"no renewal and no unicast seen", func(r *c5bRig) { r.noStandbyRenewal, r.noUnicast = true, true }, BLOCKED, "absence is not judged"},
		{"a renewal to the standby only during the outage", func(r *c5bRig) { r.noStandbyRenewal, r.outageRenewal = true, true }, FAIL, "unicast to the granting standby"},
		{"the address goes", func(r *c5bRig) {
			r.p.stateFn = func(n string) (sourceadapter.HAState, error) {
				if !r.p.startAt["primary"].IsZero() {
					r.h.setAddrs(r.name)
				}
				return r.p.defaultState(n)
			}
		}, FAIL, "no longer carries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newC5bRig(t, NameC5c)
			tc.set(r)
			// A judge that never returns has failed; the slowest case takes 0.8 s (#12).
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			v := runC5cTuned(ctx, r.e, cFast)
			needResult(t, v, tc.result)
			needReason(t, v, tc.reason)
			needWritten(t, r.e, v)
			if r.p.down["primary"] || !r.src.restored {
				t.Errorf("not put back: primary down %v, restored %v", r.p.down["primary"], r.src.restored)
			}
		})
	}
}

func TestRunC5cKeepsTheLoadBalancedPartnerAllowedToAnswer(t *testing.T) {
	r := newC5bRig(t, NameC5c)
	r.p.prof.StandbySilent = false
	r.standbyACK, r.newByPtn = true, true
	needResult(t, runC5cTuned(context.Background(), r.e, cFast), PASS)
}

// ---- C5d --------------------------------------------------------------

// c5dRig: each container is ACKed at its run by whichever peer is up,
// and both tables list every container.
type c5dRig struct {
	*cRig
	p          *fakePair
	server     map[string]string
	created    map[string]time.Time
	addrFn     func(n int) string
	no51       bool
	alternate  bool
	blind      bool
	extraACK   []DHCPMsg
	tableExtra map[string][]sourceadapter.Lease
}

func newC5dRig(t *testing.T) *c5dRig {
	c := cSetup(t, ShapeMacvlan)
	r := &c5dRig{cRig: c, p: newFakePair(c.src), server: map[string]string{}, created: map[string]time.Time{},
		tableExtra: map[string][]sourceadapter.Lease{}}
	c.e.Source = r.p
	prefix := containerName(c.e, NameC5d) + "-"
	c.h.addrFn = func(name, _ string) string {
		n := c.h.n
		r.created[name] = time.Now()
		switch {
		case r.p.down["primary"]:
			r.server[name] = r.p.ids["partner"]
		case r.alternate && n%2 == 0:
			r.server[name] = r.p.ids["partner"]
		default:
			r.server[name] = r.p.ids["primary"]
		}
		if r.addrFn != nil {
			return r.addrFn(n)
		}
		return fmt.Sprintf("10.200.1.%d", 100+n)
	}
	all := func() []sourceadapter.Lease {
		var out []sourceadapter.Lease
		for i := 1; i <= 18; i++ {
			if ct, _, ok := c.h.container(fmt.Sprintf("%s%02d", prefix, i)); ok {
				out = append(out, sourceadapter.Lease{MAC: ct.mac, Address: ct.addr, Expires: time.Now().Add(time.Hour)})
			}
		}
		return out
	}
	c.src.fn = func(int) []sourceadapter.Lease { return append(all(), r.tableExtra["union"]...) }
	r.p.peerFn = func(n string) []sourceadapter.Lease { return append(all(), r.tableExtra[n]...) }
	c.cap.fn = func(string) []DHCPMsg {
		var out []DHCPMsg
		for i := 1; i <= 18; i++ {
			name := fmt.Sprintf("%s%02d", prefix, i)
			ct, _, ok := c.h.container(name)
			if !ok || (r.blind && i == 7) {
				continue
			}
			lease := c5Lease
			if r.no51 {
				lease = 0
			}
			m := ack(r.created[name], "b", ct.addr, r.server[name], lease)
			m.CHAddr = ct.mac
			out = append(out, m)
		}
		for _, m := range r.extraACK {
			if m.At.IsZero() {
				m.At = time.Now()
			}
			out = append(out, m)
		}
		return seen(out)
	}
	return r
}

func TestRunC5dPassesWithEighteenDistinctAddresses(t *testing.T) {
	r := newC5dRig(t)
	v := runC5dTuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, r.e, v)
	needReason(t, v, "18 distinct addresses")
	needOps(t, r.p, "stop primary", "start primary", "start primary")
	parts := 0
	for _, s := range r.server {
		if s == r.p.ids["partner"] {
			parts++
		}
	}
	if len(r.server) != 18 || parts != 4 {
		t.Errorf("%d containers ACKed, %d by the partner; want 18 and 4", len(r.server), parts)
	}
	prefix := containerName(r.e, NameC5d)
	for i := 1; i <= 18; i++ {
		needCleanup(t, r.h.bRunner, "", fmt.Sprintf("%s-%02d", prefix, i))
	}
}

func TestRunC5dJudges(t *testing.T) {
	t0 := time.Now()
	for _, tc := range []struct {
		name   string
		set    func(*c5dRig)
		result Result
		reason string
	}{
		{"two containers carry one address", func(r *c5dRig) {
			r.addrFn = func(n int) string {
				if n == 12 {
					return "10.200.1.103"
				}
				return fmt.Sprintf("10.200.1.%d", 100+n)
			}
		}, FAIL, "both carry 10.200.1.103"},
		{"a peer table holds an address twice", func(r *c5dRig) {
			r.tableExtra["partner"] = []sourceadapter.Lease{{MAC: "aa:bb:cc:99:00:01", Address: "10.200.1.105", Expires: t0.Add(time.Hour)}}
		}, FAIL, "partner-leases holds 10.200.1.105"},
		{"the union holds an address twice", func(r *c5dRig) {
			r.tableExtra["union"] = []sourceadapter.Lease{{MAC: "aa:bb:cc:99:00:01", Address: "10.200.1.105", Expires: t0.Add(time.Hour)}}
		}, FAIL, "union-leases holds 10.200.1.105"},
		{"an expired second holder is no double", func(r *c5dRig) {
			r.tableExtra["union"] = []sourceadapter.Lease{{MAC: "aa:bb:cc:99:00:01", Address: "10.200.1.105", Expires: t0.Add(-time.Second)}}
		}, PASS, "18 distinct"},
		{"the capture ACKs one address to two clients", func(r *c5dRig) {
			m := ack(time.Time{}, "z", "10.200.1.101", r.p.ids["partner"], time.Hour)
			m.CHAddr = "aa:bb:cc:99:00:02"
			r.extraACK = []DHCPMsg{m}
		}, FAIL, "overlapping leases"},
		{"a container loses its address", func(r *c5dRig) {
			r.h.setAddrs(containerName(r.e, NameC5d)+"-03", "10.200.1.250")
		}, FAIL, "does not carry its address 10.200.1.103"},
		{"an ACK without option 51", func(r *c5dRig) { r.no51 = true }, BLOCKED, "carries no option 51"},
		{"the observer missed a container", func(r *c5dRig) { r.blind = true }, BLOCKED, "holds no ACK of 10.200.1.107"},
		{"the partner never takes over", func(r *c5dRig) {
			r.p.stateFn = func(string) (sourceadapter.HAState, error) { return sourceadapter.HAState{State: "hot-standby"}, nil }
		}, BLOCKED, "did not take over"},
		{"a load-balanced pair answered from one peer", func(r *c5dRig) { r.p.prof.StandbySilent = false }, BLOCKED, "split was not exercised"},
		{"a load-balanced pair answered from both", func(r *c5dRig) { r.p.prof.StandbySilent, r.alternate = false, true }, PASS, "18 distinct"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newC5dRig(t)
			tc.set(r)
			v := runC5dTuned(context.Background(), r.e, cFast)
			needResult(t, v, tc.result)
			needReason(t, v, tc.reason)
			needWritten(t, r.e, v)
			if r.p.down["primary"] {
				t.Error("the primary was left stopped")
			}
		})
	}
}

func TestOverlappingACKsJudgesTheLeaseWindows(t *testing.T) {
	t0 := time.Unix(1000, 0)
	a := DHCPMsg{At: t0, YIAddr: "10.0.0.5", CHAddr: "m1", LeaseTime: time.Minute}
	for name, tc := range map[string]struct {
		b    DHCPMsg
		want bool
	}{
		"same client again":           {DHCPMsg{At: t0.Add(time.Second), YIAddr: "10.0.0.5", CHAddr: "m1", LeaseTime: time.Minute}, false},
		"other client inside":         {DHCPMsg{At: t0.Add(59 * time.Second), YIAddr: "10.0.0.5", CHAddr: "m2", LeaseTime: time.Minute}, true},
		"other client at the expiry":  {DHCPMsg{At: t0.Add(time.Minute), YIAddr: "10.0.0.5", CHAddr: "m2", LeaseTime: time.Minute}, false},
		"other client, other address": {DHCPMsg{At: t0.Add(time.Second), YIAddr: "10.0.0.6", CHAddr: "m2", LeaseTime: time.Minute}, false},
		"client id differs, same mac": {DHCPMsg{At: t0.Add(time.Second), YIAddr: "10.0.0.5", CHAddr: "m1", ClientID: "c2", LeaseTime: time.Minute}, true},
	} {
		if got := overlappingACKs([]DHCPMsg{a, tc.b}) != ""; got != tc.want {
			t.Errorf("%s: overlap %v, want %v", name, got, tc.want)
		}
	}
}

// ---- applicability and the HA samples ---------------------------------

func TestPairCellRunsC5AndLeavesC9C10AndC12NA(t *testing.T) {
	pair := sourceadapter.NewKeaPair(nil, nil, "10.200.8.2", "10.200.8.3")
	want := map[string]string{NameC9: "without the HA hook", NameC10: "split brain", NameC12: "docker-net-dhcp-lab#11"}
	for _, s := range Catalog {
		ok, reason := Applicable(s, pair)
		switch s.Name {
		case NameC5, NameC5b, NameC5c, NameC5d, NameC1, NameC2, NameC3, NameC4, NameC6, NameC6b, NameC7, NameC8:
			if !ok {
				t.Errorf("%s is N/A on the pair: %s", s.Name, reason)
			}
		case NameC9, NameC10, NameC12:
			if ok || !strings.Contains(reason, want[s.Name]) {
				t.Errorf("%s: applicable %v, reason %q, want N/A naming %q", s.Name, ok, reason, want[s.Name])
			}
		}
	}
}

func TestHASampleRecordsEachPeerUnjudged(t *testing.T) {
	c := cSetup(t, ShapeMacvlan)
	p := newFakePair(c.src)
	c.e.Source = p
	p.down["partner"] = true
	path := haSample(context.Background(), c.e, "probe", "ha-state-before")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, "primary state=partner-down clock=") || !strings.Contains(got, "skew=0s") || !strings.Contains(got, `partner error="connection refused"`) {
		t.Fatalf("sample %q", got)
	}
	if haSample(context.Background(), cSetup(t, ShapeMacvlan).e, "probe", "x") != "" {
		t.Error("a single source got a sample")
	}
	p.stateFn = func(n string) (sourceadapter.HAState, error) {
		if n == "primary" {
			return sourceadapter.HAState{State: "hot-standby", Clock: time.Now().Add(5 * time.Second)}, nil
		}
		return sourceadapter.HAState{State: "hot-standby"}, nil
	}
	b, err = os.ReadFile(haSample(context.Background(), c.e, "probe", "ha-state-after"))
	if err != nil {
		t.Fatal(err)
	}
	got = string(b)
	if !strings.Contains(got, "primary state=hot-standby clock=") || !strings.Contains(got, "skew=5s") || !strings.Contains(got, "partner state=hot-standby clock=unknown\n") {
		t.Fatalf("sample %q", got)
	}
}

func TestRunOneAddsHASamplesToEveryPassAndFail(t *testing.T) {
	shortReadyWait(t)
	c := cSetup(t, ShapeMacvlan)
	p := newFakePair(c.src)
	c.e.Source = p
	c.e.Host = &fakeRunOneHostRunner{installed: true, pgrepOK: true}
	for _, tc := range []struct {
		v    Verdict
		want bool
	}{
		{Verdict{Result: PASS, Evidence: map[string]string{}}, true},
		{Verdict{Result: FAIL, Evidence: map[string]string{}}, true},
		{Verdict{Result: FAIL}, true},
		{Verdict{Result: BLOCKED}, false},
		{Verdict{Result: BLOCKED, Evidence: map[string]string{}}, false},
	} {
		s := Scenario{Name: "probe", Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: func(context.Context, Env) Verdict { return tc.v }}
		v := RunOne(context.Background(), s, c.e)
		_, b := v.Evidence["ha-state-before"]
		_, a := v.Evidence["ha-state-after"]
		if b != tc.want || a != tc.want {
			t.Errorf("%s: before %v after %v, want %v", tc.v.Result, b, a, tc.want)
		}
	}
	v := withHASamples(Verdict{Result: PASS, Evidence: map[string]string{}}, "", "after.txt")
	if _, ok := v.Evidence["ha-state-before"]; ok || v.Evidence["ha-state-after"] != "after.txt" {
		t.Errorf("a missing sample was recorded: %v", v.Evidence)
	}
}

// TestLabyamlPinsTheGroupBBand: lab.yaml's peer-address rule keeps the
// peers off the addresses group B hands out (#12).
func TestLabyamlPinsTheGroupBBand(t *testing.T) {
	if labyaml.GroupBBandFirstHost != reserveBaseHost || labyaml.GroupBBandLastHost != classPoolLastHost || labyaml.DNSOptionHost != dnsOptionHost {
		t.Fatalf("labyaml band %d-%d, %d; scenario band %d-%d, %d", labyaml.GroupBBandFirstHost, labyaml.GroupBBandLastHost,
			labyaml.DNSOptionHost, reserveBaseHost, classPoolLastHost, dnsOptionHost)
	}
}
