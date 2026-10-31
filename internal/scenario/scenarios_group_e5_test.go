package scenario

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// e5Host scripts the docker host for the E5 runner: the plugin's pid,
// the boot id and each container's StartedAt, which onWindow may move.
type e5Host struct {
	*bRunner
	pids, boots []string
	pidN, bootN int
	started     map[string]string
}

func next(vals []string, n *int) string {
	v := vals[min(*n, len(vals)-1)]
	*n++
	return v
}

func (h *e5Host) Run(ctx context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "pgrep -x net-dhcp"):
		h.cmds = append(h.cmds, cmd)
		return next(h.pids, &h.pidN), nil
	case strings.Contains(cmd, "boot_id"):
		h.cmds = append(h.cmds, cmd)
		return next(h.boots, &h.bootN), nil
	case strings.Contains(cmd, ".State.StartedAt"):
		h.cmds = append(h.cmds, cmd)
		name := strings.Fields(cmd)[len(strings.Fields(cmd))-1]
		if h.containers[name] == nil {
			return "", errors.New("no such container " + name)
		}
		if s, ok := h.started[name]; ok {
			return s, nil
		}
		return "2026-10-31T10:00:00Z", nil
	}
	return h.bRunner.Run(ctx, cmd)
}

// e5Src serves the journal (pre, then pre plus one renewing run per
// container once the window passed) and a table holding every container.
type e5Src struct {
	*fakeAdapter
	h          *e5Host
	pre        []sourceadapter.ServerEvent
	done       bool
	extra      []sourceadapter.ServerEvent
	mutatePre  func([]sourceadapter.ServerEvent) []sourceadapter.ServerEvent
	eventsErr  error
	leasesGone bool
	leaseAsked int
}

func (s *e5Src) ShortenLeaseTime(ctx context.Context, n int) (func(context.Context) error, error) {
	s.leaseAsked = n
	return s.fakeAdapter.ShortenLeaseTime(ctx, n)
}

func (s *e5Src) ServerEvents(context.Context, time.Time, string) ([]sourceadapter.ServerEvent, error) {
	if s.eventsErr != nil {
		return nil, s.eventsErr
	}
	pre := append([]sourceadapter.ServerEvent(nil), s.pre...)
	if !s.done {
		return pre, nil
	}
	if s.mutatePre != nil {
		pre = s.mutatePre(pre)
	}
	for _, c := range s.h.fleet() {
		srv, _ := e5Run(c.mac, c.addr, 20, 180, 40*time.Second)
		pre = append(pre, srv...)
	}
	return append(pre, s.extra...), nil
}

func (s *e5Src) Leases(context.Context) ([]sourceadapter.Lease, error) {
	if s.leasesGone && s.done {
		return nil, nil
	}
	var out []sourceadapter.Lease
	for _, c := range s.h.fleet() {
		cid, _ := ipvlanClientID(c.endpointID)
		out = append(out, sourceadapter.Lease{MAC: c.mac, Address: c.addr, ClientID: cid, Expires: time.Now().Add(time.Hour)})
	}
	return out, nil
}

func (h *e5Host) fleet() []*bIdent {
	var out []*bIdent
	for i := 1; i <= e5Fleet; i++ {
		for name, c := range h.containers {
			if strings.HasSuffix(name, NameE5+"-"+string(rune('0'+i))) {
				out = append(out, c)
			}
		}
	}
	return out
}

type e5Rig struct {
	h        *e5Host
	src      *e5Src
	e        Env
	t        e5Tune
	slept    []time.Duration
	onWindow func()
}

func e5Setup(t *testing.T, shape Shape) *e5Rig {
	t.Helper()
	h := &e5Host{bRunner: newBRunner(), pids: []string{"4242"}, boots: []string{"boot-1"}, started: map[string]string{}}
	if shape == ShapeIpvlan {
		h.forceMAC = "02:42:0a:c8:01:02"
	}
	fa := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapServerEvents}}
	src := &e5Src{fakeAdapter: fa, h: h, pre: []sourceadapter.ServerEvent{
		e5Srv("ACK", "aa:bb:cc:00:00:01", "10.200.1.101", -500),
		e5Srv("ACK", "02:ff:ff:ff:ff:ff", "10.200.1.190", -400),
	}}
	r := &e5Rig{h: h, src: src}
	e := bEnv(t, h, src, shape)
	e.Capture = &cCapture{fn: func(ident string) []DHCPMsg {
		for _, c := range h.fleet() {
			if id, _ := cIdent(shape, c.mac, c.endpointID); strings.EqualFold(id, ident) {
				_, w := e5Run(c.mac, c.addr, 20, 180, 40*time.Second)
				for i := range w {
					w[i].CHAddr = c.mac
				}
				return w
			}
		}
		return nil
	}}
	r.e = e
	clock := eT0
	r.t = e5Tune{
		now: func() time.Time { return clock },
		sleep: func(_ context.Context, d time.Duration) error {
			r.slept = append(r.slept, d)
			clock = clock.Add(d)
			if len(r.slept) == 1 {
				// the window's end checks take time on a real host
				clock = clock.Add(2 * time.Second)
				src.done = true
				if r.onWindow != nil {
					r.onWindow()
				}
			}
			return nil
		},
	}
	return r
}

// removedAfterRun: runContainer's own pre-clean `docker rm -f` comes
// before the run, so only a removal after the last run counts.
func removedAfterRun(cmds []string, name string) bool {
	ran, rm := -1, -1
	for i, c := range cmds {
		switch {
		case strings.Contains(c, "docker run") && strings.Contains(c, name):
			ran = i
		case strings.Contains(c, "docker rm -f "+name):
			rm = i
		}
	}
	return ran >= 0 && rm > ran
}

func (r *e5Rig) run() Verdict { return runE5Tuned(context.Background(), r.e, r.t) }

func TestRunE5PassesOnEveryShape(t *testing.T) {
	for _, shape := range Shapes {
		t.Run(string(shape), func(t *testing.T) {
			r := e5Setup(t, shape)
			v := r.run()
			needResult(t, v, PASS)
			for _, want := range []string{"accelerated soak (40s lease, 3m0s window)", "kept 10.200.1.101: 9 renewals", "kept 10.200.1.102: 9 renewals"} {
				if !strings.Contains(v.Reason, want) {
					t.Errorf("reason %q lacks %q", v.Reason, want)
				}
			}
			if !r.src.shortened || !r.src.restored || r.src.leaseAsked != 40 {
				t.Errorf("lease shortened=%v restored=%v asked=%d", r.src.shortened, r.src.restored, r.src.leaseAsked)
			}
			for i := 1; i <= e5Fleet; i++ {
				name := containerName(r.e, NameE5) + "-" + string(rune('0'+i))
				if !removedAfterRun(r.h.cmds, name) {
					t.Errorf("%s was not removed after it ran: %v", name, r.h.cmds)
				}
			}
			for _, label := range []string{"server-events", "capture-1", "capture-2", "leases-start-1", "leases-end-2"} {
				if p := v.Evidence[label]; p == "" {
					t.Errorf("no %s evidence", label)
				} else if _, err := os.Stat(p); err != nil {
					t.Errorf("%s evidence unreadable: %v", label, err)
				}
			}
		})
	}
}

// Row 11 and 12: the window and lease set on Env reach the source, the
// wait and the verdict.
func TestRunE5UsesTheSoakParameters(t *testing.T) {
	r := e5Setup(t, ShapeBridge)
	r.e.Soak = SoakParams{Window: 10 * time.Minute, Lease: 60}
	v := r.run()
	if r.src.leaseAsked != 60 || len(r.slept) == 0 || r.slept[0] != 10*time.Minute {
		t.Errorf("lease asked %d, slept %v; want 60 and 10m first", r.src.leaseAsked, r.slept)
	}
	for i := 1; i <= e5Fleet; i++ {
		run := "docker run -d --name " + containerName(r.e, NameE5) + "-" + string(rune('0'+i)) + " "
		if !r.h.has(run) || !r.h.has("alpine:3.20 sleep 1200") {
			t.Errorf("container %d does not outlive the 10m window plus the slack: %v", i, r.h.cmds)
		}
	}
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "accelerated soak (60s lease, 10m0s window)") || !strings.Contains(v.Reason, "9 renewals in 10m2s with a 40s lease, RFC 2131 section 4.4.5 needs at least 15") {
		t.Errorf("reason %q does not judge the 10m window", v.Reason)
	}
	r = e5Setup(t, ShapeBridge)
	r.e.Soak = SoakParams{Window: 30 * time.Second}
	v = r.run()
	needResult(t, v, BLOCKED)
	if len(r.h.cmds) != 0 || r.src.shortened {
		t.Errorf("an invalid window touched the cell: %v", r.h.cmds)
	}
}

// Row 4: the plugin restarting under the fleet fails; a host reboot or a
// restarted container is the host's, BLOCKED.
func TestRunE5HostEvents(t *testing.T) {
	r := e5Setup(t, ShapeBridge)
	r.h.pids = []string{"4242", "5151"}
	v := r.run()
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "pid 4242, then 5151") {
		t.Errorf("reason %q", v.Reason)
	}

	r = e5Setup(t, ShapeMacvlan)
	r.h.boots = []string{"boot-1", "boot-2"}
	v = r.run()
	needResult(t, v, BLOCKED)
	if !strings.Contains(v.Reason, "rebooted inside the window") {
		t.Errorf("reason %q", v.Reason)
	}

	r = e5Setup(t, ShapeBridge)
	r.onWindow = func() { r.h.started[containerName(r.e, NameE5)+"-2"] = "2026-10-31T10:30:00Z" }
	v = r.run()
	needResult(t, v, BLOCKED)
	if !strings.Contains(v.Reason, "restarted inside the window") {
		t.Errorf("reason %q", v.Reason)
	}
}

// Row 5: a container re-attached under the same start time and address
// is a restart, not a PASS; and a plugin restart that comes with a
// container restart is BLOCKED (the engine restarted), never a FAIL.
func TestRunE5ReattachedAndEngineRestartBlock(t *testing.T) {
	r := e5Setup(t, ShapeBridge)
	r.onWindow = func() { r.h.containers[containerName(r.e, NameE5)+"-1"].endpointID = "reattached" }
	v := r.run()
	needResult(t, v, BLOCKED)
	if !strings.Contains(v.Reason, "restarted inside the window") {
		t.Errorf("reason %q", v.Reason)
	}

	r = e5Setup(t, ShapeBridge)
	r.h.pids = []string{"4242", "5151"}
	r.onWindow = func() { r.h.started[containerName(r.e, NameE5)+"-2"] = "2026-10-31T10:30:00Z" }
	v = r.run()
	needResult(t, v, BLOCKED)
	if !strings.Contains(v.Reason, "pid 4242, then 5151") {
		t.Errorf("reason %q", v.Reason)
	}
}

// Row 2 and 13: docker reporting another address, or the source's table
// losing the lease, fails.
func TestRunE5EndStateFails(t *testing.T) {
	r := e5Setup(t, ShapeBridge)
	r.onWindow = func() { r.h.containers[containerName(r.e, NameE5)+"-1"].addr = "10.200.1.150" }
	v := r.run()
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "docker reports 10.200.1.150") {
		t.Errorf("reason %q", v.Reason)
	}

	r = e5Setup(t, ShapeBridge)
	r.src.leasesGone = true
	v = r.run()
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "after the 3m0s window") {
		t.Errorf("reason %q", v.Reason)
	}
}

// Row 10: the fleet's baseline lines changing blocks; another client's
// changing does not.
func TestRunE5Baseline(t *testing.T) {
	r := e5Setup(t, ShapeBridge)
	r.src.mutatePre = func(p []sourceadapter.ServerEvent) []sourceadapter.ServerEvent { return p[1:] }
	v := r.run()
	needResult(t, v, BLOCKED)
	if !strings.Contains(v.Reason, "changed under the baseline (1 lines before)") {
		t.Errorf("reason %q", v.Reason)
	}

	r = e5Setup(t, ShapeBridge)
	r.src.mutatePre = func(p []sourceadapter.ServerEvent) []sourceadapter.ServerEvent { return p[:1] }
	needResult(t, r.run(), PASS)
}

// The live 1 h run's BLOCK: the source logged one more renewal between
// the capture read and the journal read.
func TestRunE5ToleratesARenewalAfterTheCapture(t *testing.T) {
	r := e5Setup(t, ShapeBridge)
	r.onWindow = func() {
		c := r.h.fleet()[0]
		r.src.extra = []sourceadapter.ServerEvent{e5Srv("ACK", c.mac, c.addr, 185)}
	}
	needResult(t, r.run(), PASS)
	if r.src.extra == nil {
		t.Fatal("the late renewal was never served")
	}
}

// Row 8 through the runner: a refusal in the window reaches the judge.
func TestRunE5RefusalFails(t *testing.T) {
	r := e5Setup(t, ShapeIpvlan)
	r.src.extra = []sourceadapter.ServerEvent{e5Srv("NAK", "02:42:0a:c8:01:02", "", 90)}
	v := r.run()
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "the source logged NAK for 02:42:0a:c8:01:02") {
		t.Errorf("reason %q", v.Reason)
	}
}

func TestRunE5BlocksWithoutWitnesses(t *testing.T) {
	r := e5Setup(t, ShapeBridge)
	r.e.Capture = nil
	needResult(t, r.run(), BLOCKED)
	r = e5Setup(t, ShapeBridge)
	r.src.eventsErr = errors.New("journal off")
	v := r.run()
	needResult(t, v, BLOCKED)
	if !r.src.restored {
		t.Error("the lease time was not restored")
	}
}
