package scenario

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group C (#23): the source fails, is slow, or comes back without its
// lease file. Every scenario that stops, impairs or reconfigures the
// source puts it back by defer; the Ready gate in runOneInner recovers
// whatever a crash left behind before the next scenario. A wire rule is
// judged on the live observer capture (Env.Capture), never on the
// plugin's own logs.

// cTiming holds every wait group C takes; the tests run it in
// milliseconds. Bounds that judge the plugin are constants below and
// are never tuned.
type cTiming struct {
	lease     int           // ShortenLeaseTime: T1 60 s, T2 105 s, expiry 120 s
	anchor    time.Duration // wait for the bind's ACK to show in the capture
	poll      time.Duration
	stopAfter time.Duration // C2, C3: stop this long after the bind
	c2Start   time.Duration // C2: start at bind + this (between T1 and T2)
	c2Settle  time.Duration // C2: the renewed expiry must show by bind + this
	c3Record  time.Duration // C3: record the container's address at bind + this
	c3Start   time.Duration // C3: start at bind + this (past expiry)
	c3Window  time.Duration // C3: a lease within this after Start
	c4Wait    time.Duration // C4: judge at bind + this
	c1Settle  time.Duration // C1: wait after Start before reading the table
	c10Lift   time.Duration // C10(b): lift the loss by this even without two DISCOVERs
	c6bWindow time.Duration // C6b: the conflict must be resolved within this of the squat
	c8Settle  time.Duration // C8: no lease for the failed client id within this of the restore
	c8Links   time.Duration // C8: the host's link count must be back within this
	c9Wait    time.Duration // C9: the renumbered lease must show by bind + this
	c5Wait    time.Duration // C5b-C5d: bound on a pair's state change (measured 4.8-6.2 s, lab #12)
	c12bWait  time.Duration // C12b: judge at bind + this, past T1 (60 s) and before T2 (105 s), lab #11
}

var cDefault = cTiming{
	lease: 120, anchor: 10 * time.Second, poll: 5 * time.Second,
	stopAfter: 10 * time.Second, c2Start: 80 * time.Second, c2Settle: 150 * time.Second,
	c3Record: 140 * time.Second, c3Start: 150 * time.Second, c3Window: 120 * time.Second,
	c4Wait: 135 * time.Second, c1Settle: 40 * time.Second, c10Lift: 20 * time.Second,
	c6bWindow: 30 * time.Second, c8Settle: 40 * time.Second, c8Links: 10 * time.Second, c9Wait: 200 * time.Second,
	c5Wait: 60 * time.Second, c12bWait: 75 * time.Second,
}

// The plugin's documented client timing (docs/reference.md): DISCOVER
// retransmits at 4, 8, 16, 32 s with ±1 s jitter; lease_timeout fails a
// create at about 34 s by default; validate_dhcp waits 8 s. C1 bounds, pinned from the kea run of
// plugin v2.5.0 (#23): c1b 15.26-15.46 s, c1 31.13-31.29 s on all three
// shapes. c1b ends on the plugin's own 12 s timeout. c1 ends on the
// engine's ~30 s plugin-request timeout, before the documented 34 s, so
// its min is measured less 3 s and its max is 34 s plus 3 s. cGapSlack
// adds timer and capture latency to the jitter.
const (
	cJitter      = time.Second
	cGapSlack    = 250 * time.Millisecond
	cGap1        = 4 * time.Second
	cGap2        = 8 * time.Second
	c1bWallMin   = 12 * time.Second
	c1bWallMax   = 18500 * time.Millisecond
	c1WallMin    = 28 * time.Second
	c1WallMax    = 37 * time.Second
	c10Delay     = 2 * time.Second
	c10MinWall   = 4 * time.Second
	c11RefuseMax = 12 * time.Second
)

func within(d, want, tol time.Duration) bool { return d >= want-tol && d <= want+tol }

// runNeverReached backs C5 and F6, F7: no adapter declares their
// capability, so Applicable answers N/A before Run (capabilityNAReason).
func runNeverReached(_ context.Context, e Env) Verdict {
	return blocked("unreachable", e.Cell, e.Shape, "a scenario whose capability no adapter declares reached Run", e.GitSHA)
}

func writeEvidence(path, body string) error { return os.WriteFile(path, []byte(body), 0o644) }

// discoverGaps returns the gaps between the first n DISCOVERs in msgs.
func discoverGaps(msgs []DHCPMsg, n int) []time.Duration {
	d := messagesOfType(msgs, "DISCOVER")
	var gaps []time.Duration
	for i := 1; i < len(d) && i < n; i++ {
		gaps = append(gaps, d[i].At.Sub(d[i-1].At))
	}
	return gaps
}

func runC1(ctx context.Context, e Env) Verdict { return runC1Tuned(ctx, e, cDefault) }

// runC1Tuned -- source down at create: with the source stopped, a
// container on -c1b (lease_timeout=12s) and then one on -c1 (default)
// must both fail inside the plugin's documented bounds, retransmitting
// on schedule, and leave no endpoint and no lease behind.
func runC1Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	if v, ok := bIPAMNA(NameC1, e); ok {
		return v
	}
	type run struct {
		suffix, net, id, wire, container string
		opts                             []string
		min, max                         time.Duration
		gaps                             int
		res                              timedResult
		from                             time.Time
	}
	runs := []*run{
		{suffix: "c1b", opts: []string{"lease_timeout=12s"}, min: c1bWallMin, max: c1bWallMax, gaps: 1},
		{suffix: "c1", min: c1WallMin, max: c1WallMax, gaps: 2},
	}
	for _, r := range runs {
		r.id = "lab-" + r.suffix + "-" + string(e.Shape)
		r.wire = b2WireClientID(r.id)
		r.container = containerName(e, NameC1) + "-" + r.suffix
		net, down, err := cNetwork(ctx, e, r.suffix, append([]string{"client_id=" + r.id}, r.opts...))
		defer down()
		if err != nil {
			return fail(NameC1, e.Cell, e.Shape, fmt.Sprintf("could not create the %s network with the source up: %v", r.suffix, err), nil, e.GitSHA)
		}
		r.net = net
		defer removeContainer(bCleanupCtx(ctx), e.Host, r.container)
	}
	// A failed Stop may have stopped it anyway: Start runs on every
	// path that called Stop, as in cOutage.
	started := false
	defer func() {
		if !started {
			_ = e.Source.Start(bCleanupCtx(ctx))
		}
	}()
	if err := e.Source.Stop(ctx); err != nil {
		return blocked(NameC1, e.Cell, e.Shape, fmt.Sprintf("could not stop the source: %v", err), e.GitSHA)
	}
	for _, r := range runs {
		r.from = time.Now()
		res, err := timedDockerRun(ctx, e.Host, r.net, r.container)
		if err != nil {
			return blocked(NameC1, e.Cell, e.Shape, fmt.Sprintf("docker run on %s: %v", r.net, err), e.GitSHA)
		}
		r.res = res
	}
	if err := e.Source.Start(ctx); err != nil {
		return blocked(NameC1, e.Cell, e.Shape, fmt.Sprintf("could not start the source again: %v", err), e.GitSHA)
	}
	started = true
	if err := sleepCtx(ctx, t.c1Settle); err != nil {
		return blocked(NameC1, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}

	ev := map[string]string{}
	var runLog strings.Builder
	var fails []string
	snap := evidencePath(e, NameC1, "leases-after-start")
	leases, err := writeLeaseSnapshot(ctx, e.Source, snap)
	if err != nil {
		return blocked(NameC1, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
	}
	ev["leases-after-start"] = snap
	for _, r := range runs {
		fmt.Fprintf(&runLog, "%s on %s: exit %d after %s\n%s\n", r.container, r.net, r.res.RC, r.res.Wall, r.res.Out)
		if r.res.RC == 0 {
			fails = append(fails, fmt.Sprintf("%s started with the source down", r.suffix))
		} else if r.res.Wall < r.min || r.res.Wall > r.max {
			fails = append(fails, fmt.Sprintf("%s failed after %s, outside %s-%s", r.suffix, r.res.Wall.Round(100*time.Millisecond), r.min, r.max))
		}
		msgs, err := readCapture(ctx, e, NameC1, "capture-"+r.suffix, r.wire, ev)
		if err != nil {
			return blocked(NameC1, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
		}
		// The client id is this scenario's alone, so every message for
		// it after the run started is this run's.
		down := messagesAfter(msgs, r.from)
		gaps := discoverGaps(down, r.gaps+1)
		want := []time.Duration{cGap1, cGap2}[:r.gaps]
		if n := len(messagesOfType(down, "DISCOVER")); n < len(want)+1 {
			fails = append(fails, fmt.Sprintf("%s: the capture shows %d DISCOVER(s) from %s while the source was down, want at least %d", r.suffix, n, r.wire, len(want)+1))
		} else {
			for i, w := range want {
				if !within(gaps[i], w, cJitter+cGapSlack) {
					fails = append(fails, fmt.Sprintf("%s: DISCOVER gap %d was %s, want %s ±%s", r.suffix, i+1, gaps[i].Round(100*time.Millisecond), w, cJitter+cGapSlack))
				}
			}
		}
		if l := active(leasesForIdent(leases, r.wire), time.Now()); len(l) > 0 {
			fails = append(fails, fmt.Sprintf("%s: %s after Start the source holds a lease on %s for %s, an acquisition outlived the failed endpoint", r.suffix, t.c1Settle, l[0].Address, r.wire))
		}
		n, err := endpointCount(ctx, e.Host, r.net)
		if err != nil {
			return blocked(NameC1, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
		if n != 0 {
			fails = append(fails, fmt.Sprintf("%s still lists %d endpoint(s)", r.suffix, n))
		}
	}
	runsPath := evidencePath(e, NameC1, "runs")
	if err := writeEvidence(runsPath, runLog.String()); err != nil {
		return blocked(NameC1, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	ev["runs"] = runsPath
	if len(fails) > 0 {
		return fail(NameC1, e.Cell, e.Shape, strings.Join(fails, "; "), ev, e.GitSHA)
	}
	return pass(NameC1, e.Cell, e.Shape, fmt.Sprintf("with the source down %s failed after %s and %s after %s, DISCOVERs on schedule, no endpoint and no lease left %s after Start",
		runs[0].suffix, runs[0].res.Wall.Round(100*time.Millisecond), runs[1].suffix, runs[1].res.Wall.Round(100*time.Millisecond), t.c1Settle), ev, e.GitSHA)
}

// cStartBound is the common start of C2, C3 and C4: a short lease, a
// container on the cell's main network, its lease in the table, and the
// bind time from the capture. A non-nil Verdict ends the scenario.
type cBound struct {
	name, mac, addr, endpointID, ident string
	bindAt                             time.Time
	bindMsg                            DHCPMsg
	before                             sourceadapter.Lease
	ev                                 map[string]string
}

func cStartBound(ctx context.Context, e Env, scenario string, t cTiming) (cBound, func(), *Verdict) {
	var b cBound
	restore, err := e.Source.ShortenLeaseTime(ctx, t.lease)
	if err != nil {
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("could not shorten the lease to %d s: %v", t.lease, err), e.GitSHA)
		return b, func() {}, &v
	}
	b.name = containerName(e, scenario)
	cleanup := func() {
		removeContainer(bCleanupCtx(ctx), e.Host, b.name)
		_ = restore(bCleanupCtx(ctx))
	}
	b.mac, b.addr, b.endpointID, err = runContainer(ctx, e.Host, e.Shape, e.Network, b.name)
	if err != nil {
		v := fail(scenario, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
		return b, cleanup, &v
	}
	if b.ident, err = cIdent(e.Shape, b.mac, b.endpointID); err != nil {
		v := fail(scenario, e.Cell, e.Shape, err.Error(), nil, e.GitSHA)
		return b, cleanup, &v
	}
	b.ev = map[string]string{}
	if b.bindMsg, err = bindACK(ctx, e, scenario, b.ident, b.addr, t.anchor, t.poll, b.ev); err != nil {
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("no bind time: %v", err), e.GitSHA)
		return b, cleanup, &v
	}
	b.bindAt = b.bindMsg.At
	snap := evidencePath(e, scenario, "leases-before")
	l, _, ok, err := lookupLease(ctx, e.Source, e.Shape, b.mac, b.addr, b.endpointID, snap)
	if err != nil {
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
		return b, cleanup, &v
	}
	b.ev["leases-before"] = snap
	if !ok {
		v := fail(scenario, e.Cell, e.Shape, "after the first lease: "+leaseFailReason(e.Shape, b.mac, b.addr, b.endpointID), b.ev, e.GitSHA)
		return b, cleanup, &v
	}
	b.before = l
	return b, cleanup, nil
}

// sawClientUnicast reports whether msgs hold a client-sent message to a
// unicast IP (a renewing REQUEST, RELEASE or INFORM): its Ethernet
// destination is the server's MAC, so it reaches the observer only on a
// flooding bridge (build-bridge.sh hub mode). A server reply to a unicast
// IP proves nothing: the plugin's broadcast flag sends it to ff:ff:ff:ff:
// ff:ff (the v2.5.0 kea capture holds such ACKs without their REQUESTs).
func sawClientUnicast(msgs []DHCPMsg) bool {
	for _, m := range msgs {
		switch m.Type {
		case "REQUEST", "RELEASE", "INFORM":
			if m.Dst != "" && m.Dst != "255.255.255.255" {
				return true
			}
		}
	}
	return false
}

func runC2(ctx context.Context, e Env) Verdict { return runC2Tuned(ctx, e, cDefault) }

// runC2Tuned -- the source is down from bind + 10 s to bind + 80 s,
// across T1: the client must try to renew while it is down, then keep
// its address once the source answers again.
func runC2Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	b, cleanup, v := cStartBound(ctx, e, NameC2, t)
	defer cleanup()
	if v != nil {
		return *v
	}
	stopAt, startAt, v := cOutage(ctx, e, NameC2, b.bindAt.Add(t.stopAfter), b.bindAt.Add(t.c2Start))
	if v != nil {
		return *v
	}
	snap := evidencePath(e, NameC2, "leases-after")
	deadline := b.bindAt.Add(t.c2Settle)
	var after sourceadapter.Lease
	for {
		l, _, ok, err := lookupLease(ctx, e.Source, e.Shape, b.mac, b.addr, b.endpointID, snap)
		if err != nil {
			return blocked(NameC2, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
		}
		if ok && l.Expires.After(b.before.Expires) {
			after = l
			break
		}
		if time.Now().After(deadline) {
			b.ev["leases-after"] = snap
			return fail(NameC2, e.Cell, e.Shape, fmt.Sprintf("by bind + %s the source's table shows no renewed lease of %s for %s (expiry was %s)", t.c2Settle, b.addr, b.ident, b.before.Expires.UTC().Format(time.RFC3339)), b.ev, e.GitSHA)
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return blocked(NameC2, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
	}
	b.ev["leases-after"] = snap
	msgs, err := readCapture(ctx, e, NameC2, "capture", b.ident, b.ev)
	if err != nil {
		return blocked(NameC2, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	inOutage := messagesBetween(msgs, stopAt, startAt)
	for _, m := range inOutage {
		if m.Type == "ACK" || m.Type == "NAK" {
			return blocked(NameC2, e.Cell, e.Shape, fmt.Sprintf("the capture shows a %s to %s at %s, inside the outage: the source was not down", m.Type, b.ident, m.At.UTC().Format("15:04:05.000")), e.GitSHA)
		}
	}
	if len(messagesOfType(inOutage, "REQUEST")) == 0 {
		all, err := readCapture(ctx, e, NameC2, "capture-all", "*", b.ev)
		if err != nil {
			return blocked(NameC2, e.Cell, e.Shape, fmt.Sprintf("could not read the whole capture: %v", err), e.GitSHA)
		}
		if !sawClientUnicast(all) {
			return blocked(NameC2, e.Cell, e.Shape, "the capture holds no REQUEST from "+b.ident+" inside the outage and no client-sent unicast frame from any client: the observer cannot see a unicast renewal, so its absence is not judged", e.GitSHA)
		}
		return fail(NameC2, e.Cell, e.Shape, fmt.Sprintf("the capture shows no REQUEST from %s while the source was down (%s-%s): no renewal was attempted", b.ident, stopAt.UTC().Format("15:04:05"), startAt.UTC().Format("15:04:05")), b.ev, e.GitSHA)
	}
	own, err := containerAddrs(ctx, e.Host, b.name)
	if err != nil {
		return fail(NameC2, e.Cell, e.Shape, err.Error(), b.ev, e.GitSHA)
	}
	if !containsAddr(own, b.addr) {
		return fail(NameC2, e.Cell, e.Shape, fmt.Sprintf("the container no longer carries %s after the outage (it carries %v)", b.addr, own), b.ev, e.GitSHA)
	}
	secs, err := reachableWithRetry(ctx, e.Source, b.addr)
	if err != nil {
		return fail(NameC2, e.Cell, e.Shape, fmt.Sprintf("%s kept and renewed but not reachable after %ds: %v", b.addr, secs, err), b.ev, e.GitSHA)
	}
	return pass(NameC2, e.Cell, e.Shape, fmt.Sprintf("%s tried to renew while the source was down, kept %s, the table's expiry moved from %s to %s, reachable after %ds",
		b.ident, b.addr, b.before.Expires.UTC().Format("15:04:05"), after.Expires.UTC().Format("15:04:05"), secs), b.ev, e.GitSHA)
}

// cOutage stops the source at stopAt and starts it at startAt, and
// returns the lab clock's times of both. The source is started again by
// defer if the scenario ends early.
func cOutage(ctx context.Context, e Env, scenario string, stopAt, startAt time.Time, during ...func() *Verdict) (time.Time, time.Time, *Verdict) {
	if err := sleepUntil(ctx, stopAt); err != nil {
		v := blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
		return time.Time{}, time.Time{}, &v
	}
	if err := e.Source.Stop(ctx); err != nil {
		_ = e.Source.Start(bCleanupCtx(ctx))
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("could not stop the source: %v", err), e.GitSHA)
		return time.Time{}, time.Time{}, &v
	}
	stopped := time.Now()
	for _, f := range during {
		if v := f(); v != nil {
			_ = e.Source.Start(bCleanupCtx(ctx))
			return time.Time{}, time.Time{}, v
		}
	}
	if err := sleepUntil(ctx, startAt); err != nil {
		_ = e.Source.Start(bCleanupCtx(ctx))
		v := blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
		return time.Time{}, time.Time{}, &v
	}
	started := time.Now()
	if err := e.Source.Start(ctx); err != nil {
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("could not start the source again: %v", err), e.GitSHA)
		return time.Time{}, time.Time{}, &v
	}
	return stopped, started, nil
}

func runC3(ctx context.Context, e Env) Verdict { return runC3Tuned(ctx, e, cDefault) }

// runC3Tuned -- the source is down from bind + 10 s to bind + 150 s,
// past expiry: within 120 s of Start the container must hold an address
// the source's table shows for its identity, and be reachable. Same or
// new address is recorded, not judged.
func runC3Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	b, cleanup, v := cStartBound(ctx, e, NameC3, t)
	defer cleanup()
	if v != nil {
		return *v
	}
	recordPath := evidencePath(e, NameC3, "addr-past-expiry")
	record := func() *Verdict {
		if err := sleepUntil(ctx, b.bindAt.Add(t.c3Record)); err != nil {
			v := blocked(NameC3, e.Cell, e.Shape, err.Error(), e.GitSHA)
			return &v
		}
		own, err := containerAddrs(ctx, e.Host, b.name)
		body := fmt.Sprintf("bind + %s, source down: container carries %v\n", t.c3Record, own)
		if err != nil {
			body = fmt.Sprintf("bind + %s, source down: %v\n", t.c3Record, err)
		}
		if err := writeEvidence(recordPath, body); err != nil {
			v := blocked(NameC3, e.Cell, e.Shape, err.Error(), e.GitSHA)
			return &v
		}
		b.ev["addr-past-expiry"] = recordPath
		return nil
	}
	_, startAt, v := cOutage(ctx, e, NameC3, b.bindAt.Add(t.stopAfter), b.bindAt.Add(t.c3Start), record)
	if v != nil {
		return *v
	}
	snap := evidencePath(e, NameC3, "leases-after")
	deadline := startAt.Add(t.c3Window)
	var last string
	for {
		leases, err := writeLeaseSnapshot(ctx, e.Source, snap)
		if err != nil {
			return blocked(NameC3, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
		}
		b.ev["leases-after"] = snap
		own, err := containerAddrs(ctx, e.Host, b.name)
		if err != nil {
			return fail(NameC3, e.Cell, e.Shape, err.Error(), b.ev, e.GitSHA)
		}
		for _, l := range active(leasesForIdent(leases, b.ident), time.Now()) {
			if !containsAddr(own, l.Address) {
				continue
			}
			secs, err := reachableWithRetry(ctx, e.Source, l.Address)
			if err != nil {
				return fail(NameC3, e.Cell, e.Shape, fmt.Sprintf("%s holds %s again but it is not reachable after %ds: %v", b.ident, l.Address, secs, err), b.ev, e.GitSHA)
			}
			kept := "kept " + b.addr
			if l.Address != b.addr {
				kept = fmt.Sprintf("moved from %s to %s", b.addr, l.Address)
			}
			return pass(NameC3, e.Cell, e.Shape, fmt.Sprintf("after the source was down past expiry, %s %s within %s of Start, in the table and in the container, reachable after %ds",
				b.ident, kept, time.Since(startAt).Round(time.Second), secs), b.ev, e.GitSHA)
		}
		last = fmt.Sprintf("the container carries %v, the table's active leases for %s are %v", own, b.ident, addrsOf(active(leasesForIdent(leases, b.ident), time.Now())))
		if time.Now().After(deadline) {
			return fail(NameC3, e.Cell, e.Shape, fmt.Sprintf("%s after Start no active lease for %s matches the container's own address: %s", t.c3Window, b.ident, last), b.ev, e.GitSHA)
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return blocked(NameC3, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
	}
}

func addrsOf(leases []sourceadapter.Lease) []string {
	var out []string
	for _, l := range leases {
		out = append(out, l.Address)
	}
	return out
}

func runC4(ctx context.Context, e Env) Verdict { return runC4Tuned(ctx, e, cDefault) }

// runC4Tuned -- the source restarts with an empty lease file: by bind +
// 135 s (past T1 and expiry) the source must hold exactly one lease for
// the identity, on the address the container carries, and no other
// identity on that address.
func runC4Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	b, cleanup, v := cStartBound(ctx, e, NameC4, t)
	defer cleanup()
	if v != nil {
		return *v
	}
	if err := e.Source.ResetLeases(ctx); err != nil {
		return blocked(NameC4, e.Cell, e.Shape, fmt.Sprintf("could not reset the source's lease file: %v", err), e.GitSHA)
	}
	resetSnap := evidencePath(e, NameC4, "leases-after-reset")
	leases, err := writeLeaseSnapshot(ctx, e.Source, resetSnap)
	if err != nil {
		return blocked(NameC4, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table after the reset: %v", err), e.GitSHA)
	}
	if len(leases) != 0 {
		return blocked(NameC4, e.Cell, e.Shape, fmt.Sprintf("the source still lists %d lease(s) after the reset, %v: the lease file was not cleared", len(leases), addrsOf(leases)), e.GitSHA)
	}
	b.ev["leases-after-reset"] = resetSnap
	if err := sleepUntil(ctx, b.bindAt.Add(t.c4Wait)); err != nil {
		return blocked(NameC4, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	snap := evidencePath(e, NameC4, "leases-after")
	if leases, err = writeLeaseSnapshot(ctx, e.Source, snap); err != nil {
		return blocked(NameC4, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
	}
	b.ev["leases-after"] = snap
	if _, err := readCapture(ctx, e, NameC4, "capture", b.ident, b.ev); err != nil {
		return blocked(NameC4, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	now := time.Now()
	mine := active(leasesForIdent(leases, b.ident), now)
	if len(mine) != 1 {
		return fail(NameC4, e.Cell, e.Shape, fmt.Sprintf("bind + %s after a lease file reset the source holds %d active lease(s) for %s, want exactly one: %v", t.c4Wait, len(mine), b.ident, addrsOf(mine)), b.ev, e.GitSHA)
	}
	own, err := containerAddrs(ctx, e.Host, b.name)
	if err != nil {
		return fail(NameC4, e.Cell, e.Shape, err.Error(), b.ev, e.GitSHA)
	}
	if !containsAddr(own, mine[0].Address) {
		return fail(NameC4, e.Cell, e.Shape, fmt.Sprintf("the source leases %s to %s, the container carries %v", mine[0].Address, b.ident, own), b.ev, e.GitSHA)
	}
	for _, l := range active(leases, now) {
		if l.Address == mine[0].Address && !strings.EqualFold(l.MAC, b.ident) && !strings.EqualFold(l.ClientID, b.ident) {
			return fail(NameC4, e.Cell, e.Shape, fmt.Sprintf("%s is also leased to another identity (mac %s, client id %s)", l.Address, l.MAC, l.ClientID), b.ev, e.GitSHA)
		}
	}
	secs, err := reachableWithRetry(ctx, e.Source, mine[0].Address)
	if err != nil {
		return fail(NameC4, e.Cell, e.Shape, fmt.Sprintf("%s leased again but not reachable after %ds: %v", mine[0].Address, secs, err), b.ev, e.GitSHA)
	}
	return pass(NameC4, e.Cell, e.Shape, fmt.Sprintf("after a lease file reset the source holds one lease for %s on %s (was %s), which the container carries, reachable after %ds",
		b.ident, mine[0].Address, b.addr, secs), b.ev, e.GitSHA)
}

func runC10(ctx context.Context, e Env) Verdict { return runC10Tuned(ctx, e, cDefault) }

// runC10Tuned -- (a) every reply from the source 2 s late: the
// container still gets its lease; (b) every reply lost until the client
// has retransmitted twice: it keeps retransmitting on schedule and is
// leased once the loss lifts. Reachability is checked after each
// restore, since ping cannot pass under the delay.
func runC10Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	ev := map[string]string{}
	if v := c10UnderDelay(ctx, e, ev); v != nil {
		return *v
	}
	return c10UnderLoss(ctx, e, t, ev)
}

func c10UnderDelay(ctx context.Context, e Env, ev map[string]string) *Verdict {
	verdict := func(v Verdict) *Verdict { return &v }
	restore, err := e.Source.Impair(ctx, c10Delay, 0)
	if err != nil {
		return verdict(blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not delay the source's replies: %v", err), e.GitSHA))
	}
	restored := false
	defer func() {
		if !restored {
			_ = restore(bCleanupCtx(ctx))
		}
	}()
	name := containerName(e, NameC10) + "-a"
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	res, err := timedDockerRun(ctx, e.Host, e.Network, name)
	if err != nil {
		return verdict(blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("docker run: %v", err), e.GitSHA))
	}
	if res.RC != 0 {
		return verdict(fail(NameC10, e.Cell, e.Shape, fmt.Sprintf("(a) with a %s reply delay the container did not start (exit %d after %s): %s", c10Delay, res.RC, res.Wall.Round(100*time.Millisecond), strings.TrimSpace(res.Out)), nil, e.GitSHA))
	}
	mac, addr, endpointID, err := inspectContainer(ctx, e.Host, e.Shape, name)
	if err != nil {
		return verdict(fail(NameC10, e.Cell, e.Shape, "(a) "+err.Error(), nil, e.GitSHA))
	}
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return verdict(fail(NameC10, e.Cell, e.Shape, "(a) "+err.Error(), nil, e.GitSHA))
	}
	snap := evidencePath(e, NameC10, "leases-delay")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
	if err != nil {
		return verdict(blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA))
	}
	ev["leases-delay"] = snap
	if !ok {
		return verdict(fail(NameC10, e.Cell, e.Shape, "(a) "+leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA))
	}
	own, err := containerAddrs(ctx, e.Host, name)
	if err != nil || !containsAddr(own, addr) {
		return verdict(fail(NameC10, e.Cell, e.Shape, fmt.Sprintf("(a) the container does not carry its leased %s (carries %v, %v)", addr, own, err), ev, e.GitSHA))
	}
	msgs, err := readCapture(ctx, e, NameC10, "capture-delay", ident, ev)
	if err != nil {
		return verdict(blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA))
	}
	// A reply that is not late, or a run faster than two late replies,
	// means the delay never acted: the lab's fault, not the plugin's.
	if res.Wall < c10MinWall {
		return verdict(blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("(a) leased after %s, under the %s two delayed replies take: the delay did not act", res.Wall.Round(100*time.Millisecond), c10MinWall), e.GitSHA))
	}
	if gap, ok := offerDelay(msgs); !ok || gap < c10Delay {
		return verdict(blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("(a) the capture shows no OFFER %s or more after its DISCOVER (found %v): the delay did not act", c10Delay, gap), e.GitSHA))
	}
	if err := restore(ctx); err != nil {
		return verdict(blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not lift the delay: %v", err), e.GitSHA))
	}
	restored = true
	if secs, err := reachableWithRetry(ctx, e.Source, addr); err != nil {
		return verdict(fail(NameC10, e.Cell, e.Shape, fmt.Sprintf("(a) %s not reachable after %ds once the delay was lifted: %v", addr, secs, err), ev, e.GitSHA))
	}
	ev["note-delay"] = writeNote(e, NameC10, "note-delay", fmt.Sprintf("(a) %s leased %s after %s under a %s reply delay\n", ident, addr, res.Wall.Round(100*time.Millisecond), c10Delay))
	return nil
}

// offerDelay is the time from the last DISCOVER before the first OFFER
// to that OFFER, matched by xid.
func offerDelay(msgs []DHCPMsg) (time.Duration, bool) {
	sent := map[string]time.Time{}
	for _, m := range msgs {
		switch m.Type {
		case "DISCOVER":
			sent[m.XID] = m.At
		case "OFFER":
			if at, ok := sent[m.XID]; ok {
				return m.At.Sub(at), true
			}
		}
	}
	return 0, false
}

func writeNote(e Env, scenario, label, body string) string {
	p := evidencePath(e, scenario, label)
	_ = writeEvidence(p, body)
	return p
}

func c10UnderLoss(ctx context.Context, e Env, t cTiming, ev map[string]string) Verdict {
	restore, err := e.Source.Impair(ctx, 0, 100)
	if err != nil {
		return blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not drop the source's replies: %v", err), e.GitSHA)
	}
	restored := false
	lift := func() error {
		if restored {
			return nil
		}
		restored = true
		return restore(bCleanupCtx(ctx))
	}
	defer func() { _ = lift() }()
	name := containerName(e, NameC10) + "-b"
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)

	from := time.Now()
	type ran struct {
		res timedResult
		err error
	}
	done := make(chan ran, 1)
	go func() {
		res, err := timedDockerRun(ctx, e.Host, e.Network, name)
		done <- ran{res, err}
	}()
	// Lift once one new identity has sent two DISCOVERs into the loss
	// (defeat A6): a fixed 6 s would lift before the second on a slow
	// attach. The run's own identity is not known until it returns.
	liftedAfter, err := c10WaitTwoDiscovers(ctx, e, t, from, ev)
	if err != nil {
		_ = lift()
		<-done
		return blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not watch the capture under loss: %v", err), e.GitSHA)
	}
	if err := lift(); err != nil {
		<-done
		return blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not lift the loss: %v", err), e.GitSHA)
	}
	r := <-done
	if r.err != nil {
		return blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("docker run: %v", r.err), e.GitSHA)
	}
	if r.res.RC != 0 {
		return fail(NameC10, e.Cell, e.Shape, fmt.Sprintf("(b) the container did not start once the loss lifted %s in (exit %d after %s): %s", liftedAfter.Round(100*time.Millisecond), r.res.RC, r.res.Wall.Round(100*time.Millisecond), strings.TrimSpace(r.res.Out)), ev, e.GitSHA)
	}
	mac, addr, endpointID, err := inspectContainer(ctx, e.Host, e.Shape, name)
	if err != nil {
		return fail(NameC10, e.Cell, e.Shape, "(b) "+err.Error(), ev, e.GitSHA)
	}
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return fail(NameC10, e.Cell, e.Shape, "(b) "+err.Error(), ev, e.GitSHA)
	}
	snap := evidencePath(e, NameC10, "leases-loss")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
	if err != nil {
		return blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
	}
	ev["leases-loss"] = snap
	if !ok {
		return fail(NameC10, e.Cell, e.Shape, "(b) "+leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
	}
	msgs, err := readCapture(ctx, e, NameC10, "capture-loss", ident, ev)
	if err != nil {
		return blocked(NameC10, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	var before []DHCPMsg
	for _, m := range messagesAfter(msgs, from) {
		if m.Type == "OFFER" {
			break
		}
		before = append(before, m)
	}
	disc := messagesOfType(before, "DISCOVER")
	if len(disc) < 3 {
		return fail(NameC10, e.Cell, e.Shape, fmt.Sprintf("(b) the capture shows %d DISCOVER(s) from %s before the first OFFER, want at least 3", len(disc), ident), ev, e.GitSHA)
	}
	gaps := discoverGaps(before, 3)
	for i, w := range []time.Duration{cGap1, cGap2} {
		if !within(gaps[i], w, cJitter+cGapSlack) {
			return fail(NameC10, e.Cell, e.Shape, fmt.Sprintf("(b) DISCOVER gap %d was %s, want %s ±%s", i+1, gaps[i].Round(100*time.Millisecond), w, cJitter+cGapSlack), ev, e.GitSHA)
		}
	}
	secs, err := reachableWithRetry(ctx, e.Source, addr)
	if err != nil {
		return fail(NameC10, e.Cell, e.Shape, fmt.Sprintf("(b) %s not reachable after %ds: %v", addr, secs, err), ev, e.GitSHA)
	}
	return pass(NameC10, e.Cell, e.Shape, fmt.Sprintf("leased under a %s reply delay; under total loss %s retransmitted %d DISCOVERs (gaps %s, %s) and was leased %s once the loss lifted, reachable after %ds",
		c10Delay, ident, len(disc), gaps[0].Round(100*time.Millisecond), gaps[1].Round(100*time.Millisecond), addr, secs), ev, e.GitSHA)
}

// c10WaitTwoDiscovers polls the whole capture from `from` until one
// chaddr/client id has sent two DISCOVERs, or t.c10Lift passes; either
// way the caller lifts the loss.
func c10WaitTwoDiscovers(ctx context.Context, e Env, t cTiming, from time.Time, ev map[string]string) (time.Duration, error) {
	deadline := from.Add(t.c10Lift)
	for {
		msgs, err := readCapture(ctx, e, NameC10, "capture-under-loss", "*", ev)
		if err != nil {
			return 0, err
		}
		seen := map[string]int{}
		for _, m := range messagesOfType(messagesAfter(msgs, from), "DISCOVER") {
			k := m.CHAddr + "/" + m.ClientID
			if seen[k]++; seen[k] >= 2 {
				return time.Since(from), nil
			}
		}
		if time.Now().After(deadline) {
			return time.Since(from), nil
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return 0, err
		}
	}
}

func runC11(ctx context.Context, e Env) Verdict { return runC11Tuned(ctx, e, cDefault) }

// runC11Tuned -- validate_dhcp=true: with the source up the create
// succeeds and its probe leaves exactly one lease, on a locally
// administered MAC no container has; with the source down the create
// is refused within the probe's 8 s plus 4 s and leaves no network.
// N/A on bridge: the plugin refuses validate_dhcp there.
func runC11Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	if v, ok := bIPAMNA(NameC11, e); ok {
		return v
	}
	if e.Shape == ShapeBridge {
		return na(NameC11, e.Cell, e.Shape, "plugin docs/reference.md, validate_dhcp: \"Bridge mode rejects the option.\"", e.GitSHA)
	}
	ev := map[string]string{}
	beforeSnap := evidencePath(e, NameC11, "leases-before")
	before, err := writeLeaseSnapshot(ctx, e.Source, beforeSnap)
	if err != nil {
		return blocked(NameC11, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
	}
	ev["leases-before"] = beforeSnap
	net, res, down, err := timedNetworkCreate(ctx, e, "c11", []string{"validate_dhcp=true"})
	defer down()
	if err != nil {
		return blocked(NameC11, e.Cell, e.Shape, fmt.Sprintf("network create: %v", err), e.GitSHA)
	}
	if res.RC != 0 {
		return fail(NameC11, e.Cell, e.Shape, fmt.Sprintf("%s with validate_dhcp=true was refused with the source up (exit %d after %s): %s", net, res.RC, res.Wall.Round(100*time.Millisecond), strings.TrimSpace(res.Out)), ev, e.GitSHA)
	}
	afterSnap := evidencePath(e, NameC11, "leases-after-create")
	var probe []sourceadapter.Lease
	deadline := time.Now().Add(t.anchor)
	for {
		after, err := writeLeaseSnapshot(ctx, e.Source, afterSnap)
		if err != nil {
			return blocked(NameC11, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
		}
		if probe = newLeases(before, after); len(probe) > 0 || time.Now().After(deadline) {
			break
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return blocked(NameC11, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
	}
	ev["leases-after-create"] = afterSnap
	if len(probe) != 1 {
		return fail(NameC11, e.Cell, e.Shape, fmt.Sprintf("the validate_dhcp probe left %d new lease(s) in the source's table, want exactly one: %v", len(probe), addrsOf(probe)), ev, e.GitSHA)
	}
	if !locallyAdministered(probe[0].MAC) {
		return fail(NameC11, e.Cell, e.Shape, fmt.Sprintf("the probe's lease on %s has MAC %q, not a locally administered one", probe[0].Address, probe[0].MAC), ev, e.GitSHA)
	}
	macs, err := allContainerMACs(ctx, e.Host)
	if err != nil {
		return blocked(NameC11, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if macs[strings.ToLower(probe[0].MAC)] {
		return fail(NameC11, e.Cell, e.Shape, fmt.Sprintf("the probe's lease MAC %s belongs to a container", probe[0].MAC), ev, e.GitSHA)
	}

	defer func() { _ = e.Source.Start(bCleanupCtx(ctx)) }()
	if err := e.Source.Stop(ctx); err != nil {
		return blocked(NameC11, e.Cell, e.Shape, fmt.Sprintf("could not stop the source: %v", err), e.GitSHA)
	}
	netB, resB, downB, err := timedNetworkCreate(ctx, e, "c11b", []string{"validate_dhcp=true"})
	defer downB()
	if err != nil {
		return blocked(NameC11, e.Cell, e.Shape, fmt.Sprintf("network create: %v", err), e.GitSHA)
	}
	runsPath := writeNote(e, NameC11, "creates", fmt.Sprintf("%s (source up): exit %d after %s\n%s\n%s (source down): exit %d after %s\n%s\n",
		net, res.RC, res.Wall, res.Out, netB, resB.RC, resB.Wall, resB.Out))
	ev["creates"] = runsPath
	if resB.RC == 0 {
		return fail(NameC11, e.Cell, e.Shape, fmt.Sprintf("%s with validate_dhcp=true was created with the source down", netB), ev, e.GitSHA)
	}
	if resB.Wall > c11RefuseMax {
		return fail(NameC11, e.Cell, e.Shape, fmt.Sprintf("%s was refused after %s, over the %s the 8 s probe allows", netB, resB.Wall.Round(100*time.Millisecond), c11RefuseMax), ev, e.GitSHA)
	}
	if networkExists(ctx, e.Host, netB) {
		return fail(NameC11, e.Cell, e.Shape, fmt.Sprintf("%s was refused but docker still lists it", netB), ev, e.GitSHA)
	}
	return pass(NameC11, e.Cell, e.Shape, fmt.Sprintf("validate_dhcp: created with the source up, its probe left one lease on %s for locally administered %s; refused after %s with the source down, no network left",
		probe[0].Address, probe[0].MAC, resB.Wall.Round(100*time.Millisecond)), ev, e.GitSHA)
}

// newLeases are the rows in after whose MAC/client id/address triple
// is not in before.
func newLeases(before, after []sourceadapter.Lease) []sourceadapter.Lease {
	key := func(l sourceadapter.Lease) string {
		return strings.ToLower(l.MAC) + "|" + strings.ToLower(l.ClientID) + "|" + l.Address
	}
	had := map[string]bool{}
	for _, l := range before {
		had[key(l)] = true
	}
	var out []sourceadapter.Lease
	for _, l := range after {
		if !had[key(l)] {
			out = append(out, l)
		}
	}
	return out
}

// locallyAdministered: the 0x02 bit of the first octet (IEEE 802).
func locallyAdministered(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0
}

// allContainerMACs is every MAC docker reports for any container on the
// docker host, running or not.
func allContainerMACs(ctx context.Context, r sourceadapter.Runner) (map[string]bool, error) {
	out, err := r.Run(ctx, `sudo docker ps -aq | xargs -r sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}} {{end}}'`)
	if err != nil {
		return nil, fmt.Errorf("listing container MACs: %w", err)
	}
	macs := map[string]bool{}
	for _, m := range strings.Fields(out) {
		macs[strings.ToLower(m)] = true
	}
	return macs, nil
}
