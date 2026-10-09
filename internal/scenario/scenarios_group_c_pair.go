package scenario

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// The failover pair scenarios (lab #12): C5-C5d run on a pair cell
// only, reach one peer at a time through PairControl, and time T1 and
// T2 from the bound ACK's own option 51 (RFC 2131 4.4.5: 0.5 and 0.875).

func runC5(ctx context.Context, e Env) Verdict  { return runC5Tuned(ctx, e, cDefault) }
func runC5b(ctx context.Context, e Env) Verdict { return runC5bTuned(ctx, e, cDefault) }
func runC5c(ctx context.Context, e Env) Verdict { return runC5cTuned(ctx, e, cDefault) }
func runC5d(ctx context.Context, e Env) Verdict { return runC5dTuned(ctx, e, cDefault) }

// c5Pair is e.Source's per-peer control; a pair without one is BLOCKED.
func c5Pair(e Env, scenario string) (sourceadapter.PairControl, *Verdict) {
	pc, ok := e.Source.(sourceadapter.PairControl)
	if !ok || len(pc.PeerNames()) != 2 {
		v := blocked(scenario, e.Cell, e.Shape, "the source declares a failover pair but offers no control of its two peers", e.GitSHA)
		return nil, &v
	}
	return pc, nil
}

// peerTable is e.Source with Leases read from one peer only, so
// lookupLease and its snapshot work on a single peer's table.
type peerTable struct {
	sourceadapter.Adapter
	pc   sourceadapter.PairControl
	name string
}

func (p peerTable) Leases(ctx context.Context) ([]sourceadapter.Lease, error) {
	return p.pc.PeerLeases(ctx, p.name)
}

// peerByServerID names the peer whose server-id is id, and the other.
func peerByServerID(pc sourceadapter.PairControl, id string) (string, string, bool) {
	names := pc.PeerNames()
	for i, n := range names {
		if sid, err := pc.PeerServerID(n); err == nil && sid == id {
			return n, names[1-i], true
		}
	}
	return "", "", false
}

func serverID(pc sourceadapter.PairControl, name string) string {
	id, _ := pc.PeerServerID(name)
	return id
}

// waitPeerStates polls until every named peer reports want, within bound.
func waitPeerStates(ctx context.Context, pc sourceadapter.PairControl, want string, bound, poll time.Duration, names ...string) (time.Time, error) {
	deadline := time.Now().Add(bound)
	for {
		var last []string
		for _, n := range names {
			st, err := pc.PeerState(ctx, n)
			if err != nil {
				last = append(last, fmt.Sprintf("%s: %v", n, err))
			} else if st.State != want {
				last = append(last, fmt.Sprintf("%s: %s", n, st.State))
			}
		}
		if len(last) == 0 {
			return time.Now(), nil
		}
		if time.Now().After(deadline) {
			return time.Time{}, fmt.Errorf("not %s within %s (%s)", want, bound, strings.Join(last, "; "))
		}
		if err := sleepCtx(ctx, poll); err != nil {
			return time.Time{}, err
		}
	}
}

// c5Back starts a stopped peer and waits for the pair's normal state,
// best effort: a cleanup leaves the next scenario a whole pair.
func c5Back(ctx context.Context, pc sourceadapter.PairControl, name string, t cTiming) {
	if pc.StartPeer(ctx, name) == nil {
		_, _ = waitPeerStates(ctx, pc, pc.Profile().Normal, t.c5Wait, t.poll, pc.PeerNames()...)
	}
}

// c5Rebind finds a broadcast REQUEST for addr in [from, until) and the
// ACK of it from serverID before until.
func c5Rebind(msgs []DHCPMsg, addr, serverID string, from, until time.Time) (DHCPMsg, DHCPMsg, bool) {
	for _, r := range messagesOfType(msgs, "REQUEST") {
		if r.Dst != "255.255.255.255" || r.At.Before(from) || !r.At.Before(until) || (r.CIAddr != addr && r.Requested != addr) {
			continue
		}
		for _, a := range messagesOfType(msgs, "ACK") {
			if a.XID == r.XID && a.Server == serverID && a.YIAddr == addr && !a.At.Before(r.At) && a.At.Before(until) {
				return r, a, true
			}
		}
	}
	return DHCPMsg{}, DHCPMsg{}, false
}

// runC5Tuned -- the peer that granted the lease stops at bind + 10 s:
// the client's T1 renewal to it goes unanswered and its T2 rebind must
// be ACKed by the survivor before the lease expires.
func runC5Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	pc, v := c5Pair(e, NameC5)
	if v != nil {
		return *v
	}
	b, cleanup, v := cStartBound(ctx, e, NameC5, t)
	defer cleanup()
	if v != nil {
		return *v
	}
	lease := b.bindMsg.LeaseTime
	if lease <= 0 {
		return blocked(NameC5, e.Cell, e.Shape, "the bound ACK carries no option 51: T1 and T2 cannot be timed", e.GitSHA)
	}
	dead, survivor, ok := peerByServerID(pc, b.bindMsg.Server)
	if !ok {
		return blocked(NameC5, e.Cell, e.Shape, fmt.Sprintf("the bound ACK's server-id %q is neither peer's: the granting peer is unknown", b.bindMsg.Server), e.GitSHA)
	}
	deadID, survivorID := b.bindMsg.Server, serverID(pc, survivor)
	t1, t2, expiry := b.bindAt.Add(lease/2), b.bindAt.Add(lease*7/8), b.bindAt.Add(lease)
	if err := sleepUntil(ctx, b.bindAt.Add(t.stopAfter)); err != nil {
		return blocked(NameC5, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	defer c5Back(bCleanupCtx(ctx), pc, dead, t)
	if err := pc.StopPeer(ctx, dead); err != nil {
		return blocked(NameC5, e.Cell, e.Shape, fmt.Sprintf("could not stop the granting peer %s: %v", dead, err), e.GitSHA)
	}
	stopAt := time.Now()
	snap := evidencePath(e, NameC5, "survivor-leases")
	view := peerTable{Adapter: e.Source, pc: pc, name: survivor}
	var after sourceadapter.Lease
	polls := 0
	for {
		own, err := containerAddrs(ctx, e.Host, b.name)
		if err != nil {
			return fail(NameC5, e.Cell, e.Shape, err.Error(), b.ev, e.GitSHA)
		}
		polls++
		if !containsAddr(own, b.addr) {
			return fail(NameC5, e.Cell, e.Shape, fmt.Sprintf("at bind + %s the container no longer carries %s (it carries %v)", time.Since(b.bindAt).Round(time.Second), b.addr, own), b.ev, e.GitSHA)
		}
		if !time.Now().Before(t2) {
			l, _, ok, err := lookupLease(ctx, view, e.Shape, b.mac, b.addr, b.endpointID, snap)
			if err != nil {
				return blocked(NameC5, e.Cell, e.Shape, fmt.Sprintf("could not read the survivor's table: %v", err), e.GitSHA)
			}
			if ok && l.Expires.After(b.before.Expires) {
				after = l
				break
			}
		}
		if time.Now().After(expiry) {
			b.ev["survivor-leases"] = snap
			return fail(NameC5, e.Cell, e.Shape, fmt.Sprintf("by the lease's expiry (bind + %s) the survivor %s's table shows no renewed lease of %s for %s", lease, survivor, b.addr, b.ident), b.ev, e.GitSHA)
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return blocked(NameC5, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
	}
	b.ev["survivor-leases"] = snap
	msgs, err := readCapture(ctx, e, NameC5, "capture", b.ident, b.ev)
	if err != nil {
		return blocked(NameC5, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	for _, m := range messagesOfType(messagesAfter(msgs, stopAt), "ACK") {
		if m.Server == deadID {
			return blocked(NameC5, e.Cell, e.Shape, fmt.Sprintf("the capture shows an ACK from the stopped peer %s at %s: the stop did not land", deadID, m.At.UTC().Format("15:04:05.000")), e.GitSHA)
		}
	}
	renewals := 0
	for _, m := range messagesOfType(messagesBetween(msgs, t1.Add(-cJitter), t2), "REQUEST") {
		if m.Dst == deadID {
			renewals++
		}
	}
	if renewals == 0 {
		all, err := readCapture(ctx, e, NameC5, "capture-all", "*", b.ev)
		if err != nil {
			return blocked(NameC5, e.Cell, e.Shape, fmt.Sprintf("could not read the whole capture: %v", err), e.GitSHA)
		}
		if !sawClientUnicast(all) {
			return blocked(NameC5, e.Cell, e.Shape, "the capture holds no REQUEST to "+deadID+" between T1 and T2 and no client-sent unicast frame from any client: the observer cannot see a unicast renewal, so its absence is not judged", e.GitSHA)
		}
		return fail(NameC5, e.Cell, e.Shape, fmt.Sprintf("no REQUEST from %s unicast to the granting server %s between T1 (%s) and T2 (%s) of the bound ACK's %s lease", b.ident, deadID, t1.UTC().Format("15:04:05"), t2.UTC().Format("15:04:05"), lease), b.ev, e.GitSHA)
	}
	req, ack, ok := c5Rebind(msgs, b.addr, survivorID, t2.Add(-cJitter), expiry)
	if !ok {
		return fail(NameC5, e.Cell, e.Shape, fmt.Sprintf("no broadcast REQUEST for %s after T2 (%s) ACKed by the survivor %s before the expiry (%s)", b.addr, t2.UTC().Format("15:04:05"), survivorID, expiry.UTC().Format("15:04:05")), b.ev, e.GitSHA)
	}
	secs, err := reachableWithRetry(ctx, e.Source, b.addr)
	if err != nil {
		return fail(NameC5, e.Cell, e.Shape, fmt.Sprintf("%s rebound to the survivor but not reachable after %ds: %v", b.addr, secs, err), b.ev, e.GitSHA)
	}
	return pass(NameC5, e.Cell, e.Shape, fmt.Sprintf("%s bound by %s for %s; %d renewal(s) unicast to it after its stop went unanswered; the rebind at bind + %s (secs %d) was ACKed by %s with %s; the survivor's expiry moved from %s to %s; %s held at all %d polls; reachable after %ds",
		b.ident, deadID, lease, renewals, req.At.Sub(b.bindAt).Round(10*time.Millisecond), req.Secs, survivorID, ack.YIAddr,
		b.before.Expires.UTC().Format("15:04:05"), after.Expires.UTC().Format("15:04:05"), b.addr, polls, secs), b.ev, e.GitSHA)
}

// c5Outage is a container leased while the primary is stopped and the
// partner has taken over (C5b, kept by C5c).
type c5Outage struct {
	primary, partner, primaryID, partnerID string
	name, mac, addr, endpointID, ident     string
	ack                                    DHCPMsg
	wall                                   time.Duration
	ev                                     map[string]string
}

// c5StartOutage stops the primary, waits for the partner's survivor
// state and leases one new container. shorten sets C2's short lease
// first, on both peers. The cleanup removes the container, starts the
// primary and restores the lease time, in that order.
func c5StartOutage(ctx context.Context, e Env, scenario string, pc sourceadapter.PairControl, t cTiming, shorten bool) (c5Outage, func(), *Verdict) {
	names := pc.PeerNames()
	o := c5Outage{primary: names[0], partner: names[1], ev: map[string]string{}}
	o.primaryID, o.partnerID = serverID(pc, o.primary), serverID(pc, o.partner)
	restore := func(context.Context) error { return nil }
	if shorten {
		r, err := e.Source.ShortenLeaseTime(ctx, t.lease)
		if err != nil {
			v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("could not shorten the lease to %d s: %v", t.lease, err), e.GitSHA)
			return o, func() {}, &v
		}
		restore = r
	}
	o.name = containerName(e, scenario)
	cleanup := func() {
		removeContainer(bCleanupCtx(ctx), e.Host, o.name)
		c5Back(bCleanupCtx(ctx), pc, o.primary, t)
		_ = restore(bCleanupCtx(ctx))
	}
	if err := pc.StopPeer(ctx, o.primary); err != nil {
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("could not stop the primary %s: %v", o.primary, err), e.GitSHA)
		return o, cleanup, &v
	}
	survivor := pc.Profile().Survivor
	if _, err := waitPeerStates(ctx, pc, survivor, t.c5Wait, t.poll, o.partner); err != nil {
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("the partner did not take over: %v", err), e.GitSHA)
		return o, cleanup, &v
	}
	res, err := timedDockerRun(ctx, e.Host, e.Network, o.name)
	if err != nil {
		v := blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
		return o, cleanup, &v
	}
	o.wall = res.Wall
	if res.RC != 0 {
		v := fail(scenario, e.Cell, e.Shape, fmt.Sprintf("with the primary down and the partner %s, docker run exited %d after %s: %s", survivor, res.RC, o.wall.Round(10*time.Millisecond), strings.TrimSpace(res.Out)), nil, e.GitSHA)
		return o, cleanup, &v
	}
	if o.mac, o.addr, o.endpointID, err = inspectContainer(ctx, e.Host, e.Shape, o.name); err != nil {
		v := fail(scenario, e.Cell, e.Shape, fmt.Sprintf("with the primary down the container started but %v", err), nil, e.GitSHA)
		return o, cleanup, &v
	}
	if o.wall > c1WallMax {
		v := fail(scenario, e.Cell, e.Shape, fmt.Sprintf("with the primary down the lease took %s, over C1's %s bound", o.wall.Round(10*time.Millisecond), c1WallMax), nil, e.GitSHA)
		return o, cleanup, &v
	}
	if o.ident, err = cIdent(e.Shape, o.mac, o.endpointID); err != nil {
		v := fail(scenario, e.Cell, e.Shape, err.Error(), nil, e.GitSHA)
		return o, cleanup, &v
	}
	if o.ack, err = bindACK(ctx, e, scenario, o.ident, o.addr, t.anchor, t.poll, o.ev); err != nil {
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("no bind ACK: %v", err), e.GitSHA)
		return o, cleanup, &v
	}
	switch o.ack.Server {
	case o.partnerID:
	case o.primaryID:
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("the stopped primary %s ACKed %s: the stop did not land", o.primaryID, o.addr), e.GitSHA)
		return o, cleanup, &v
	default:
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("the ACK's server-id %q is neither peer's", o.ack.Server), e.GitSHA)
		return o, cleanup, &v
	}
	snap := evidencePath(e, scenario, "partner-leases")
	_, _, ok, err := lookupLease(ctx, peerTable{Adapter: e.Source, pc: pc, name: o.partner}, e.Shape, o.mac, o.addr, o.endpointID, snap)
	if err != nil {
		v := blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("could not read the partner's table: %v", err), e.GitSHA)
		return o, cleanup, &v
	}
	o.ev["partner-leases"] = snap
	if !ok {
		v := fail(scenario, e.Cell, e.Shape, "the partner ACKed but its table lacks the lease: "+leaseFailReason(e.Shape, o.mac, o.addr, o.endpointID), o.ev, e.GitSHA)
		return o, cleanup, &v
	}
	return o, cleanup, nil
}

// runC5bTuned -- the primary is down before the container starts: the
// partner must lease it within C1's bound.
func runC5bTuned(ctx context.Context, e Env, t cTiming) Verdict {
	pc, v := c5Pair(e, NameC5b)
	if v != nil {
		return *v
	}
	o, cleanup, v := c5StartOutage(ctx, e, NameC5b, pc, t, false)
	defer cleanup()
	if v != nil {
		return *v
	}
	return pass(NameC5b, e.Cell, e.Shape, fmt.Sprintf("with the primary stopped and the partner %s, %s was leased %s by %s in %s (secs %d), and the partner's table holds it",
		pc.Profile().Survivor, o.ident, o.addr, o.partnerID, o.wall.Round(10*time.Millisecond), o.ack.Secs), o.ev, e.GitSHA)
}

// runC5cTuned -- C5b's container is kept, the primary returns: its own
// table holds the outage lease, the container keeps its address through
// its next renew cycle, and a new container is leased.
func runC5cTuned(ctx context.Context, e Env, t cTiming) Verdict {
	pc, v := c5Pair(e, NameC5c)
	if v != nil {
		return *v
	}
	o, cleanup, v := c5StartOutage(ctx, e, NameC5c, pc, t, true)
	defer cleanup()
	if v != nil {
		return *v
	}
	prof := pc.Profile()
	if err := pc.StartPeer(ctx, o.primary); err != nil {
		return blocked(NameC5c, e.Cell, e.Shape, fmt.Sprintf("could not start the primary again: %v", err), e.GitSHA)
	}
	normalAt, err := waitPeerStates(ctx, pc, prof.Normal, t.c5Wait, t.poll, o.primary, o.partner)
	if err != nil {
		return blocked(NameC5c, e.Cell, e.Shape, fmt.Sprintf("the pair did not return: %v", err), e.GitSHA)
	}
	snap := evidencePath(e, NameC5c, "returning-leases")
	_, _, ok, err := lookupLease(ctx, peerTable{Adapter: e.Source, pc: pc, name: o.primary}, e.Shape, o.mac, o.addr, o.endpointID, snap)
	if err != nil {
		return blocked(NameC5c, e.Cell, e.Shape, fmt.Sprintf("could not read the returning primary's table: %v", err), e.GitSHA)
	}
	o.ev["returning-leases"] = snap
	if !ok {
		return fail(NameC5c, e.Cell, e.Shape, "the returning primary's table lacks the outage lease: "+leaseFailReason(e.Shape, o.mac, o.addr, o.endpointID), o.ev, e.GitSHA)
	}
	msgs, err := readCapture(ctx, e, NameC5c, "capture-normal", o.ident, o.ev)
	if err != nil {
		return blocked(NameC5c, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	last, ok := lastACKOf(messagesBetween(msgs, time.Time{}, normalAt), o.addr)
	if !ok || last.LeaseTime <= 0 {
		return blocked(NameC5c, e.Cell, e.Shape, "no ACK with option 51 before the pair returned: the renew cycle cannot be timed", e.GitSHA)
	}
	deadline := last.At.Add(last.LeaseTime)
	var renewed DHCPMsg
	for renewed.At.IsZero() {
		own, err := containerAddrs(ctx, e.Host, o.name)
		if err != nil {
			return fail(NameC5c, e.Cell, e.Shape, err.Error(), o.ev, e.GitSHA)
		}
		if !containsAddr(own, o.addr) {
			return fail(NameC5c, e.Cell, e.Shape, fmt.Sprintf("after the primary returned the container no longer carries %s (it carries %v)", o.addr, own), o.ev, e.GitSHA)
		}
		msgs, err = readCapture(ctx, e, NameC5c, "capture", o.ident, o.ev)
		if err != nil {
			return blocked(NameC5c, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
		}
		for _, m := range messagesOfType(messagesAfter(msgs, normalAt), "ACK") {
			switch {
			case m.YIAddr != o.addr:
			case m.Server == o.primaryID:
				renewed = m
			case m.Server == o.partnerID && prof.StandbySilent:
				return blocked(NameC5c, e.Cell, e.Shape, fmt.Sprintf("the standby %s ACKed at %s while the primary runs: the source broke the premise, the rebind path was not exercised", o.partnerID, m.At.UTC().Format("15:04:05.000")), e.GitSHA)
			}
		}
		if !renewed.At.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			return fail(NameC5c, e.Cell, e.Shape, fmt.Sprintf("no ACK of %s from the returned primary %s by the lease's expiry (%s)", o.addr, o.primaryID, deadline.UTC().Format("15:04:05")), o.ev, e.GitSHA)
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return blocked(NameC5c, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
	}
	for _, m := range messagesOfType(messagesBetween(msgs, normalAt, renewed.At), "REQUEST") {
		if m.Dst == o.primaryID {
			return fail(NameC5c, e.Cell, e.Shape, fmt.Sprintf("%s renewed with a REQUEST unicast to the returned primary %s at %s, not to %s, the server that granted the lease", o.ident, o.primaryID, m.At.UTC().Format("15:04:05.000"), o.partnerID), o.ev, e.GitSHA)
		}
	}
	renewals := 0
	if prof.StandbySilent {
		req, ack, ok := c5Rebind(msgs, o.addr, o.primaryID, normalAt, deadline)
		if !ok {
			return fail(NameC5c, e.Cell, e.Shape, fmt.Sprintf("the returned primary's ACK of %s at %s answers no broadcast REQUEST: the rebind after the standby's silence was not seen", o.addr, renewed.At.UTC().Format("15:04:05.000")), o.ev, e.GitSHA)
		}
		for _, m := range messagesOfType(messagesBetween(msgs, normalAt, req.At), "REQUEST") {
			if m.Dst == o.partnerID {
				renewals++
			}
		}
		if renewals == 0 {
			all, err := readCapture(ctx, e, NameC5c, "capture-all", "*", o.ev)
			if err != nil {
				return blocked(NameC5c, e.Cell, e.Shape, fmt.Sprintf("could not read the whole capture: %v", err), e.GitSHA)
			}
			if !sawClientUnicast(all) {
				return blocked(NameC5c, e.Cell, e.Shape, "the capture holds no REQUEST to the standby "+o.partnerID+" before the rebind and no client-sent unicast frame from any client: the observer cannot see a unicast renewal, so its absence is not judged", e.GitSHA)
			}
			return fail(NameC5c, e.Cell, e.Shape, fmt.Sprintf("no REQUEST from %s unicast to the granting standby %s between the pair's return and the rebind at %s", o.ident, o.partnerID, req.At.UTC().Format("15:04:05.000")), o.ev, e.GitSHA)
		}
		renewed = ack
	}
	second := o.name + "-new"
	defer removeContainer(bCleanupCtx(ctx), e.Host, second)
	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, second)
	if err != nil {
		return fail(NameC5c, e.Cell, e.Shape, fmt.Sprintf("after the primary returned a new container did not start: %v", err), o.ev, e.GitSHA)
	}
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return fail(NameC5c, e.Cell, e.Shape, err.Error(), o.ev, e.GitSHA)
	}
	ack, err := bindACK(ctx, e, NameC5c, ident, addr, t.anchor, t.poll, o.ev)
	if err != nil {
		return blocked(NameC5c, e.Cell, e.Shape, fmt.Sprintf("no bind ACK for the new container: %v", err), e.GitSHA)
	}
	if prof.StandbySilent && ack.Server != o.primaryID {
		return fail(NameC5c, e.Cell, e.Shape, fmt.Sprintf("the new container was ACKed by %s, not the primary %s", ack.Server, o.primaryID), o.ev, e.GitSHA)
	}
	path := ""
	if prof.StandbySilent {
		path = fmt.Sprintf("%d renewal(s) unicast to the standby %s went unanswered; ", renewals, o.partnerID)
	}
	return pass(NameC5c, e.Cell, e.Shape, fmt.Sprintf("the returned primary's table holds %s for %s; %sthe container kept it and the primary ACKed it at %s (secs %d); a new container was leased %s by %s",
		o.addr, o.ident, path, renewed.At.UTC().Format("15:04:05"), renewed.Secs, addr, ack.Server), o.ev, e.GitSHA)
}

// c5dIdent is an ACK's client identity: option 61, else chaddr.
func c5dIdent(m DHCPMsg) string {
	if m.ClientID != "" {
		return m.ClientID
	}
	return m.CHAddr
}

// doubleActive names an address that two identities hold unexpired.
func doubleActive(leases []sourceadapter.Lease, now time.Time) string {
	held := map[string]map[string]bool{}
	for _, l := range leases {
		if !l.Expires.After(now) {
			continue
		}
		id := l.ClientID
		if id == "" {
			id = l.MAC
		}
		if held[l.Address] == nil {
			held[l.Address] = map[string]bool{}
		}
		held[l.Address][id] = true
	}
	var bad []string
	for a, ids := range held {
		if len(ids) > 1 {
			bad = append(bad, a)
		}
	}
	sort.Strings(bad)
	return strings.Join(bad, ", ")
}

// overlappingACKs names a yiaddr ACKed to two identities whose
// (ACK, ACK + option 51) windows overlap.
func overlappingACKs(acks []DHCPMsg) string {
	for i, a := range acks {
		for _, b := range acks[i+1:] {
			if a.YIAddr == "" || a.YIAddr != b.YIAddr || c5dIdent(a) == c5dIdent(b) {
				continue
			}
			if a.At.Before(b.At.Add(b.LeaseTime)) && b.At.Before(a.At.Add(a.LeaseTime)) {
				return fmt.Sprintf("%s to %s at %s and to %s at %s", a.YIAddr, c5dIdent(a), a.At.UTC().Format("15:04:05.000"), c5dIdent(b), b.At.UTC().Format("15:04:05.000"))
			}
		}
	}
	return ""
}

// runC5dTuned -- 10 containers with both peers up, 4 while the primary
// is down, 4 after it returns: no address may go to two identities.
func runC5dTuned(ctx context.Context, e Env, t cTiming) Verdict {
	pc, v := c5Pair(e, NameC5d)
	if v != nil {
		return *v
	}
	names, prof := pc.PeerNames(), pc.Profile()
	primary, partner := names[0], names[1]
	start := time.Now()
	type ct struct{ name, addr string }
	var cts []ct
	defer func() {
		for _, c := range cts {
			removeContainer(bCleanupCtx(ctx), e.Host, c.name)
		}
	}()
	ev := map[string]string{}
	create := func(n int) *Verdict {
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("%s-%02d", containerName(e, NameC5d), len(cts)+1)
			cts = append(cts, ct{name: name})
			_, addr, _, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
			if err != nil {
				v := fail(NameC5d, e.Cell, e.Shape, fmt.Sprintf("container %d of 18 did not start: %v", len(cts), err), nil, e.GitSHA)
				return &v
			}
			cts[len(cts)-1].addr = addr
		}
		return nil
	}
	if v := create(10); v != nil {
		return *v
	}
	defer c5Back(bCleanupCtx(ctx), pc, primary, t)
	if err := pc.StopPeer(ctx, primary); err != nil {
		return blocked(NameC5d, e.Cell, e.Shape, fmt.Sprintf("could not stop the primary %s: %v", primary, err), e.GitSHA)
	}
	if _, err := waitPeerStates(ctx, pc, prof.Survivor, t.c5Wait, t.poll, partner); err != nil {
		return blocked(NameC5d, e.Cell, e.Shape, fmt.Sprintf("the partner did not take over: %v", err), e.GitSHA)
	}
	if v := create(4); v != nil {
		return *v
	}
	if err := pc.StartPeer(ctx, primary); err != nil {
		return blocked(NameC5d, e.Cell, e.Shape, fmt.Sprintf("could not start the primary again: %v", err), e.GitSHA)
	}
	if _, err := waitPeerStates(ctx, pc, prof.Normal, t.c5Wait, t.poll, primary, partner); err != nil {
		return blocked(NameC5d, e.Cell, e.Shape, fmt.Sprintf("the pair did not return: %v", err), e.GitSHA)
	}
	if v := create(4); v != nil {
		return *v
	}
	seen := map[string]string{}
	for _, c := range cts {
		own, err := containerAddrs(ctx, e.Host, c.name)
		if err != nil {
			return fail(NameC5d, e.Cell, e.Shape, err.Error(), nil, e.GitSHA)
		}
		if !containsAddr(own, c.addr) {
			return fail(NameC5d, e.Cell, e.Shape, fmt.Sprintf("%s does not carry its address %s (it carries %v)", c.name, c.addr, own), nil, e.GitSHA)
		}
		if other, dup := seen[c.addr]; dup {
			return fail(NameC5d, e.Cell, e.Shape, fmt.Sprintf("%s and %s both carry %s", other, c.name, c.addr), nil, e.GitSHA)
		}
		seen[c.addr] = c.name
	}
	now := time.Now()
	tables := []struct {
		label string
		a     sourceadapter.Adapter
	}{{primary + "-leases", peerTable{Adapter: e.Source, pc: pc, name: primary}}, {partner + "-leases", peerTable{Adapter: e.Source, pc: pc, name: partner}}, {"union-leases", e.Source}}
	for _, tb := range tables {
		snap := evidencePath(e, NameC5d, tb.label)
		leases, err := writeLeaseSnapshot(ctx, tb.a, snap)
		if err != nil {
			return blocked(NameC5d, e.Cell, e.Shape, fmt.Sprintf("could not read %s: %v", tb.label, err), e.GitSHA)
		}
		ev[tb.label] = snap
		if bad := doubleActive(leases, now); bad != "" {
			return fail(NameC5d, e.Cell, e.Shape, fmt.Sprintf("%s holds %s for two identities at once", tb.label, bad), ev, e.GitSHA)
		}
	}
	msgs, err := readCapture(ctx, e, NameC5d, "capture-all", "*", ev)
	if err != nil {
		return blocked(NameC5d, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	acks := messagesOfType(messagesAfter(msgs, start), "ACK")
	for _, c := range cts {
		if _, ok := lastACKOf(acks, c.addr); !ok {
			return blocked(NameC5d, e.Cell, e.Shape, fmt.Sprintf("the capture holds no ACK of %s (%s): the observer missed it, so the wire cannot be judged", c.addr, c.name), e.GitSHA)
		}
	}
	for _, a := range acks {
		if a.LeaseTime <= 0 {
			return blocked(NameC5d, e.Cell, e.Shape, fmt.Sprintf("the ACK of %s at %s carries no option 51: its window cannot be judged", a.YIAddr, a.At.UTC().Format("15:04:05.000")), e.GitSHA)
		}
	}
	if bad := overlappingACKs(acks); bad != "" {
		return fail(NameC5d, e.Cell, e.Shape, "the capture shows one address ACKed to two identities with overlapping leases: "+bad, ev, e.GitSHA)
	}
	if !prof.StandbySilent {
		ids := map[string]bool{}
		for i, a := range acks {
			if i < 10 {
				ids[a.Server] = true
			}
		}
		if !ids[serverID(pc, primary)] || !ids[serverID(pc, partner)] {
			return blocked(NameC5d, e.Cell, e.Shape, "the first 10 ACKs do not come from both peers: the load-balanced split was not exercised", e.GitSHA)
		}
	}
	return pass(NameC5d, e.Cell, e.Shape, fmt.Sprintf("18 containers (10 with both peers up, 4 with the primary down, 4 after its return) carry 18 distinct addresses; no table and no pair of %d ACKs gives one address to two identities at once", len(acks)), ev, e.GitSHA)
}
