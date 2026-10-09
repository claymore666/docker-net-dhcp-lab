package scenario

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group C's hostile segment (#23): a squatter on the address the
// source offers, a second server, an exhausted pool and a renumbered
// subnet. Each actor or rewrite is undone by defer on every path; the
// Ready gate catches what a crash leaves behind.

// declinedFor reports whether msgs hold a DECLINE naming addr.
func declinedFor(msgs []DHCPMsg, addr string) bool {
	for _, m := range messagesOfType(msgs, "DECLINE") {
		if m.Requested == addr || m.CIAddr == addr {
			return true
		}
	}
	return false
}

// offeredTo reports whether msgs hold an OFFER of addr.
func offeredTo(msgs []DHCPMsg, addr string) bool {
	for _, m := range messagesOfType(msgs, "OFFER") {
		if m.YIAddr == addr {
			return true
		}
	}
	return false
}

func leasedOn(leases []sourceadapter.Lease, addr string) bool {
	for _, l := range leases {
		if l.Address == addr {
			return true
		}
	}
	return false
}

func runC6(ctx context.Context, e Env) Verdict { return runC6Tuned(ctx, e, cDefault) }

// runC6Tuned -- conflict_check=wait: the source offers X, reserved for
// the network's client id, while a squatter holds X and ignores ping;
// the client must DECLINE X and never carry it.
func runC6Tuned(ctx context.Context, e Env, _ cTiming) Verdict {
	if v, ok := bIPAMNA(NameC6, e); ok {
		return v
	}
	i, err := shapeIndex(e.Shape)
	if err != nil {
		return blocked(NameC6, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	x, err := groupCAddr(e, c6BaseHost+i)
	if err != nil {
		return blocked(NameC6, e.Cell, e.Shape, fmt.Sprintf("no usable squat address: %v", err), e.GitSHA)
	}
	id := "lab-c6-" + string(e.Shape)
	wire := b2WireClientID(id)
	// The reservation stays, as B1's and B2's do: it names this client
	// id alone and an address no other scenario uses (groupCAddr).
	if err := e.Source.ReserveClientID(ctx, wire, x); err != nil {
		return blocked(NameC6, e.Cell, e.Shape, fmt.Sprintf("could not reserve %s for %s: %v", x, wire, err), e.GitSHA)
	}
	stop, err := e.Source.Squat(ctx, x, false)
	if err != nil {
		return blocked(NameC6, e.Cell, e.Shape, fmt.Sprintf("could not put a squatter on %s: %v", x, err), e.GitSHA)
	}
	defer func() { _ = stop(bCleanupCtx(ctx)) }()
	net, down, err := cNetwork(ctx, e, "c6", []string{"client_id=" + id, "conflict_check=wait"})
	defer down()
	if err != nil {
		return blocked(NameC6, e.Cell, e.Shape, fmt.Sprintf("could not create the c6 network: %v", err), e.GitSHA)
	}
	name := containerName(e, NameC6)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	from := time.Now()
	res, err := timedDockerRun(ctx, e.Host, net, name)
	if err != nil {
		return blocked(NameC6, e.Cell, e.Shape, fmt.Sprintf("docker run on %s: %v", net, err), e.GitSHA)
	}
	ev := map[string]string{}
	ev["run"] = writeNote(e, NameC6, "run", fmt.Sprintf("%s on %s: exit %d after %s\n%s\n", name, net, res.RC, res.Wall, res.Out))
	msgs, err := readCapture(ctx, e, NameC6, "capture", wire, ev)
	if err != nil {
		return blocked(NameC6, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	msgs = messagesAfter(msgs, from)
	snap := evidencePath(e, NameC6, "leases-after")
	leases, err := writeLeaseSnapshot(ctx, e.Source, snap)
	if err != nil {
		return blocked(NameC6, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
	}
	ev["leases-after"] = snap
	if !offeredTo(msgs, x) {
		return blocked(NameC6, e.Cell, e.Shape, fmt.Sprintf("the capture shows no OFFER of the reserved %s to %s: the squatter was never tested", x, wire), e.GitSHA)
	}
	if !declinedFor(msgs, x) {
		return fail(NameC6, e.Cell, e.Shape, fmt.Sprintf("the source offered %s, held by a squatter, and the capture shows no DECLINE of it from %s", x, wire), ev, e.GitSHA)
	}
	mine := active(leasesForIdent(leases, wire), time.Now())
	if leasedOn(mine, x) {
		return fail(NameC6, e.Cell, e.Shape, fmt.Sprintf("%s DECLINEd %s but the source still holds an active lease on it for that id", wire, x), ev, e.GitSHA)
	}
	if res.RC != 0 {
		return pass(NameC6, e.Cell, e.Shape, fmt.Sprintf("branch run-failed: %s DECLINEd the squatted %s and docker run failed (exit %d after %s); no active lease on %s for it",
			wire, x, res.RC, res.Wall.Round(100*time.Millisecond), x), ev, e.GitSHA)
	}
	own, err := containerAddrs(ctx, e.Host, name)
	if err != nil {
		return fail(NameC6, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
	}
	if containsAddr(own, x) {
		return fail(NameC6, e.Cell, e.Shape, fmt.Sprintf("the container carries the squatted %s (carries %v)", x, own), ev, e.GitSHA)
	}
	for _, l := range mine {
		if containsAddr(own, l.Address) {
			return pass(NameC6, e.Cell, e.Shape, fmt.Sprintf("branch other-address: %s DECLINEd the squatted %s and came up on %s, which the source leases to it", wire, x, l.Address), ev, e.GitSHA)
		}
	}
	return fail(NameC6, e.Cell, e.Shape, fmt.Sprintf("the container started carrying %v, none of it an active lease for %s (the table shows %v)", own, wire, addrsOf(mine)), ev, e.GitSHA)
}

func runC6b(ctx context.Context, e Env) Verdict { return runC6bTuned(ctx, e, cDefault) }

// runC6bTuned -- conflict_check=async: a squatter takes the container's
// leased X and announces it; within 30 s the client must DECLINE X and
// move to a Y the source leases to it.
func runC6bTuned(ctx context.Context, e Env, t cTiming) Verdict {
	if v, ok := bIPAMNA(NameC6b, e); ok {
		return v
	}
	net, down, err := cNetwork(ctx, e, "c6b", []string{"conflict_check=async"})
	defer down()
	if err != nil {
		return blocked(NameC6b, e.Cell, e.Shape, fmt.Sprintf("could not create the c6b network: %v", err), e.GitSHA)
	}
	name := containerName(e, NameC6b)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	mac, x, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameC6b, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return fail(NameC6b, e.Cell, e.Shape, err.Error(), nil, e.GitSHA)
	}
	stop, err := e.Source.Squat(ctx, x, true)
	if err != nil {
		return blocked(NameC6b, e.Cell, e.Shape, fmt.Sprintf("could not put a squatter on %s: %v", x, err), e.GitSHA)
	}
	defer func() { _ = stop(bCleanupCtx(ctx)) }()
	squatAt := time.Now()
	ev := map[string]string{}
	snap := evidencePath(e, NameC6b, "leases-after")
	var last string
	for {
		own, err := containerAddrs(ctx, e.Host, name)
		if err != nil {
			return fail(NameC6b, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
		}
		msgs, err := readCapture(ctx, e, NameC6b, "capture", ident, ev)
		if err != nil {
			return blocked(NameC6b, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
		}
		leases, err := writeLeaseSnapshot(ctx, e.Source, snap)
		if err != nil {
			return blocked(NameC6b, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
		}
		ev["leases-after"] = snap
		mine := active(leasesForIdent(leases, ident), time.Now())
		declined := declinedFor(messagesAfter(msgs, squatAt), x)
		if declined && !containsAddr(own, x) && !leasedOn(mine, x) {
			for _, l := range mine {
				if containsAddr(own, l.Address) {
					return pass(NameC6b, e.Cell, e.Shape, fmt.Sprintf("%s DECLINEd %s %s after a squatter announced it and moved to %s, which the source leases to it",
						ident, x, time.Since(squatAt).Round(time.Second), l.Address), ev, e.GitSHA)
				}
			}
		}
		last = fmt.Sprintf("DECLINE of %s seen: %t; the container carries %v; the table's active leases for %s are %v", x, declined, own, ident, addrsOf(mine))
		if time.Since(squatAt) > t.c6bWindow {
			return fail(NameC6b, e.Cell, e.Shape, fmt.Sprintf("%s after a squatter took %s: %s", t.c6bWindow, x, last), ev, e.GitSHA)
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return blocked(NameC6b, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
	}
}

func runC7(ctx context.Context, e Env) Verdict { return runC7Tuned(ctx, e, cDefault) }

// runC7Tuned -- a rogue server on the segment: a network that denies it
// and a network that allows only the real source must both take their
// lease from the source although the rogue offered too.
func runC7Tuned(ctx context.Context, e Env, _ cTiming) Verdict {
	if v, ok := bIPAMNA(NameC7, e); ok {
		return v
	}
	var hosts [3]string
	for i, h := range []int{rogueHost, rogueFirstHost, rogueLastHost} {
		a, err := groupCAddr(e, h)
		if err != nil {
			return blocked(NameC7, e.Cell, e.Shape, fmt.Sprintf("no usable rogue address: %v", err), e.GitSHA)
		}
		hosts[i] = a
	}
	rogue := hosts[0]
	stop, err := e.Source.StartRogue(ctx, rogue, hosts[1], hosts[2])
	if err != nil {
		return blocked(NameC7, e.Cell, e.Shape, fmt.Sprintf("could not start the rogue server on %s: %v", rogue, err), e.GitSHA)
	}
	defer func() { _ = stop(bCleanupCtx(ctx)) }()
	ev := map[string]string{}
	var done []string
	for _, r := range []struct{ suffix, opt string }{
		{"c7", "dhcp_deny_servers=" + rogue},
		{"c7b", "dhcp_servers=" + e.SourceAddr},
	} {
		net, down, err := cNetwork(ctx, e, r.suffix, []string{r.opt})
		defer down()
		if err != nil {
			return blocked(NameC7, e.Cell, e.Shape, fmt.Sprintf("could not create the %s network: %v", r.suffix, err), e.GitSHA)
		}
		name := containerName(e, NameC7) + "-" + r.suffix
		defer removeContainer(bCleanupCtx(ctx), e.Host, name)
		mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
		if err != nil {
			return fail(NameC7, e.Cell, e.Shape, fmt.Sprintf("%s (%s): container did not start: %v", r.suffix, r.opt, err), ev, e.GitSHA)
		}
		ident, err := cIdent(e.Shape, mac, endpointID)
		if err != nil {
			return fail(NameC7, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
		}
		msgs, err := readCapture(ctx, e, NameC7, "capture-"+r.suffix, ident, ev)
		if err != nil {
			return blocked(NameC7, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
		}
		rogueOffers := 0
		for _, m := range messagesOfType(msgs, "OFFER") {
			if m.Server == rogue {
				rogueOffers++
			}
		}
		if rogueOffers == 0 {
			return blocked(NameC7, e.Cell, e.Shape, fmt.Sprintf("%s: the capture shows no OFFER from the rogue %s to %s: the rogue never competed", r.suffix, rogue, ident), e.GitSHA)
		}
		real := 0
		for _, m := range messagesOfType(msgs, "REQUEST") {
			switch m.Server {
			case rogue:
				return fail(NameC7, e.Cell, e.Shape, fmt.Sprintf("%s (%s): %s sent a REQUEST naming the rogue %s", r.suffix, r.opt, ident, rogue), ev, e.GitSHA)
			case e.SourceAddr:
				real++
			}
		}
		if real == 0 {
			return fail(NameC7, e.Cell, e.Shape, fmt.Sprintf("%s (%s): the capture shows no REQUEST from %s naming the source %s", r.suffix, r.opt, ident, e.SourceAddr), ev, e.GitSHA)
		}
		if !inMainPool(e, addr) {
			return fail(NameC7, e.Cell, e.Shape, fmt.Sprintf("%s (%s): the container got %s, outside the source's pool %s-%s", r.suffix, r.opt, addr, e.PoolStart, e.PoolEnd), ev, e.GitSHA)
		}
		snap := evidencePath(e, NameC7, "leases-"+r.suffix)
		_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
		if err != nil {
			return blocked(NameC7, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
		}
		ev["leases-"+r.suffix] = snap
		if !ok {
			return fail(NameC7, e.Cell, e.Shape, r.suffix+": "+leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
		}
		rl, err := e.Source.RogueLeases(ctx)
		if err != nil {
			return blocked(NameC7, e.Cell, e.Shape, fmt.Sprintf("could not read the rogue's lease file: %v", err), e.GitSHA)
		}
		if mine := leasesForIdent(rl, ident); len(mine) > 0 {
			return fail(NameC7, e.Cell, e.Shape, fmt.Sprintf("%s (%s): the rogue's lease file holds a lease for %s: %v", r.suffix, r.opt, ident, addrsOf(mine)), ev, e.GitSHA)
		}
		done = append(done, fmt.Sprintf("%s (%s) leased %s from the source after %d rogue OFFER(s)", r.suffix, r.opt, addr, rogueOffers))
	}
	return pass(NameC7, e.Cell, e.Shape, strings.Join(done, "; ")+"; the rogue's lease file holds neither", ev, e.GitSHA)
}

// hostLinkCount is how many links the docker host lists.
func hostLinkCount(ctx context.Context, r sourceadapter.Runner) (int, error) {
	out, err := r.Run(ctx, "ip -o link show | wc -l")
	if err != nil {
		return 0, fmt.Errorf("counting the docker host's links: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("counting the docker host's links: %q is not a count", out)
	}
	return n, nil
}

func runC8(ctx context.Context, e Env) Verdict { return runC8Tuned(ctx, e, cDefault) }

// runC8Tuned -- an exhausted pool: with the pool narrowed to two
// addresses and both held, a third container must fail cleanly, leave
// no endpoint or link, and no acquisition may outlive it once the pool
// is restored; a fourth container then gets a lease.
func runC8Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	if v, ok := bIPAMNA(NameC8, e); ok {
		return v
	}
	first, err1 := groupCAddr(e, c8FirstHost)
	last, err2 := groupCAddr(e, c8LastHost)
	if err1 != nil || err2 != nil {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("no usable narrow pool: %v %v", err1, err2), e.GitSHA)
	}
	restore, err := e.Source.NarrowPool(ctx, first, last)
	if err != nil {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("could not narrow the pool to %s-%s: %v", first, last, err), e.GitSHA)
	}
	restored := false
	defer func() {
		if !restored {
			_ = restore(bCleanupCtx(ctx))
		}
	}()
	base := containerName(e, NameC8)
	held := map[string]bool{}
	for _, s := range []string{"-fill1", "-fill2"} {
		defer removeContainer(bCleanupCtx(ctx), e.Host, base+s)
		_, addr, _, err := runContainer(ctx, e.Host, e.Shape, e.Network, base+s)
		if err != nil {
			return fail(NameC8, e.Cell, e.Shape, fmt.Sprintf("fill container %s did not start with the pool %s-%s free: %v", base+s, first, last, err), nil, e.GitSHA)
		}
		held[addr] = true
	}
	if !held[first] || !held[last] {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("the fill containers hold %v, not %s and %s: the pool was not narrowed", keys(held), first, last), e.GitSHA)
	}
	id := "lab-c8-" + string(e.Shape)
	wire := b2WireClientID(id)
	net, down, err := cNetwork(ctx, e, "c8", []string{"client_id=" + id})
	defer down()
	if err != nil {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("could not create the c8 network: %v", err), e.GitSHA)
	}
	linksBefore, err := hostLinkCount(ctx, e.Host)
	if err != nil {
		return blocked(NameC8, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	third := base + "-c8"
	defer removeContainer(bCleanupCtx(ctx), e.Host, third)
	from := time.Now()
	res, err := timedDockerRun(ctx, e.Host, net, third)
	if err != nil {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("docker run on %s: %v", net, err), e.GitSHA)
	}
	ev := map[string]string{}
	ev["run"] = writeNote(e, NameC8, "run", fmt.Sprintf("%s on %s: exit %d after %s\n%s\n", third, net, res.RC, res.Wall, res.Out))
	msgs, err := readCapture(ctx, e, NameC8, "capture", wire, ev)
	if err != nil {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	msgs = messagesAfter(msgs, from)
	if o := messagesOfType(msgs, "OFFER"); len(o) > 0 {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("the source offered %s to %s with both pool addresses held: the pool was not exhausted", o[0].YIAddr, wire), e.GitSHA)
	}
	if res.RC == 0 {
		return fail(NameC8, e.Cell, e.Shape, fmt.Sprintf("%s started on %s with no OFFER on the wire and the pool exhausted", third, net), ev, e.GitSHA)
	}
	if len(messagesOfType(msgs, "DISCOVER")) == 0 {
		return fail(NameC8, e.Cell, e.Shape, fmt.Sprintf("the capture shows no DISCOVER from %s during its run", wire), ev, e.GitSHA)
	}
	if n, err := endpointCount(ctx, e.Host, net); err != nil {
		return blocked(NameC8, e.Cell, e.Shape, err.Error(), e.GitSHA)
	} else if n != 0 {
		return fail(NameC8, e.Cell, e.Shape, fmt.Sprintf("%s still lists %d endpoint(s) after the failed run", net, n), ev, e.GitSHA)
	}
	linksAfter := 0
	for deadline := time.Now().Add(t.c8Links); ; {
		if linksAfter, err = hostLinkCount(ctx, e.Host); err != nil {
			return blocked(NameC8, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
		if linksAfter == linksBefore || time.Now().After(deadline) {
			break
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return blocked(NameC8, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
	}
	if linksAfter != linksBefore {
		return fail(NameC8, e.Cell, e.Shape, fmt.Sprintf("the docker host lists %d links %s after the failed run, %d before it", linksAfter, t.c8Links, linksBefore), ev, e.GitSHA)
	}
	if err := restore(ctx); err != nil {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("could not restore the pool: %v", err), e.GitSHA)
	}
	restored = true
	if err := sleepCtx(ctx, t.c8Settle); err != nil {
		return blocked(NameC8, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	snap := evidencePath(e, NameC8, "leases-after-restore")
	leases, err := writeLeaseSnapshot(ctx, e.Source, snap)
	if err != nil {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
	}
	ev["leases-after-restore"] = snap
	if l := leasesForIdent(leases, wire); len(l) > 0 {
		return fail(NameC8, e.Cell, e.Shape, fmt.Sprintf("%s after the pool was restored the source leased %s to %s: an acquisition outlived the failed endpoint", t.c8Settle, l[0].Address, wire), ev, e.GitSHA)
	}
	fourth := base + "-4"
	defer removeContainer(bCleanupCtx(ctx), e.Host, fourth)
	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, fourth)
	if err != nil {
		return fail(NameC8, e.Cell, e.Shape, fmt.Sprintf("after the pool was restored a fourth container did not start: %v", err), ev, e.GitSHA)
	}
	snap4 := evidencePath(e, NameC8, "leases-fourth")
	if _, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap4); err != nil {
		return blocked(NameC8, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
	} else if !ok {
		ev["leases-fourth"] = snap4
		return fail(NameC8, e.Cell, e.Shape, "fourth container: "+leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
	}
	ev["leases-fourth"] = snap4
	return pass(NameC8, e.Cell, e.Shape, fmt.Sprintf("with %s and %s held, %s failed after %s with no OFFER, no endpoint and no link left; no lease for it %s after the restore; a fourth container leased %s",
		first, last, wire, res.Wall.Round(100*time.Millisecond), t.c8Settle, addr), ev, e.GitSHA)
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func runC9(ctx context.Context, e Env) Verdict { return runC9Tuned(ctx, e, cDefault) }

// c9NetworkWhat names C9's own network, which carries no option, in its
// N/A reason (#23).
const c9NetworkWhat = "C9's own network beside the cell's"

// runC9Tuned -- the source moves to a new subnet under a short lease:
// by bind + 200 s the container must carry, inside its own namespace,
// the new lease the table shows, route via the new source address and
// be reachable. The source is put back and its lease file reset.
func runC9Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	if v, ok := ipamNA(NameC9, e, c9NetworkWhat); ok {
		return v
	}
	subnet, srv, first, last, err := c9Target(e)
	if err != nil {
		return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("no renumber target: %v", err), e.GitSHA)
	}
	restoreLease, err := e.Source.ShortenLeaseTime(ctx, t.lease)
	if err != nil {
		return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("could not shorten the lease to %d s: %v", t.lease, err), e.GitSHA)
	}
	defer func() { _ = restoreLease(bCleanupCtx(ctx)) }()
	net, down, err := cNetwork(ctx, e, "c9", nil)
	defer down()
	if err != nil {
		return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("could not create the c9 network: %v", err), e.GitSHA)
	}
	name := containerName(e, NameC9)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	mac, x, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameC9, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return fail(NameC9, e.Cell, e.Shape, err.Error(), nil, e.GitSHA)
	}
	ev := map[string]string{}
	bindAt, err := bindAnchor(ctx, e, NameC9, ident, x, t.anchor, t.poll, ev)
	if err != nil {
		return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("no bind time: %v", err), e.GitSHA)
	}
	restoreNet, err := e.Source.Renumber(ctx, subnet, srv, first, last)
	if err != nil {
		return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("could not renumber the source to %s: %v", subnet, err), e.GitSHA)
	}
	putBack := false
	defer func() {
		if !putBack {
			_ = restoreNet(bCleanupCtx(ctx))
		}
	}()
	renumberedAt := time.Now()
	v := c9Judge(ctx, e, t, c9Case{name: name, ident: ident, x: x, subnet: subnet, srv: srv, bindAt: bindAt, from: renumberedAt}, ev)
	putBack = true
	if err := restoreNet(ctx); err != nil {
		return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("could not put the source back on %s: %v", e.SegSubnet, err), e.GitSHA)
	}
	if err := e.Source.ResetLeases(ctx); err != nil {
		return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("could not reset the source's lease file after the renumber: %v", err), e.GitSHA)
	}
	return v
}

type c9Case struct {
	name, ident, x, subnet, srv string
	bindAt, from                time.Time
}

// c9Judge polls until the container's own namespace, the table and the
// default route all show the new subnet, or bind + c9Wait passes.
func c9Judge(ctx context.Context, e Env, t cTiming, c c9Case, ev map[string]string) Verdict {
	s := netip.MustParsePrefix(c.subnet)
	snap := evidencePath(e, NameC9, "leases-after")
	deadline := c.bindAt.Add(t.c9Wait)
	var last string
	for {
		own, err := containerAddrs(ctx, e.Host, c.name)
		if err != nil {
			return fail(NameC9, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
		}
		leases, err := writeLeaseSnapshot(ctx, e.Source, snap)
		if err != nil {
			return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
		}
		ev["leases-after"] = snap
		gw, err := containerDefaultGateway(ctx, e.Host, c.name)
		if err != nil {
			return fail(NameC9, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
		}
		mine := active(leasesForIdent(leases, c.ident), time.Now())
		if !containsAddr(own, c.x) && gw == c.srv {
			for _, l := range mine {
				a, err := netip.ParseAddr(l.Address)
				if err != nil || !s.Contains(a) || !containsAddr(own, l.Address) {
					continue
				}
				secs, err := reachableWithRetry(ctx, e.Source, l.Address)
				if err != nil {
					return fail(NameC9, e.Cell, e.Shape, fmt.Sprintf("%s moved to %s in %s but it is not reachable after %ds: %v", c.ident, l.Address, c.subnet, secs, err), ev, e.GitSHA)
				}
				msgs, err := readCapture(ctx, e, NameC9, "capture", c.ident, ev)
				if err != nil {
					return blocked(NameC9, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
				}
				naks := len(messagesOfType(messagesAfter(msgs, c.from), "NAK"))
				return pass(NameC9, e.Cell, e.Shape, fmt.Sprintf("%s moved from %s to %s (%s) %s after the renumber, in the table and in its own namespace, default route via %s, reachable after %ds; NAKs on the wire: %d (recorded, not judged)",
					c.ident, c.x, l.Address, c.subnet, time.Since(c.from).Round(time.Second), c.srv, secs, naks), ev, e.GitSHA)
			}
		}
		last = fmt.Sprintf("the container carries %v with default route via %q; the table's active leases for %s are %v", own, gw, c.ident, addrsOf(mine))
		if time.Now().After(deadline) {
			return fail(NameC9, e.Cell, e.Shape, fmt.Sprintf("by bind + %s after the source moved to %s: %s", t.c9Wait, c.subnet, last), ev, e.GitSHA)
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return blocked(NameC9, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
	}
}
