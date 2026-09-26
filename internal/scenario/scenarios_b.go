package scenario

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// a9StopWait is how long runA9 leaves the container down between `docker
// stop` and `docker start`: long enough to be a real wait, not an
// instant stop/start pair that would never exercise anything a bare
// restart (A2) does not already cover (#3 part 2).
const a9StopWait = 5 * time.Second

// runA9 -- stop, wait, start: an explicit `docker stop` followed by an
// explicit `docker start` on the same container, after a real wait in
// between. Like A2, an address change is reported, not failed on: this
// event is mechanically the same endpoint teardown/rebuild A2 already
// carves an ipvlan exception for, just driven by two separate commands
// with a pause in between rather than one `docker restart` (#3 part 2).
func runA9(ctx context.Context, e Env) Verdict {
	return runA9Tuned(ctx, e, a9StopWait)
}

// runA9Tuned is runA9 with the stop/start wait broken out, the same
// split waitHostRebooted/waitHostRebootedTuned already establishes: a
// real 5s wait is the point of the scenario, not something a test
// should have to sit through.
func runA9Tuned(ctx context.Context, e Env, stopWait time.Duration) Verdict {
	name := containerName(e, NameA9)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA9, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA9, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA9, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA9, e.Cell, e.Shape, "before stop: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker stop %s", name)); err != nil {
		return fail(NameA9, e.Cell, e.Shape, fmt.Sprintf("docker stop: %v", err), evBefore, e.GitSHA)
	}
	select {
	case <-time.After(stopWait):
	case <-ctx.Done():
		return fail(NameA9, e.Cell, e.Shape, ctx.Err().Error(), evBefore, e.GitSHA)
	}
	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker start %s", name)); err != nil {
		return fail(NameA9, e.Cell, e.Shape, fmt.Sprintf("docker start: %v", err), evBefore, e.GitSHA)
	}
	if err := waitContainerRunning(ctx, e.Host, name); err != nil {
		return fail(NameA9, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}

	afterMac, afterAddr, afterEndpointID, err := inspectContainer(ctx, e.Host, e.Shape, name)
	if err != nil {
		return fail(NameA9, e.Cell, e.Shape, fmt.Sprintf("inspect after start: %v", err), evBefore, e.GitSHA)
	}
	afterSnap := evidencePath(e, NameA9, "leases-after")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, afterMac, afterAddr, afterEndpointID, afterSnap)
	if err != nil {
		return fail(NameA9, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after start: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA9, e.Cell, e.Shape, "after start: "+leaseFailReason(e.Shape, afterMac, afterAddr, afterEndpointID), ev, e.GitSHA)
	}

	note := fmt.Sprintf("kept address %s", addr)
	if afterAddr != addr {
		note = fmt.Sprintf("got a new lease (%s -> %s)", addr, afterAddr)
	}
	secs, err := reachableWithRetry(ctx, e.Source, afterAddr)
	if err != nil {
		return fail(NameA9, e.Cell, e.Shape,
			fmt.Sprintf("stopped, waited %s, started; mac %s has a lease for %s, but the source could not reach it within %ds: %v", stopWait, afterMac, afterAddr, secs, err), ev, e.GitSHA)
	}
	return pass(NameA9, e.Cell, e.Shape,
		fmt.Sprintf("stopped, waited %s, started again: %s, confirmed in the source's table, reachable from the source after %ds", stopWait, note, secs),
		ev, e.GitSHA)
}

// runA10 -- kill + restart policy: `docker kill` (SIGKILL) simulating a
// crash, recovered by Docker's own --restart unless-stopped, never a
// manual start (issue #3 part 2). Two things this scenario asserts that
// A2/A9 do not: the recovery is confirmed by a genuinely new
// State.StartedAt (not a race that reads the still-dying old process as
// already back), and the source's table must show exactly one lease for
// the recovered address -- a duplicate row there would mean the kill
// path minted a second lease instead of reusing the endpoint's own.
// Address kept is required on bridge/macvlan, the same ipvlan carve-out
// A2 already documents applies here too: this is the same
// endpoint-teardown-and-rebuild event, just triggered by a kill instead
// of an explicit restart command.
func runA10(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA10)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainerPolicy(ctx, e.Host, e.Shape, e.Network, name, "unless-stopped")
	if err != nil {
		return fail(NameA10, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA10, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA10, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA10, e.Cell, e.Shape, "before kill: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	beforeStartedAt, err := containerStartedAt(ctx, e.Host, name)
	if err != nil {
		return fail(NameA10, e.Cell, e.Shape, fmt.Sprintf("could not read StartedAt before kill: %v", err), evBefore, e.GitSHA)
	}
	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker kill %s", name)); err != nil {
		return fail(NameA10, e.Cell, e.Shape, fmt.Sprintf("docker kill: %v", err), evBefore, e.GitSHA)
	}
	if err := waitContainerRestarted(ctx, e.Host, name, beforeStartedAt, 30*time.Second); err != nil {
		return fail(NameA10, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}

	afterMac, afterAddr, afterEndpointID, err := inspectContainer(ctx, e.Host, e.Shape, name)
	if err != nil {
		return fail(NameA10, e.Cell, e.Shape, fmt.Sprintf("inspect after restart-policy recovery: %v", err), evBefore, e.GitSHA)
	}
	afterSnap := evidencePath(e, NameA10, "leases-after")
	lease, leases, ok, err := lookupLease(ctx, e.Source, e.Shape, afterMac, afterAddr, afterEndpointID, afterSnap)
	if err != nil {
		return fail(NameA10, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after kill: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA10, e.Cell, e.Shape, "after kill: "+leaseFailReason(e.Shape, afterMac, afterAddr, afterEndpointID), ev, e.GitSHA)
	}

	dupes := 0
	for _, l := range leases {
		if l.Address == afterAddr {
			dupes++
		}
	}
	if dupes > 1 {
		return fail(NameA10, e.Cell, e.Shape,
			fmt.Sprintf("address %s appears %d times in the source's table after the kill: a duplicate lease, not one", afterAddr, dupes), ev, e.GitSHA)
	}

	if afterAddr != addr && e.Shape != ShapeIpvlan {
		return fail(NameA10, e.Cell, e.Shape,
			fmt.Sprintf("address changed across a kill+restart-policy recovery: %s -> %s", addr, afterAddr), ev, e.GitSHA)
	}
	secs, err := reachableWithRetry(ctx, e.Source, afterAddr)
	if err != nil {
		return fail(NameA10, e.Cell, e.Shape,
			fmt.Sprintf("killed, restart policy brought it back, mac %s has one confirmed lease for %s, but the source could not reach it within %ds: %v", afterMac, afterAddr, secs, err), ev, e.GitSHA)
	}
	note := fmt.Sprintf("kept address %s", addr)
	if afterAddr != addr {
		note = fmt.Sprintf("address changed (%s -> %s) as documented for ipvlan (#219)", addr, afterAddr)
	}
	return pass(NameA10, e.Cell, e.Shape,
		fmt.Sprintf("container killed, restart policy recovered it, %s, exactly one lease for it in the source's table (hostname %q), reachable from the source after %ds", note, lease.Hostname, secs),
		ev, e.GitSHA)
}

// runA11 -- pause/unpause: `docker pause` freezes the container's own
// process tree via the cgroups freezer; it never touches the network
// namespace or the endpoint, so the lease must read identically before
// and after, and the container must answer again once unpaused (#3
// part 2).
func runA11(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA11)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA11, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA11, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA11, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA11, e.Cell, e.Shape, "before pause: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	if err := pauseContainer(ctx, e.Host, name); err != nil {
		return fail(NameA11, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	if err := unpauseContainer(ctx, e.Host, name); err != nil {
		return fail(NameA11, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}

	afterSnap := evidencePath(e, NameA11, "leases-after")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, afterSnap)
	if err != nil {
		return fail(NameA11, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after unpause: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA11, e.Cell, e.Shape, "after unpause: "+leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
	}
	secs, err := reachableWithRetry(ctx, e.Source, addr)
	if err != nil {
		return fail(NameA11, e.Cell, e.Shape,
			fmt.Sprintf("paused then unpaused, mac %s still has a lease for %s, but the source could not reach it within %ds: %v", mac, addr, secs, err), ev, e.GitSHA)
	}
	return pass(NameA11, e.Cell, e.Shape,
		fmt.Sprintf("paused then unpaused, lease for %s (mac %s) untouched in the source's table both times, reachable from the source after %ds", addr, mac, secs),
		ev, e.GitSHA)
}

// runA12 -- network disconnect/reconnect while running:
// docs/reference.md's own release_lease table names `docker network
// disconnect` as one of the three events that make an endpoint leave
// its sandbox, alongside `docker stop` and `docker rm` of a running
// container. What that means here is reported, not asserted either
// way: with every network in this lab left at release_lease's own
// default (never), the lease should still be held at disconnect, but
// this scenario's PASS bar is what the outcome asks for -- a lease and
// reachability after reconnect -- not the disconnect-time behaviour by
// itself.
func runA12(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA12)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA12, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA12, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA12, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA12, e.Cell, e.Shape, "before disconnect: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	if err := disconnectNetwork(ctx, e.Host, e.Network, name); err != nil {
		return fail(NameA12, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	disconnSnap := evidencePath(e, NameA12, "leases-at-disconnect")
	_, _, stillLeased, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, disconnSnap)
	if err != nil {
		return fail(NameA12, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table at disconnect: %v", err), evBefore, e.GitSHA)
	}
	disconnectNote := "lease released at disconnect"
	if stillLeased {
		disconnectNote = "lease held at disconnect (this network's release_lease is the default, never)"
	}

	if err := connectNetwork(ctx, e.Host, e.Network, name); err != nil {
		return fail(NameA12, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	afterMac, afterAddr, afterEndpointID, err := inspectContainer(ctx, e.Host, e.Shape, name)
	if err != nil {
		return fail(NameA12, e.Cell, e.Shape, fmt.Sprintf("inspect after reconnect: %v", err), evBefore, e.GitSHA)
	}
	afterSnap := evidencePath(e, NameA12, "leases-after-reconnect")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, afterMac, afterAddr, afterEndpointID, afterSnap)
	if err != nil {
		return fail(NameA12, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after reconnect: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-at-disconnect": disconnSnap, "leases-after-reconnect": afterSnap}
	if !ok {
		return fail(NameA12, e.Cell, e.Shape, "after reconnect: "+leaseFailReason(e.Shape, afterMac, afterAddr, afterEndpointID), ev, e.GitSHA)
	}
	secs, err := reachableWithRetry(ctx, e.Source, afterAddr)
	if err != nil {
		return fail(NameA12, e.Cell, e.Shape,
			fmt.Sprintf("reconnected and mac %s has a lease for %s, but the source could not reach it within %ds: %v", afterMac, afterAddr, secs, err), ev, e.GitSHA)
	}
	return pass(NameA12, e.Cell, e.Shape,
		fmt.Sprintf("disconnected then reconnected while running (%s), reconnect got address %s, confirmed in the source's table, reachable from the source after %ds", disconnectNote, afterAddr, secs),
		ev, e.GitSHA)
}

// runA13 -- one container, two plugin networks: N/A on the two
// host-bridge shapes, where SegmentNIC is already wholly enslaved to
// the one bridge NetworkUp built for the caller's own shape and cannot
// also be enslaved to a second bridge (issue #3 part 2,
// NetworkUpSecondary's doc comment). On the three parent-attached
// shapes, a second independent network on the same parent NIC is a
// real, supported configuration, so it is attempted, not defaulted to
// N/A.
func runA13(ctx context.Context, e Env) Verdict {
	if e.Shape == ShapeBridge || e.Shape == ShapeBridgeIPAM {
		return na(NameA13, e.Cell, e.Shape,
			"the docker host's segment NIC is already wholly enslaved to this shape's one host bridge; it cannot also be enslaved to a second bridge for a second network", e.GitSHA)
	}

	name := containerName(e, NameA13)
	net2 := NetworkName(e.Cell, e.Shape) + "-a13b"
	defer removeContainer(ctx, e.Host, name)
	defer NetworkDownSecondary(ctx, e.Host, net2)

	if err := NetworkUpSecondary(ctx, e.Host, net2, e.Shape); err != nil {
		return fail(NameA13, e.Cell, e.Shape, fmt.Sprintf("could not bring up a second network: %v", err), nil, e.GitSHA)
	}

	mac1, addr1, endpointID1, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA13, e.Cell, e.Shape, fmt.Sprintf("container did not start on the first network: %v", err), nil, e.GitSHA)
	}
	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker network connect %s %s", net2, name)); err != nil {
		return fail(NameA13, e.Cell, e.Shape, fmt.Sprintf("docker network connect %s %s: %v", net2, name, err), nil, e.GitSHA)
	}
	mac2, addr2, endpointID2, err := inspectContainerNetwork(ctx, e.Host, e.Shape, name, net2)
	if err != nil {
		return fail(NameA13, e.Cell, e.Shape, fmt.Sprintf("inspect on the second network: %v", err), nil, e.GitSHA)
	}

	snap := evidencePath(e, NameA13, "leases-after")
	_, leases, ok1, err := lookupLease(ctx, e.Source, e.Shape, mac1, addr1, endpointID1, snap)
	if err != nil {
		return fail(NameA13, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-after": snap}
	if !ok1 {
		return fail(NameA13, e.Cell, e.Shape, "first network: "+leaseFailReason(e.Shape, mac1, addr1, endpointID1), ev, e.GitSHA)
	}

	var ok2 bool
	if e.Shape == ShapeIpvlan {
		cid, cidErr := ipvlanClientID(endpointID2)
		if cidErr != nil {
			return fail(NameA13, e.Cell, e.Shape, fmt.Sprintf("second network: %v", cidErr), ev, e.GitSHA)
		}
		_, ok2 = findLeaseByClientID(leases, cid)
	} else {
		_, ok2 = findLease(leases, mac2, addr2)
	}
	if !ok2 {
		return fail(NameA13, e.Cell, e.Shape, "second network: "+leaseFailReason(e.Shape, mac2, addr2, endpointID2), ev, e.GitSHA)
	}
	if addr1 == addr2 {
		return fail(NameA13, e.Cell, e.Shape,
			fmt.Sprintf("both networks reported the same address %s for one container; want two distinct leases", addr1), ev, e.GitSHA)
	}

	secs1, err := reachableWithRetry(ctx, e.Source, addr1)
	if err != nil {
		return fail(NameA13, e.Cell, e.Shape,
			fmt.Sprintf("two distinct leases confirmed (%s, %s), but the first network's address was not reachable within %ds: %v", addr1, addr2, secs1, err), ev, e.GitSHA)
	}
	secs2, err := reachableWithRetry(ctx, e.Source, addr2)
	if err != nil {
		return fail(NameA13, e.Cell, e.Shape,
			fmt.Sprintf("two distinct leases confirmed (%s, %s), but the second network's address was not reachable within %ds: %v", addr1, addr2, secs2, err), ev, e.GitSHA)
	}
	return pass(NameA13, e.Cell, e.Shape,
		fmt.Sprintf("one container on two plugin networks: %s (reachable after %ds) and %s (reachable after %ds), both confirmed in the source's own table", addr1, secs1, addr2, secs2),
		ev, e.GitSHA)
}

// a14LeaseSeconds and a14Wait are A14's timing budget (issue #3 part 2):
// a valid-lifetime this short pushes every RFC 2131 client's own T1
// fallback (roughly half the lease) well under a14Wait, so waiting
// a14Wait genuinely runs the scenario past T1 without running past the
// lease's own end. A container whose client never renewed at all would,
// by the time a14Wait elapses, either lose its lease from the source's
// own table (kea and isc-dhcp both already exclude an expired binding
// from what their own Leases() returns -- kea.go's lease4-get-all only
// lists current bindings, iscdhcp.go's parseISCLeases drops any block
// whose latest "binding state" is not "active") or become unreachable
// if the address were reused elsewhere; either failure mode is a FAIL
// here, not a pass. dnsmasq's own leases file does not carry the same
// guarantee -- its own expiry field is read but not parsed here -- so
// an unrenewed dnsmasq lease could still read as present for a beat
// past its real expiry; reachability is still checked on dnsmasq too,
// and a real regression there would likely still show as a source-side
// allocation conflict on a busy segment, but this is a narrower, known
// proxy on dnsmasq specifically, not a gap being hidden.
const (
	a14LeaseSeconds = 40
	a14Wait         = 25 * time.Second
)

// runA14 -- short server lease time: shortens the source's own
// valid-lifetime/default-lease-time to a14LeaseSeconds for the
// duration of this scenario (ShortenLeaseTime, restored via defer
// whatever the outcome), then waits past the RFC 2131 T1 fallback and
// confirms the SAME lease (same mac/client-id, same address) is still
// held and reachable -- the source's own table is the outside evidence
// for "renewed," not the plugin's own counters.
func runA14(ctx context.Context, e Env) Verdict {
	return runA14Tuned(ctx, e, a14LeaseSeconds, a14Wait)
}

// runA14Tuned is runA14 with the lease time and the post-shorten wait
// broken out, the same split waitHostRebooted/waitHostRebootedTuned
// already establishes: the real 40s lease and 25s wait are the point of
// the scenario (long enough to clear a real RFC 2131 T1 fallback), not
// something a unit test should have to sit through.
func runA14Tuned(ctx context.Context, e Env, leaseSeconds int, wait time.Duration) Verdict {
	restore, err := e.Source.ShortenLeaseTime(ctx, leaseSeconds)
	if err != nil {
		return fail(NameA14, e.Cell, e.Shape, fmt.Sprintf("could not shorten the source's lease time: %v", err), nil, e.GitSHA)
	}
	defer restore(ctx)

	name := containerName(e, NameA14)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA14, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA14, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA14, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA14, e.Cell, e.Shape, "before T1: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	select {
	case <-time.After(wait):
	case <-ctx.Done():
		return fail(NameA14, e.Cell, e.Shape, ctx.Err().Error(), evBefore, e.GitSHA)
	}

	afterSnap := evidencePath(e, NameA14, "leases-after-t1")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, afterSnap)
	if err != nil {
		return fail(NameA14, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after %s: %v", wait, err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after-t1": afterSnap}
	if !ok {
		return fail(NameA14, e.Cell, e.Shape,
			fmt.Sprintf("with a %ds lease, %s dropped out of the source's table %s after the first lease (past its T1 renewal point): %s", leaseSeconds, addr, wait, leaseFailReason(e.Shape, mac, addr, endpointID)), ev, e.GitSHA)
	}
	secs, err := reachableWithRetry(ctx, e.Source, addr)
	if err != nil {
		return fail(NameA14, e.Cell, e.Shape,
			fmt.Sprintf("with a %ds lease, %s still confirmed in the source's table %s later, but not reachable within %ds: %v", leaseSeconds, addr, wait, secs, err), ev, e.GitSHA)
	}
	corroborate(ctx, e, mac, ev, NameA14, "capture-check")
	return pass(NameA14, e.Cell, e.Shape,
		fmt.Sprintf("with a %ds lease, address %s still confirmed in the source's table %s later (past its T1 renewal point) and reachable after %ds", leaseSeconds, addr, wait, secs),
		ev, e.GitSHA)
}

// replicaCreated records one A15 replica's identity, shared between
// runA15 and countConfirmedLeases.
type replicaCreated struct{ name, mac, addr, endpointID string }

// countConfirmedLeases snapshots the source's table once and counts how
// many of created have a distinct confirmed lease -- the discipline
// runA8 already established for a burst, reused here for A15's three
// counts (base, scaled up, scaled down) so all three share one
// implementation.
func countConfirmedLeases(ctx context.Context, e Env, created []replicaCreated, snapPath string) (int, error) {
	confirmed := 0
	seen := map[string]bool{}
	for _, c := range created {
		lease, _, ok, err := lookupLease(ctx, e.Source, e.Shape, c.mac, c.addr, c.endpointID, snapPath)
		if err != nil {
			return 0, fmt.Errorf("could not read source lease table: %w", err)
		}
		if ok && !seen[lease.Address] {
			seen[lease.Address] = true
			confirmed++
		}
	}
	return confirmed, nil
}

// runA15 -- compose scale up and down. This lab has no docker compose
// binary in its containers image, so "scale" is modelled the way
// compose's own --scale does it under the hood: N replica containers on
// the same network, added and removed by name -- the same
// multi-container idiom A8 already uses for its burst -- rather than
// left undone for lack of the compose binary itself (issue #3 part 2).
// Scaling up must mint new, distinct confirmed leases without
// disturbing the replicas already up; scaling back down must leave the
// removed replicas' network endpoints gone, not stranded.
func runA15(ctx context.Context, e Env) Verdict {
	const base, scaleTo = 3, 5
	nameAt := func(i int) string { return containerName(e, NameA15) + "-" + strconv.Itoa(i) }

	var up []replicaCreated
	defer func() {
		for _, c := range up {
			removeContainer(ctx, e.Host, c.name)
		}
	}()

	for i := 0; i < base; i++ {
		mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, nameAt(i))
		if err != nil {
			return fail(NameA15, e.Cell, e.Shape, fmt.Sprintf("replica %d/%d did not start: %v", i+1, base, err), nil, e.GitSHA)
		}
		up = append(up, replicaCreated{nameAt(i), mac, addr, endpointID})
	}

	baseSnap := evidencePath(e, NameA15, "leases-base")
	confirmed, err := countConfirmedLeases(ctx, e, up, baseSnap)
	if err != nil {
		return fail(NameA15, e.Cell, e.Shape, err.Error(), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-base": baseSnap}
	if confirmed != base {
		return fail(NameA15, e.Cell, e.Shape, fmt.Sprintf("%d/%d base replicas have a distinct confirmed lease", confirmed, base), ev, e.GitSHA)
	}

	for i := base; i < scaleTo; i++ {
		mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, nameAt(i))
		if err != nil {
			return fail(NameA15, e.Cell, e.Shape, fmt.Sprintf("scale-up replica %d/%d did not start: %v", i+1, scaleTo, err), ev, e.GitSHA)
		}
		up = append(up, replicaCreated{nameAt(i), mac, addr, endpointID})
	}
	scaledSnap := evidencePath(e, NameA15, "leases-scaled-up")
	confirmed, err = countConfirmedLeases(ctx, e, up, scaledSnap)
	if err != nil {
		return fail(NameA15, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
	}
	ev["leases-scaled-up"] = scaledSnap
	if confirmed != scaleTo {
		return fail(NameA15, e.Cell, e.Shape, fmt.Sprintf("scaled up to %d replicas but only %d have a distinct confirmed lease", scaleTo, confirmed), ev, e.GitSHA)
	}

	removed, remaining := up[base:], up[:base]
	up = remaining
	for _, c := range removed {
		removeContainer(ctx, e.Host, c.name)
	}
	downSnap := evidencePath(e, NameA15, "leases-scaled-down")
	confirmed, err = countConfirmedLeases(ctx, e, remaining, downSnap)
	if err != nil {
		return fail(NameA15, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
	}
	ev["leases-scaled-down"] = downSnap
	if confirmed != base {
		return fail(NameA15, e.Cell, e.Shape,
			fmt.Sprintf("after scaling back down, only %d/%d original replicas still have a confirmed lease", confirmed, base), ev, e.GitSHA)
	}
	for _, c := range removed {
		hasEndpoint, err := networkContainsEndpoint(ctx, e.Host, e.Network, c.endpointID)
		if err != nil {
			return fail(NameA15, e.Cell, e.Shape, fmt.Sprintf("could not read network state for removed replica %s: %v", c.name, err), ev, e.GitSHA)
		}
		if hasEndpoint {
			return fail(NameA15, e.Cell, e.Shape,
				fmt.Sprintf("removed replica %s still has an endpoint on network %s: stranded state", c.name, e.Network), ev, e.GitSHA)
		}
	}

	sample := remaining[0]
	secs, err := reachableWithRetry(ctx, e.Source, sample.addr)
	if err != nil {
		return fail(NameA15, e.Cell, e.Shape,
			fmt.Sprintf("scale up/down left %d confirmed replicas with no stranded state, but %s (%s) was not reachable within %ds: %v", confirmed, sample.name, sample.addr, secs, err), ev, e.GitSHA)
	}
	return pass(NameA15, e.Cell, e.Shape,
		fmt.Sprintf("scaled %d -> %d -> %d: every step's replicas had distinct confirmed leases, the %d removed on scale-down left no stranded endpoint, sampled reachable after %ds",
			base, scaleTo, base, scaleTo-base, secs),
		ev, e.GitSHA)
}

// runA16 -- forced remove of a running container (`docker rm -f`, never
// stopped first): docs/reference.md's own release_lease table names
// this as one of the three events, alongside `docker stop` and `docker
// network disconnect`, that make an endpoint leave its sandbox. Every
// network this lab brings up is left at release_lease's own default
// (never, docs/reference.md): no DHCPRELEASE is sent on any of the
// three events, so the address stays in the source's own table exactly
// as it was, leased until it expires. That is the documented behaviour
// this scenario asserts -- a lease that vanished from the table here
// would mean the plugin released on a network that never asked for
// that, a real defect, not a lab fault. "No leftover endpoint or state"
// is checked against Docker's own network inspect output, not the
// plugin's.
func runA16(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA16)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA16, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA16, "leases-before")
	lease, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA16, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA16, e.Cell, e.Shape, "before force-remove: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker rm -f %s", name)); err != nil {
		return fail(NameA16, e.Cell, e.Shape, fmt.Sprintf("docker rm -f a running container failed: %v", err), evBefore, e.GitSHA)
	}

	hasEndpoint, err := networkContainsEndpoint(ctx, e.Host, e.Network, endpointID)
	if err != nil {
		return fail(NameA16, e.Cell, e.Shape, fmt.Sprintf("could not read network state after force-remove: %v", err), evBefore, e.GitSHA)
	}
	if hasEndpoint {
		return fail(NameA16, e.Cell, e.Shape,
			fmt.Sprintf("network %s still lists endpoint %s after a forced remove of its running container", e.Network, endpointID), evBefore, e.GitSHA)
	}

	afterSnap := evidencePath(e, NameA16, "leases-after")
	_, _, stillLeased, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, afterSnap)
	if err != nil {
		return fail(NameA16, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after force-remove: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !stillLeased {
		return fail(NameA16, e.Cell, e.Shape,
			fmt.Sprintf("lease for %s (mac %s) is gone from the source's table after a forced remove, but this network's release_lease is the default (never): nothing should have released it", addr, mac), ev, e.GitSHA)
	}
	return pass(NameA16, e.Cell, e.Shape,
		fmt.Sprintf("forced remove of a running container: network %s no longer lists its endpoint, and its lease for %s (mac %s, hostname %q) is still held exactly as release_lease=never documents", e.Network, addr, mac, lease.Hostname),
		ev, e.GitSHA)
}
