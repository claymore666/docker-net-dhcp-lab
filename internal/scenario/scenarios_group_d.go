package scenario

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group D (#23) and the IPv6 rows of group F: each row creates its own
// network with the IPv6 option, starts one container and judges it on
// the M=1 A=1 baseline the source cell advertises. An IPAM shape refuses
// a second network, so D1, D1b and D2 recreate the cell's main network
// with the option instead (dNetwork); the other rows are N/A there.

// dState gates every row on the release that gave the client ipv6_mode.
func dState(e Env, name string) (Verdict, bool) {
	present, err := clientHasFeature(e.PluginTag, dSince)
	if err != nil {
		return blocked(name, e.Cell, e.Shape, err.Error(), e.GitSHA), true
	}
	if !present {
		return na(name, e.Cell, e.Shape, "ipv6_mode arrived in plugin v2.2.0 (#821); this tag is older", e.GitSHA), true
	}
	return Verdict{}, false
}

// dRead is one container's reads after its endpoint came up.
type dRead struct {
	mac, endpointID string
	start, settled  d6Read
	inspect         string
	route           netip.Addr
	hasRoute        bool
	msgs            []DHCP6Msg
	ras             []RAMsg
	leases          []sourceadapter.Lease6
}

func hasNAReply(msgs []DHCP6Msg, _ []RAMsg) bool {
	for _, m := range msgs {
		if m.Type == "REPLY" && HasAddr(m.NA) {
			return true
		}
	}
	return false
}

func hasAutoRA(_ []DHCP6Msg, ras []RAMsg) bool {
	for _, ra := range ras {
		for _, p := range ra.PIOs {
			if p.Auto {
				return true
			}
		}
	}
	return false
}

func firstEventAt(msgs []DHCP6Msg, ras []RAMsg, lease func([]DHCP6Msg, []RAMsg) bool) time.Time {
	for _, m := range msgs {
		if lease([]DHCP6Msg{m}, nil) {
			return m.At
		}
	}
	for _, ra := range ras {
		if lease(nil, []RAMsg{ra}) {
			return ra.At
		}
	}
	return time.Now()
}

func readAddrs(ctx context.Context, e Env, scenario, label, name string, route string, ev map[string]string) (d6Read, error) {
	at := time.Now()
	as, err := containerAddrs6(ctx, e.Host, name)
	if err != nil {
		return d6Read{}, err
	}
	p := evidencePath(e, scenario, label)
	if err := writeAddrs6(p, as, route); err != nil {
		return d6Read{}, err
	}
	ev[label] = p
	return d6Read{At: at, Addrs: as}, nil
}

// dCollect starts the container on net and reads it at start and once
// settled: dSettle after the first lease event, the Reply for DHCPv6
// and the RA for SLAAC (design row note "Settled"). A nil error with a
// non-nil startErr is a container that did not start.
func dCollect(ctx context.Context, e Env, scenario, net string, t0 time.Time, lease func([]DHCP6Msg, []RAMsg) bool, ev map[string]string) (r dRead, startErr, err error) {
	return dCollectWith(ctx, e, scenario, net, t0, lease, ev, true)
}

// dCollectWith is dCollect; leases false skips the source's DHCPv6 table,
// which kea serves from the daemon StopV6Server stopped (D3c).
func dCollectWith(ctx context.Context, e Env, scenario, net string, t0 time.Time, lease func([]DHCP6Msg, []RAMsg) bool, ev map[string]string, leases bool) (r dRead, startErr, err error) {
	name := containerName(e, scenario)
	r.mac, _, r.endpointID, startErr = runContainer(ctx, e.Host, e.Shape, net, name)
	if startErr != nil {
		return r, startErr, nil
	}
	if r.start, err = readAddrs(ctx, e, scenario, "addrs-start", name, "-", ev); err != nil {
		return r, nil, err
	}
	ll, _ := linkLocal(r.start.Addrs)
	ident := v6Ident(r.mac, ll)
	msgs, ras, err := dCapture(ctx, e, scenario, "capture-v6-lease", ident, t0, lease, ev)
	if err != nil {
		return r, nil, fmt.Errorf("could not read the capture: %w", err)
	}
	if err := sleepUntil(ctx, firstEventAt(msgs, ras, lease).Add(dSettle)); err != nil {
		return r, nil, err
	}
	gw, ok, routeText, err := containerRoute6(ctx, e.Host, name)
	if err != nil {
		return r, nil, err
	}
	r.route, r.hasRoute = gw, ok
	if r.settled, err = readAddrs(ctx, e, scenario, "addrs-settled", name, routeText, ev); err != nil {
		return r, nil, err
	}
	if r.inspect, err = inspectField(ctx, e.Host, name, "GlobalIPv6Address"); err != nil {
		return r, nil, err
	}
	if leases {
		if r.leases, err = e.Source.Leases6(ctx); err != nil {
			return r, nil, fmt.Errorf("could not read the source's DHCPv6 table: %w", err)
		}
	}
	all := func([]DHCP6Msg, []RAMsg) bool { return true }
	if r.msgs, r.ras, err = dCapture(ctx, e, scenario, "capture-v6", ident, t0, all, ev); err != nil {
		return r, nil, fmt.Errorf("could not read the capture: %w", err)
	}
	return r, nil, nil
}

func (r dRead) d1Obs(ctx context.Context, e Env) d1Obs {
	o := d1Obs{Msgs: r.msgs, RAs: r.ras, Leases: r.leases, Start: r.start, Settled: r.settled,
		Inspect: r.inspect, Route: r.route, HasRoute: r.hasRoute}
	if x, _, ok := exchange6(r.msgs); ok {
		na, _ := firstAddr(x.Reply.NA)
		_, o.PingErr = reachableWithRetry(ctx, e.Source, na.Addr.String())
	} else {
		o.PingErr = errors.New("no lease to ping")
	}
	return o
}

// dhcp6Row is D1, D1b and the DHCPv6 rapid commit and temporary address
// rows: one container on a DHCPv6 network.
// cleanup is never nil; the caller defers it, so the ping and the health
// read still see the container.
func dhcp6Row(ctx context.Context, e Env, scenario, suffix string, opts []string) (r dRead, ev map[string]string, cleanup func(*Verdict), v Verdict, ok bool) {
	ev = map[string]string{}
	t0 := time.Now().Add(-2 * time.Second)
	net, down, err := dNetwork(ctx, e, scenario, suffix, opts)
	cleanup = func(v *Verdict) {
		removeContainer(bCleanupCtx(ctx), e.Host, containerName(e, scenario))
		down(v)
	}
	if err != nil {
		return r, ev, cleanup, dCreateFailed(e, scenario, opts, err), false
	}
	r, startErr, err := dCollect(ctx, e, scenario, net, t0, hasNAReply, ev)
	if err != nil {
		return r, ev, cleanup, blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA), false
	}
	if startErr != nil {
		return r, ev, cleanup, fail(scenario, e.Cell, e.Shape, fmt.Sprintf("container did not start (%v): %v", opts, startErr), nil, e.GitSHA), false
	}
	return r, ev, cleanup, Verdict{}, true
}

func runD1Like(ctx context.Context, e Env, scenario, suffix, opt string) (v Verdict) {
	if v, stop := dState(e, scenario); stop {
		return v
	}
	r, ev, cleanup, bad, ok := dhcp6Row(ctx, e, scenario, suffix, []string{opt})
	defer cleanup(&v)
	if !ok {
		return bad
	}
	o, _ := judgeD1(r.d1Obs(ctx, e))
	return fFinish(scenario, e, o, opt, ev)
}

// runD1 -- DHCPv6 lease with ipv6_mode=dhcp.
func runD1(ctx context.Context, e Env) Verdict {
	return runD1Like(ctx, e, NameD1, "d1", "ipv6_mode=dhcp")
}

// runD1b -- the same with ipv6=true, documented as "the short spelling
// of `ipv6_mode=dhcp`" (#1125 is the pair that answered differently).
func runD1b(ctx context.Context, e Env) Verdict {
	return runD1Like(ctx, e, NameD1b, "d1b", "ipv6=true")
}

// raOff stops the segment's RAs and returns the time after which the
// capture must hold none; radvd's final RA lands before it.
func raOff(ctx context.Context, e Env) (time.Time, func(context.Context) error, error) {
	restore, err := e.Source.SetRA(ctx, sourceadapter.RAParams{Off: true})
	if err != nil {
		return time.Time{}, restore, fmt.Errorf("could not stop the RAs at the source: %w", err)
	}
	return time.Now().Add(2 * time.Second), restore, nil
}

// noRARow is D1c and D2b: RAs off, one container on a network with opt.
func noRARow(ctx context.Context, e Env, scenario, suffix, opt string) (v Verdict) {
	if v, ok := bIPAMNA(scenario, e); ok {
		return v
	}
	if v, stop := dState(e, scenario); stop {
		return v
	}
	tOff, restore, err := raOff(ctx, e)
	defer fRestoreInto(bCleanupCtx(ctx), e, scenario, restore, &v)
	if err != nil {
		return blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	ev := map[string]string{}
	net, down, err := cNetwork(ctx, e, suffix, []string{opt})
	defer down()
	if err != nil {
		return fail(scenario, e.Cell, e.Shape, fmt.Sprintf("could not create the network (%s): %v", opt, err), nil, e.GitSHA)
	}
	name := containerName(e, scenario)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	mac, _, _, startErr := runContainer(ctx, e.Host, e.Shape, net, name)
	var settled d6Read
	var inspect string
	ident := "-"
	if startErr == nil {
		if err := sleepCtx(ctx, dSettle); err != nil {
			return blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
		if settled, err = readAddrs(ctx, e, scenario, "addrs-settled", name, "-", ev); err != nil {
			return blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
		if inspect, err = inspectField(ctx, e.Host, name, "GlobalIPv6Address"); err != nil {
			return blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
		ll, _ := linkLocal(settled.Addrs)
		ident = v6Ident(mac, ll)
	}
	msgs, ras, err := dCapture(ctx, e, scenario, "capture-v6", ident, tOff, func([]DHCP6Msg, []RAMsg) bool { return true }, ev)
	if err != nil {
		return blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	if o, ok := judgeNoRA(ras); !ok {
		return fFinish(scenario, e, o, "", ev)
	}
	if scenario == NameD2b {
		return fFinish(scenario, e, judgeEndpointFails(startErr), opt, ev)
	}
	return fFinish(scenario, e, judgeD1c(startErr, msgs, settled.Addrs, inspect), opt, ev)
}

// runD1c -- ipv6_mode=dhcp on a segment with no RA.
func runD1c(ctx context.Context, e Env) Verdict {
	return noRARow(ctx, e, NameD1c, "d1c", "ipv6_mode=dhcp")
}

// runD2b -- ipv6_mode=slaac on a segment with no RA; on ipvlan the
// network itself is refused, which D2 judges.
func runD2b(ctx context.Context, e Env) Verdict {
	if e.Shape == ShapeIpvlan {
		return na(NameD2b, e.Cell, e.Shape, "ipv6_mode=slaac is refused on ipvlan (plugin docs/reference.md); "+NameD2+" judges that refusal", e.GitSHA)
	}
	return noRARow(ctx, e, NameD2b, "d2b", "ipv6_mode=slaac")
}

// runD2 -- SLAAC with ipv6_mode=slaac; on ipvlan the create is refused.
func runD2(ctx context.Context, e Env) (v Verdict) {
	if v, stop := dState(e, NameD2); stop {
		return v
	}
	const opt = "ipv6_mode=slaac"
	ev := map[string]string{}
	t0 := time.Now().Add(-2 * time.Second)
	net, down, err := dNetwork(ctx, e, NameD2, "d2", []string{opt})
	defer down(&v)
	if e.Shape == ShapeIpvlan {
		return fFinish(NameD2, e, judgeRefused(opt, err), "", ev)
	}
	if err != nil {
		return dCreateFailed(e, NameD2, []string{opt}, err)
	}
	defer removeContainer(bCleanupCtx(ctx), e.Host, containerName(e, NameD2))
	r, startErr, err := dCollect(ctx, e, NameD2, net, t0, hasAutoRA, ev)
	if err != nil {
		return blocked(NameD2, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if startErr != nil {
		return fail(NameD2, e.Cell, e.Shape, fmt.Sprintf("container did not start (%s): %v", opt, startErr), nil, e.GitSHA)
	}
	o := judgeD2(d2Obs{Msgs: r.msgs, RAs: r.ras, Leases: r.leases, MAC: r.mac, Start: r.start, Settled: r.settled, Inspect: r.inspect})
	return fFinish(NameD2, e, o, "", ev)
}

// runF4 -- DHCPv6 rapid commit: with rapid_commit set the Solicit
// carries option 14 and a source with rapid commit on answers the Reply
// at once. All three sources support it; the source setting is put back
// by defer.
func runF4(ctx context.Context, e Env) (v Verdict) {
	if v, ok := bIPAMNA(NameF4, e); ok {
		return v
	}
	if v, stop := dState(e, NameF4); stop {
		return v
	}
	present, blk := clientState(e, NameF4)
	if blk != nil {
		return *blk
	}
	serverRapid := serverHas(e.Source, sourceadapter.CapRapidCommit6)
	if serverRapid {
		restore, err := fEnable(ctx, e, sourceadapter.FeatureRapidCommit6, sourceadapter.FeatureParams{})
		defer fRestoreInto(bCleanupCtx(ctx), e, NameF4, restore, &v)
		if err != nil {
			return blocked(NameF4, e.Cell, e.Shape, fmt.Sprintf("could not turn DHCPv6 rapid commit on at the source: %v", err), e.GitSHA)
		}
	}
	opts := []string{"ipv6_mode=dhcp"}
	if present {
		opts = append(opts, "rapid_commit=true")
	}
	r, ev, cleanup, bad, ok := dhcp6Row(ctx, e, NameF4, "f4", opts)
	defer cleanup(&v)
	if !ok {
		return bad
	}
	d1, x := judgeD1(r.d1Obs(ctx, e))
	if d1.Result != PASS {
		return fFinish(NameF4, e, d1, "", ev)
	}
	return fFinish(NameF4, e, judgeF4Wire(present, serverRapid, x), d1.Reason, ev)
}

// runF5 -- temporary address: with ipv6_temporary set the client asks
// for an IA_TA beside the IA_NA. Kea 2.6.3 grants none (CapTemporary6
// not declared), so on kea the documented fallback is what is judged.
func runF5(ctx context.Context, e Env) (v Verdict) {
	if v, ok := bIPAMNA(NameF5, e); ok {
		return v
	}
	if v, stop := dState(e, NameF5); stop {
		return v
	}
	present, blk := clientState(e, NameF5)
	if blk != nil {
		return *blk
	}
	serverTA := serverHas(e.Source, sourceadapter.CapTemporary6)
	if serverTA {
		restore, err := fEnable(ctx, e, sourceadapter.FeatureTemporary6, sourceadapter.FeatureParams{})
		defer fRestoreInto(bCleanupCtx(ctx), e, NameF5, restore, &v)
		if err != nil {
			return blocked(NameF5, e.Cell, e.Shape, fmt.Sprintf("could not turn temporary addresses on at the source: %v", err), e.GitSHA)
		}
	}
	opts := []string{"ipv6_mode=dhcp"}
	if present {
		opts = append(opts, "ipv6_temporary=true")
	}
	r, ev, cleanup, bad, ok := dhcp6Row(ctx, e, NameF5, "f5", opts)
	defer cleanup(&v)
	if !ok {
		return bad
	}
	o := r.d1Obs(ctx, e)
	hp := evidencePath(e, NameF5, "plugin-health")
	h, found, err := pluginHealth(ctx, e.Host, r.endpointID, hp)
	if err != nil && present {
		return blocked(NameF5, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if err == nil {
		ev["plugin-health"] = hp
	}
	return fFinish(NameF5, e, judgeF5(o, present, serverTA, found, h.IPv6TemporaryAddress), "", ev)
}

// errMainSwap marks a swap the lab could not set up, BLOCKED rather than a
// plugin FAIL (#23 group D part 2).
var errMainSwap = errors.New("the IPAM main-network swap")

// dCreateFailed is the verdict for a network dNetwork could not create.
func dCreateFailed(e Env, scenario string, opts []string, err error) Verdict {
	if errors.Is(err, errMainSwap) {
		return blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	return fail(scenario, e.Cell, e.Shape, fmt.Sprintf("could not create the network (%v): %v", opts, err), nil, e.GitSHA)
}

// dNetwork is the row's own network, cNetwork's; on an IPAM shape, which
// refuses a second network (bIPAMNA), the cell's main network is
// recreated with opts instead and down rebuilds it with NetworkUp
// (DESIGN-23d Notes, "IPAM shapes"; #23). A rebuild that fails turns
// the verdict BLOCKED, as fRestoreInto does, so the cell is recovered.
func dNetwork(ctx context.Context, e Env, scenario, suffix string, opts []string) (net string, down func(*Verdict), err error) {
	if e.Shape != ShapeBridgeIPAM && e.Shape != ShapeMacvlanIPAM {
		net, d, err := cNetwork(ctx, e, suffix, opts)
		return net, func(*Verdict) { d() }, err
	}
	// The rebuild is NetworkUp's, so it only restores the main network when
	// that is the network this run was given (#23 group D part 2).
	if want := NetworkName(e.Cell, e.Shape); e.Network != want {
		return "", func(*Verdict) {}, fmt.Errorf("%w: main network %s is not %s, the one NetworkUp rebuilds", errMainSwap, e.Network, want)
	}
	down = func(v *Verdict) {
		fRestoreInto(bCleanupCtx(ctx), e, scenario, func(c context.Context) error {
			_, err := NetworkUp(c, e.Host, e.Cell, e.Shape)
			return err
		}, v)
	}
	create, err := networkCreateCmd(e.Shape, e.Network, hostBridgeName(e.Network), opts)
	if err != nil {
		return "", down, err
	}
	if _, err := e.Host.Run(ctx, "sudo docker network rm "+e.Network); err != nil {
		return "", down, fmt.Errorf("%w: remove the main network %s: %v", errMainSwap, e.Network, err)
	}
	if _, err := e.Host.Run(ctx, create); err != nil {
		return "", down, err
	}
	return e.Network, down, nil
}
