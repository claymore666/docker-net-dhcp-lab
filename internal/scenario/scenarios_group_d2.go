package scenario

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group D part 2 (#23): rows that toggle the segment's RAs or the
// source's DHCPv6 server (D3, D4) and the PD and PREF64 rows of group F.
// Each toggle's restore is deferred into fRestoreInto, so a source left
// changed turns the verdict BLOCKED (DESIGN-23d, "Ready/Recover").

// v6Plan is what a row advertises beside the cell's Subnet6 /64: the
// second PIO (D4), the PREF64 /96 and the PD pool, all inside
// the cell's /56 so no two cells overlap (DESIGN-23d, "RA/v6 source").
type v6Plan struct {
	Second, Pref64, PDPool netip.Prefix
}

func v6Derive(subnet6 string) (v6Plan, error) {
	p, err := netip.ParsePrefix(subnet6)
	if err != nil || !p.Addr().Is6() || p.Bits() != 64 {
		return v6Plan{}, fmt.Errorf("the cell's IPv6 subnet %q is not a /64", subnet6)
	}
	b := p.Addr().As16()
	if b[7] != 0 {
		return v6Plan{}, fmt.Errorf("the cell's IPv6 subnet %s does not start its /56 (low byte of the fourth group must be 00)", p)
	}
	at := func(lo byte, bits int) netip.Prefix {
		c := b
		c[7] = lo
		return netip.PrefixFrom(netip.AddrFrom16(c), bits)
	}
	return v6Plan{Second: at(0x01, 64), Pref64: at(0x64, 96), PDPool: at(0x80, 57)}, nil
}

// d2Gate is bIPAMNA, then dState, then the release a row's option needs (#821, #23).
func d2Gate(e Env, name string, since [3]int, why string) (Verdict, bool) {
	if v, ok := bIPAMNA(name, e); ok {
		return v, true
	}
	if v, stop := dState(e, name); stop {
		return v, true
	}
	present, err := clientHasFeature(e.PluginTag, since)
	if err != nil {
		return blocked(name, e.Cell, e.Shape, err.Error(), e.GitSHA), true
	}
	if !present {
		return na(name, e.Cell, e.Shape, why+"; this tag is older", e.GitSHA), true
	}
	return Verdict{}, false
}

// ipvlanSlaacNA: slaac and auto are refused on ipvlan, which D2 and D3a
// judge (plugin docs/reference.md, ipv6_mode) (#23 rows D2, D3a).
func ipvlanSlaacNA(name string, e Env) (Verdict, bool) {
	if e.Shape != ShapeIpvlan {
		return Verdict{}, false
	}
	return na(name, e.Cell, e.Shape, "ipv6_mode=slaac and auto are refused on ipvlan (plugin docs/reference.md); "+NameD2+" and "+NameD3a+" judge that refusal", e.GitSHA), true
}

// judgeIpvlanRefusal creates the row's network on ipvlan and judges the
// refusal; a create that went through is torn down again (#23).
func judgeIpvlanRefusal(ctx context.Context, e Env, name, suffix string, opts []string) Verdict {
	_, down, err := cNetwork(ctx, e, suffix, opts)
	down()
	return fFinish(name, e, judgeRefused(strings.Join(opts, " "), err), "", map[string]string{})
}

// once makes a restore safe to call early and again from the defer (#23).
func once(f func(context.Context) error) func(context.Context) error {
	done := false
	var err error
	return func(c context.Context) error {
		if !done {
			done = true
			if f != nil {
				err = f(c)
			}
		}
		return err
	}
}

func setRA(ctx context.Context, e Env, p sourceadapter.RAParams) (func(context.Context) error, error) {
	restore, err := e.Source.SetRA(ctx, p)
	return once(restore), err
}

// containerText runs one read-only command in the container and keeps
// its output as evidence under label (#23).
func containerText(ctx context.Context, e Env, scenario, label, name, cmd string, ev map[string]string) (string, error) {
	out, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker exec %s %s", name, cmd))
	if err != nil {
		return "", fmt.Errorf("docker exec %s %s: %w", name, cmd, err)
	}
	p := evidencePath(e, scenario, label)
	if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
		return "", err
	}
	ev[label] = p
	return out, nil
}

func (r dRead) d2Obs() d2Obs {
	return d2Obs{Msgs: r.msgs, RAs: r.ras, Leases: r.leases, MAC: r.mac, Start: r.start, Settled: r.settled, Inspect: r.inspect}
}

// d3Row is D3a and D3b: the RA set to want, one container on an auto
// network, the wire's flags proven, then judge (#23 rows D3a, D3b).
func d3Row(ctx context.Context, e Env, name string, want sourceadapter.RAParams, ready func([]DHCP6Msg, []RAMsg) bool, judge func(dRead) fOutcome) (v Verdict) {
	if v, stop := d2Gate(e, name, dSince, "ipv6_mode arrived in plugin v2.2.0 (#821)"); stop {
		return v
	}
	opts := []string{"ipv6_mode=auto"}
	if e.Shape == ShapeIpvlan {
		return judgeIpvlanRefusal(ctx, e, name, "d3", opts)
	}
	restore, err := setRA(ctx, e, want)
	defer fRestoreInto(bCleanupCtx(ctx), e, name, restore, &v)
	if err != nil {
		return blocked(name, e.Cell, e.Shape, fmt.Sprintf("could not set the RA to M=%v A=%v: %v", want.Managed, want.Autonomous, err), e.GitSHA)
	}
	ev := map[string]string{}
	t0 := time.Now()
	net, down, err := cNetwork(ctx, e, "d3", opts)
	defer down()
	if err != nil {
		return fail(name, e.Cell, e.Shape, fmt.Sprintf("could not create the network (%v): %v", opts, err), nil, e.GitSHA)
	}
	defer removeContainer(bCleanupCtx(ctx), e.Host, containerName(e, name))
	r, startErr, err := dCollect(ctx, e, name, net, t0, ready, ev)
	if err != nil {
		return blocked(name, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if startErr != nil {
		return fail(name, e.Cell, e.Shape, fmt.Sprintf("container did not start (%v): %v", opts, startErr), nil, e.GitSHA)
	}
	flags, ok := judgeRAFlags(r.ras, want)
	if !ok {
		return fFinish(name, e, flags, "", ev)
	}
	return fFinish(name, e, judge(r), "wire "+flags.Reason, ev)
}

// runD3a -- auto with M=1 A=0: "the managed-address flag means DHCPv6"
// (docs, ipv6_mode), judged as D1; on ipvlan the create is refused (#23 row D3a).
func runD3a(ctx context.Context, e Env) Verdict {
	return d3Row(ctx, e, NameD3a, sourceadapter.RAParams{Managed: true}, hasNAReply, func(r dRead) fOutcome {
		o, _ := judgeD1(r.d1Obs(ctx, e))
		return o
	})
}

// runD3b -- auto with M=0 A=1: "a clear flag means the prefix", judged
// as D2 (#23 row D3b).
func runD3b(ctx context.Context, e Env) Verdict {
	return d3Row(ctx, e, NameD3b, sourceadapter.RAParams{Autonomous: true}, hasAutoRA, func(r dRead) fOutcome {
		return judgeD2(r.d2Obs())
	})
}

// runD3c -- M=1 A=1 with the source's DHCPv6 server stopped, three legs
// on one network name, removed between them (which also clears the
// plugin's DHCPV6_ABSENCE_MEMORY, docs): auto falls back to the prefix,
// auto with ipv6_auto_strict=true fails the endpoint, dhcp fails it (#23 row D3c).
func runD3c(ctx context.Context, e Env) (v Verdict) {
	if v, stop := d2Gate(e, NameD3c, dSince, "ipv6_mode arrived in plugin v2.2.0 (#821)"); stop {
		return v
	}
	if e.Shape == ShapeIpvlan {
		return judgeIpvlanRefusal(ctx, e, NameD3c, "d3", []string{"ipv6_mode=auto"})
	}
	if !serverHas(e.Source, sourceadapter.CapV6ServerStop) {
		return na(NameD3c, e.Cell, e.Shape, capabilityNAReason[sourceadapter.CapV6ServerStop], e.GitSHA)
	}
	restore, err := e.Source.StopV6Server(ctx)
	defer fRestoreInto(bCleanupCtx(ctx), e, NameD3c, restore, &v)
	if err != nil {
		return blocked(NameD3c, e.Cell, e.Shape, fmt.Sprintf("could not stop the source's DHCPv6 server: %v", err), e.GitSHA)
	}
	ev := map[string]string{}
	auto, err := d3cAutoLeg(ctx, e, ev)
	if err != nil {
		return blocked(NameD3c, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if auto.Result != PASS {
		return fFinish(NameD3c, e, auto, "auto leg", ev)
	}
	reasons := []string{"auto: " + auto.Reason}
	for _, leg := range [][]string{{"ipv6_mode=auto", "ipv6_auto_strict=true"}, {"ipv6_mode=dhcp"}} {
		o, err := d3cFailLeg(ctx, e, leg, ev)
		if err != nil {
			return blocked(NameD3c, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
		if o.Result != PASS {
			return fFinish(NameD3c, e, o, strings.Join(reasons, "; "), ev)
		}
		reasons = append(reasons, o.Reason)
	}
	return fFinish(NameD3c, e, fOK("%s", strings.Join(reasons, "; ")), "", ev)
}

func d3cAutoLeg(ctx context.Context, e Env, ev map[string]string) (fOutcome, error) {
	before, err := pluginHealthBody(ctx, e.Host, evidencePath(e, NameD3c, "plugin-health-before"))
	if err != nil {
		return fOutcome{}, err
	}
	ev["plugin-health-before"] = evidencePath(e, NameD3c, "plugin-health-before")
	opts := []string{"ipv6_mode=auto"}
	t0 := time.Now()
	net, down, err := cNetwork(ctx, e, "d3", opts)
	defer down()
	if err != nil {
		return fFail("could not create the network (%v): %v", opts, err), nil
	}
	defer removeContainer(bCleanupCtx(ctx), e.Host, containerName(e, NameD3c))
	r, startErr, err := dCollectWith(ctx, e, NameD3c, net, t0, hasAutoRA, ev, false)
	if err != nil {
		return fOutcome{}, err
	}
	if startErr != nil {
		return fFail("the container did not start under ipv6_mode=auto with a silent DHCPv6 server; the docs fall back to the prefix: %v", startErr), nil
	}
	if flags, ok := judgeRAFlags(r.ras, sourceadapter.BaselineRA); !ok {
		return flags, nil
	}
	after, err := pluginHealthBody(ctx, e.Host, evidencePath(e, NameD3c, "plugin-health"))
	if err != nil {
		return fOutcome{}, err
	}
	ev["plugin-health"] = evidencePath(e, NameD3c, "plugin-health")
	fallbacks := "unreadable"
	if b, ok := healthCounter(before, "dhcpv6_auto_fallbacks"); ok {
		if a, ok := healthCounter(after, "dhcpv6_auto_fallbacks"); ok {
			fallbacks = fmt.Sprintf("+%d", a-b)
		}
	}
	return judgeD3cAuto(r.d2Obs(), fallbacks), nil
}

func d3cFailLeg(ctx context.Context, e Env, opts []string, ev map[string]string) (fOutcome, error) {
	t0 := time.Now()
	net, down, err := cNetwork(ctx, e, "d3", opts)
	defer down()
	if err != nil {
		return fFail("could not create the network (%v): %v", opts, err), nil
	}
	name := containerName(e, NameD3c)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	_, _, _, startErr := runContainer(ctx, e.Host, e.Shape, net, name)
	leg := strings.TrimPrefix(opts[len(opts)-1], "ipv6_")
	var settled []addr6
	var msgs []DHCP6Msg
	if startErr == nil {
		r, err := readAddrs(ctx, e, NameD3c, "addrs-"+leg, name, "-", ev)
		if err != nil {
			return fOutcome{}, err
		}
		settled = r.Addrs
	} else {
		// A failed container has no MAC to filter on, so the whole link
		// since this leg's network create is read; one container per row
		// bounds it (DESIGN-23d defeat A2, #23).
		solicited := func(ms []DHCP6Msg, _ []RAMsg) bool {
			return slices.ContainsFunc(ms, func(m DHCP6Msg) bool { return m.Type == "SOLICIT" })
		}
		if msgs, _, err = dCapture(ctx, e, NameD3c, "capture-v6-"+leg, "*", t0, solicited, ev); err != nil {
			return fOutcome{}, fmt.Errorf("could not read the capture: %w", err)
		}
	}
	return judgeD3cFails(strings.Join(opts, " "), startErr, settled, msgs), nil
}

// runD3d -- the RA's managed flag turned on while an auto endpoint runs.
// The docs state no rule for it, so the row records what the container
// did and is not judged (DESIGN-23d row D3d); the flip itself must be on
// the wire or the record means nothing.
func runD3d(ctx context.Context, e Env) (v Verdict) {
	if v, stop := d2Gate(e, NameD3d, dSince, "ipv6_mode arrived in plugin v2.2.0 (#821)"); stop {
		return v
	}
	if v, ok := ipvlanSlaacNA(NameD3d, e); ok {
		return v
	}
	want := sourceadapter.RAParams{Autonomous: true}
	restore, err := setRA(ctx, e, want)
	defer fRestoreInto(bCleanupCtx(ctx), e, NameD3d, restore, &v)
	if err != nil {
		return blocked(NameD3d, e.Cell, e.Shape, fmt.Sprintf("could not set the RA to M=0 A=1: %v", err), e.GitSHA)
	}
	ev := map[string]string{}
	t0 := time.Now()
	net, down, err := cNetwork(ctx, e, "d3", []string{"ipv6_mode=auto"})
	defer down()
	if err != nil {
		return fail(NameD3d, e.Cell, e.Shape, fmt.Sprintf("could not create the network (ipv6_mode=auto): %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameD3d)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	r, startErr, err := dCollect(ctx, e, NameD3d, net, t0, hasAutoRA, ev)
	if err != nil {
		return blocked(NameD3d, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if startErr != nil {
		return fail(NameD3d, e.Cell, e.Shape, fmt.Sprintf("container did not start (ipv6_mode=auto, M=0 A=1): %v", startErr), nil, e.GitSHA)
	}
	if flags, ok := judgeRAFlags(r.ras, want); !ok {
		return fFinish(NameD3d, e, flags, "before the flip", ev)
	}
	if err := restore(ctx); err != nil {
		return blocked(NameD3d, e.Cell, e.Shape, fmt.Sprintf("could not turn the managed flag on: %v", err), e.GitSHA)
	}
	tFlip := time.Now()
	if err := sleepCtx(ctx, fCaptureWait); err != nil {
		return blocked(NameD3d, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	after, err := readAddrs(ctx, e, NameD3d, "addrs-after-flip", name, "-", ev)
	if err != nil {
		return blocked(NameD3d, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	ll, _ := linkLocal(r.start.Addrs)
	all := func([]DHCP6Msg, []RAMsg) bool { return true }
	msgs, ras, err := dCapture(ctx, e, NameD3d, "capture-v6-after-flip", v6Ident(r.mac, ll), tFlip, all, ev)
	if err != nil {
		return blocked(NameD3d, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	return d3dRecord(NameD3d, e, msgs, ras, r.settled.Addrs, after.Addrs)
}

// d3dRecord is D3d's verdict: BLOCKED unless an RA after the flip
// carries M=1, else N/A carrying the record (an N/A holds no evidence,
// verdict.go) (#23 row D3d).
func d3dRecord(name string, e Env, msgs []DHCP6Msg, ras []RAMsg, before, after []addr6) Verdict {
	flipped := false
	for _, ra := range ras {
		flipped = flipped || ra.Managed
	}
	if !flipped {
		return blocked(name, e.Cell, e.Shape, fmt.Sprintf("no RA with M=1 on the wire after the flip (%d RAs); nothing was recorded", len(ras)), e.GitSHA)
	}
	var types []string
	for _, m := range msgs {
		types = append(types, m.Type)
	}
	return na(name, e.Cell, e.Shape, fmt.Sprintf("recorded, not judged (the docs state no rule for a runtime flip): RA M 0 to 1; the container then sent %v and held %v (before %v)",
		collapse(types), addrList(after), addrList(before)), e.GitSHA)
}

func addrList(as []addr6) []string {
	var out []string
	for _, a := range globals(as) {
		out = append(out, a.Addr.String())
	}
	return out
}

func hasTwoAutoPIOs(_ []DHCP6Msg, ras []RAMsg) bool {
	for _, ra := range ras {
		if len(autoPrefixes([]RAMsg{ra})) >= 2 {
			return true
		}
	}
	return false
}

// d4Row is D4, D4m and D4b: a second autonomous PIO beside the cell's,
// one container on a slaac network (-d4) (#23 row D4).
func d4Row(ctx context.Context, e Env, name string) (v Verdict) {
	if v, stop := d2Gate(e, name, dSince, "ipv6_mode arrived in plugin v2.2.0 (#821)"); stop {
		return v
	}
	if v, ok := ipvlanSlaacNA(name, e); ok {
		return v
	}
	plan, err := v6Derive(e.Subnet6)
	if err != nil {
		return blocked(name, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	first, _ := netip.ParsePrefix(e.Subnet6)
	want := sourceadapter.RAParams{Autonomous: true, Second: plan.Second}
	restore, err := setRA(ctx, e, want)
	defer fRestoreInto(bCleanupCtx(ctx), e, name, restore, &v)
	if err != nil {
		return blocked(name, e.Cell, e.Shape, fmt.Sprintf("could not advertise the second prefix %s: %v", plan.Second, err), e.GitSHA)
	}
	opts := []string{"ipv6_mode=slaac"}
	var main netip.Prefix
	if name == NameD4m {
		main = plan.Second
		opts = append(opts, "ipv6_main_prefix="+main.String())
	}
	ev := map[string]string{}
	t0 := time.Now()
	net, down, err := cNetwork(ctx, e, "d4", opts)
	defer down()
	if err != nil {
		return fail(name, e.Cell, e.Shape, fmt.Sprintf("could not create the network (%v): %v", opts, err), nil, e.GitSHA)
	}
	cname := containerName(e, name)
	defer removeContainer(bCleanupCtx(ctx), e.Host, cname)
	r, startErr, err := dCollect(ctx, e, name, net, t0, hasTwoAutoPIOs, ev)
	if err != nil {
		return blocked(name, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if startErr != nil {
		return fail(name, e.Cell, e.Shape, fmt.Sprintf("container did not start (%v): %v", opts, startErr), nil, e.GitSHA)
	}
	if flags, ok := judgeRAFlags(r.ras, want); !ok {
		return fFinish(name, e, flags, "", ev)
	}
	o := judgeD4(d4Obs{d2Obs: r.d2Obs(), Main: main})
	if name != NameD4b || o.Result != PASS {
		return fFinish(name, e, o, "", ev)
	}
	return d4bWithdraw(ctx, e, cname, r, first, plan.Second, restore, o.Reason, ev)
}

func runD4(ctx context.Context, e Env) Verdict  { return d4Row(ctx, e, NameD4) }
func runD4m(ctx context.Context, e Env) Verdict { return d4Row(ctx, e, NameD4m) }
func runD4b(ctx context.Context, e Env) Verdict { return d4Row(ctx, e, NameD4b) }

// d4bPoll is how long D4b waits for the container to act on an RA: two
// of the cell's RA intervals and the plugin's refresh (#23 row D4b).
const d4bPoll = 45 * time.Second

// d4bRAWait is the least D4b waits after the expiry RA is set, so the
// capture holds one: the cells' radvd and dnsmasq send every 10 s at most
// (cloud-init templates, MaxRtrAdvInterval and ra-param) (#23 row D4b).
const d4bRAWait = 25 * time.Second

// d4bWithdraw drops the second PIO (the baseline again), then advertises
// it with valid lifetime 0; dnsmasq cannot send the second
// (ErrRAUnsupported), so there the drop is judged alone (#23 row D4b).
func d4bWithdraw(ctx context.Context, e Env, cname string, r dRead, first, second netip.Prefix, drop func(context.Context) error, d4 string, ev map[string]string) (v Verdict) {
	if err := drop(ctx); err != nil {
		return blocked(NameD4b, e.Cell, e.Shape, fmt.Sprintf("could not drop the second prefix: %v", err), e.GitSHA)
	}
	a2, _ := eui64(second, r.mac)
	tDrop := time.Now()
	addrs, routes, ras, err := d4bAwait(ctx, e, cname, r, "drop", tDrop, func(as []addr6, _ string) bool {
		_, on := findAddr6(as, a2)
		return !on
	}, ev)
	if err != nil {
		return blocked(NameD4b, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	routeKept, err := clientHasFeature(e.PluginTag, [3]int{2, 2, 3})
	if err != nil {
		return blocked(NameD4b, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	o := judgeD4bDrop(ras, addrs, routes, first, second, r.mac, routeKept)
	if o.Result != PASS {
		return fFinish(NameD4b, e, o, d4, ev)
	}
	restore, err := setRA(ctx, e, sourceadapter.RAParams{Autonomous: true, Second: second, SecondExpired: true})
	defer fRestoreInto(bCleanupCtx(ctx), e, NameD4b, restore, &v)
	if errors.Is(err, sourceadapter.ErrRAUnsupported) {
		return fFinish(NameD4b, e, o, d4+"; the valid-lifetime-0 step is not run, the source cannot send it ("+err.Error()+")", ev)
	}
	if err != nil {
		return blocked(NameD4b, e.Cell, e.Shape, fmt.Sprintf("could not advertise %s with valid lifetime 0: %v", second, err), e.GitSHA)
	}
	tExp := time.Now()
	addrs, routes, ras, err = d4bAwait(ctx, e, cname, r, "expired", tExp, func(_ []addr6, rt string) bool {
		_, on := routeFor(rt, second)
		return !on && time.Since(tExp) > d4bRAWait
	}, ev)
	if err != nil {
		return blocked(NameD4b, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	x := judgeD4bExpired(ras, addrs, routes, second, r.mac)
	if x.Result != PASS {
		return fFinish(NameD4b, e, x, d4+"; "+o.Reason, ev)
	}
	return fFinish(NameD4b, e, fOK("%s; %s", o.Reason, x.Reason), d4, ev)
}

// d4bAwait reads the container every 3 s until done or d4bPoll, then the
// capture from `from` on (#23 row D4b).
func d4bAwait(ctx context.Context, e Env, cname string, r dRead, step string, from time.Time, done func([]addr6, string) bool, ev map[string]string) ([]addr6, string, []RAMsg, error) {
	var as []addr6
	var routes string
	var err error
	for end := from.Add(d4bPoll); ; {
		if as, err = containerAddrs6(ctx, e.Host, cname); err != nil {
			return nil, "", nil, err
		}
		if routes, err = e.Host.Run(ctx, fmt.Sprintf("sudo docker exec %s ip -6 route show", cname)); err != nil {
			return nil, "", nil, fmt.Errorf("docker exec %s ip -6 route: %w", cname, err)
		}
		if done(as, routes) || time.Now().After(end) {
			break
		}
		if err := sleepCtx(ctx, 3*time.Second); err != nil {
			return nil, "", nil, err
		}
	}
	p := evidencePath(e, NameD4b, "addrs-"+step)
	if err := writeAddrs6(p, as, strings.TrimSpace(routes)); err != nil {
		return nil, "", nil, err
	}
	ev["addrs-"+step] = p
	ll, _ := linkLocal(r.start.Addrs)
	all := func([]DHCP6Msg, []RAMsg) bool { return true }
	_, ras, err := dCapture(ctx, e, NameD4b, "capture-v6-"+step, v6Ident(r.mac, ll), from, all, ev)
	if err != nil {
		return nil, "", nil, fmt.Errorf("could not read the capture: %w", err)
	}
	return as, routes, ras, nil
}

// runF6 -- prefix delegation, ipv6_mode=dhcp with ipv6_pd=64 (v2.5.0,
// #214): kea and isc delegate from the cell's pool; dnsmasq declares no
// CapPD and is the documented no-prefix case; ipvlan refuses the option.
func runF6(ctx context.Context, e Env) (v Verdict) {
	if v, stop := d2Gate(e, NameF6, [3]int{2, 5, 0}, "ipv6_pd arrived in plugin v2.5.0 (#214)"); stop {
		return v
	}
	opts := []string{"ipv6_mode=dhcp", "ipv6_pd=64"}
	if e.Shape == ShapeIpvlan {
		return judgeIpvlanRefusal(ctx, e, NameF6, "f6", opts)
	}
	plan, err := v6Derive(e.Subnet6)
	if err != nil {
		return blocked(NameF6, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	serverPD := serverHas(e.Source, sourceadapter.CapPD)
	if serverPD {
		restore, err := fEnable(ctx, e, sourceadapter.FeaturePD, sourceadapter.FeatureParams{PDPool: plan.PDPool})
		defer fRestoreInto(bCleanupCtx(ctx), e, NameF6, restore, &v)
		if err != nil {
			return blocked(NameF6, e.Cell, e.Shape, fmt.Sprintf("could not turn prefix delegation on at the source: %v", err), e.GitSHA)
		}
	}
	r, ev, cleanup, bad, ok := dhcp6Row(ctx, e, NameF6, "f6", opts)
	defer cleanup(&v)
	if !ok {
		return bad
	}
	o := r.d1Obs(ctx, e)
	routes, err := containerText(ctx, e, NameF6, "routes-v6", containerName(e, NameF6), "ip -6 route show", ev)
	if err != nil {
		return blocked(NameF6, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	hp := evidencePath(e, NameF6, "plugin-health")
	h, found, err := pluginHealth(ctx, e.Host, r.endpointID, hp)
	if err != nil {
		return blocked(NameF6, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	ev["plugin-health"] = hp
	return fFinish(NameF6, e, judgeF6(o, serverPD, plan.PDPool, routes, h, found), "", ev)
}

// f7Settle is how long the PREF64 row lets the plugin act on the first
// RA carrying PREF64 before it reads the container and /Plugin.Health:
// the cells send an RA every 10 s at most (cloud-init templates, #23).
var f7Settle = 15 * time.Second

// runF7 -- PREF64 (v2.4.0): the container starts on the baseline RA and
// its routes and resolv.conf are read; then kea and isc add the cell's
// /96 to the RA, dnsmasq's RA cannot carry it and is the negative case
// (DESIGN-23d row F7-pref64).
func runF7(ctx context.Context, e Env) (v Verdict) {
	if v, stop := d2Gate(e, NameF7, fSince4, "nat64_prefixes arrived in plugin v2.4.0"); stop {
		return v
	}
	if v, ok := ipvlanSlaacNA(NameF7, e); ok {
		return v
	}
	plan, err := v6Derive(e.Subnet6)
	if err != nil {
		return blocked(NameF7, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	serverP := serverHas(e.Source, sourceadapter.CapPref64)
	const opt = "ipv6_mode=slaac"
	ev := map[string]string{}
	t0 := time.Now()
	net, down, err := cNetwork(ctx, e, "f7", []string{opt})
	defer down()
	if err != nil {
		return fail(NameF7, e.Cell, e.Shape, fmt.Sprintf("could not create the network (%s): %v", opt, err), nil, e.GitSHA)
	}
	name := containerName(e, NameF7)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	r, startErr, err := dCollect(ctx, e, NameF7, net, t0, hasAutoRA, ev)
	if err != nil {
		return blocked(NameF7, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if startErr != nil {
		return fail(NameF7, e.Cell, e.Shape, fmt.Sprintf("container did not start (%s): %v", opt, startErr), nil, e.GitSHA)
	}
	if d2 := judgeD2(r.d2Obs()); d2.Result != PASS {
		return fFinish(NameF7, e, d2, "", ev)
	}
	var rd f7Reads
	if rd.BaseRoutes, err = containerText(ctx, e, NameF7, "routes-v6-before", name, "ip -6 route show", ev); err != nil {
		return blocked(NameF7, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	if rd.BaseResolv, err = containerText(ctx, e, NameF7, "resolv-conf-before", name, "cat /etc/resolv.conf", ev); err != nil {
		return blocked(NameF7, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	tSet := time.Now()
	if serverP {
		p := sourceadapter.BaselineRA
		p.Pref64 = plan.Pref64
		restore, err := setRA(ctx, e, p)
		defer fRestoreInto(bCleanupCtx(ctx), e, NameF7, restore, &v)
		if err != nil {
			return blocked(NameF7, e.Cell, e.Shape, fmt.Sprintf("could not advertise PREF64 %s: %v", plan.Pref64, err), e.GitSHA)
		}
	}
	ll, _ := linkLocal(r.start.Addrs)
	ras, err := f7Read(ctx, e, name, r, v6Ident(r.mac, ll), tSet, serverP, &rd, ev)
	if err != nil {
		return blocked(NameF7, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	return fFinish(NameF7, e, judgeF7(ras, serverP, rd), "", ev)
}

// f7Read waits for an RA after tSet (one carrying PREF64 when the source
// was set to send it), lets the plugin act on it, then reads the
// container and /Plugin.Health; it returns the RAs since tSet (#23 row F7-pref64).
func f7Read(ctx context.Context, e Env, name string, r dRead, ident string, tSet time.Time, serverP bool, rd *f7Reads, ev map[string]string) ([]RAMsg, error) {
	ready := func(_ []DHCP6Msg, ras []RAMsg) bool {
		return slices.ContainsFunc(ras, func(ra RAMsg) bool { return !serverP || len(ra.Pref64) > 0 })
	}
	if _, _, err := dCapture(ctx, e, NameF7, "capture-v6-pref64-wait", ident, tSet, ready, ev); err != nil {
		return nil, fmt.Errorf("could not read the capture: %w", err)
	}
	if err := sleepCtx(ctx, f7Settle); err != nil {
		return nil, err
	}
	after, err := readAddrs(ctx, e, NameF7, "addrs-after", name, "-", ev)
	if err != nil {
		return nil, err
	}
	rd.Addrs = after.Addrs
	if rd.Routes, err = containerText(ctx, e, NameF7, "routes-v6-after", name, "ip -6 route show", ev); err != nil {
		return nil, err
	}
	if rd.Resolv, err = containerText(ctx, e, NameF7, "resolv-conf-after", name, "cat /etc/resolv.conf", ev); err != nil {
		return nil, err
	}
	hp := evidencePath(e, NameF7, "plugin-health")
	if rd.Health, rd.Found, err = pluginHealth(ctx, e.Host, r.endpointID, hp); err != nil {
		return nil, err
	}
	ev["plugin-health"] = hp
	all := func([]DHCP6Msg, []RAMsg) bool { return true }
	_, ras, err := dCapture(ctx, e, NameF7, "capture-v6-pref64", ident, tSet, all, ev)
	if err != nil {
		return nil, fmt.Errorf("could not read the capture: %w", err)
	}
	return ras, nil
}
