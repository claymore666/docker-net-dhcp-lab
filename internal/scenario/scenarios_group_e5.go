package scenario

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// E5 (lab #15 soak): a small fleet holds its leases for Env.Soak's
// window at a shortened lease time. Two containers are enough to split
// ipvlan's shared hardware address by address and stay inside the
// segment pool (MinPoolAddresses).
const e5Fleet = 2

// e5LifeSlack keeps the soak containers alive past the window for the
// end checks; they are removed on return either way.
const e5LifeSlack = 10 * time.Minute

// e5Tune carries the waits and the clock that times each container's
// hold, so a unit test need not sit through the window.
type e5Tune struct {
	tail  time.Duration
	sleep func(context.Context, time.Duration) error
	now   func() time.Time
}

var e5Real = e5Tune{tail: 5 * time.Second, sleep: sleepCtx, now: time.Now}

// e5Start is what one container showed when it started.
type e5Start struct {
	name, mac, addr, endpoint, started, ident string
	at                                        time.Time
}

func runE5(ctx context.Context, e Env) Verdict { return runE5Tuned(ctx, e, e5Real) }

// runE5Tuned -- t.tail is the wait for the source's last journal lines.
func runE5Tuned(ctx context.Context, e Env, t e5Tune) Verdict {
	ev := map[string]string{}
	blk := func(format string, a ...any) Verdict {
		return blocked(NameE5, e.Cell, e.Shape, fmt.Sprintf(format, a...), e.GitSHA)
	}
	bad := func(format string, a ...any) Verdict {
		return fail(NameE5, e.Cell, e.Shape, fmt.Sprintf(format, a...), ev, e.GitSHA)
	}
	p, err := e.Soak.Resolved()
	if err != nil {
		return blk("%v", err)
	}
	if e.Capture == nil {
		return blk("no capture reader for this run: the wire side cannot be read")
	}
	restore, err := e.Source.ShortenLeaseTime(ctx, p.Lease)
	if err != nil {
		return bad("could not shorten the source's lease time: %v", err)
	}
	defer restore(bCleanupCtx(ctx))
	pid0, err := pluginPID(ctx, e.Host)
	if err != nil {
		return blk("could not read the plugin's process before the window: %v", err)
	}
	boot0, err := bootID(ctx, e.Host)
	if err != nil {
		return blk("could not read the docker host's boot id: %v", err)
	}
	since := time.Now().Add(-eSinceSlack).UTC()
	base, err := e.Source.ServerEvents(ctx, since, "")
	if err != nil {
		return blk("could not read the source's journal before the window: %v", err)
	}

	var fleet []e5Start
	for i := 1; i <= e5Fleet; i++ {
		s := e5Start{name: fmt.Sprintf("%s-%d", containerName(e, NameE5), i), at: t.now()}
		defer removeContainer(bCleanupCtx(ctx), e.Host, s.name)
		if s.mac, s.addr, s.endpoint, err = runContainerFor(ctx, e.Host, e.Shape, e.Network, s.name, p.Window+t.tail+e5LifeSlack); err != nil {
			return bad("container %s did not start: %v", s.name, err)
		}
		if s.started, err = containerStartedAt(ctx, e.Host, s.name); err != nil {
			return blk("%v", err)
		}
		if s.ident, err = cIdent(e.Shape, s.mac, s.endpoint); err != nil {
			return blk("no wire identity for %s: %v", s.name, err)
		}
		if v, ok := e5Leased(ctx, e, s, fmt.Sprintf("leases-start-%d", i), "at the start", ev); !ok {
			return v
		}
		fleet = append(fleet, s)
	}

	if err := t.sleep(ctx, p.Window); err != nil {
		return bad("%v", err)
	}
	end := t.now()

	var restarted, moved []string
	for _, s := range fleet {
		started, err := containerStartedAt(ctx, e.Host, s.name)
		if err != nil {
			return blk("%s is gone at the end of the window: %v", s.name, err)
		}
		_, addr, endpoint, err := inspectContainer(ctx, e.Host, e.Shape, s.name)
		if err != nil {
			return blk("could not inspect %s at the end of the window: %v", s.name, err)
		}
		switch {
		case started != s.started || endpoint != s.endpoint:
			restarted = append(restarted, fmt.Sprintf("%s (started %s, then %s)", s.name, s.started, started))
		case addr != s.addr:
			moved = append(moved, fmt.Sprintf("docker reports %s for %s, it started with %s", addr, s.name, s.addr))
		}
	}
	boot1, err := bootID(ctx, e.Host)
	if err != nil {
		return blk("could not read the docker host's boot id after the window: %v", err)
	}
	if boot1 != boot0 {
		return blk("the docker host rebooted inside the window (boot id %s, then %s)", boot0, boot1)
	}
	pid1, err := pluginPID(ctx, e.Host)
	if err != nil {
		return blk("could not read the plugin's process after the window: %v", err)
	}
	if len(restarted) > 0 {
		return blk("a soak container restarted inside the window, which the plugin cannot cause (plugin pid %s, then %s): %s", pid0, pid1, strings.Join(restarted, "; "))
	}
	if pid1 != pid0 {
		return bad("the plugin's process changed inside the window (pid %s, then %s): it restarted under running containers", pid0, pid1)
	}
	if len(moved) > 0 {
		return bad("%s", strings.Join(moved, "; "))
	}
	for i, s := range fleet {
		if v, ok := e5Leased(ctx, e, s, fmt.Sprintf("leases-end-%d", i+1), fmt.Sprintf("after the %s window", p.Window), ev); !ok {
			return v
		}
	}
	cut := t.now()
	if err := t.sleep(ctx, t.tail); err != nil {
		return bad("%v", err)
	}

	o := e5Obs{Lease: p.Lease, Window: p.Window, Cut: cut}
	macs := map[string]bool{}
	for i, s := range fleet {
		msgs, err := readCapture(ctx, e, NameE5, fmt.Sprintf("capture-%d", i+1), s.ident, ev)
		if err != nil {
			return blk("could not read the capture for %s: %v", s.name, err)
		}
		mac, err := e5WireMAC(e.Shape, s.mac, msgs)
		if err != nil {
			return blk("%s: %v", s.name, err)
		}
		macs[mac] = true
		o.Members = append(o.Members, e5Member{Name: s.name, MAC: mac, Addr: s.addr, Wire: msgs, Held: end.Sub(s.at)})
	}
	final, err := e.Source.ServerEvents(ctx, since, "")
	if err != nil {
		return blk("could not read the source's journal after the window: %v", err)
	}
	fb, ff := e5OfFleet(base, macs), e5OfFleet(final, macs)
	if len(ff) < len(fb) || !sameEvents(ff[:len(fb)], fb) {
		return blk("the source's journal for the fleet's hardware addresses changed under the baseline (%d lines before): the new lines cannot be told apart", len(fb))
	}
	o.Fresh = ff[len(fb):]
	if err := writeEvidenceE5(e, o, ev); err != nil {
		return bad("could not keep the evidence: %v", err)
	}
	return fFinish(NameE5, e, judgeE5(o), "", ev)
}

// e5Leased is the source's own table holding s's address, and the
// observer reaching it.
func e5Leased(ctx context.Context, e Env, s e5Start, label, when string, ev map[string]string) (Verdict, bool) {
	snap := evidencePath(e, NameE5, label)
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, s.mac, s.addr, s.endpoint, snap)
	if err != nil {
		return fail(NameE5, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table %s: %v", when, err), ev, e.GitSHA), false
	}
	ev[label] = snap
	if !ok {
		return fail(NameE5, e.Cell, e.Shape, fmt.Sprintf("%s, %s: %s", s.name, when, leaseFailReason(e.Shape, s.mac, s.addr, s.endpoint)), ev, e.GitSHA), false
	}
	if secs, err := reachableWithRetry(ctx, e.Source, s.addr); err != nil {
		return fail(NameE5, e.Cell, e.Shape, fmt.Sprintf("%s, %s: %s is leased but not reachable within %ds: %v", s.name, when, s.addr, secs, err), ev, e.GitSHA), false
	}
	return Verdict{}, true
}

// e5WireMAC is the hardware address the source logs s under: its own,
// or under ipvlan the parent's, read from the capture as E1 does.
func e5WireMAC(shape Shape, mac string, msgs []DHCPMsg) (string, error) {
	if shape != ShapeIpvlan {
		return strings.ToLower(mac), nil
	}
	wire := ""
	for _, m := range msgs {
		if m.CHAddr == "" || (wire != "" && !strings.EqualFold(m.CHAddr, wire)) {
			return "", fmt.Errorf("the capture carries more than one hardware address")
		}
		wire = strings.ToLower(m.CHAddr)
	}
	if wire == "" {
		return "", fmt.Errorf("the capture holds no message")
	}
	return wire, nil
}

func e5OfFleet(evs []sourceadapter.ServerEvent, macs map[string]bool) []sourceadapter.ServerEvent {
	var out []sourceadapter.ServerEvent
	for _, ev := range evs {
		if macs[strings.ToLower(ev.MAC)] {
			out = append(out, ev)
		}
	}
	return out
}

// writeEvidenceE5 keeps the source lines the judge read, one per line.
func writeEvidenceE5(e Env, o e5Obs, ev map[string]string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# soak window %s, lease %ds, fleet %d\n", o.Window, o.Lease, len(o.Members))
	for _, m := range o.Members {
		fmt.Fprintf(&b, "# %s %s %s held %s\n", m.Name, m.MAC, m.Addr, m.Held.Round(time.Second))
	}
	for _, x := range o.Fresh {
		fmt.Fprintf(&b, "%s %s %s %s\n", x.At.UTC().Format(time.RFC3339), x.Type, x.MAC, x.IP)
	}
	p := evidencePath(e, NameE5, "server-events")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		return err
	}
	ev["server-events"] = p
	return nil
}
