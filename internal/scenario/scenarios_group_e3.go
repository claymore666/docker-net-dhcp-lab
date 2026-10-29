package scenario

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
)

// Group E (lab #15 PR 3): E3a the host-side link names, E3b the VLAN
// parent. The judges are in groupe3_judge.go; this file collects what
// they read from the docker host and the observer.

const (
	e3aShortName = "e3a-hn" // a valid <=15 byte ifname: the container name becomes the link name
	e3aNetSuffix = "e3a"
	e3bNetSuffix = "e3b"
	e3bVLANName  = "eth1.100"
	e3bUserVlan  = "vlan100"
)

// e3Tune carries the waits so a unit test need not sit through them. (#15)
type e3Tune struct {
	poll, linkWait, captureWait, parentWindow time.Duration
}

var e3Real = e3Tune{poll: time.Second, linkWait: 20 * time.Second, captureWait: 15 * time.Second, parentWindow: 20 * time.Second}

// e3Links reads `ip -d -o link show` on the docker host into evidence. (#15)
func e3Links(ctx context.Context, e Env, scenario, label string, ev map[string]string) ([]ipLink, error) {
	out, err := e.Host.Run(ctx, "ip -d -o link show")
	if err != nil {
		return nil, fmt.Errorf("ip -d -o link show: %w", err)
	}
	path := evidencePath(e, scenario, label)
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return nil, err
	}
	ev[label] = path
	return parseIPLinks(out), nil
}

// e3LinksUntil polls the host's links until done is true or linkWait ends,
// and returns the last read either way. (#15)
func e3LinksUntil(ctx context.Context, e Env, scenario, label string, ev map[string]string, t e3Tune, done func([]ipLink) bool) ([]ipLink, error) {
	deadline := time.Now().Add(t.linkWait)
	for {
		ls, err := e3Links(ctx, e, scenario, label, ev)
		if err != nil || done(ls) || time.Now().After(deadline) {
			return ls, err
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return ls, err
		}
	}
}

func e3HealthCounters(ctx context.Context, e Env, scenario, label string, ev map[string]string) (map[string]int64, error) {
	path := evidencePath(e, scenario, label)
	body, err := pluginHealthBody(ctx, e.Host, path)
	if err != nil {
		return nil, err
	}
	ev[label] = path
	c := map[string]int64{}
	for _, n := range []string{"host_ifnames_applied", "host_ifname_failures", "host_ifname_conflicts"} {
		v, ok := healthCounter(body, n)
		if !ok {
			return nil, fmt.Errorf("/Plugin.Health has no %s", n)
		}
		c[n] = v
	}
	return c, nil
}

func runE3a(ctx context.Context, e Env) Verdict { return runE3aTuned(ctx, e, e3Real) }

// runE3aTuned -- bridge: the host-side link is dh-<endpoint[:12]> on the
// network's bridge, and host_ifname=container_name renames it (kernel 6.2
// and later) or fails as counted (earlier). macvlan and ipvlan: no host
// link is named and host_ifname is refused (#15 E3a).
func runE3aTuned(ctx context.Context, e Env, t e3Tune) Verdict {
	if v, ok := ipamNA(NameE3a, e, "the host_ifname network"); ok {
		return v
	}
	ev := map[string]string{}
	bad := func(format string, a ...any) Verdict {
		return fail(NameE3a, e.Cell, e.Shape, fmt.Sprintf(format, a...), ev, e.GitSHA)
	}
	blk := func(format string, a ...any) Verdict {
		return blocked(NameE3a, e.Cell, e.Shape, fmt.Sprintf(format, a...), e.GitSHA)
	}
	kernel, err := e.Host.Run(ctx, "uname -r")
	if err != nil {
		return blk("could not read the docker host's kernel version: %v", err)
	}
	kernel = strings.TrimSpace(kernel)
	before, err := e3Links(ctx, e, NameE3a, "links-before", ev)
	if err != nil {
		return blk("%v", err)
	}
	if usesHostBridge(e.Shape) {
		return e3aBridge(ctx, e, t, kernel, before, ev)
	}
	return e3aParent(ctx, e, t, before, ev, bad, blk)
}

func e3aBridge(ctx context.Context, e Env, t e3Tune, kernel string, before []ipLink, ev map[string]string) Verdict {
	bridge := hostBridgeName(e.Network)
	bad := func(format string, a ...any) Verdict {
		return fail(NameE3a, e.Cell, e.Shape, fmt.Sprintf(format, a...), ev, e.GitSHA)
	}
	blk := func(format string, a ...any) Verdict {
		return blocked(NameE3a, e.Cell, e.Shape, fmt.Sprintf(format, a...), e.GitSHA)
	}
	o := e3aBridgeObs{Kernel: kernel, Bridge: bridge, Before: before, RenameName: e3aShortName}
	noLeft := func(ls []ipLink) bool { return len(hostLinkLeftovers(before, ls, bridge)) == 0 }

	leg := func(suffix, name string, opts []string, label string) (endpoint string, during, after []ipLink, err error) {
		net, err := NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, suffix, opts)
		defer NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, suffix)
		if err != nil {
			return "", nil, nil, fmt.Errorf("network create: %w", err)
		}
		defer removeContainer(bCleanupCtx(ctx), e.Host, name)
		if _, _, endpoint, err = runContainer(ctx, e.Host, e.Shape, net, name); err != nil {
			return "", nil, nil, fmt.Errorf("container start: %w", err)
		}
		if during, err = e3Links(ctx, e, NameE3a, label+"-during", ev); err != nil {
			return endpoint, nil, nil, err
		}
		removeContainer(bCleanupCtx(ctx), e.Host, name)
		NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, suffix)
		after, err = e3LinksUntil(ctx, e, NameE3a, label+"-after", ev, t, noLeft)
		return endpoint, during, after, err
	}

	var err error
	if o.EndpointID, o.During, o.After, err = leg(e3aNetSuffix, containerName(e, NameE3a), nil, "default"); err != nil {
		return bad("default-name leg: %v", err)
	}
	c0, err := e3HealthCounters(ctx, e, NameE3a, "health-before", ev)
	if err != nil {
		return blk("%v", err)
	}
	if o.RenameEndpoint, o.RenameDuring, o.RenameAfter, err = leg(e3aNetSuffix+"-hn", e3aShortName, []string{"host_ifname=container_name"}, "rename"); err != nil {
		return bad("host_ifname leg: %v", err)
	}
	c1, err := e3HealthCounters(ctx, e, NameE3a, "health-after", ev)
	if err != nil {
		return blk("%v", err)
	}
	o.AppliedDelta = c1["host_ifnames_applied"] - c0["host_ifnames_applied"]
	o.FailuresDelta = c1["host_ifname_failures"] - c0["host_ifname_failures"]
	o.ConflDelta = c1["host_ifname_conflicts"] - c0["host_ifname_conflicts"]
	return fFinish(NameE3a, e, judgeE3aBridge(o), "", ev)
}

func e3aParent(ctx context.Context, e Env, t e3Tune, before []ipLink, ev map[string]string, bad, blk func(string, ...any) Verdict) Verdict {
	mode := "macvlan"
	if e.Shape == ShapeIpvlan {
		mode = "ipvlan"
	}
	o := e3aParentObs{Mode: mode, Before: before}
	net, err := NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, e3aNetSuffix, nil)
	defer NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3aNetSuffix)
	if err != nil {
		return bad("network create: %v", err)
	}
	name := containerName(e, NameE3a)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	if _, _, _, err := runContainer(ctx, e.Host, e.Shape, net, name); err != nil {
		return bad("container start: %v", err)
	}
	if o.During, err = e3Links(ctx, e, NameE3a, "links-during", ev); err != nil {
		return blk("%v", err)
	}
	_, rerr := NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, e3aNetSuffix+"-hn", []string{"host_ifname=container_name"})
	defer NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3aNetSuffix+"-hn")
	if rerr == nil {
		o.RefusalCreated = true
	} else {
		o.RefusalErr = rerr.Error()
	}
	removeContainer(bCleanupCtx(ctx), e.Host, name)
	NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3aNetSuffix)
	NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3aNetSuffix+"-hn")
	report, left, err := WaitParentClean(ctx, e.Host, SegmentNIC, t.parentWindow, t.poll)
	if err != nil {
		return blk("read the children of %s: %v", SegmentNIC, err)
	}
	path := evidencePath(e, NameE3a, "parent-clean")
	if werr := os.WriteFile(path, []byte(report), 0o644); werr == nil {
		ev["parent-clean"] = path
	}
	for _, c := range left {
		o.Left = append(o.Left, c.String())
	}
	return fFinish(NameE3a, e, judgeE3aParent(o), "", ev)
}

func runE3b(ctx context.Context, e Env) Verdict { return runE3bTuned(ctx, e, e3Real) }

// e3bMade records which pre-created links the run made, so the cleanup
// removes exactly those and never a link the plugin owns (#15 row 9).
type e3bMade struct{ vlan100, dummy bool }

// e3bCleanup removes the links the scenario pre-created and only those:
// a link is deleted when this run made it and the name still carries the
// kind it made. `ip link del NAME type K` does not refuse another kind
// (measured in a netns), so the kind is read first. (#15)
func e3bCleanup(ctx context.Context, e Env, m *e3bMade) {
	var links []ipLink
	read := false
	if out, err := e.Host.Run(ctx, "ip -d -o link show"); err == nil {
		links, read = parseIPLinks(out), true
	}
	for _, c := range []struct {
		made       bool
		name, kind string
	}{{m.vlan100, e3bUserVlan, "vlan"}, {m.dummy, e3bVLANName, "dummy"}} {
		if !c.made {
			continue
		}
		if l, there := findLink(links, c.name); read && (!there || l.Kind != c.kind) {
			continue
		}
		_, _ = e.Host.Run(ctx, "sudo ip link del "+c.name+" type "+c.kind)
	}
}

// runE3bTuned -- -o vlan=100 on macvlan/ipvlan makes eth1.100, the lease
// comes from the VLAN pool the source serves on its own eth1.100, the
// tagged capture shows it, and the two documented refusals leave a
// user-made link alone (#15 E3b).
func runE3bTuned(ctx context.Context, e Env, t e3Tune) Verdict {
	if v, ok := ipamNA(NameE3b, e, "the vlan network"); ok {
		return v
	}
	if usesHostBridge(e.Shape) {
		return na(NameE3b, e.Cell, e.Shape, "the plugin refuses vlan in bridge mode (\"vlan cannot be set in mode=bridge\"); a VLAN parent exists only for macvlan and ipvlan", e.GitSHA)
	}
	ev := map[string]string{}
	bad := func(format string, a ...any) Verdict {
		return fail(NameE3b, e.Cell, e.Shape, fmt.Sprintf(format, a...), ev, e.GitSHA)
	}
	blk := func(format string, a ...any) Verdict {
		return blocked(NameE3b, e.Cell, e.Shape, fmt.Sprintf(format, a...), e.GitSHA)
	}
	if e.VLAN == nil {
		return blk("no VLAN witness for this run: the tagged capture and the bridge flag cannot be read")
	}
	filtering, err := e.VLAN.Filtering(ctx)
	if err != nil {
		return blk("could not read the segment bridge's vlan_filtering: %v", err)
	}
	if filtering != "0" {
		return blk("the segment bridge has vlan_filtering=%s: it would drop or re-tag VLAN 100 frames and the tagged leg could not witness anything", filtering)
	}
	subnet, err := labyaml.VLANSubnet(e.SegSubnet)
	if err != nil {
		return blk("no VLAN 100 subnet for this cell: %v", err)
	}
	before, err := e3Links(ctx, e, NameE3b, "links-before", ev)
	if err != nil {
		return blk("%v", err)
	}
	for _, n := range []string{e3bVLANName, e3bUserVlan} {
		if _, there := findLink(before, n); there {
			return blk("%s exists on the docker host before the run: it is not ours to use or remove", n)
		}
	}
	made := &e3bMade{}
	defer e3bCleanup(bCleanupCtx(ctx), e, made)

	o := e3bObs{Parent: SegmentNIC, VLANName: e3bVLANName, VLANSubnet: subnet}
	net, err := NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, e3bNetSuffix, []string{"vlan=100"})
	defer NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3bNetSuffix)
	if err != nil {
		return bad("network create with vlan=100: %v", err)
	}
	name := containerName(e, NameE3b)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return bad("container start: %v", err)
	}
	o.Addr, o.MAC = addr, mac
	if o.During, err = e3Links(ctx, e, NameE3b, "links-during", ev); err != nil {
		return blk("%v", err)
	}
	lease, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, evidencePath(e, NameE3b, "leases"))
	if err != nil {
		return bad("could not read the source's lease table: %v", err)
	}
	ev["leases"] = evidencePath(e, NameE3b, "leases")
	o.LeaseFound, o.LeaseAddr = ok, lease.Address

	deadline := time.Now().Add(t.captureWait)
	for {
		text, terr := e.VLAN.Tagged(ctx, evidencePath(e, NameE3b, "tagged"))
		if terr != nil {
			return blk("%v", terr)
		}
		ev["tagged"] = evidencePath(e, NameE3b, "tagged")
		o.Tagged = parseTaggedReplies(text)
		if e3bSawGrant(o) || time.Now().After(deadline) {
			break
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return bad("%v", err)
		}
	}
	removeContainer(bCleanupCtx(ctx), e.Host, name)
	NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3bNetSuffix)
	if o.After, err = e3LinksUntil(ctx, e, NameE3b, "links-after", ev, t, func(ls []ipLink) bool { _, still := findLink(ls, e3bVLANName); return !still }); err != nil {
		return blk("%v", err)
	}
	if _, still := findLink(o.After, e3bVLANName); still {
		return fFinish(NameE3b, e, judgeE3b(o), "", ev)
	}

	// Refusal 1: the same VLAN ID already exists under another name. (#15)
	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo ip link add %s link %s type vlan id 100", e3bUserVlan, SegmentNIC)); err != nil {
		return blk("could not pre-create %s: %v", e3bUserVlan, err)
	}
	made.vlan100 = true
	_, r1 := NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, e3bNetSuffix+"-r1", []string{"vlan=100"})
	defer NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3bNetSuffix+"-r1")
	if r1 == nil {
		o.R1Created = true
	} else {
		o.R1Err = r1.Error()
	}
	NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3bNetSuffix+"-r1")
	if _, err := e.Host.Run(ctx, "sudo ip link del "+e3bUserVlan+" type vlan"); err != nil {
		return blk("could not remove the pre-created %s: %v", e3bUserVlan, err)
	}
	made.vlan100 = false

	// Refusal 2: a user-made dummy sits where the plugin would put the VLAN. (#15)
	if _, err := e.Host.Run(ctx, "sudo ip link add "+e3bVLANName+" type dummy"); err != nil {
		return blk("could not pre-create the dummy %s: %v", e3bVLANName, err)
	}
	made.dummy = true
	_, r2 := NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, e3bNetSuffix+"-r2", []string{"vlan=100"})
	defer NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3bNetSuffix+"-r2")
	if r2 == nil {
		o.R2Created = true
	} else {
		o.R2Err = r2.Error()
	}
	NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, e3bNetSuffix+"-r2")
	if o.R2After, err = e3Links(ctx, e, NameE3b, "links-after-dummy", ev); err != nil {
		return blk("%v", err)
	}
	return fFinish(NameE3b, e, judgeE3b(o), "", ev)
}

func e3bSawGrant(o e3bObs) bool {
	for _, r := range o.Tagged {
		if r.VLAN == 100 && r.YourIP == o.Addr && r.MAC == strings.ToLower(o.MAC) {
			return true
		}
	}
	return false
}
