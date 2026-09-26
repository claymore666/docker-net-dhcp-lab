package scenario

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// containerName is deterministic per cell x shape x scenario: a re-run
// finds and removes exactly the container a previous run left, the same
// discipline NetworkUp already applies to the network itself.
func containerName(e Env, scenario string) string {
	return fmt.Sprintf("lab-%s-%s-%s", e.Cell, e.Shape, scenario)
}

func evidencePath(e Env, scenario, label string) string {
	return filepath.Join(e.EvidenceDir, fmt.Sprintf("%s-%s-%s-%s.txt", e.Cell, e.Shape, scenario, label))
}

// corroborate adds a capture-based cross-check as an extra evidence
// file, best-effort: ipvlan shares one MAC across every slave, so a
// capture cannot be tied to one container's exchange there, and a
// capture read failure is never fatal to a verdict the lease table
// already backs. It never flips a PASS to FAIL by itself (issue #3: the
// source's own lease table is the verdict; the capture corroborates
// it), but a disagreement is recorded in the evidence file's own text so
// it is never silently dropped.
func corroborate(ctx context.Context, e Env, mac string, ev map[string]string, scenario, label string) {
	if e.Shape == ShapeIpvlan || e.PCAP == "" {
		return
	}
	path := evidencePath(e, scenario, label)
	reason, err := dhcpExchangeReason(ctx, e.RepoRoot, e.PCAP, mac)
	var text string
	if err != nil {
		text = fmt.Sprintf("dhcp_exchange_reason error: %v\n", err)
	} else if reason == "" {
		text = "clean 4-message exchange for this mac in the cell capture\n"
	} else {
		text = fmt.Sprintf("capture disagreement: %s\n", reason)
	}
	if writeErr := os.WriteFile(path, []byte(text), 0o644); writeErr == nil {
		ev[label] = path
	}
}

// runA1 -- first lease: a fresh container on a fresh network must get an
// address the source's own table confirms.
func runA1(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA1)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA1, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}

	snap := evidencePath(e, NameA1, "leases-after")
	lease, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
	if err != nil {
		return fail(NameA1, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-after": snap}
	if !ok {
		return fail(NameA1, e.Cell, e.Shape, leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
	}
	corroborate(ctx, e, mac, ev, NameA1, "capture-check")
	return pass(NameA1, e.Cell, e.Shape,
		fmt.Sprintf("container mac %s got address %s, confirmed in the source's own lease table (hostname %q)", mac, addr, lease.Hostname),
		ev, e.GitSHA)
}

// runA2 -- container restart: the same container, stopped and started
// again by Docker itself, must keep the same address in the source's
// table. A changed address is a FAIL, never tuned away. Re-inspects the
// container after the restart rather than reusing the pre-restart mac
// and endpoint id: ipvlan mints a fresh endpoint id (and so a fresh
// client-id) on every restart (docs/reference.md "DHCP identity", #219),
// which the "after" lookup must use, not the "before" one.
func runA2(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA2)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA2, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA2, e.Cell, e.Shape, "before restart: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker restart %s", name)); err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("docker restart failed: %v", err), evBefore, e.GitSHA)
	}
	if err := waitContainerRunning(ctx, e.Host, name); err != nil {
		return fail(NameA2, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	_, afterAddr, afterEndpointID, err := inspectContainer(ctx, e.Host, e.Shape, name)
	if err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("inspect after restart: %v", err), evBefore, e.GitSHA)
	}

	afterSnap := evidencePath(e, NameA2, "leases-after")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, afterAddr, afterEndpointID, afterSnap)
	if err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after restart: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA2, e.Cell, e.Shape, "after restart: "+leaseFailReason(e.Shape, mac, afterAddr, afterEndpointID), ev, e.GitSHA)
	}
	if afterAddr != addr {
		return fail(NameA2, e.Cell, e.Shape,
			fmt.Sprintf("address changed across restart: %s -> %s", addr, afterAddr), ev, e.GitSHA)
	}
	return pass(NameA2, e.Cell, e.Shape,
		fmt.Sprintf("container restarted, kept address %s, confirmed in the source's table both times", addr),
		ev, e.GitSHA)
}

// runA3 -- compose down/up: removing and recreating the container (a new
// random MAC, same as `docker compose down; up` would give it unless
// pinned) must still produce a confirmed lease. It does not require the
// same address -- release-on-down is a source policy choice, not a
// plugin defect -- and reports whether the address was reused or
// changed without failing on either.
func runA3(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA3)
	defer removeContainer(ctx, e.Host, name)

	mac1, addr1, endpointID1, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA3, e.Cell, e.Shape, fmt.Sprintf("container did not start (down): %v", err), nil, e.GitSHA)
	}
	downSnap := evidencePath(e, NameA3, "leases-down")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac1, addr1, endpointID1, downSnap)
	if err != nil {
		return fail(NameA3, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evDown := map[string]string{"leases-down": downSnap}
	if !ok {
		return fail(NameA3, e.Cell, e.Shape, "before down: "+leaseFailReason(e.Shape, mac1, addr1, endpointID1), evDown, e.GitSHA)
	}
	removeContainer(ctx, e.Host, name)

	mac2, addr2, endpointID2, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA3, e.Cell, e.Shape, fmt.Sprintf("container did not start (up): %v", err), evDown, e.GitSHA)
	}
	upSnap := evidencePath(e, NameA3, "leases-up")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac2, addr2, endpointID2, upSnap)
	if err != nil {
		return fail(NameA3, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after up: %v", err), evDown, e.GitSHA)
	}
	ev := map[string]string{"leases-down": downSnap, "leases-up": upSnap}
	if !ok {
		return fail(NameA3, e.Cell, e.Shape, "after up: "+leaseFailReason(e.Shape, mac2, addr2, endpointID2), ev, e.GitSHA)
	}
	reuse := "reused the same address"
	if addr2 != addr1 {
		reuse = fmt.Sprintf("got a different address (%s -> %s)", addr1, addr2)
	}
	return pass(NameA3, e.Cell, e.Shape,
		fmt.Sprintf("fresh container after down/up got address %s, confirmed in the source's table (%s)", addr2, reuse),
		ev, e.GitSHA)
}

// runA4 -- daemon restart: dockerd on the docker host is restarted while
// the container is up; PASS needs all of: the container Running again,
// the source's own table showing the same MAC with a renewed or new
// lease, and the source able to reach the container afterwards. The
// container runs with --restart unless-stopped: with no restart policy
// Docker never brings a container back after dockerd restarts or the
// host reboots, by design, so a scenario testing that case would be
// testing a container no real user would run this way, not the plugin
// (issue #3, lead directive 2026-09-26).
func runA4(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA4)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainerPolicy(ctx, e.Host, e.Shape, e.Network, name, "unless-stopped")
	if err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA4, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA4, e.Cell, e.Shape, "before restart: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	if _, err := e.Host.Run(ctx, "sudo systemctl restart docker"); err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("systemctl restart docker: %v", err), evBefore, e.GitSHA)
	}
	if err := waitDockerBack(ctx, e.Host, 60*time.Second); err != nil {
		return fail(NameA4, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	if err := waitContainerRunning(ctx, e.Host, name); err != nil {
		return fail(NameA4, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	afterMac, afterAddr, afterEndpointID, err := inspectContainer(ctx, e.Host, e.Shape, name)
	if err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("inspect after daemon restart: %v", err), evBefore, e.GitSHA)
	}
	afterSnap := evidencePath(e, NameA4, "leases-after")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, afterMac, afterAddr, afterEndpointID, afterSnap)
	if err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after daemon restart: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA4, e.Cell, e.Shape, "after daemon restart: "+leaseFailReason(e.Shape, afterMac, afterAddr, afterEndpointID), ev, e.GitSHA)
	}
	leaseNote := fmt.Sprintf("kept address %s", addr)
	if afterAddr != addr {
		leaseNote = fmt.Sprintf("got a new address (%s -> %s)", addr, afterAddr)
	}
	if err := e.Source.Reachable(ctx, afterAddr); err != nil {
		return fail(NameA4, e.Cell, e.Shape,
			fmt.Sprintf("container running and mac %s has a lease for %s, but the source could not reach it: %v", afterMac, afterAddr, err), ev, e.GitSHA)
	}
	return pass(NameA4, e.Cell, e.Shape,
		fmt.Sprintf("dockerd restarted, container running, %s, confirmed in the source's table both times, reachable from the source", leaseNote),
		ev, e.GitSHA)
}

// runA5 -- host reboot: the whole docker host VM reboots. Bounded waits
// for the boot id to change and settle, then dockerd, then the
// container, then PASS needs all of: Running again, the source's table
// showing the same MAC with a renewed or new lease, and the source able
// to reach the container. Same --restart unless-stopped reasoning as
// A4: with no restart policy the container is never supposed to survive
// a host reboot, by Docker's own design (issue #3, lead directive
// 2026-09-26). The 30s Running-wait bound is unchanged; if it proves too
// short once a real restart policy is in play, that is a genuine finding
// to report, never a reason to widen it.
func runA5(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA5)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainerPolicy(ctx, e.Host, e.Shape, e.Network, name, "unless-stopped")
	if err != nil {
		return fail(NameA5, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA5, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA5, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA5, e.Cell, e.Shape, "before reboot: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	beforeBootID, err := bootID(ctx, e.Host)
	if err != nil {
		return fail(NameA5, e.Cell, e.Shape, fmt.Sprintf("could not read boot id before reboot: %v", err), evBefore, e.GitSHA)
	}

	// systemctl reboot drops this very SSH connection; that is expected,
	// not a failure to surface (issue #3 defeat list on waitHostRebooted).
	_, _ = e.Host.Run(ctx, "sudo systemctl reboot")
	if err := waitHostRebooted(ctx, e.Host, beforeBootID, 3*time.Minute); err != nil {
		return fail(NameA5, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	if err := waitContainerRunning(ctx, e.Host, name); err != nil {
		return fail(NameA5, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	afterAddr, err := inspectField(ctx, e.Host, name, "IPAddress")
	if err != nil {
		return fail(NameA5, e.Cell, e.Shape, fmt.Sprintf("inspect after reboot: %v", err), evBefore, e.GitSHA)
	}
	afterSnap := evidencePath(e, NameA5, "leases-after")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, afterAddr, endpointID, afterSnap)
	if err != nil {
		return fail(NameA5, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after reboot: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA5, e.Cell, e.Shape, "after reboot: "+leaseFailReason(e.Shape, mac, afterAddr, endpointID), ev, e.GitSHA)
	}
	leaseNote := fmt.Sprintf("kept address %s", addr)
	if afterAddr != addr {
		leaseNote = fmt.Sprintf("got a new address (%s -> %s)", addr, afterAddr)
	}
	if err := e.Source.Reachable(ctx, afterAddr); err != nil {
		return fail(NameA5, e.Cell, e.Shape,
			fmt.Sprintf("container running and mac %s has a lease for %s, but the source could not reach it: %v", mac, afterAddr, err), ev, e.GitSHA)
	}
	return pass(NameA5, e.Cell, e.Shape,
		fmt.Sprintf("host rebooted, container running, %s, confirmed in the source's table both times, reachable from the source", leaseNote),
		ev, e.GitSHA)
}

// runA6 -- plugin upgrade from the previous release: install
// e.PreviousPluginTag (named explicitly in lab.yaml, never derived by
// decrementing e.PluginTag's patch number -- issue #3, lead directive
// 2026-09-26, since the real previous release is not always a patch
// predecessor, e.g. v2.3.0-rc1's previous is v2.2.3) under the same
// alias, confirm a lease under it, then upgrade in place to e.PluginTag
// and confirm the pre-existing container's lease survived. The install
// only sets DHCP_LOG_LEVEL if the previous tag actually declares that
// setting -- an older version may not have it, and installing with an
// unknown setting fails outright (same directive). N/A when
// e.PreviousPluginTag is empty: a documented, narrow limitation, never a
// silent guess at an unrelated tag.
func runA6(ctx context.Context, e Env) Verdict {
	prev := e.PreviousPluginTag
	if prev == "" {
		return na(NameA6, e.Cell, e.Shape, "no previous_plugin_tag configured for this cell", e.GitSHA)
	}

	name := containerName(e, NameA6)
	defer removeContainer(ctx, e.Host, name)

	_, _ = e.Host.Run(ctx, "sudo docker plugin disable "+pluginAlias)
	_, _ = e.Host.Run(ctx, "sudo docker plugin rm "+pluginAlias)
	if _, err := installPluginChecked(ctx, e.Host, pluginAlias, prev, map[string]string{"DHCP_LOG_LEVEL": "debug"}); err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("install previous tag %s: %v", prev, err), nil, e.GitSHA)
	}

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("container did not start under %s: %v", prev, err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA6, "leases-before-upgrade")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table under %s: %v", prev, err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before-upgrade": beforeSnap}
	if !ok {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("under %s: %s", prev, leaseFailReason(e.Shape, mac, addr, endpointID)), evBefore, e.GitSHA)
	}

	if _, err := e.Host.Run(ctx, "sudo docker plugin disable "+pluginAlias); err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("disable before upgrade: %v", err), evBefore, e.GitSHA)
	}
	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker plugin upgrade %s %s --grant-all-permissions --skip-remote-check", pluginAlias, e.PluginTag)); err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("upgrade to %s: %v", e.PluginTag, err), evBefore, e.GitSHA)
	}
	if _, err := e.Host.Run(ctx, "sudo docker plugin enable "+pluginAlias); err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("enable after upgrade: %v", err), evBefore, e.GitSHA)
	}

	installed, err := installedPluginTag(ctx, e.Host)
	if err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("could not read installed plugin tag after upgrade: %v", err), evBefore, e.GitSHA)
	}
	if installed != e.PluginTag {
		return fail(NameA6, e.Cell, e.Shape,
			fmt.Sprintf("installed reference after upgrade is %q, expected %q", installed, e.PluginTag), evBefore, e.GitSHA)
	}

	afterSnap := evidencePath(e, NameA6, "leases-after-upgrade")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, afterSnap)
	if err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after upgrade: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before-upgrade": beforeSnap, "leases-after-upgrade": afterSnap}
	if !ok {
		return fail(NameA6, e.Cell, e.Shape, "after upgrade: "+leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
	}
	return pass(NameA6, e.Cell, e.Shape,
		fmt.Sprintf("upgraded %s -> %s, pre-existing container's lease %s confirmed after", prev, e.PluginTag, addr),
		ev, e.GitSHA)
}

// runA7 -- plugin killed: the plugin's own process (visible directly via
// the host PID namespace it requests) is sent SIGKILL. The verdict is
// about the pre-existing container's lease surviving, not about
// auto-restart specifically; the reason records whether recovery needed
// a manual nudge, as an honest finding either way.
func runA7(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA7)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameA7, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA7, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameA7, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA7, e.Cell, e.Shape, "before kill: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}

	pid, err := pluginPID(ctx, e.Host)
	if err != nil {
		return fail(NameA7, e.Cell, e.Shape, fmt.Sprintf("could not find plugin process: %v", err), evBefore, e.GitSHA)
	}
	if _, err := e.Host.Run(ctx, "sudo kill -9 "+pid); err != nil {
		return fail(NameA7, e.Cell, e.Shape, fmt.Sprintf("kill -9 %s: %v", pid, err), evBefore, e.GitSHA)
	}

	recoveredBy, err := waitPluginBack(ctx, e.Host)
	if err != nil {
		return fail(NameA7, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}

	afterSnap := evidencePath(e, NameA7, "leases-after")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, afterSnap)
	if err != nil {
		return fail(NameA7, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after kill: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA7, e.Cell, e.Shape, "after kill: "+leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
	}
	return pass(NameA7, e.Cell, e.Shape,
		fmt.Sprintf("plugin process killed, recovered by %s, pre-existing lease %s still confirmed", recoveredBy, addr),
		ev, e.GitSHA)
}

// runA8 -- fleet burst: N containers started sequentially (CreateEndpoint
// is serialized by Docker itself); the source's table is read once at
// the end and distinct confirmed leases are counted -- never the
// plugin's own request-volume counters (issue #3 defeat list).
func runA8(ctx context.Context, e Env) Verdict {
	const n = 10
	type created struct {
		name, mac, addr, endpointID string
	}
	var containers []created
	defer func() {
		for _, c := range containers {
			removeContainer(ctx, e.Host, c.name)
		}
	}()

	for i := 0; i < n; i++ {
		name := containerName(e, NameA8) + "-" + strconv.Itoa(i)
		mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
		if err != nil {
			return fail(NameA8, e.Cell, e.Shape,
				fmt.Sprintf("container %d/%d (%s) did not start: %v", i+1, n, name, err), nil, e.GitSHA)
		}
		containers = append(containers, created{name, mac, addr, endpointID})
	}

	snap := evidencePath(e, NameA8, "leases-after")
	confirmed := 0
	seen := map[string]bool{}
	for _, c := range containers {
		lease, _, ok, err := lookupLease(ctx, e.Source, e.Shape, c.mac, c.addr, c.endpointID, snap)
		if err != nil {
			return fail(NameA8, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
		}
		if ok && !seen[lease.Address] {
			seen[lease.Address] = true
			confirmed++
		}
	}
	ev := map[string]string{"leases-after": snap}
	if confirmed != n {
		return fail(NameA8, e.Cell, e.Shape,
			fmt.Sprintf("%d of %d containers started but only %d have a distinct confirmed lease", n, n, confirmed), ev, e.GitSHA)
	}
	return pass(NameA8, e.Cell, e.Shape,
		fmt.Sprintf("%d containers started, %d distinct confirmed leases in the source's own table", n, confirmed),
		ev, e.GitSHA)
}
