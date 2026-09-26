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

	mac, addr, err := runContainer(ctx, e.Host, e.Network, name)
	if err != nil {
		return fail(NameA1, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}

	snap := evidencePath(e, NameA1, "leases-after")
	lease, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, snap)
	if err != nil {
		return fail(NameA1, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-after": snap}
	if !ok {
		return fail(NameA1, e.Cell, e.Shape, leaseFailReason(e.Shape, mac, addr), ev, e.GitSHA)
	}
	corroborate(ctx, e, mac, ev, NameA1, "capture-check")
	return pass(NameA1, e.Cell, e.Shape,
		fmt.Sprintf("container mac %s got address %s, confirmed in the source's own lease table (hostname %q)", mac, addr, lease.Hostname),
		ev, e.GitSHA)
}

// runA2 -- container restart: the same container, stopped and started
// again by Docker itself, must keep the same address in the source's
// table. A changed address is a FAIL, never tuned away.
func runA2(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA2)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, err := runContainer(ctx, e.Host, e.Network, name)
	if err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA2, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, beforeSnap)
	if err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA2, e.Cell, e.Shape, "before restart: "+leaseFailReason(e.Shape, mac, addr), evBefore, e.GitSHA)
	}

	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker restart %s", name)); err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("docker restart failed: %v", err), evBefore, e.GitSHA)
	}
	if err := waitContainerRunning(ctx, e.Host, name); err != nil {
		return fail(NameA2, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
	}
	afterAddr, err := inspectField(ctx, e.Host, name, "IPAddress")
	if err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("inspect after restart: %v", err), evBefore, e.GitSHA)
	}

	afterSnap := evidencePath(e, NameA2, "leases-after")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, afterAddr, afterSnap)
	if err != nil {
		return fail(NameA2, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after restart: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA2, e.Cell, e.Shape, "after restart: "+leaseFailReason(e.Shape, mac, afterAddr), ev, e.GitSHA)
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

	mac1, addr1, err := runContainer(ctx, e.Host, e.Network, name)
	if err != nil {
		return fail(NameA3, e.Cell, e.Shape, fmt.Sprintf("container did not start (down): %v", err), nil, e.GitSHA)
	}
	downSnap := evidencePath(e, NameA3, "leases-down")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac1, addr1, downSnap)
	if err != nil {
		return fail(NameA3, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evDown := map[string]string{"leases-down": downSnap}
	if !ok {
		return fail(NameA3, e.Cell, e.Shape, "before down: "+leaseFailReason(e.Shape, mac1, addr1), evDown, e.GitSHA)
	}
	removeContainer(ctx, e.Host, name)

	mac2, addr2, err := runContainer(ctx, e.Host, e.Network, name)
	if err != nil {
		return fail(NameA3, e.Cell, e.Shape, fmt.Sprintf("container did not start (up): %v", err), evDown, e.GitSHA)
	}
	upSnap := evidencePath(e, NameA3, "leases-up")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac2, addr2, upSnap)
	if err != nil {
		return fail(NameA3, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after up: %v", err), evDown, e.GitSHA)
	}
	ev := map[string]string{"leases-down": downSnap, "leases-up": upSnap}
	if !ok {
		return fail(NameA3, e.Cell, e.Shape, "after up: "+leaseFailReason(e.Shape, mac2, addr2), ev, e.GitSHA)
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
// the container is up; the container's address must still be confirmed
// in the source's table afterwards.
func runA4(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA4)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, err := runContainer(ctx, e.Host, e.Network, name)
	if err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA4, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, beforeSnap)
	if err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA4, e.Cell, e.Shape, "before restart: "+leaseFailReason(e.Shape, mac, addr), evBefore, e.GitSHA)
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
	afterAddr, err := inspectField(ctx, e.Host, name, "IPAddress")
	if err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("inspect after daemon restart: %v", err), evBefore, e.GitSHA)
	}
	afterSnap := evidencePath(e, NameA4, "leases-after")
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, afterAddr, afterSnap)
	if err != nil {
		return fail(NameA4, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after daemon restart: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA4, e.Cell, e.Shape, "after daemon restart: "+leaseFailReason(e.Shape, mac, afterAddr), ev, e.GitSHA)
	}
	if afterAddr != addr {
		return fail(NameA4, e.Cell, e.Shape,
			fmt.Sprintf("address changed across daemon restart: %s -> %s", addr, afterAddr), ev, e.GitSHA)
	}
	return pass(NameA4, e.Cell, e.Shape,
		fmt.Sprintf("dockerd restarted, container kept address %s, confirmed in the source's table both times", addr),
		ev, e.GitSHA)
}

// runA5 -- host reboot: the whole docker host VM reboots. Bounded waits
// for SSH, then dockerd, then the container, then re-confirms the
// address in the source's table.
func runA5(ctx context.Context, e Env) Verdict {
	name := containerName(e, NameA5)
	defer removeContainer(ctx, e.Host, name)

	mac, addr, err := runContainer(ctx, e.Host, e.Network, name)
	if err != nil {
		return fail(NameA5, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA5, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, beforeSnap)
	if err != nil {
		return fail(NameA5, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA5, e.Cell, e.Shape, "before reboot: "+leaseFailReason(e.Shape, mac, addr), evBefore, e.GitSHA)
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
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, afterAddr, afterSnap)
	if err != nil {
		return fail(NameA5, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after reboot: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA5, e.Cell, e.Shape, "after reboot: "+leaseFailReason(e.Shape, mac, afterAddr), ev, e.GitSHA)
	}
	if afterAddr != addr {
		return fail(NameA5, e.Cell, e.Shape,
			fmt.Sprintf("address changed across host reboot: %s -> %s", addr, afterAddr), ev, e.GitSHA)
	}
	return pass(NameA5, e.Cell, e.Shape,
		fmt.Sprintf("host rebooted, container kept address %s, confirmed in the source's table both times", addr),
		ev, e.GitSHA)
}

// runA6 -- plugin upgrade from the previous release: install the
// patch-decremented predecessor of e.PluginTag under the same alias,
// confirm a lease under it, then upgrade in place to e.PluginTag and
// confirm the pre-existing container's lease survived. N/A when no
// patch predecessor can be derived (e.g. patch 0) -- a documented, narrow
// limitation, never a silent guess at an unrelated tag.
func runA6(ctx context.Context, e Env) Verdict {
	prev, err := previousTag(e.PluginTag)
	if err != nil {
		return na(NameA6, e.Cell, e.Shape, fmt.Sprintf("no previous tag to upgrade from: %v", err), e.GitSHA)
	}

	name := containerName(e, NameA6)
	defer removeContainer(ctx, e.Host, name)

	_, _ = e.Host.Run(ctx, "sudo docker plugin disable "+pluginAlias)
	_, _ = e.Host.Run(ctx, "sudo docker plugin rm "+pluginAlias)
	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker plugin install --grant-all-permissions --alias %s %s DHCP_LOG_LEVEL=debug", pluginAlias, prev)); err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("install previous tag %s: %v", prev, err), nil, e.GitSHA)
	}

	mac, addr, err := runContainer(ctx, e.Host, e.Network, name)
	if err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("container did not start under %s: %v", prev, err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA6, "leases-before-upgrade")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, beforeSnap)
	if err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table under %s: %v", prev, err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before-upgrade": beforeSnap}
	if !ok {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("under %s: %s", prev, leaseFailReason(e.Shape, mac, addr)), evBefore, e.GitSHA)
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
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, addr, afterSnap)
	if err != nil {
		return fail(NameA6, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after upgrade: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before-upgrade": beforeSnap, "leases-after-upgrade": afterSnap}
	if !ok {
		return fail(NameA6, e.Cell, e.Shape, "after upgrade: "+leaseFailReason(e.Shape, mac, addr), ev, e.GitSHA)
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

	mac, addr, err := runContainer(ctx, e.Host, e.Network, name)
	if err != nil {
		return fail(NameA7, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameA7, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, beforeSnap)
	if err != nil {
		return fail(NameA7, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameA7, e.Cell, e.Shape, "before kill: "+leaseFailReason(e.Shape, mac, addr), evBefore, e.GitSHA)
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
	_, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, addr, afterSnap)
	if err != nil {
		return fail(NameA7, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after kill: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if !ok {
		return fail(NameA7, e.Cell, e.Shape, "after kill: "+leaseFailReason(e.Shape, mac, addr), ev, e.GitSHA)
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
		name, mac, addr string
	}
	var containers []created
	defer func() {
		for _, c := range containers {
			removeContainer(ctx, e.Host, c.name)
		}
	}()

	for i := 0; i < n; i++ {
		name := containerName(e, NameA8) + "-" + strconv.Itoa(i)
		mac, addr, err := runContainer(ctx, e.Host, e.Network, name)
		if err != nil {
			return fail(NameA8, e.Cell, e.Shape,
				fmt.Sprintf("container %d/%d (%s) did not start: %v", i+1, n, name, err), nil, e.GitSHA)
		}
		containers = append(containers, created{name, mac, addr})
	}

	snap := evidencePath(e, NameA8, "leases-after")
	confirmed := 0
	seen := map[string]bool{}
	for _, c := range containers {
		lease, _, ok, err := lookupLease(ctx, e.Source, e.Shape, c.mac, c.addr, snap)
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
