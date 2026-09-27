// Package scenario is the runner issue #3 part 1 asks for: scenario x
// cell x shape, filtered by source capability, its verdicts always
// backed by outside evidence (the source's own lease table, a capture,
// or observer reachability), never the plugin's own counters alone.
package scenario

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Shape is one of the three null-IPAM network shapes the scenarios run
// on. Bridge needs a one-time host bridge on the docker host's own
// segment NIC (docs/bridge-mode.md); macvlan and ipvlan share -o
// mode/parent (docs/parent-attached-modes.md) in the plugin repo.
type Shape string

const (
	ShapeBridge  Shape = "bridge"
	ShapeMacvlan Shape = "macvlan"
	ShapeIpvlan  Shape = "ipvlan"
	// ShapeBridgeIPAM and ShapeMacvlanIPAM run the plugin as its own
	// IPAM driver (--ipam-driver <same tag as -d>) instead of null-IPAM
	// (issue #3 part 2, plugin repo README "IPAM driver mode"). There is
	// no ipvlan-IPAM shape: the plugin repo's own issue #949 refuses
	// ipvlan under its IPAM driver, so that combination is the plugin's
	// documented limitation, not an omission here.
	ShapeBridgeIPAM  Shape = "bridge-ipam"
	ShapeMacvlanIPAM Shape = "macvlan-ipam"
)

var Shapes = []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan, ShapeBridgeIPAM, ShapeMacvlanIPAM}

// usesHostBridge reports whether shape needs NetworkUp/
// ensureBridgePresent's host-bridge machinery: both bridge shapes do,
// driven by which shapes attach through a host bridge at all, never by
// which IPAM driver they use (#3 part 2).
func usesHostBridge(shape Shape) bool {
	return shape == ShapeBridge || shape == ShapeBridgeIPAM
}

// ipamDriverFor is "null" for the three original shapes and this
// shape's own driver alias for the two IPAM shapes (#3 part 2).
func ipamDriverFor(shape Shape) string {
	if shape == ShapeBridgeIPAM || shape == ShapeMacvlanIPAM {
		return driverAlias
	}
	return "null"
}

// SegmentNIC is the docker host's dedicated segment interface (wired by
// up-cell.sh's own network=bridge=<segment> attachment). It never
// carries the docker host's own address -- that is eth0/mgmt -- so
// enslaving it under bridge mode costs the docker host nothing, unlike
// the host-address warning in docs/bridge-mode.md.
const SegmentNIC = "eth1"

// pluginAlias matches the alias every docker_host's cloud-init installs
// the plugin under (cloud-init/docker-host-user-data.tmpl.yaml), the
// same one scripts/run-source-lease-test.sh already uses; `docker plugin
// disable/upgrade/enable/inspect` all take this bare name. driverAlias
// is the same alias with the tag `docker network create -d` expects.
const pluginAlias = "net-dhcp-under-test"
const driverAlias = pluginAlias + ":latest"

// hostBridgeName derives a short, deterministic kernel interface name from
// the network name. The kernel enforces IFNAMSIZ (16 bytes including the
// terminator, 15 usable) on any link name; "br-" plus the full network
// name overflows that for every real cell -- the first live bridge-shape
// run against a real cell (kea) failed with "Attribute failed policy
// validation", the kernel's own IFNAMSIZ rejection, on `ip link add
// br-labrun-kea-bridge` (20 bytes). A short hash keeps the name
// deterministic per cell x shape without depending on the cell name's
// length; every other cell name in lab.yaml overflowed the same way.
func hostBridgeName(netName string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(netName))
	return fmt.Sprintf("brl%08x", h.Sum32())
}

// NetworkName is deterministic per cell x shape, so a re-run finds and
// clears exactly the network a previous run left, rather than a fresh
// randomly-suffixed one that could coexist with a stale leftover.
func NetworkName(cell string, shape Shape) string {
	return fmt.Sprintf("labrun-%s-%s", cell, shape)
}

// forwardRuleAdd, forwardRuleCheck and forwardRuleDel are the exact
// recipe docs/bridge-mode.md's "Prepare a host bridge" walkthrough gives
// (line 53): appended (-A, not CI harness's -I), -i only (no -o mirror),
// IPv4 only. `grep -rn ip6tables docs/` in the plugin repo has zero
// hits -- the page's only IPv6 content is the unrelated ipv6_mode
// network option -- so this stays IPv4-only, matching what a user who
// follows the page verbatim would actually run.
func forwardRuleAdd(br string) string {
	return fmt.Sprintf("sudo iptables -A FORWARD -i %s -j ACCEPT", br)
}
func forwardRuleCheck(br string) string {
	return fmt.Sprintf("sudo iptables -C FORWARD -i %s -j ACCEPT", br)
}
func forwardRuleDel(br string) string {
	return fmt.Sprintf("sudo iptables -D FORWARD -i %s -j ACCEPT", br)
}

// writeRemoteFile idempotently overwrites path on r with content via a
// heredoc in a single remote command -- SSHRunner passes remoteCmd
// through to the remote shell unchanged (ssh.go), so an embedded
// heredoc executes there as one command, with no local temp file and no
// interactive editor.
func writeRemoteFile(ctx context.Context, r sourceadapter.Runner, path, content string) error {
	cmd := fmt.Sprintf("sudo tee %s >/dev/null <<'LABEOF'\n%sLABEOF\n", path, content)
	if _, err := r.Run(ctx, cmd); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// writeBridgePersistence writes docs/bridge-mode.md's own "Ubuntu /
// netplan" recipe ("Make the bridge persistent"), verbatim apart from
// substituting its example names for this lab's real ones (my-bridge
// -> br, eth0 -> SegmentNIC): a NetworkUp that only ever built the
// bridge with `ip link` (as it used to) did not survive a reboot, so
// A5's evidence was read against a bridge that was already gone (#3).
//
// The docs' *other* recipe, systemd-networkd, was tried first and
// dropped: the lab's docker-host VMs are themselves netplan-managed
// (cloud-init renders eth1's own config through it), and
// systemd-networkd applies only the first *.network file that matches
// an interface, by filename order across /etc and /run together --
// cloud-init's own file for eth1 always wins that race against the
// docs' example unit, silently, and eth1 never gets enslaved. A
// lab-only fix (renumbering the port unit to win the race) was
// rejected: that only made the lab win a race a real user on the same
// stack would lose, so it stopped testing what a user actually does.
// This race is a gap in the plugin's bridge-mode docs, not reproduced
// here. netplan itself has no such race: it merges each interface's
// config across every matching file instead of taking the first, so
// this recipe applies cleanly over cloud-init's own file for eth1
// with no renumbering trick needed.
//
// Docs finding recorded rather than worked around: the docs' own
// netplan recipe sets dhcp4: true on the bridge because the documented
// use case replaces the host's own LAN uplink with the bridge. This
// lab's segment bridge carries only container traffic -- SegmentNIC's
// own comment above says it "never carries the docker host's own
// address" -- so applying the recipe verbatim gives the docker host
// one extra, harmless DHCP lease on the segment for as long as the
// bridge exists. It shows up as one extra row in every lease snapshot
// but never affects a verdict, since every lookup in this package
// matches by an exact mac/address/client-id, never by counting rows.
const bridgeNetplanPath = "/etc/netplan/60-dhcp-bridge.yaml"

func writeBridgePersistence(ctx context.Context, r sourceadapter.Runner, br string) error {
	netplan := fmt.Sprintf(
		"network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    %s:\n      dhcp4: false\n      dhcp6: false\n  bridges:\n    %s:\n      interfaces: [%s]\n      dhcp4: true\n      parameters:\n        stp: false\n        forward-delay: 0\n",
		SegmentNIC, br, SegmentNIC)

	if err := writeRemoteFile(ctx, r, bridgeNetplanPath, netplan); err != nil {
		return err
	}
	// docs/bridge-mode.md's own next command, verbatim: netplan refuses
	// to apply a world-readable config with an embedded secret-shaped
	// field, and 600 is what the doc's command block sets regardless.
	if _, err := r.Run(ctx, fmt.Sprintf("sudo chmod 600 %s", bridgeNetplanPath)); err != nil {
		return fmt.Errorf("chmod %s: %w", bridgeNetplanPath, err)
	}
	return nil
}

// bridgeConfigPaths lists the file writeBridgePersistence writes for
// br, the single source of truth for both writing and removing it.
func bridgeConfigPaths(br string) []string {
	return []string{bridgeNetplanPath}
}

// ensureIptablesPersistent installs the package docs/bridge-mode.md's
// firewall-persistence table names for iptables, only if it is not
// already present -- measured live against a real cell's docker-host
// image, which does not carry it by default (#3).
func ensureIptablesPersistent(ctx context.Context, r sourceadapter.Runner) error {
	if _, err := r.Run(ctx, "dpkg -s iptables-persistent >/dev/null 2>&1"); err == nil {
		return nil
	}
	cmd := "sudo DEBIAN_FRONTEND=noninteractive apt-get update && " +
		"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent"
	if _, err := r.Run(ctx, cmd); err != nil {
		return fmt.Errorf("install iptables-persistent: %w", err)
	}
	return nil
}

// bridgeReady checks the three things docs/bridge-mode.md's recipe is
// supposed to produce: the bridge link exists, the segment NIC is
// enslaved to it, and the FORWARD rule is present. Every check is
// exit-code based, the same -C convention forwardRuleCheck already
// uses, never text-parsed stdout (#3): the readiness gate before each
// scenario also checks that the shape's bridge is present.
func bridgeReady(ctx context.Context, r sourceadapter.Runner, br string) bool {
	if _, err := r.Run(ctx, fmt.Sprintf("ip link show %s", br)); err != nil {
		return false
	}
	if _, err := r.Run(ctx, fmt.Sprintf("readlink -f /sys/class/net/%s/master | grep -q '/%s$'", SegmentNIC, br)); err != nil {
		return false
	}
	if _, err := r.Run(ctx, forwardRuleCheck(br)); err != nil {
		return false
	}
	return true
}

// ensureBridgePresent is the readiness gate that runs before any
// bridge-shape scenario: the shape's bridge must actually be there, not
// assumed from an earlier bring-up in the same run. A missing or broken
// bridge is rebuilt via NetworkUp; a rebuild that still does not leave
// it ready is reported so RunOne can BLOCK rather than let every
// scenario in the shape cascade-fail against a bridge that silently is
// not there (#3). A no-op for macvlan/ipvlan, which have no host
// bridge.
func ensureBridgePresent(ctx context.Context, r sourceadapter.Runner, cell string, shape Shape) error {
	if !usesHostBridge(shape) {
		return nil
	}
	br := hostBridgeName(NetworkName(cell, shape))
	if bridgeReady(ctx, r, br) {
		return nil
	}
	if _, err := NetworkUp(ctx, r, cell, shape); err != nil {
		return fmt.Errorf("bridge %s not present and could not be rebuilt: %w", br, err)
	}
	if !bridgeReady(ctx, r, br) {
		return fmt.Errorf("bridge %s rebuilt but still not ready", br)
	}
	return nil
}

// NetworkUp brings up one shape's null-IPAM network on the docker host.
// It clears any previous run's network (and, for bridge, its host
// bridge) first: a stale leftover must never let a fresh create look
// like a fresh lease (issue #3 defeat list).
func NetworkUp(ctx context.Context, r sourceadapter.Runner, cell string, shape Shape) (string, error) {
	NetworkDown(ctx, r, cell, shape)
	net := NetworkName(cell, shape)
	switch shape {
	case ShapeBridge, ShapeBridgeIPAM:
		br := hostBridgeName(net)
		if err := writeBridgePersistence(ctx, r, br); err != nil {
			return "", fmt.Errorf("networkup(%s): %w", shape, err)
		}
		if _, err := r.Run(ctx, "sudo netplan apply"); err != nil {
			return "", fmt.Errorf("networkup(%s): sudo netplan apply: %w", shape, err)
		}
		if err := ensureIptablesPersistent(ctx, r); err != nil {
			return "", fmt.Errorf("networkup(%s): %w", shape, err)
		}
		if _, err := r.Run(ctx, forwardRuleAdd(br)); err != nil {
			return "", fmt.Errorf("networkup(%s): %s: %w", shape, forwardRuleAdd(br), err)
		}
		// The FORWARD rule above is the only thing standing between a
		// clean create and a bridge that silently drops every DHCP
		// packet: br_netfilter routes bridged traffic through FORWARD,
		// whose default policy is DROP (issue #3 lab-vs-plugin split).
		// Verify the rule is actually there before trusting it, so a
		// missing rule fails right here, by name, instead of surfacing
		// forty seconds later as an unexplained scenario timeout.
		if _, err := r.Run(ctx, forwardRuleCheck(br)); err != nil {
			return "", fmt.Errorf(
				"networkup(%s): required firewall rule not present: %q (docs/bridge-mode.md, \"Prepare a host bridge\"); bridge shape cannot pass DHCP traffic without it: %w",
				shape, forwardRuleAdd(br), err)
		}
		if _, err := r.Run(ctx, "sudo netfilter-persistent save"); err != nil {
			return "", fmt.Errorf("networkup(%s): sudo netfilter-persistent save: %w", shape, err)
		}
		if !bridgeReady(ctx, r, br) {
			return "", fmt.Errorf("networkup(%s): bridge %s or its %s port did not come up after netplan apply", shape, br, SegmentNIC)
		}
		create := fmt.Sprintf("sudo docker network create -d %s --ipam-driver %s -o bridge=%s %s", driverAlias, ipamDriverFor(shape), br, net)
		if _, err := r.Run(ctx, create); err != nil {
			return "", fmt.Errorf("networkup(%s): %s: %w", shape, create, err)
		}
	case ShapeMacvlan, ShapeIpvlan, ShapeMacvlanIPAM:
		mode := "macvlan"
		if shape == ShapeIpvlan {
			mode = "ipvlan"
		}
		create := fmt.Sprintf("sudo docker network create -d %s --ipam-driver %s -o mode=%s -o parent=%s %s",
			driverAlias, ipamDriverFor(shape), mode, SegmentNIC, net)
		if _, err := r.Run(ctx, create); err != nil {
			return "", fmt.Errorf("networkup(%s): %w", shape, err)
		}
	default:
		return "", fmt.Errorf("networkup: unknown shape %q", shape)
	}
	return net, nil
}

// NetworkUpInternal brings up an ordinary Docker bridge network with
// Docker's own default driver and IPAM, no plugin driver and no
// SegmentNIC involvement at all: the "internal network" half of A13's
// compose-app case (issue #3 part 2, redesigned 2026-09-27). Works
// identically under every shape, since it never touches the segment.
func NetworkUpInternal(ctx context.Context, r sourceadapter.Runner, netName string) error {
	_, _ = r.Run(ctx, fmt.Sprintf("sudo docker network rm %s", netName))
	if _, err := r.Run(ctx, fmt.Sprintf("sudo docker network create %s", netName)); err != nil {
		return fmt.Errorf("networkupinternal: %w", err)
	}
	return nil
}

// NetworkDownInternal removes the network NetworkUpInternal created.
// Best-effort and idempotent, the same style NetworkDown already uses.
func NetworkDownInternal(ctx context.Context, r sourceadapter.Runner, netName string) {
	_, _ = r.Run(ctx, fmt.Sprintf("sudo docker network rm %s", netName))
}

// NetworkDown removes a shape's network and, for bridge mode, releases
// the segment NIC. Best-effort and idempotent, matching down-cell.sh's
// own style: every step tolerates the thing it removes already being
// gone, since NetworkUp calls this first on every run including the
// very first one.
func NetworkDown(ctx context.Context, r sourceadapter.Runner, cell string, shape Shape) {
	net := NetworkName(cell, shape)
	_, _ = r.Run(ctx, fmt.Sprintf("sudo docker network rm %s", net))
	if usesHostBridge(shape) {
		br := hostBridgeName(net)
		// Undoes forwardRuleAdd in NetworkUp. iptables rules are matched
		// by interface name, not a live link, so this is safe (and still
		// a no-op if already gone) whatever order the bridge itself gets
		// torn down in below; without it, every run's ACCEPT rule for
		// its now-deleted bridge name pile up in FORWARD forever.
		_, _ = r.Run(ctx, forwardRuleDel(br))
		_, _ = r.Run(ctx, fmt.Sprintf("sudo ip link set %s nomaster", SegmentNIC))
		_, _ = r.Run(ctx, fmt.Sprintf("sudo ip link del %s", br))
		// Symmetric with writeBridgePersistence: without removing the
		// netplan config too, the bridge would resurrect itself on the
		// docker host's next real reboot even after this run tore it
		// down (#3). The reapply after removing it hands
		// eth1 back to cloud-init's own
		// dhcp4: false stanza for that interface.
		_, _ = r.Run(ctx, "sudo rm -f "+strings.Join(bridgeConfigPaths(br), " "))
		_, _ = r.Run(ctx, "sudo netplan apply")
		_, _ = r.Run(ctx, "sudo netfilter-persistent save")
	}
}

// isolationWaitWindow is IsolateIPAMNetwork's fallback when a network
// cannot be recreated: long enough to clear the IPAM-mode identity hold
// docs/reference.md documents in "Restart stability (MAC and IP)" -> "In
// IPAM mode" (a minute), with the same margin the docs give
// release_lease=on_remove's own sweep worst case (65-80s), so a slow
// sweep cycle can never still be inside the hold when this returns.
const isolationWaitWindow = 80 * time.Second

// IsolateIPAMNetwork breaks the plugin's IPAM-mode identity hold between
// two scenarios that would otherwise run back to back on the same
// network (issue #3 part 2, lab fault). Undocumented by this lab until
// now: docs/reference.md's "Restart stability (MAC and IP)" -> "In IPAM
// mode" section says a container that stops or is removed keeps its
// DHCP identity and address for a minute, and "the next container that
// starts on that network claims them: whichever container that is". Two
// scenarios run back to back on the one network the lab reused for a
// whole shape's run, so the second one's container was that "next
// container" often enough to read as a flaky plugin result, when the
// two-run pair it landed in was the actual cause.
//
// Recreating the network is the fix, not a workaround: the hold is a
// record tied to the network Docker just removed, and "`docker network
// rm` hands back every address the network still holds, at once"
// (docs/internals.md), so a fresh network never has a previous
// scenario's record to claim. Recreation
// is attempted first for every IPAM shape; only if it fails does this
// fall back to sleeping out isolationWaitWindow, so a transient
// NetworkUp error never silently reuses a network that might still be
// inside the hold. sleep is injectable so a test can assert the
// fallback path runs without a real 80s wait; nil uses time.Sleep.
// Returns the network name the caller's Env.Network should use next,
// and which method this call actually used, to be logged so a redo
// pass's own evidence says how each scenario pair was isolated.
//
// The wait-out fallback is only safe when the network it is about to
// reuse still exists. NetworkUp always runs NetworkDown first, and
// NetworkDown ignores its own `docker network rm` error (it has to,
// since it also runs on a network that was never created): if the rm
// half of that pair succeeded and a later step in NetworkUp then
// failed, nothing is left by that name at all, and sleeping out the
// hold before handing that name back would let the next scenario fail
// at container start on a network that is not there -- recorded as a
// plugin FAIL for a lab fault. That case is a lab error instead: it
// comes back as err with net and method empty, so the caller aborts
// this shape's run without writing a verdict for any scenario still
// queued behind it, the same way it already does for an undersized
// pool (issue #3).
func IsolateIPAMNetwork(ctx context.Context, r sourceadapter.Runner, cell string, shape Shape, sleep func(time.Duration)) (net, method string, err error) {
	if shape != ShapeBridgeIPAM && shape != ShapeMacvlanIPAM {
		return "", "", fmt.Errorf("isolateipamnetwork: shape %q is not an IPAM shape; the identity hold this isolates against does not exist under null-IPAM (docs/reference.md)", shape)
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	newNet, upErr := NetworkUp(ctx, r, cell, shape)
	if upErr == nil {
		return newNet, "network recreated between scenarios", nil
	}
	existing := NetworkName(cell, shape)
	if !networkExists(ctx, r, existing) {
		return "", "", fmt.Errorf(
			"isolateipamnetwork: network recreate failed (%w) and %s no longer exists (NetworkUp's own removal of the old network succeeded before the failing step); this is a lab error, not a scenario to run against a missing network",
			upErr, existing)
	}
	sleep(isolationWaitWindow)
	return existing, fmt.Sprintf("network recreate failed (%v); waited %s for the identity-hold window to expire instead", upErr, isolationWaitWindow), nil
}

// networkExists reports whether net is a network docker currently
// knows about. IsolateIPAMNetwork's wait-out fallback is only safe to
// take when this is true (issue #3): a `docker network
// inspect` that fails means there is nothing left for the fallback to
// reuse.
func networkExists(ctx context.Context, r sourceadapter.Runner, net string) bool {
	_, err := r.Run(ctx, fmt.Sprintf("sudo docker network inspect %s >/dev/null", net))
	return err == nil
}
