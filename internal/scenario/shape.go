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

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Shape is one of the three null-IPAM network shapes group A runs
// against. Bridge needs a one-time host bridge on the docker host's own
// segment NIC (docs/bridge-mode.md); macvlan and ipvlan share -o
// mode/parent (docs/parent-attached-modes.md) in the plugin repo.
type Shape string

const (
	ShapeBridge  Shape = "bridge"
	ShapeMacvlan Shape = "macvlan"
	ShapeIpvlan  Shape = "ipvlan"
)

var Shapes = []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan}

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

// writeBridgePersistence writes docs/bridge-mode.md's own
// systemd-networkd recipe ("Make the bridge persistent"), verbatim
// apart from substituting its example names for this lab's real ones
// (my-bridge -> br, eth0 -> SegmentNIC): a NetworkUp that only ever
// built the bridge with `ip link` (as it used to) did not survive a
// reboot, so A5's evidence was read against a bridge that was already
// gone (issue #3, lead directive 2026-09-26, item 1).
//
// Docs finding, recorded rather than worked around (the directive: "if
// the docs are not enough on their own, that is a docs finding: record
// it, and do not add anything the docs do not say"): the docs' own
// 30-my-bridge.network stanza sets DHCP=ipv4 because the documented use
// case replaces the host's own LAN uplink with the bridge. This lab's
// segment bridge carries only container traffic -- SegmentNIC's own
// comment above says it "never carries the docker host's own address"
// -- so applying the recipe verbatim gives the docker host one extra,
// harmless DHCP lease on the segment for as long as the bridge exists.
// It shows up as one extra row in every lease snapshot but never
// affects a verdict, since every lookup in this package matches by an
// exact mac/address/client-id, never by counting rows.
// portUnitPrefix is lower than cloud-init's own "10-netplan-seg0.network"
// (cloud-init/network-config.tmpl.yaml, __SEG_MAC__ match): systemd-networkd
// applies only the first *.network file that matches an interface, in
// filename order across /etc and /run together, and ignores the rest.
// The docs' own example number for this file ("20-eth0.network") loses
// that race against cloud-init's unit, measured live on a fresh cell
// (kea/bridge): eth1 stayed unenslaved and NetworkUp's own readiness
// check caught it, correctly, as "did not come up" -- not a docs
// problem, since a real host's port NIC has no such rival unit; this
// lab's own cloud-init does. The stanza's content is still the docs'
// text verbatim; only this file's number changes, to win the match.
const portUnitPrefix = "05"

func writeBridgePersistence(ctx context.Context, r sourceadapter.Runner, br string) error {
	netdev := fmt.Sprintf("[NetDev]\nName=%s\nKind=bridge\n\n[Bridge]\nSTP=false\nForwardDelaySec=0\n", br)
	ethNetwork := fmt.Sprintf("[Match]\nName=%s\n\n[Network]\nBridge=%s\n", SegmentNIC, br)
	brNetwork := fmt.Sprintf("[Match]\nName=%s\n\n[Network]\nDHCP=ipv4\nConfigureWithoutCarrier=yes\n", br)

	if err := writeRemoteFile(ctx, r, fmt.Sprintf("/etc/systemd/network/10-%s.netdev", br), netdev); err != nil {
		return err
	}
	if err := writeRemoteFile(ctx, r, fmt.Sprintf("/etc/systemd/network/%s-%s-%s.network", portUnitPrefix, SegmentNIC, br), ethNetwork); err != nil {
		return err
	}
	if err := writeRemoteFile(ctx, r, fmt.Sprintf("/etc/systemd/network/30-%s.network", br), brNetwork); err != nil {
		return err
	}
	return nil
}

// bridgeUnitPaths lists the three files writeBridgePersistence writes
// for br, the single source of truth for both writing and removing them.
func bridgeUnitPaths(br string) []string {
	return []string{
		fmt.Sprintf("/etc/systemd/network/10-%s.netdev", br),
		fmt.Sprintf("/etc/systemd/network/%s-%s-%s.network", portUnitPrefix, SegmentNIC, br),
		fmt.Sprintf("/etc/systemd/network/30-%s.network", br),
	}
}

// ensureIptablesPersistent installs the package docs/bridge-mode.md's
// firewall-persistence table names for iptables, only if it is not
// already present -- measured live against a real cell's docker-host
// image, which does not carry it by default (issue #3, lead directive
// 2026-09-26, item 1).
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
// uses, never text-parsed stdout (issue #3, lead directive 2026-09-26,
// item 1: "the readiness gate before each scenario also checks that the
// shape's bridge is present").
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

// ensureBridgePresent is the readiness gate item 1 asks for: before any
// bridge-shape scenario, the shape's bridge must actually be there, not
// assumed from an earlier bring-up in the same run. A missing or broken
// bridge is rebuilt via NetworkUp; a rebuild that still does not leave
// it ready is reported so RunOne can BLOCK rather than let every
// scenario in the shape cascade-fail against a bridge that silently is
// not there (issue #3, lead directive 2026-09-26, item 1). A no-op for
// macvlan/ipvlan, which have no host bridge.
func ensureBridgePresent(ctx context.Context, r sourceadapter.Runner, cell string, shape Shape) error {
	if shape != ShapeBridge {
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
	case ShapeBridge:
		br := hostBridgeName(net)
		if err := writeBridgePersistence(ctx, r, br); err != nil {
			return "", fmt.Errorf("networkup(bridge): %w", err)
		}
		if _, err := r.Run(ctx, "sudo systemctl enable --now systemd-networkd"); err != nil {
			return "", fmt.Errorf("networkup(bridge): sudo systemctl enable --now systemd-networkd: %w", err)
		}
		if _, err := r.Run(ctx, "sudo networkctl reload"); err != nil {
			return "", fmt.Errorf("networkup(bridge): sudo networkctl reload: %w", err)
		}
		if err := ensureIptablesPersistent(ctx, r); err != nil {
			return "", fmt.Errorf("networkup(bridge): %w", err)
		}
		if _, err := r.Run(ctx, forwardRuleAdd(br)); err != nil {
			return "", fmt.Errorf("networkup(bridge): %s: %w", forwardRuleAdd(br), err)
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
				"networkup(bridge): required firewall rule not present: %q (docs/bridge-mode.md, \"Prepare a host bridge\"); bridge shape cannot pass DHCP traffic without it: %w",
				forwardRuleAdd(br), err)
		}
		if _, err := r.Run(ctx, "sudo netfilter-persistent save"); err != nil {
			return "", fmt.Errorf("networkup(bridge): sudo netfilter-persistent save: %w", err)
		}
		if !bridgeReady(ctx, r, br) {
			return "", fmt.Errorf("networkup(bridge): bridge %s or its %s port did not come up after the systemd-networkd reload", br, SegmentNIC)
		}
		create := fmt.Sprintf("sudo docker network create -d %s --ipam-driver null -o bridge=%s %s", driverAlias, br, net)
		if _, err := r.Run(ctx, create); err != nil {
			return "", fmt.Errorf("networkup(bridge): %s: %w", create, err)
		}
	case ShapeMacvlan, ShapeIpvlan:
		create := fmt.Sprintf("sudo docker network create -d %s --ipam-driver null -o mode=%s -o parent=%s %s",
			driverAlias, shape, SegmentNIC, net)
		if _, err := r.Run(ctx, create); err != nil {
			return "", fmt.Errorf("networkup(%s): %w", shape, err)
		}
	default:
		return "", fmt.Errorf("networkup: unknown shape %q", shape)
	}
	return net, nil
}

// NetworkDown removes a shape's network and, for bridge mode, releases
// the segment NIC. Best-effort and idempotent, matching down-cell.sh's
// own style: every step tolerates the thing it removes already being
// gone, since NetworkUp calls this first on every run including the
// very first one.
func NetworkDown(ctx context.Context, r sourceadapter.Runner, cell string, shape Shape) {
	net := NetworkName(cell, shape)
	_, _ = r.Run(ctx, fmt.Sprintf("sudo docker network rm %s", net))
	if shape == ShapeBridge {
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
		// unit files too, the bridge would resurrect itself on the
		// docker host's next real reboot even after this run tore it
		// down (issue #3, lead directive 2026-09-26, item 1).
		_, _ = r.Run(ctx, "sudo rm -f "+strings.Join(bridgeUnitPaths(br), " "))
		_, _ = r.Run(ctx, "sudo networkctl reload")
		_, _ = r.Run(ctx, "sudo netfilter-persistent save")
	}
}
