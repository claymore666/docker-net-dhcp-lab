// Package scenario is the runner issue #3 part 1 asks for: scenario x
// cell x shape, filtered by source capability, its verdicts always
// backed by outside evidence (the source's own lease table, a capture,
// or observer reachability), never the plugin's own counters alone.
package scenario

import (
	"context"
	"fmt"
	"hash/fnv"

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
		cmds := []string{
			fmt.Sprintf("sudo ip link add %s type bridge", br),
			fmt.Sprintf("sudo ip link set %s up", br),
			fmt.Sprintf("sudo ip link set %s down", SegmentNIC),
			fmt.Sprintf("sudo ip link set %s master %s", SegmentNIC, br),
			fmt.Sprintf("sudo ip link set %s up", SegmentNIC),
			forwardRuleAdd(br),
		}
		for _, c := range cmds {
			if _, err := r.Run(ctx, c); err != nil {
				return "", fmt.Errorf("networkup(bridge): %s: %w", c, err)
			}
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
	}
}
