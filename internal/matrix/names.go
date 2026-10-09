// Package matrix renders one or more run bundles into the plain-English
// results page issue #4 asks for. It never touches the network or
// libvirt: every input is already on disk (labctl run's verdict files
// and its resolved-lab.json), the same "reads evidence, never runs
// anything" shape labctl leases already has for a source's own table.
package matrix

import "github.com/claymore666/docker-net-dhcp-lab/internal/scenario"

// PlainNames is the one place a scenario.Name constant is spelled out
// in plain words. A rendered page never shows a scenario id in its
// prose (issue #4): every id appears only in this table and in a
// verdict's own file name, so a reader of the results page never has
// to already know the catalog's own naming scheme to follow what a row
// tested.
var PlainNames = map[string]string{
	scenario.NameA1:  "first lease",
	scenario.NameA2:  "container restart",
	scenario.NameA3:  "compose down/up",
	scenario.NameA4:  "daemon restart",
	scenario.NameA5:  "host reboot",
	scenario.NameA5b: "host reboot, fixed MAC",
	scenario.NameA6:  "plugin upgrade",
	scenario.NameA7:  "plugin killed",
	scenario.NameA8:  "fleet burst",
	scenario.NameA9:  "stop, wait, start",
	scenario.NameA10: "kill under a restart policy",
	scenario.NameA11: "pause/unpause",
	scenario.NameA12: "network disconnect/reconnect",
	scenario.NameA13: "two networks, one container",
	scenario.NameA14: "short lease renewal",
	scenario.NameA15: "compose scale",
	scenario.NameA16: "forced remove of a running container",
	scenario.NameB1:  "reservation by MAC",
	scenario.NameB2:  "reservation by client id",
	scenario.NameB3:  "DNS registration",
	scenario.NameB4:  "same MAC, same address",
	scenario.NameB5:  "vendor class pool",
	scenario.NameB6:  "option change on renewal",
	scenario.NameB7:  "lease release on remove",
	scenario.NameB8:  "three containers at once",
	scenario.NameC1:  "source down at create",
	scenario.NameC2:  "source down past T1",
	scenario.NameC3:  "source down past expiry",
	scenario.NameC4:  "source restart without its lease file",
	scenario.NameC5:  "failover, primary killed",
	scenario.NameC6:  "early squatter",
	scenario.NameC6b: "late squatter",
	scenario.NameC7:  "rogue server",
	scenario.NameC8:  "pool exhausted",
	scenario.NameC9:  "subnet renumbered",
	scenario.NameC10: "reply delay and loss",
	scenario.NameC11: "validate_dhcp at create",
	scenario.NameC12: "relay",
	scenario.NameD1:  "DHCPv6 address",
	scenario.NameD1b: "DHCPv6 address, ipv6=true",
	scenario.NameD1c: "DHCPv6 mode without router advertisements",
	scenario.NameD2:  "SLAAC address",
	scenario.NameD2b: "SLAAC mode without router advertisements",
	scenario.NameF1:  "user class pool",
	scenario.NameF2a: "IPv6-only preferred, not asked for",
	scenario.NameF2b: "IPv6-only preferred, sent unasked",
	scenario.NameF3:  "rapid commit, IPv4",
	scenario.NameF4:  "rapid commit, IPv6",
	scenario.NameF5:  "temporary IPv6 address",
	scenario.NameF6:  "IPv6 prefix delegation",
	scenario.NameF7:  "NAT64 prefix in router advertisements",
	scenario.NameF8:  "FORCERENEW, signed and unsigned",
}

// Order is the row order the results page renders in: scenario.Catalog's
// own order, so a change to the catalog's ordering moves the page with
// it instead of drifting from a second, hand-kept list.
func Order() []string {
	out := make([]string, 0, len(scenario.Catalog))
	for _, s := range scenario.Catalog {
		out = append(out, s.Name)
	}
	return out
}

// PlainName returns id's plain-word name, and false when id is not in
// PlainNames -- callers treat that as a hard error (issue #4: an
// unmapped id must never fall back to being printed raw).
func PlainName(id string) (string, bool) {
	name, ok := PlainNames[id]
	return name, ok
}
