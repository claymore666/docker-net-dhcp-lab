package sourceadapter

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// The relay VM's fixed names (#11): eth1 faces the Docker host's segment,
// eth2 the source's server segment; netplan sets both by MAC.
const (
	relayService      = "isc-dhcp-relay"
	relayClientNIC    = "eth1"
	relayServerNIC    = "eth2"
	RelayDefaultsPath = "/etc/default/isc-dhcp-relay"
	RelayNftPath      = "/etc/nftables.conf"
)

// RelayParams is what WithRelay holds the relay and the source to, all
// from lab.yaml (#11). Addresses with a prefix length are CIDR.
type RelayParams struct {
	ClientAddr   string // relay eth1, the giaddr and the router
	ServerAddr   string // relay eth2, the source's next hop to ClientSubnet
	SourceAddr   string // the source's segment address, dhcrelay's target
	ClientSubnet string
	PoolStart    string
	AgentOptions bool
	Source       Runner // the source VM, for its route back (Ready check 6)
}

func (p RelayParams) parse() (client, server netip.Prefix, source, pool netip.Addr, subnet netip.Prefix, err error) {
	if client, err = netip.ParsePrefix(p.ClientAddr); err != nil {
		return
	}
	if server, err = netip.ParsePrefix(p.ServerAddr); err != nil {
		return
	}
	if source, err = netip.ParseAddr(p.SourceAddr); err != nil {
		return
	}
	if pool, err = netip.ParseAddr(p.PoolStart); err != nil {
		return
	}
	subnet, err = netip.ParsePrefix(p.ClientSubnet)
	return
}

// RenderRelayDefaults is the one rendering of /etc/default/isc-dhcp-relay:
// up-relay.sh writes it through `labctl resolve` and Ready compares the
// file byte for byte against it. The Debian init script is replaced by a
// native unit that reads only SERVERS and OPTIONS (#11).
func RenderRelayDefaults(p RelayParams) (string, error) {
	if _, _, _, _, _, err := p.parse(); err != nil {
		return "", fmt.Errorf("relay params: %w", err)
	}
	opts := "-4"
	if p.AgentOptions {
		opts += " -a"
	}
	opts += " -id " + relayClientNIC + " -iu " + relayServerNIC
	return "SERVERS=\"" + p.SourceAddr + "\"\nINTERFACES=\"\"\nOPTIONS=\"" + opts + "\"\n", nil
}

// RelayNftRuleset is /etc/nftables.conf on the relay: it replaces the
// whole ruleset and forwards only between the two segment legs, so a
// container can never reach the management network through the relay
// (defeat 2 of the relay design, #11; measured in a netns, M5).
const RelayNftRuleset = `#!/usr/sbin/nft -f
flush ruleset

table inet lab_relay {
	chain forward {
		type filter hook forward priority 0; policy drop;
		iifname "eth1" oifname "eth2" accept
		iifname "eth2" oifname "eth1" accept
	}
}
`

// relayNftListing is `nft list ruleset` after RelayNftRuleset loads, one
// trimmed line each; nftables 1.1 prints priority 0 as "filter" (M, #11).
var relayNftListing = []string{
	"table inet lab_relay {",
	"chain forward {",
	"type filter hook forward priority filter; policy drop;",
	`iifname "eth1" oifname "eth2" accept`,
	`iifname "eth2" oifname "eth1" accept`,
	"}",
	"}",
}

type relayAdapter struct {
	Adapter
	relay Runner
	p     RelayParams
}

// WithRelay wraps a source that sits behind a relay VM (#11): Ready also
// holds the relay and the source's route back to the client segment,
// Recover puts both back, and every other method is the inner adapter's.
func WithRelay(inner Adapter, relay Runner, p RelayParams) Adapter {
	return &relayAdapter{Adapter: inner, relay: relay, p: p}
}

func (a *relayAdapter) Capabilities() []Capability {
	caps := a.Adapter.Capabilities()
	if !slices.Contains(caps, CapRelay) {
		caps = append(slices.Clone(caps), CapRelay)
	}
	return caps
}

func (a *relayAdapter) Ready(ctx context.Context) error {
	if err := a.Adapter.Ready(ctx); err != nil {
		return err
	}
	return a.relayReady(ctx)
}

func (a *relayAdapter) relayReady(ctx context.Context) error {
	client, server, _, pool, _, err := a.p.parse()
	if err != nil {
		return fmt.Errorf("relay params: %w", err)
	}
	if _, err := a.relay.Run(ctx, "sudo systemctl is-active --quiet "+relayService+" && pgrep -x dhcrelay"); err != nil {
		return fmt.Errorf("relay: is-active %s && pgrep dhcrelay failed (service down, no dhcrelay, or relay unreachable): %w", relayService, err)
	}
	fwd, err := a.relay.Run(ctx, "sysctl -n net.ipv4.ip_forward")
	if err != nil {
		return fmt.Errorf("relay: read ip_forward: %w", err)
	}
	if strings.TrimSpace(fwd) != "1" {
		return fmt.Errorf("relay: net.ipv4.ip_forward is %q, not 1", strings.TrimSpace(fwd))
	}
	for _, leg := range []struct {
		nic  string
		want netip.Prefix
	}{{relayClientNIC, client}, {relayServerNIC, server}} {
		out, err := a.relay.Run(ctx, "ip -4 -o addr show dev "+leg.nic)
		if err != nil {
			return fmt.Errorf("relay: read %s addresses: %w", leg.nic, err)
		}
		if got := inetAddrs(out); len(got) != 1 || got[0] != leg.want.String() {
			return fmt.Errorf("relay: %s carries %v, lab.yaml says exactly %s", leg.nic, got, leg.want)
		}
	}
	rs, err := a.relay.Run(ctx, "sudo nft list ruleset")
	if err != nil {
		return fmt.Errorf("relay: nft list ruleset: %w", err)
	}
	if got := trimmedLines(rs); !slices.Equal(got, relayNftListing) {
		return fmt.Errorf("relay: nft ruleset is not the forward-only drop table: %q", got)
	}
	want, err := RenderRelayDefaults(a.p)
	if err != nil {
		return err
	}
	cfg, err := a.relay.Run(ctx, "sudo cat "+RelayDefaultsPath)
	if err != nil {
		return fmt.Errorf("relay: read %s: %w", RelayDefaultsPath, err)
	}
	if cfg != want {
		return fmt.Errorf("relay: %s differs from the rendering of lab.yaml", RelayDefaultsPath)
	}
	if a.p.Source == nil {
		return fmt.Errorf("relay params: no source runner for the route check")
	}
	route, err := a.p.Source.Run(ctx, "ip -4 route get "+pool.String())
	if err != nil {
		return fmt.Errorf("source: route to %s: %w", pool, err)
	}
	if !routeVia(route, server.Addr().String(), segmentNIC) {
		return fmt.Errorf("source: %s is not routed via %s dev %s: %q", pool, server.Addr(), segmentNIC, strings.TrimSpace(route))
	}
	return nil
}

func (a *relayAdapter) Recover(ctx context.Context) error {
	if err := a.Adapter.Recover(ctx); err != nil {
		return err
	}
	_, server, _, _, subnet, err := a.p.parse()
	if err != nil {
		return fmt.Errorf("relay params: %w", err)
	}
	cfg, err := RenderRelayDefaults(a.p)
	if err != nil {
		return err
	}
	if err := writeRemoteConfig(ctx, a.relay, RelayDefaultsPath, cfg); err != nil {
		return fmt.Errorf("recover relay: write %s: %w", RelayDefaultsPath, err)
	}
	if err := writeRemoteConfig(ctx, a.relay, RelayNftPath, RelayNftRuleset); err != nil {
		return fmt.Errorf("recover relay: write %s: %w", RelayNftPath, err)
	}
	for _, cmd := range []string{
		"sudo nft -f " + RelayNftPath,
		"sudo sysctl -qw net.ipv4.ip_forward=1",
		"sudo systemctl restart " + relayService,
	} {
		if _, err := a.relay.Run(ctx, cmd); err != nil {
			return fmt.Errorf("recover relay: %s: %w", cmd, err)
		}
	}
	if a.p.Source == nil {
		return fmt.Errorf("relay params: no source runner for the route")
	}
	cmd := fmt.Sprintf("sudo ip route replace %s via %s dev %s", subnet.Masked(), server.Addr(), segmentNIC)
	if _, err := a.p.Source.Run(ctx, cmd); err != nil {
		return fmt.Errorf("recover source route: %w", err)
	}
	return nil
}

// inetAddrs pulls the CIDR field out of `ip -4 -o addr show` lines.
func inetAddrs(out string) []string {
	var got []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				got = append(got, f[i+1])
			}
		}
	}
	return got
}

func trimmedLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// routeVia reports whether `ip route get` output names next hop via on
// device dev, as separate words.
func routeVia(out, via, dev string) bool {
	f := strings.Fields(out)
	gotVia, gotDev := false, false
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			gotVia = gotVia || f[i+1] == via
		case "dev":
			gotDev = gotDev || f[i+1] == dev
		}
	}
	return gotVia && gotDev
}

// RelayMACs reads the relay's client and server leg MACs once (#11): a
// renewal on the client segment is unicast to the client leg's MAC, and
// the relay design's scenarios match frames on it.
func RelayMACs(ctx context.Context, relay Runner) (client, server string, err error) {
	out, err := relay.Run(ctx, "cat /sys/class/net/"+relayClientNIC+"/address /sys/class/net/"+relayServerNIC+"/address")
	if err != nil {
		return "", "", fmt.Errorf("relay MACs: %w", err)
	}
	fields := strings.Fields(out)
	if len(fields) != 2 {
		return "", "", fmt.Errorf("relay MACs: want two addresses, got %q", out)
	}
	for _, f := range fields {
		if _, err := net.ParseMAC(f); err != nil {
			return "", "", fmt.Errorf("relay MACs: %w", err)
		}
	}
	return fields[0], fields[1], nil
}
