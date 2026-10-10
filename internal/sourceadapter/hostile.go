package sourceadapter

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// The group C rewrites (C8 NarrowPool, C9 Renumber, #23) anchor on the
// main pool each cloud-init source template writes. A group F feature
// may have added a class test before the pool (features_*.go), which
// the optional groups below step over.
var (
	keaMainPoolRE     = regexp.MustCompile(`(\{ "pool": ")[^"]*(", "client-class": "not-b5" \})`)
	iscMainRangeRE    = regexp.MustCompile(`(?m)^([ \t]*deny members of "b5";\n(?:[ \t]*deny members of "[^"]*";\n)*[ \t]*range )[^;\n]*(;)`)
	dnsmasqMainPoolRE = regexp.MustCompile(`(?m)^(dhcp-range=tag:!b5,(?:tag:[^,\n]+,)*)[^,\n]+,[^,\n]+(,)`)

	keaIfacesLineRE   = regexp.MustCompile(`(?m)^[ \t]*"interfaces-config": [^\n]*\},$`)
	keaControlLineRE  = regexp.MustCompile(`(?m)^[ \t]*"control-socket": [^\n]*\},$`)
	keaLeaseDBLineRE  = regexp.MustCompile(`(?m)^[ \t]*"lease-database": [^\n]*\},$`)
	iscMaxLeaseTimeRE = regexp.MustCompile(`(?m)^max-lease-time\s+[0-9]+;$`)
	iscAuthRE         = regexp.MustCompile(`(?m)^authoritative;$`)
	dnsmasqKeepRE     = regexp.MustCompile(`(?m)^(?:interface=[^\n]*|bind-interfaces|except-interface=[^\n]*|dhcp-authoritative)$`)
	dnsmasqMainTimeRE = regexp.MustCompile(`(?m)^dhcp-range=tag:!b5,(?:tag:[^,\n]+,)*[^,\n]+,[^,\n]+,([^,\n]+)$`)
)

func validatePool(first, last string) (netip.Addr, netip.Addr, error) {
	f, err := validateAddr(first)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	l, err := validateAddr(last)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	fa, la := netip.MustParseAddr(f), netip.MustParseAddr(l)
	if fa.Compare(la) > 0 {
		return fa, la, fmt.Errorf("pool %s - %s is backwards", fa, la)
	}
	return fa, la, nil
}

func narrowPoolVia(ctx context.Context, r Runner, path string, re *regexp.Regexp, format, first, last string, restart func(context.Context) error, label string) (func(context.Context) error, error) {
	f, l, err := validatePool(first, last)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	pool := fmt.Sprintf(format, f, l)
	return enableFeatureViaSubstitution(ctx, r, path, pool,
		[]configEdit{{re, "${1}" + strings.ReplaceAll(pool, "$", "$$") + "${2}", "the main pool"}}, restart, label)
}

// NarrowPool shrinks the main pool to first-last (C8, #23).
func (a *KeaAdapter) NarrowPool(ctx context.Context, first, last string) (func(context.Context) error, error) {
	return narrowPoolVia(ctx, a.Runner, "/etc/kea/kea-dhcp4.conf", keaMainPoolRE, "%s - %s", first, last,
		func(ctx context.Context) error { return a.Restart(ctx) }, "kea")
}

func (a *ISCDHCPAdapter) NarrowPool(ctx context.Context, first, last string) (func(context.Context) error, error) {
	return narrowPoolVia(ctx, a.Runner, "/etc/dhcp/dhcpd.conf", iscMainRangeRE, "%s %s", first, last,
		func(ctx context.Context) error { return a.Restart(ctx) }, "isc-dhcp")
}

func (a *DnsmasqAdapter) NarrowPool(ctx context.Context, first, last string) (func(context.Context) error, error) {
	return narrowPoolVia(ctx, a.Runner, "/etc/dnsmasq.conf", dnsmasqMainPoolRE, "%s,%s", first, last,
		func(ctx context.Context) error { return a.Restart(ctx) }, "dnsmasq")
}

// Renumber moves the segment to subnet: eth1 to addr, one pool
// first-last, routers addr, no reservations or classes, the lease
// time kept (C9, #23).
func (a *KeaAdapter) Renumber(ctx context.Context, subnet, addr, first, last string) (func(context.Context) error, error) {
	p, err := validateRenumber(subnet, addr, first, last)
	if err != nil {
		return nil, err
	}
	return a.host().renumberVia(ctx, a.Runner, "/etc/kea/kea-dhcp4.conf", p, renderKeaRenumbered,
		func(ctx context.Context) error { return a.Restart(ctx) }, "kea")
}

func (a *ISCDHCPAdapter) Renumber(ctx context.Context, subnet, addr, first, last string) (func(context.Context) error, error) {
	p, err := validateRenumber(subnet, addr, first, last)
	if err != nil {
		return nil, err
	}
	return a.host().renumberVia(ctx, a.Runner, "/etc/dhcp/dhcpd.conf", p, renderISCRenumbered,
		func(ctx context.Context) error { return a.Restart(ctx) }, "isc-dhcp")
}

func (a *DnsmasqAdapter) Renumber(ctx context.Context, subnet, addr, first, last string) (func(context.Context) error, error) {
	p, err := validateRenumber(subnet, addr, first, last)
	if err != nil {
		return nil, err
	}
	return a.host().renumberVia(ctx, a.Runner, "/etc/dnsmasq.conf", p, renderDnsmasqRenumbered,
		func(ctx context.Context) error { return a.Restart(ctx) }, "dnsmasq")
}

// renderKeaRenumbered gives the new subnet id 2: the leases the old
// subnet (id 1) handed out stay in the memfile but match no subnet.
func renderKeaRenumbered(orig string, p renumberPlan) (string, error) {
	var keep [5]string
	for i, x := range []struct {
		re   *regexp.Regexp
		what string
	}{{keaIfacesLineRE, "interfaces-config lines"}, {keaControlLineRE, "control-socket lines"}, {keaLeaseDBLineRE, "lease-database lines"},
		{keaValidLifetimeRE, "valid-lifetime entries"}, {keaLeaseCmdsHookRE, "lease_cmds hook entries"}} {
		m, err := onlyMatch(x.re, orig, x.what)
		if err != nil {
			return "", err
		}
		keep[i] = strings.TrimSpace(m)
	}
	return fmt.Sprintf(`{
"Dhcp4": {
  %s
  %s
  %s
  %s
  "hooks-libraries": [
    %s
  ],
  "subnet4": [
    {
      "id": 2,
      "subnet": "%s",
      "pools": [ { "pool": "%s - %s" } ],
      "option-data": [ { "name": "routers", "data": "%s" } ]
    }
  ]
}
}
`, keep[0], keep[1], keep[2], keep[3], keep[4], p.subnet, p.first, p.last, p.addr), nil
}

func renderISCRenumbered(orig string, p renumberPlan) (string, error) {
	lt, err := onlyMatch(iscDefaultLeaseTimeRE, orig, "default-lease-time statements")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(lt + "\n")
	if m := iscMaxLeaseTimeRE.FindString(orig); m != "" {
		b.WriteString(m + "\n")
	}
	if iscAuthRE.MatchString(orig) {
		b.WriteString("authoritative;\n")
	}
	fmt.Fprintf(&b, "subnet %s netmask %s {\n  range %s %s;\n  option routers %s;\n}\n", p.subnet.Addr(), p.netmask(), p.first, p.last, p.addr)
	return b.String(), nil
}

func renderDnsmasqRenumbered(orig string, p renumberPlan) (string, error) {
	m := dnsmasqMainTimeRE.FindAllStringSubmatch(orig, -1)
	if len(m) != 1 {
		return "", fmt.Errorf("found %d main dhcp-range lines in the running config, want 1", len(m))
	}
	keep := dnsmasqKeepRE.FindAllString(orig, -1)
	if len(keep) == 0 || !strings.HasPrefix(keep[0], "interface=") {
		return "", fmt.Errorf("running config does not start with an interface= line to keep")
	}
	return fmt.Sprintf("%s\ndhcp-range=%s,%s,%s\ndhcp-option=3,%s\n", strings.Join(keep, "\n"), p.first, p.last, m[0][1], p.addr), nil
}

func (a *KeaAdapter) Squat(ctx context.Context, addr string, announce bool) (func(context.Context) error, error) {
	return a.host().squat(ctx, a.Runner, addr, announce)
}
func (a *ISCDHCPAdapter) Squat(ctx context.Context, addr string, announce bool) (func(context.Context) error, error) {
	return a.host().squat(ctx, a.Runner, addr, announce)
}
func (a *DnsmasqAdapter) Squat(ctx context.Context, addr string, announce bool) (func(context.Context) error, error) {
	return a.host().squat(ctx, a.Runner, addr, announce)
}

func (a *KeaAdapter) StartRogue(ctx context.Context, serverAddr, first, last string) (func(context.Context) error, error) {
	return a.host().startRogue(ctx, a.Runner, serverAddr, first, last)
}
func (a *ISCDHCPAdapter) StartRogue(ctx context.Context, serverAddr, first, last string) (func(context.Context) error, error) {
	return a.host().startRogue(ctx, a.Runner, serverAddr, first, last)
}
func (a *DnsmasqAdapter) StartRogue(ctx context.Context, serverAddr, first, last string) (func(context.Context) error, error) {
	return a.host().startRogue(ctx, a.Runner, serverAddr, first, last)
}

func (a *KeaAdapter) RogueLeases(ctx context.Context) ([]Lease, error) {
	return a.host().rogueLeases(ctx, a.Runner)
}
func (a *ISCDHCPAdapter) RogueLeases(ctx context.Context) ([]Lease, error) {
	return a.host().rogueLeases(ctx, a.Runner)
}
func (a *DnsmasqAdapter) RogueLeases(ctx context.Context) ([]Lease, error) {
	return a.host().rogueLeases(ctx, a.Runner)
}
