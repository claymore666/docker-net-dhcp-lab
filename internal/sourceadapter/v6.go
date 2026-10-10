package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// RAParams is what SetRA changes on the segment's router advertisements;
// the baseline is Managed and Autonomous with one PIO (#23 group D).
// Off stops them: radvd stops (its final RA carries router lifetime 0,
// radvd.conf(5)), dnsmasq drops enable-ra and slaac, both of which send
// RAs on their own (MEASURED dnsmasq 2.91, #23). Second adds a second
// PIO and a second eth1 address; SecondExpired advertises it with valid
// and preferred lifetime 0 (D4b). Pref64 adds RFC 8781's option.
type RAParams struct {
	Off                 bool
	Managed, Autonomous bool
	Second              netip.Prefix
	SecondExpired       bool
	Pref64              netip.Prefix
}

// ErrRAUnsupported wraps a SetRA refusal for an RA the source cannot
// send at all (dnsmasq: PREF64, a valid lifetime 0), so a row can tell
// it from a failed toggle (#23 D4b).
var ErrRAUnsupported = errors.New("this source's RA cannot carry it")

// BaselineRA is the M=1 A=1 single-PIO advertisement every cell starts from (#23).
var BaselineRA = RAParams{Managed: true, Autonomous: true}

var ulaRange = netip.MustParsePrefix("fd00::/8")

// validateULA returns p masked, refusing anything outside fd00::/8 or
// with a length outside [min, max]; a ULA is all the lab advertises (RFC 4193).
func validateULA(p netip.Prefix, min, max int) (netip.Prefix, error) {
	if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%v is not an IPv6 prefix", p)
	}
	if p.Bits() < min || p.Bits() > max {
		return netip.Prefix{}, fmt.Errorf("%v: length %d is outside %d to %d", p, p.Bits(), min, max)
	}
	if !ulaRange.Contains(p.Addr()) {
		return netip.Prefix{}, fmt.Errorf("%v is not a unique local prefix (fd00::/8)", p)
	}
	return p.Masked(), nil
}

func validateRA(p RAParams) (RAParams, error) {
	if p.Off {
		if p != (RAParams{Off: true}) {
			return p, errors.New("SetRA: Off takes no other field")
		}
		return p, nil
	}
	if !p.Managed && !p.Autonomous {
		return p, errors.New("SetRA: M=0 A=0 advertises no address source; no scenario uses it")
	}
	var err error
	if p.Second.IsValid() {
		if p.Second, err = validateULA(p.Second, 64, 64); err != nil {
			return p, fmt.Errorf("SetRA: second prefix: %w", err)
		}
	} else if p.SecondExpired {
		return p, errors.New("SetRA: SecondExpired needs Second")
	}
	if p.Pref64.IsValid() {
		if p.Pref64, err = validateULA(p.Pref64, 96, 96); err != nil {
			return p, fmt.Errorf("SetRA: PREF64: %w", err)
		}
	}
	if p == BaselineRA {
		return p, errors.New("SetRA: these parameters are the baseline; nothing to change")
	}
	return p, nil
}

// pdBounds returns the first and the last /64 inside pool (RFC 8415 section 6.3).
func pdBounds(pool netip.Prefix) (netip.Addr, netip.Addr) {
	b := pool.Masked().Addr().As16()
	for i := pool.Bits(); i < 64; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	return pool.Masked().Addr(), netip.AddrFrom16(b)
}

// secondAddr is the source's address in the second prefix, ::2 as on
// the main one (lab.yaml seg_address6) (#23 row D4).
func secondAddr(p netip.Prefix) string {
	b := p.Addr().As16()
	b[15] = 2
	return netip.PrefixFrom(netip.AddrFrom16(b), p.Bits()).String()
}

var (
	radvdManagedRE = regexp.MustCompile(`(?m)^([ \t]*)AdvManagedFlag on;`)
	radvdAutoRE    = regexp.MustCompile(`(?m)^([ \t]*)AdvAutonomous on;`)
	radvdIfaceEnd  = regexp.MustCompile(`(?m)^\};\n?\z`)
)

// renderRadvd edits the baseline radvd.conf cloud-init writes; every
// anchor must match, so a drifted file is refused, never half-edited (#23).
func renderRadvd(orig string, p RAParams) (string, error) {
	var edits []configEdit
	if !p.Managed {
		edits = append(edits, configEdit{radvdManagedRE, "${1}AdvManagedFlag off;", "the managed flag"})
	}
	if !p.Autonomous {
		edits = append(edits, configEdit{radvdAutoRE, "${1}AdvAutonomous off;", "the autonomous flag"})
	}
	var add strings.Builder
	if p.Second.IsValid() {
		valid, pref := 7200, 3600
		if p.SecondExpired {
			valid, pref = 0, 0
		}
		fmt.Fprintf(&add, "  prefix %s {\n    AdvOnLink on;\n    AdvAutonomous %s;\n    AdvValidLifetime %d;\n    AdvPreferredLifetime %d;\n  };\n",
			p.Second, map[bool]string{true: "on", false: "off"}[p.Autonomous], valid, pref)
	}
	if p.Pref64.IsValid() {
		fmt.Fprintf(&add, "  nat64prefix %s {\n    AdvValidLifetime 1800;\n  };\n", p.Pref64)
	}
	if add.Len() > 0 {
		edits = append(edits, configEdit{radvdIfaceEnd, add.String() + "};\n", "the interface block's end"})
	}
	out := orig
	for _, e := range edits {
		next := e.re.ReplaceAllString(out, e.repl)
		if next == out {
			return "", fmt.Errorf("anchor for %s not found in %s; refusing to change it blindly", e.what, radvdConf)
		}
		out = next
	}
	return out, nil
}

// setRAViaRadvd stops radvd for Off; otherwise it rewrites radvd.conf
// and reloads, because a restart's final RA carries router lifetime 0
// (radvd.conf(5), MEASURED radvd 2.20, #23) and would withdraw the
// router mid-scenario. The restore writes the captured bytes back.
func (h host) setRAViaRadvd(ctx context.Context, r Runner, p RAParams, label string) (func(context.Context) error, error) {
	p, err := validateRA(p)
	if err != nil {
		return nil, err
	}
	radvd := h.unit("radvd")
	if p.Off {
		if err := radvd.do(ctx, r, "stop", label); err != nil {
			return nil, err
		}
		return func(ctx context.Context) error { return radvd.do(ctx, r, "start", label) }, nil
	}
	orig, err := r.Run(ctx, "sudo cat "+radvdConf)
	if err != nil {
		return nil, fmt.Errorf("%s: read %s: %w", label, radvdConf, err)
	}
	changed, err := renderRadvd(orig, p)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	reload := func(ctx context.Context) error {
		if _, err := r.Run(ctx, "sudo systemctl reload "+radvd.name); err != nil {
			return fmt.Errorf("%s: reload %s: %w", label, radvd.name, err)
		}
		return nil
	}
	return h.applyV6(ctx, r, radvdConf, orig, changed, p.Second, reload, label)
}

// applyV6 writes changed to path, adds the second eth1 address when
// second is set, and runs apply; the restore (also run on any failure)
// writes orig back, deletes the address and applies again (#23).
func (h host) applyV6(ctx context.Context, r Runner, path, orig, changed string, second netip.Prefix, apply func(context.Context) error, label string) (func(context.Context) error, error) {
	restore := func(ctx context.Context) error {
		var errs []error
		if err := writeRemoteConfig(ctx, r, path, orig); err != nil {
			errs = append(errs, fmt.Errorf("%s: restore %s: %w", label, path, err))
		}
		if second.IsValid() {
			if _, err := r.Run(ctx, fmt.Sprintf("sudo ip -6 addr del %s dev %s", secondAddr(second), h.nic)); err != nil {
				errs = append(errs, fmt.Errorf("%s: remove the second %s address: %w", label, h.nic, err))
			}
		}
		if err := apply(ctx); err != nil {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
	if second.IsValid() {
		if _, err := r.Run(ctx, fmt.Sprintf("sudo ip -6 addr add %s dev %s nodad", secondAddr(second), h.nic)); err != nil {
			return nil, fmt.Errorf("%s: add the second %s address: %w", label, h.nic, err)
		}
	}
	if err := writeRemoteConfig(ctx, r, path, changed); err != nil {
		return nil, errors.Join(fmt.Errorf("%s: write %s: %w", label, path, err), restore(ctx))
	}
	if err := apply(ctx); err != nil {
		return nil, errors.Join(err, restore(ctx))
	}
	return restore, nil
}

const (
	keaDHCP6Conf     = "/etc/kea/kea-dhcp6.conf"
	iscDHCP6Conf     = "/etc/dhcp/dhcpd6.conf"
	dnsmasqLabV6Conf = "/etc/dnsmasq.d/lab-v6.conf"
	radvdConf        = "/etc/radvd.conf"
	// iscDHCP6PID and iscDHCP4PID are the init script's defaults
	// (/etc/init.d/isc-dhcp-server, 4.4.3-P1), which starts -4 and -6 as
	// two daemons from one script (MEASURED 2026-10-09, #23).
	iscDHCP6PID = "/var/run/dhcpd6.pid"
	iscDHCP4PID = "/var/run/dhcpd.pid"
)

func (a *KeaAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	out, err := a.Runner.Run(ctx, keaLease6Cmd)
	if err != nil {
		return nil, fmt.Errorf("kea: control agent lease6 request: %w", err)
	}
	return parseKeaLeases6(out)
}

func (a *KeaAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return a.host().setRAViaRadvd(ctx, a.Runner, p, "kea")
}

// StopV6Server stops kea-dhcp6-server, its own unit; radvd keeps
// advertising (D3c, #23).
func (a *KeaAdapter) StopV6Server(ctx context.Context) (func(context.Context) error, error) {
	u := a.host().unit("kea-dhcp6-server")
	if err := u.do(ctx, a.Runner, "stop", "kea"); err != nil {
		return nil, err
	}
	return func(ctx context.Context) error { return u.do(ctx, a.Runner, "start", "kea") }, nil
}

// restart6 restarts the DHCPv6 daemon, which Kea runs as its own unit.
func (a *KeaAdapter) restart6(ctx context.Context) error {
	return a.host().unit("kea-dhcp6-server").do(ctx, a.Runner, "restart", "kea")
}

func (a *ISCDHCPAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+iscLease6File)
	if err != nil {
		return nil, fmt.Errorf("isc-dhcp: read dhcpd6.leases: %w", err)
	}
	return parseISCLeases6(out)
}

func (a *ISCDHCPAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return a.host().setRAViaRadvd(ctx, a.Runner, p, "isc-dhcp")
}

// iscStop6Cmd stops the -6 daemon by its pid file and then requires the
// -4 daemon's pid to be alive, so a stop that took v4 with it fails (#23 row D3c).
var iscStop6Cmd = fmt.Sprintf("sudo start-stop-daemon --stop --quiet --retry 5 --pidfile %s --exec /usr/sbin/dhcpd && sudo rm -f %s && sudo start-stop-daemon --status --pidfile %s",
	iscDHCP6PID, iscDHCP6PID, iscDHCP4PID)

// StopV6Server stops only dhcpd -6; the restore restarts the unit, which
// starts both daemons again (D3c, #23).
func (a *ISCDHCPAdapter) StopV6Server(ctx context.Context) (func(context.Context) error, error) {
	restore := func(ctx context.Context) error { return a.Restart(ctx) }
	if _, err := a.Runner.Run(ctx, iscStop6Cmd); err != nil {
		return nil, errors.Join(fmt.Errorf("isc-dhcp: stop dhcpd -6 alone: %w", err), restore(ctx))
	}
	return restore, nil
}

func (a *DnsmasqAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+dnsmasqLeaseFile)
	if err != nil {
		return nil, fmt.Errorf("dnsmasq: read dnsmasq.leases: %w", err)
	}
	return parseDnsmasqLeases6(out)
}

// StopV6Server is refused: one dnsmasq serves the RA and DHCPv6, and its
// M bit comes from a serving range (D3c, #23).
func (a *DnsmasqAdapter) StopV6Server(context.Context) (func(context.Context) error, error) {
	return nil, errors.New("dnsmasq: " + DnsmasqNoV6ServerStop)
}

// DnsmasqNoV6ServerStop is why dnsmasq does not declare CapV6ServerStop (#23 row D3c).
const DnsmasqNoV6ServerStop = "one dnsmasq process sends the RA and answers DHCPv6, so the RA cannot ask for DHCPv6 while the server is silent"

// NAReason gives D3c's N/A on dnsmasq its reason (DESIGN-23d row D3,
// INFERRED there, #23).
func (a *DnsmasqAdapter) NAReason(c Capability) (string, bool) {
	if c == CapV6ServerStop {
		return DnsmasqNoV6ServerStop, true
	}
	return "", false
}

var (
	dnsmasqEnableRARE = regexp.MustCompile(`(?m)^enable-ra$`)
	dnsmasqSlaacRE    = regexp.MustCompile(`(?m)^(dhcp-range=[^,\n]+,[^,\n]+,)slaac,`)
	dnsmasqRAOnlyRE   = regexp.MustCompile(`(?m)^(dhcp-range=[^,\n]+,)[^,\n]+,slaac,`)
	dnsmasqRAParamRE  = regexp.MustCompile(`(?m)^(ra-param=.*)$`)
)

// renderDnsmasqRA maps RAParams onto the v6 range's mode (dnsmasq(8)
// dhcp-range): slaac M=1 A=1, no flag M=1 A=0, ra-only M=0 A=1. dnsmasq
// has no PREF64 and no per-PIO lifetime, so Pref64 and SecondExpired
// are refused (#23).
func renderDnsmasqRA(orig string, p RAParams) (string, error) {
	if p.Pref64.IsValid() {
		return "", fmt.Errorf("dnsmasq: its RA carries no PREF64 option (RFC 8781): %w", ErrRAUnsupported)
	}
	if p.SecondExpired {
		return "", fmt.Errorf("dnsmasq: no knob advertises a PIO with valid lifetime 0: %w", ErrRAUnsupported)
	}
	if p.Second.IsValid() && !p.Autonomous {
		return "", errors.New("dnsmasq: a second prefix is advertised ra-only, which sets A=1")
	}
	var edits []configEdit
	switch {
	case p.Managed && !p.Autonomous:
		edits = append(edits, configEdit{dnsmasqSlaacRE, "${1}", "the v6 range's slaac flag"})
	case !p.Managed:
		edits = append(edits, configEdit{dnsmasqRAOnlyRE, "${1}ra-only,", "the v6 range's slaac flag"})
	}
	if p.Second.IsValid() {
		edits = append(edits, configEdit{dnsmasqRAParamRE, fmt.Sprintf("${1}\ndhcp-range=%s,ra-only,64,2h", p.Second.Addr()), "the ra-param line"})
	}
	out := orig
	for _, e := range edits {
		next := e.re.ReplaceAllString(out, e.repl)
		if next == out {
			return "", fmt.Errorf("dnsmasq: anchor for %s not found in %s; refusing to change it blindly", e.what, dnsmasqLabV6Conf)
		}
		out = next
	}
	return out, nil
}

// SetRA on dnsmasq rewrites lab-v6.conf and restarts; DHCPv6 keeps
// answering without RAs (MEASURED 2.91, #23).
func (a *DnsmasqAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	p, err := validateRA(p)
	if err != nil {
		return nil, err
	}
	if p.Off {
		edits := []configEdit{
			{dnsmasqEnableRARE, "#lab-ra-off", "the enable-ra line"},
			{dnsmasqSlaacRE, "${1}", "the v6 range's slaac flag"},
		}
		return enableFeatureViaSubstitution(ctx, a.Runner, dnsmasqLabV6Conf, "#lab-ra-off", edits,
			func(ctx context.Context) error { return a.Restart(ctx) }, "dnsmasq")
	}
	orig, err := a.Runner.Run(ctx, "sudo cat "+dnsmasqLabV6Conf)
	if err != nil {
		return nil, fmt.Errorf("dnsmasq: read %s: %w", dnsmasqLabV6Conf, err)
	}
	changed, err := renderDnsmasqRA(orig, p)
	if err != nil {
		return nil, err
	}
	return a.host().applyV6(ctx, a.Runner, dnsmasqLabV6Conf, orig, changed, p.Second, a.Restart, "dnsmasq")
}

// units are each adapter's Ready and Recover inputs (readiness.go): the
// v4 unit and config, then the v6 configs and the units serving them.
func (a *KeaAdapter) units() sourceUnits {
	if a.V4Only {
		return sourceUnits{service: "kea-dhcp4-server", cfgPath: "/etc/kea/kea-dhcp4.conf"}
	}
	return sourceUnits{service: "kea-dhcp4-server", cfgPath: "/etc/kea/kea-dhcp4.conf", leases6: a.Leases6,
		extra: []extraConf{{keaDHCP6Conf, "kea-dhcp6-server"}, {radvdConf, "radvd"}}}
}

func (a *ISCDHCPAdapter) units() sourceUnits {
	if a.V4Only {
		return sourceUnits{service: "isc-dhcp-server", cfgPath: "/etc/dhcp/dhcpd.conf"}
	}
	return sourceUnits{service: "isc-dhcp-server", cfgPath: "/etc/dhcp/dhcpd.conf", leases6: a.Leases6,
		extra: []extraConf{{iscDHCP6Conf, "isc-dhcp-server"}, {radvdConf, "radvd"}}}
}

func (a *DnsmasqAdapter) units() sourceUnits {
	return sourceUnits{service: "dnsmasq", cfgPath: "/etc/dnsmasq.conf", leases6: a.Leases6,
		extra: []extraConf{{dnsmasqLabV6Conf, "dnsmasq"}}}
}
