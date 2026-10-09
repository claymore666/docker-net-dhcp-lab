package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// RAParams is what SetRA changes on the segment's router advertisements.
// Off stops them: radvd stops (its final RA carries router lifetime 0,
// radvd.conf(5)), dnsmasq drops enable-ra and slaac, both of which send
// RAs on their own (MEASURED dnsmasq 2.91, #23).
type RAParams struct {
	Off bool
}

func validateRA(p RAParams) error {
	if !p.Off {
		return errors.New("SetRA: only RAParams.Off is implemented")
	}
	return nil
}

// setRAViaRadvd stops radvd; the restore starts it again.
func setRAViaRadvd(ctx context.Context, r Runner, p RAParams, label string) (func(context.Context) error, error) {
	if err := validateRA(p); err != nil {
		return nil, err
	}
	if _, err := r.Run(ctx, "sudo systemctl stop radvd"); err != nil {
		return nil, fmt.Errorf("%s: stop radvd: %w", label, err)
	}
	return func(ctx context.Context) error {
		if _, err := r.Run(ctx, "sudo systemctl start radvd"); err != nil {
			return fmt.Errorf("%s: start radvd: %w", label, err)
		}
		return nil
	}, nil
}

const (
	keaDHCP6Conf     = "/etc/kea/kea-dhcp6.conf"
	iscDHCP6Conf     = "/etc/dhcp/dhcpd6.conf"
	dnsmasqLabV6Conf = "/etc/dnsmasq.d/lab-v6.conf"
	radvdConf        = "/etc/radvd.conf"
)

func (a *KeaAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	out, err := a.Runner.Run(ctx, keaLease6Cmd)
	if err != nil {
		return nil, fmt.Errorf("kea: control agent lease6 request: %w", err)
	}
	return parseKeaLeases6(out)
}

func (a *KeaAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return setRAViaRadvd(ctx, a.Runner, p, "kea")
}

// restart6 restarts the DHCPv6 daemon, which Kea runs as its own unit.
func (a *KeaAdapter) restart6(ctx context.Context) error {
	if _, err := a.Runner.Run(ctx, "sudo systemctl restart kea-dhcp6-server"); err != nil {
		return fmt.Errorf("kea: systemctl restart kea-dhcp6-server: %w", err)
	}
	return nil
}

func (a *ISCDHCPAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+iscLease6File)
	if err != nil {
		return nil, fmt.Errorf("isc-dhcp: read dhcpd6.leases: %w", err)
	}
	return parseISCLeases6(out)
}

func (a *ISCDHCPAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return setRAViaRadvd(ctx, a.Runner, p, "isc-dhcp")
}

func (a *DnsmasqAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+dnsmasqLeaseFile)
	if err != nil {
		return nil, fmt.Errorf("dnsmasq: read dnsmasq.leases: %w", err)
	}
	return parseDnsmasqLeases6(out)
}

var (
	dnsmasqEnableRARE = regexp.MustCompile(`(?m)^enable-ra$`)
	dnsmasqSlaacRE    = regexp.MustCompile(`(?m)^(dhcp-range=[^,\n]+,[^,\n]+,)slaac,`)
)

// SetRA on dnsmasq rewrites lab-v6.conf; DHCPv6 keeps answering without
// RAs (MEASURED 2.91, #23).
func (a *DnsmasqAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	if err := validateRA(p); err != nil {
		return nil, err
	}
	edits := []configEdit{
		{dnsmasqEnableRARE, "#lab-ra-off", "the enable-ra line"},
		{dnsmasqSlaacRE, "${1}", "the v6 range's slaac flag"},
	}
	return enableFeatureViaSubstitution(ctx, a.Runner, dnsmasqLabV6Conf, "#lab-ra-off", edits,
		func(ctx context.Context) error { return a.Restart(ctx) }, "dnsmasq")
}
