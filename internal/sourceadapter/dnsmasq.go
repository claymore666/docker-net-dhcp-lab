package sourceadapter

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// dnsmasqRangeRE matches the dhcp-range config line's own three fields
// (start, end, lease-time), capturing everything up to the lease-time
// field so ShortenLeaseTime can replace only that field (#3, A14).
var dnsmasqRangeRE = regexp.MustCompile(`(?m)^(dhcp-range=[^,]+,[^,]+,)[^,]+$`)

// DnsmasqAdapter reads dnsmasq's own lease file directly. ReserveMAC's
// command construction is unit-tested against a fake runner
// (adapter_test.go); restart/stop/start are implemented but not yet
// exercised against a live instance.
type DnsmasqAdapter struct {
	Runner Runner
}

func (a *DnsmasqAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease}
}

// dnsmasqLeaseFile is the on-disk lease table this adapter reads
// directly (Leases()) and is the file ResetLeases truncates (issue #3
// part 2).
const dnsmasqLeaseFile = "/var/lib/misc/dnsmasq.leases"

func (a *DnsmasqAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+dnsmasqLeaseFile)
	if err != nil {
		return nil, fmt.Errorf("dnsmasq: read dnsmasq.leases: %w", err)
	}
	return parseDnsmasqLeases(out)
}

// parseDnsmasqLeases: one line is "<expiry> <mac> <ip> <hostname>
// <client-id>". A blank file (dnsmasq creates it at startup even with
// zero leases) is a genuine empty table; a line with too few fields, or
// a MAC that does not parse, is a truncated or malformed read and must
// fail rather than silently drop that row (issue #2).
func parseDnsmasqLeases(raw string) ([]Lease, error) {
	trimmed := strings.TrimRight(raw, "\n")
	if trimmed == "" {
		return []Lease{}, nil
	}
	lines := strings.Split(trimmed, "\n")
	leases := make([]Lease, 0, len(lines))
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, fmt.Errorf("dnsmasq: lease line %d has %d field(s), want at least 4: %q", i+1, len(fields), line)
		}
		mac, ip, host := fields[1], fields[2], fields[3]
		if _, err := net.ParseMAC(mac); err != nil {
			return nil, fmt.Errorf("dnsmasq: lease line %d: invalid MAC %q: %w", i+1, mac, err)
		}
		l := Lease{MAC: mac, Address: ip, Hostname: host}
		// Field 5, the client-id (option 61), is dnsmasq's own
		// colon-hex encoding, or "*" when the client sent none
		// (#3).
		if len(fields) >= 5 && fields[4] != "*" {
			l.ClientID = strings.ToLower(fields[4])
		}
		leases = append(leases, l)
	}
	return leases, nil
}

// ReserveMAC appends a dhcp-host line to the lab's own reservations file
// under dnsmasq's conf-dir (issue #2), then restarts -- dnsmasq's SIGHUP
// reloads the lease file and a handful of directives but not a new
// dhcp-host line. hw/ip are guaranteed clean by validateMAC/validateAddr
// before they ever reach this string.
func (a *DnsmasqAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf(`echo 'dhcp-host=%s,%s' | sudo tee -a /etc/dnsmasq.d/lab-reservations.conf >/dev/null && sudo systemctl restart dnsmasq`, hw, ip)
	if _, err := a.Runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("dnsmasq: reserve %s -> %s: %w", hw, ip, err)
	}
	return nil
}

func (a *DnsmasqAdapter) Restart(ctx context.Context) error { return a.systemctl(ctx, "restart") }
func (a *DnsmasqAdapter) Stop(ctx context.Context) error    { return a.systemctl(ctx, "stop") }
func (a *DnsmasqAdapter) Start(ctx context.Context) error   { return a.systemctl(ctx, "start") }

func (a *DnsmasqAdapter) Reachable(ctx context.Context, addr string) error {
	return reachable(ctx, a.Runner, addr)
}

// ResetLeases stops dnsmasq, truncates dnsmasqLeaseFile, and starts it
// again (issue #3 part 2).
func (a *DnsmasqAdapter) ResetLeases(ctx context.Context) error {
	return resetLeasesViaTruncate(ctx, a.Runner, dnsmasqLeaseFile, "dnsmasq", "dnsmasq")
}

func (a *DnsmasqAdapter) systemctl(ctx context.Context, action string) error {
	if _, err := a.Runner.Run(ctx, "sudo systemctl "+action+" dnsmasq"); err != nil {
		return fmt.Errorf("dnsmasq: systemctl %s: %w", action, err)
	}
	return nil
}

// ShortenLeaseTime rewrites the RUNNING config's dhcp-range lease-time
// field (its third, unitless field is already seconds -- dnsmasq(8)) and
// restarts (issue #3, A14). It captures /etc/dnsmasq.conf as it stands
// right now, never /root/lab-stock-config/dnsmasq.conf.stock: that file
// is the package's own pre-install default, captured before this cell's
// own dhcp-range/pool ever got written over it (cloud-init runcmd
// order), so restoring from it would replace this cell's whole working
// config, not just undo the lease-time edit.
func (a *DnsmasqAdapter) ShortenLeaseTime(ctx context.Context, seconds int) (func(context.Context) error, error) {
	if seconds <= 0 {
		return nil, fmt.Errorf("dnsmasq: lease time must be positive, got %d", seconds)
	}
	return shortenLeaseTimeViaSubstitution(ctx, a.Runner, "/etc/dnsmasq.conf",
		dnsmasqRangeRE, fmt.Sprintf("${1}%d", seconds),
		func(ctx context.Context) error { return a.Restart(ctx) }, "dnsmasq")
}
