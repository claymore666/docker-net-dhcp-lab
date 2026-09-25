package sourceadapter

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// DnsmasqAdapter reads dnsmasq's own lease file directly. ReserveMAC and
// restart/stop/start are live-run measured (issue #2); declared here
// only after that run confirmed each one.
type DnsmasqAdapter struct {
	Runner Runner
}

func (a *DnsmasqAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart}
}

func (a *DnsmasqAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.Runner.Run(ctx, "sudo cat /var/lib/misc/dnsmasq.leases")
	if err != nil {
		return nil, fmt.Errorf("dnsmasq: read dnsmasq.leases: %w", err)
	}
	return parseDnsmasqLeases(out)
}

// parseDnsmasqLeases: one line is "<expiry> <mac> <ip> <hostname>
// <client-id>". A blank file (dnsmasq creates it at startup even with
// zero leases) is a genuine empty table; a line with too few fields, or
// a MAC that does not parse, is a truncated or malformed read and must
// fail rather than silently drop that row (issue #2 defeat list).
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
		leases = append(leases, Lease{MAC: mac, Address: ip, Hostname: host})
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

func (a *DnsmasqAdapter) systemctl(ctx context.Context, action string) error {
	if _, err := a.Runner.Run(ctx, "sudo systemctl "+action+" dnsmasq"); err != nil {
		return fmt.Errorf("dnsmasq: systemctl %s: %w", action, err)
	}
	return nil
}
