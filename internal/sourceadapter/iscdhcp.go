package sourceadapter

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ISCDHCPAdapter reads dhcpd.leases directly -- the source's own on-disk
// table, ISC dhcpd has no query API. ReserveMAC's command construction
// is unit-tested against a fake runner (adapter_test.go); restart/stop/
// start are implemented but not yet exercised against a live instance.
type ISCDHCPAdapter struct {
	Runner Runner
}

func (a *ISCDHCPAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart}
}

func (a *ISCDHCPAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.Runner.Run(ctx, "sudo cat /var/lib/dhcp/dhcpd.leases")
	if err != nil {
		return nil, fmt.Errorf("isc-dhcp: read dhcpd.leases: %w", err)
	}
	return parseISCLeases(out)
}

var (
	iscLeaseStartRE = regexp.MustCompile(`(?m)^lease\s+[\d.]+\s*\{`)
	iscLeaseBlockRE = regexp.MustCompile(`(?s)lease\s+([\d.]+)\s*\{(.*?)\n\}`)
	iscHWRE         = regexp.MustCompile(`hardware ethernet\s+([0-9a-fA-F:]+);`)
	iscHostRE       = regexp.MustCompile(`client-hostname\s+"([^"]*)";`)
	iscStateRE      = regexp.MustCompile(`binding state\s+(\w+);`)
)

// parseISCLeases keeps the LAST block per address (dhcpd appends renewals
// at the end of the file) and drops any address whose latest block is not
// "active". A lease-block count that does not match the number of blocks
// this parsed cleanly means the file was cut mid-write, and that is an
// error, never an empty table (issue #2); a file with no
// "lease " blocks at all (a fresh install before any DISCOVER) is a
// genuine empty table.
func parseISCLeases(raw string) ([]Lease, error) {
	starts := iscLeaseStartRE.FindAllStringIndex(raw, -1)
	blocks := iscLeaseBlockRE.FindAllStringSubmatch(raw, -1)
	if len(blocks) != len(starts) {
		return nil, fmt.Errorf("isc-dhcp: %d lease block(s) opened but only %d parsed cleanly; leases file looks truncated", len(starts), len(blocks))
	}
	byIP := map[string]Lease{}
	for _, b := range blocks {
		ip, body := b[1], b[2]
		if m := iscStateRE.FindStringSubmatch(body); len(m) == 2 && m[1] != "active" {
			delete(byIP, ip)
			continue
		}
		l := Lease{Address: ip}
		if m := iscHWRE.FindStringSubmatch(body); len(m) == 2 {
			l.MAC = m[1]
		}
		if m := iscHostRE.FindStringSubmatch(body); len(m) == 2 {
			l.Hostname = m[1]
		}
		byIP[ip] = l
	}
	leases := make([]Lease, 0, len(byIP))
	for _, l := range byIP {
		leases = append(leases, l)
	}
	sort.Slice(leases, func(i, j int) bool { return leases[i].Address < leases[j].Address })
	return leases, nil
}

// ReserveMAC appends a host block to the file the stock config is made
// to include (issue #2), then restarts -- dhcpd has no reload signal
// that re-reads new host declarations. hw/ip are guaranteed clean by
// validateMAC/validateAddr before they ever reach this string.
func (a *ISCDHCPAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	name := strings.ReplaceAll(hw, ":", "")
	block := fmt.Sprintf(`host lab-%s { hardware ethernet %s; fixed-address %s; }`, name, hw, ip)
	cmd := fmt.Sprintf(`echo '%s' | sudo tee -a /etc/dhcp/lab-reservations.conf >/dev/null && sudo systemctl restart isc-dhcp-server`, block)
	if _, err := a.Runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("isc-dhcp: reserve %s -> %s: %w", hw, ip, err)
	}
	return nil
}

func (a *ISCDHCPAdapter) Restart(ctx context.Context) error { return a.systemctl(ctx, "restart") }
func (a *ISCDHCPAdapter) Stop(ctx context.Context) error    { return a.systemctl(ctx, "stop") }
func (a *ISCDHCPAdapter) Start(ctx context.Context) error   { return a.systemctl(ctx, "start") }

func (a *ISCDHCPAdapter) systemctl(ctx context.Context, action string) error {
	if _, err := a.Runner.Run(ctx, "sudo systemctl "+action+" isc-dhcp-server"); err != nil {
		return fmt.Errorf("isc-dhcp: systemctl %s: %w", action, err)
	}
	return nil
}
