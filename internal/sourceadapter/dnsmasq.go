package sourceadapter

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// dnsmasqRangeRE matches the dhcp-range config line's own three fields
// (start, end, lease-time), capturing everything up to the lease-time
// field so ShortenLeaseTime can replace only that field (#3, A14).
//
// The tag:... fields are what the B5 and user-class ranges carry
// (dhcp-range=tag:!b5,tag:!f1,start,end,12h, #23, #20); without them the main range
// would no longer match once the config is tagged and A14 would break.
var dnsmasqRangeRE = regexp.MustCompile(`(?m)^(dhcp-range=(?:tag:[^,\n]+,)*[^,\n]+,[^,\n]+,)[^,\n]+$`)

// DnsmasqAdapter reads dnsmasq's own lease file directly. ReserveMAC's
// command construction is unit-tested against a fake runner
// (adapter_test.go); restart/stop/start are implemented but not yet
// exercised against a live instance.
type DnsmasqAdapter struct {
	Runner Runner
	base   baseline
}

func (a *DnsmasqAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease, CapReserveClientID, CapDNSRegistration, CapVendorClassPool, CapOptionChange, CapImpair, CapUserClassPool, CapOption108, CapRapidCommit4, CapForceRenewNonce, CapSquatter, CapRogueServer, CapNarrowPool, CapRenumber}
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
// fail rather than silently drop that row (issue #2). The v4 table ends
// at the "duid" line; the DHCPv6 rows after it are parseDnsmasqLeases6's
// (#23 group D).
func parseDnsmasqLeases(raw string) ([]Lease, error) {
	trimmed := strings.TrimRight(raw, "\n")
	if trimmed == "" {
		return []Lease{}, nil
	}
	lines := strings.Split(trimmed, "\n")
	leases := make([]Lease, 0, len(lines))
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "duid" {
			break
		}
		if len(fields) < 4 {
			return nil, fmt.Errorf("dnsmasq: lease line %d has %d field(s), want at least 4: %q", i+1, len(fields), line)
		}
		mac, ip, host := fields[1], fields[2], fields[3]
		if _, err := net.ParseMAC(mac); err != nil {
			return nil, fmt.Errorf("dnsmasq: lease line %d: invalid MAC %q: %w", i+1, mac, err)
		}
		l := Lease{MAC: mac, Address: ip, Hostname: host}
		// Field 1 is the expiry as a unix epoch; 0 means infinite
		// (dnsmasq(8)) and leaves Expires zero (B6, #23).
		if epoch, err := strconv.ParseInt(fields[0], 10, 64); err == nil && epoch > 0 {
			l.Expires = time.Unix(epoch, 0).UTC()
		}
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

// dnsmasqReserve replaces any dhcp-host line for the same key in the
// lab's reservations file under dnsmasq's conf-dir and appends the new
// one, then restarts -- dnsmasq's SIGHUP reloads the lease file and a
// handful of directives but not a new dhcp-host line. key and ip are
// validated by the callers (issue #2, #23).
func (a *DnsmasqAdapter) dnsmasqReserve(ctx context.Context, key, ip string) error {
	cmd := fmt.Sprintf(`sudo sed -i '/^dhcp-host=%s,/d' /etc/dnsmasq.d/lab-reservations.conf && echo 'dhcp-host=%s,%s' | sudo tee -a /etc/dnsmasq.d/lab-reservations.conf >/dev/null && sudo systemctl restart dnsmasq`, key, key, ip)
	if _, err := a.Runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("dnsmasq: reserve %s -> %s: %w", key, ip, err)
	}
	return nil
}

// ReserveMAC reserves ip for the MAC (issue #2).
func (a *DnsmasqAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return a.dnsmasqReserve(ctx, hw, ip)
}

// ReserveClientID reserves ip for an option 61 value with dhcp-host=
// id:<hex> (B2, #23); dnsmasq compares it with the payload as received,
// type byte included, the form its lease file prints.
func (a *DnsmasqAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	id, err := validateClientID(clientID)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return a.dnsmasqReserve(ctx, "id:"+id, ip)
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
	return resetLeasesViaTruncate(ctx, a.Runner, dnsmasqLeaseFile, nil, "dnsmasq", "dnsmasq")
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

// dnsmasqRouterOptionRE anchors SetDNSOption on the router option line
// the cloud-init template always writes.
var dnsmasqRouterOptionRE = regexp.MustCompile(`(?m)^(dhcp-option=3,[^\n]*)$`)

// SetDNSOption adds dhcp-option=6 after the router option of the
// running config and restarts (B6, #23). Without it dnsmasq advertises
// its own address as the DNS server.
func (a *DnsmasqAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	repl := fmt.Sprintf("${1}\ndhcp-option=6,%s", ip)
	return setDNSOptionViaSubstitution(ctx, a.Runner, "/etc/dnsmasq.conf",
		dnsmasqRouterOptionRE, repl, "dhcp-option=6,",
		func(ctx context.Context) error { return a.Restart(ctx) }, "dnsmasq")
}

// Ready, Recover and Impair: the shared group C bodies (readiness.go, #23).
func (a *DnsmasqAdapter) Ready(ctx context.Context) error {
	return sourceReady(ctx, a.Runner, a.units(), a.Leases, &a.base)
}

func (a *DnsmasqAdapter) Recover(ctx context.Context) error {
	return sourceRecover(ctx, a.Runner, a.units(), &a.base)
}

func (a *DnsmasqAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return impair(ctx, a.Runner, delay, lossPct)
}
