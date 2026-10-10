package sourceadapter

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ISCDHCPAdapter reads dhcpd.leases directly -- the source's own on-disk
// table, ISC dhcpd has no query API. ReserveMAC's command construction
// is unit-tested against a fake runner (adapter_test.go); restart/stop/
// start are implemented but not yet exercised against a live instance.
type ISCDHCPAdapter struct {
	Runner Runner
	// V4Only is a failover partner: its VM runs no DHCPv6 or radvd, so
	// v6 is neither declared nor held by Ready. Failover makes a pool
	// the adapter adds carry "failover peer" (lab #12).
	V4Only, Failover bool
	base             baseline
}

func (a *ISCDHCPAdapter) Capabilities() []Capability {
	if a.V4Only {
		return slices.DeleteFunc(a.allCapabilities(), func(c Capability) bool { return v6Capabilities[c] })
	}
	return a.allCapabilities()
}

func (a *ISCDHCPAdapter) allCapabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease, CapReserveClientID, CapVendorClassPool, CapOptionChange, CapImpair, CapUserClassPool, CapOption108, CapForceRenewNonce, CapSquatter, CapRogueServer, CapNarrowPool, CapRenumber, CapV6, CapRapidCommit6, CapTemporary6}
}

// iscLeaseFile is the on-disk lease table this adapter reads directly
// (Leases()) and is the file ResetLeases truncates (issue #3 part 2).
const iscLeaseFile = "/var/lib/dhcp/dhcpd.leases"

func (a *ISCDHCPAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+iscLeaseFile)
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
	iscUIDRE        = regexp.MustCompile(`(?s)uid\s+"(.*?)";`)
	// iscEndsRE reads the lease end (dhcpd.leases(5): weekday, then
	// YYYY/MM/DD HH:MM:SS in UTC); "ends never;" does not match and
	// leaves Expires zero (B6, #23).
	iscEndsRE = regexp.MustCompile(`\bends\s+\d\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2});`)
	// iscDefaultLeaseTimeRE matches dhcpd.conf's own default-lease-time
	// setting (ShortenLeaseTime, #3, A14).
	iscDefaultLeaseTimeRE = regexp.MustCompile(`default-lease-time\s+[0-9]+;`)
)

// decodeISCQuotedString turns dhcpd.leases' own C-style quoting for a
// binary field (the "uid" client-id, option 61) back into raw bytes:
// dhcpd prints a printable ASCII byte literally and any other byte as a
// three-digit octal escape ("\NNN"), the same convention as its own
// print_hw_addr/lease-dump code (#3) -- so \" and \\ are the only
// two-character escapes, and every other backslash must begin a
// three-digit octal run.
func decodeISCQuotedString(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			i++
			continue
		}
		if i+1 >= len(s) {
			return nil, fmt.Errorf("isc-dhcp: uid string ends mid-escape: %q", s)
		}
		switch next := s[i+1]; {
		case next == '"' || next == '\\':
			out = append(out, next)
			i += 2
		case next >= '0' && next <= '7':
			if i+4 > len(s) {
				return nil, fmt.Errorf("isc-dhcp: truncated octal escape in uid string: %q", s)
			}
			v, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
			if err != nil {
				return nil, fmt.Errorf("isc-dhcp: bad octal escape %q in uid string: %w", s[i+1:i+4], err)
			}
			out = append(out, byte(v))
			i += 4
		default:
			return nil, fmt.Errorf("isc-dhcp: unrecognized escape in uid string: %q", s)
		}
	}
	return out, nil
}

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
		if m := iscEndsRE.FindStringSubmatch(body); len(m) == 2 {
			if t, err := time.Parse("2006/01/02 15:04:05", m[1]); err == nil {
				l.Expires = t.UTC()
			}
		}
		if m := iscUIDRE.FindStringSubmatch(body); len(m) == 2 {
			raw, err := decodeISCQuotedString(m[1])
			if err != nil {
				return nil, fmt.Errorf("isc-dhcp: lease %s: %w", ip, err)
			}
			l.ClientID = hexColon(raw)
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

// iscReserve replaces any host block of the same name in the include
// file and appends the new one, then restarts -- dhcpd has no reload
// signal that re-reads new host declarations, and it refuses to start on
// a duplicate host name, which a rerun would otherwise create (#23).
// name, match and ip are validated by the callers.
func (a *ISCDHCPAdapter) iscReserve(ctx context.Context, name, match, ip string) error {
	block := fmt.Sprintf(`host %s { %s; fixed-address %s; }`, name, match, ip)
	cmd := fmt.Sprintf(`sudo sed -i '/^host %s /d' /etc/dhcp/lab-reservations.conf && echo '%s' | sudo tee -a /etc/dhcp/lab-reservations.conf >/dev/null && %s`, name, block, a.host().svc().restart)
	if _, err := a.Runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("isc-dhcp: reserve %s -> %s: %w", name, ip, err)
	}
	return nil
}

// ReserveMAC reserves ip for the MAC (issue #2). hw/ip are guaranteed
// clean by validateMAC/validateAddr before they ever reach the command.
func (a *ISCDHCPAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return a.iscReserve(ctx, "lab-"+strings.ReplaceAll(hw, ":", ""), "hardware ethernet "+hw, ip)
}

// ReserveClientID reserves ip for an option 61 value (B2, #23). dhcpd
// matches option dhcp-client-identifier against the whole payload, type
// byte included, which is the form its lease "uid" field records.
func (a *ISCDHCPAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	id, err := validateClientID(clientID)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return a.iscReserve(ctx, "lab-cid-"+strings.ReplaceAll(id, ":", ""), "option dhcp-client-identifier "+id, ip)
}

func (a *ISCDHCPAdapter) Restart(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "restart", "isc-dhcp")
}
func (a *ISCDHCPAdapter) Stop(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "stop", "isc-dhcp")
}
func (a *ISCDHCPAdapter) Start(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "start", "isc-dhcp")
}

func (a *ISCDHCPAdapter) Reachable(ctx context.Context, addr string) error {
	return reachable(ctx, a.Runner, addr)
}

// ResetLeases stops isc-dhcp-server, truncates iscLeaseFile, and starts
// it again (issue #3 part 2).
func (a *ISCDHCPAdapter) ResetLeases(ctx context.Context) error {
	return resetLeasesViaTruncate(ctx, a.Runner, iscLeaseFile, nil, a.host().svc(), "isc-dhcp")
}

// host is this source's userland: systemd, eth1 and /usr/sbin/tc (#9).
func (a *ISCDHCPAdapter) host() host { return debianHost("isc-dhcp-server") }

// ShortenLeaseTime rewrites the RUNNING config's default-lease-time and
// restarts (issue #3, A14). It captures /etc/dhcp/dhcpd.conf as it
// stands right now, never /root/lab-stock-config/dhcpd.conf.stock: that
// file is the package's own pre-install default, captured before this
// cell's own subnet/pool/lab-reservations.conf include ever got written
// over it, so restoring from it would drop this cell's whole working
// config. max-lease-time is left untouched: it only caps a lease a
// client explicitly requests a longer term for, and this scenario's
// bare client takes whatever default-lease-time hands it, the same
// RFC 2131 T1-at-roughly-half-the-lease fallback dnsmasq and Kea both
// rely on here too, since dhcpd sends no explicit T1/T2 of its own
// either.
func (a *ISCDHCPAdapter) ShortenLeaseTime(ctx context.Context, seconds int) (func(context.Context) error, error) {
	if seconds <= 0 {
		return nil, fmt.Errorf("isc-dhcp: lease time must be positive, got %d", seconds)
	}
	repl := fmt.Sprintf(`default-lease-time %d;`, seconds)
	return shortenLeaseTimeViaSubstitution(ctx, a.Runner, "/etc/dhcp/dhcpd.conf",
		iscDefaultLeaseTimeRE, repl,
		func(ctx context.Context) error { return a.Restart(ctx) }, "isc-dhcp")
}

// iscRoutersRE anchors SetDNSOption on the routers line the cloud-init
// template always writes inside the subnet block.
var iscRoutersRE = regexp.MustCompile(`(?m)^(\s*)(option routers [^;]*;)`)

// SetDNSOption adds an option domain-name-servers line after the routers
// line of the running config and restarts (B6, #23).
func (a *ISCDHCPAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	repl := fmt.Sprintf("${1}${2}\n${1}option domain-name-servers %s;", ip)
	return setDNSOptionViaSubstitution(ctx, a.Runner, "/etc/dhcp/dhcpd.conf",
		iscRoutersRE, repl, "option domain-name-servers",
		func(ctx context.Context) error { return a.Restart(ctx) }, "isc-dhcp")
}

// Ready, Recover and Impair: the shared group C bodies (readiness.go, #23).
func (a *ISCDHCPAdapter) Ready(ctx context.Context) error {
	return a.host().sourceReady(ctx, a.Runner, a.units(), a.Leases, &a.base)
}

func (a *ISCDHCPAdapter) Recover(ctx context.Context) error {
	return a.host().sourceRecover(ctx, a.Runner, a.units(), &a.base)
}

func (a *ISCDHCPAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return a.host().impair(ctx, a.Runner, delay, lossPct)
}
