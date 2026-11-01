package sourceadapter

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// The names the image's first logon (cloud-init/windows/firstlogon.tmpl.ps1)
// gives its objects; scenario objects all start with winFeature so Recover
// can find them again (lab #14).
const (
	winSegAlias  = "seg"
	winLabDir    = `C:\ProgramData\lab`
	winBaseline  = winLabDir + `\baseline.xml`
	winImportBak = winLabDir + `\import-backup`
	winFeature   = "labf"
)

const winNoActor = "the Windows source runs no Linux userland, so none of the lab's source-side actors (iproute2 netns, tc, python3)"

// winV6Reason is why the cell serves no DHCPv6: the image adds no v6 scope
// (lab #14, design §8 PR 5).
const winV6Reason = "the Windows image configures no DHCPv6 scope, so the cell is DHCPv4 only."

var windowsNAReasons = map[Capability]string{
	CapImpair:          "Impair puts netem on the source's segment leg; " + winNoActor + ".",
	CapSquatter:        "the squatter is a netns actor on the source; " + winNoActor + ".",
	CapRogueServer:     "the rogue server is a netns actor on the source; " + winNoActor + ".",
	CapForceRenewNonce: "SendForceRenew runs the lab's sender on the source; " + winNoActor + ". Windows Server DHCP sends no FORCERENEW (lab #14).",
	CapRapidCommit4:    "Windows Server DHCP implements rapid commit for DHCPv6 only, not option 80 for DHCPv4 (lab #14).",
	CapDNSRegistration: "the Windows image installs no DNS role, so the server's dynamic DNS updates have no zone to write (lab #14, design D3).",
	CapV6:              winV6Reason,
	CapServerEvents:    serverEventsNA,
	CapVLANPool:        vlanPoolNA,
}

// NAReason names why a capability is absent (DESIGN-910 5.2, lab #14).
func (a *WindowsAdapter) NAReason(c Capability) (string, bool) {
	why, ok := windowsNAReasons[c]
	return why, ok
}

// WindowsAdapter drives Windows Server 2025's DHCP role over OpenSSH as
// user lab: every command is PowerShell, sent as -EncodedCommand so no
// quote crosses two shells, with only validated values inside (lab #14).
type WindowsAdapter struct {
	Runner Runner
	base   baseline
}

func (a *WindowsAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapReserveClientID, CapRestart, CapShortLease, CapOptionChange, CapVendorClassPool, CapUserClassPool, CapOption108, CapNarrowPool, CapRenumber}
}

// host is this source's userland for needPortable: no actor tools.
func (a *WindowsAdapter) host() host {
	return host{unit: func(string) service { return service{name: "DHCPServer"} }, main: "windows", portable: false}
}

// winPS wraps script for the lab user's DefaultShell (PowerShell 5.1):
// stop on the first error, and exit 1 after a non-terminating one, which
// PowerShell otherwise ends with exit 0 (lab #14).
func winPS(script string) string {
	full := "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; " + script + "; if (-not $?) { exit 1 }"
	u := utf16.Encode([]rune(full))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return "powershell -NonInteractive -NoProfile -EncodedCommand " + base64.StdEncoding.EncodeToString(b)
}

// winScope binds $sid to the one scope the image keeps; two or none is a
// state no scenario left on purpose.
const winScope = `$sc = @(Get-DhcpServerv4Scope); if ($sc.Count -ne 1) { throw ('the server has ' + $sc.Count + ' scopes, the lab keeps one') }; $sid = $sc[0].ScopeId.IPAddressToString; `

func (a *WindowsAdapter) run(ctx context.Context, script string) (string, error) {
	out, err := a.Runner.Run(ctx, winPS(script))
	out = strings.ReplaceAll(out, "\r", "")
	if err != nil {
		return out, fmt.Errorf("windows: %w", err)
	}
	return out, nil
}

// winLeaseCmd prints the guest's clock, then the scope's active rows as
// one JSON array; -InputObject @() keeps a single row an array (lab #14).
const winLeaseCmd = winScope + `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); ` +
	`$l = @(Get-DhcpServerv4Lease -ScopeId $sid | Where-Object { $_.AddressState -like 'Active*' } | ForEach-Object { [ordered]@{ ` +
	`IPAddress = $_.IPAddress.IPAddressToString; ClientId = [string]$_.ClientId; HostName = [string]$_.HostName; AddressState = [string]$_.AddressState; ` +
	`Expiry = $(if ($_.LeaseExpiryTime) { ([DateTimeOffset]$_.LeaseExpiryTime).ToUnixTimeSeconds() } else { 0 }) } }); ` +
	`ConvertTo-Json -Compress -Depth 3 -InputObject $l`

func (a *WindowsAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.run(ctx, winLeaseCmd)
	if err != nil {
		return nil, fmt.Errorf("windows: read leases: %w", err)
	}
	return parseWindowsLeases(out, time.Now())
}

type winLeaseRow struct {
	IPAddress    string
	ClientId     string
	HostName     string
	AddressState string
	Expiry       int64
}

// parseWindowsLeases reads winLeaseCmd's output. Expiry is moved by the
// guest's clock offset, so a drifted guest never moves a lease-time
// verdict (design §4 Clock, lab #14).
func parseWindowsLeases(out string, now time.Time) ([]Lease, error) {
	clock, body, _ := strings.Cut(strings.TrimLeft(out, "\n "), "\n")
	guest, err := strconv.ParseInt(strings.TrimSpace(clock), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("windows: lease read: guest clock %q: %w", clock, err)
	}
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "[") {
		return nil, fmt.Errorf("windows: lease read is not a JSON array: %q", body)
	}
	var rows []winLeaseRow
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, fmt.Errorf("windows: lease read: %w", err)
	}
	var leases []Lease
	for _, r := range rows {
		if r.AddressState != "Active" && r.AddressState != "ActiveReservation" {
			continue
		}
		if _, err := validateAddr(r.IPAddress); err != nil {
			return nil, fmt.Errorf("windows: lease row %+v: %w", r, err)
		}
		l := Lease{Address: r.IPAddress, Hostname: r.HostName}
		if r.ClientId != "" {
			id, err := winClientID(r.ClientId)
			if err != nil {
				return nil, fmt.Errorf("windows: lease row %+v: %w", r, err)
			}
			l.ClientID = hexColon(winWireClientID(id))
			l.MAC = winMAC(id)
		}
		if r.Expiry > 0 {
			l.Expires = now.Add(time.Duration(r.Expiry-guest) * time.Second)
		}
		leases = append(leases, l)
	}
	return leases, nil
}

// winWireClientID restores the type byte Windows drops from its ClientId
// column for an id that is not a hardware address: the ipvlan client-id
// 00:<8 bytes> is listed as the 8 bytes (measured 2026-10-31, lab #14).
// Other type bytes are not used by any scenario, so type 0 is assumed.
func winWireClientID(id []byte) []byte {
	if winMAC(id) != "" {
		return id
	}
	return append([]byte{0}, id...)
}

// winClientID reads Windows's dash-separated client id hex.
func winClientID(s string) ([]byte, error) {
	var b []byte
	for _, p := range strings.Split(s, "-") {
		n, err := strconv.ParseUint(p, 16, 8)
		if err != nil || len(p) != 2 {
			return nil, fmt.Errorf("client id %q is not dash-separated hex bytes", s)
		}
		b = append(b, byte(n))
	}
	return b, nil
}

// winMAC is the hardware address a client id carries: Windows stores the
// chaddr when no option 61 came, six bytes, and type 1 plus the MAC for an
// Ethernet option 61 (RFC 2132 9.14); any other id names no MAC.
func winMAC(id []byte) string {
	switch {
	case len(id) == 6:
		return net.HardwareAddr(id).String()
	case len(id) == 7 && id[0] == 1:
		return net.HardwareAddr(id[1:]).String()
	}
	return ""
}

// winDash is colon-hex as Windows writes a client id.
func winDash(colonHex string) string { return strings.ReplaceAll(colonHex, ":", "-") }

// reserve drops every reservation and lease on the address or the id,
// then adds the reservation (lab #14).
func (a *WindowsAdapter) reserve(ctx context.Context, id, addr string) error {
	_, err := a.run(ctx, winScope+fmt.Sprintf(`Get-DhcpServerv4Reservation -ScopeId $sid | Where-Object { $_.IPAddress.IPAddressToString -eq '%[1]s' -or $_.ClientId -eq '%[2]s' } | Remove-DhcpServerv4Reservation; `+
		`Get-DhcpServerv4Lease -ScopeId $sid | Where-Object { $_.IPAddress.IPAddressToString -eq '%[1]s' -or $_.ClientId -eq '%[2]s' } | Remove-DhcpServerv4Lease; `+
		`Add-DhcpServerv4Reservation -ScopeId $sid -IPAddress '%[1]s' -ClientId '%[2]s' -Name '%[3]s' -Type Dhcp`, addr, id, winFeature+strings.ReplaceAll(addr, ".", "-")))
	return err
}

func (a *WindowsAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return a.reserve(ctx, winDash(hw), ip)
}

func (a *WindowsAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	id, err := validateClientID(clientID)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return a.reserve(ctx, winDash(id), ip)
}

const winWaitRunning = `(Get-Service -Name DHCPServer).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))`

func (a *WindowsAdapter) Restart(ctx context.Context) error {
	_, err := a.run(ctx, "Restart-Service -Name DHCPServer -Force; "+winWaitRunning)
	return err
}

func (a *WindowsAdapter) Stop(ctx context.Context) error {
	_, err := a.run(ctx, "Stop-Service -Name DHCPServer -Force; (Get-Service -Name DHCPServer).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))")
	return err
}

func (a *WindowsAdapter) Start(ctx context.Context) error {
	_, err := a.run(ctx, "Start-Service -Name DHCPServer; "+winWaitRunning)
	return err
}

// Reachable pings from the server with ping.exe straight through the ssh
// shell (cmd.exe): a PowerShell start costs 7 s on this guest, which alone
// exceeds the scenarios' 10 s window (lab #14). The image's firewall admits
// echo on every profile (firstlogon "lab-icmp-in"). ping's exit status is 0
// for "Destination host unreachable" replies from the server's own address,
// so only a "Reply from <addr>: bytes=" or "time" line counts.
func (a *WindowsAdapter) Reachable(ctx context.Context, addr string) error {
	flag := "-4"
	ip, err := validateAddr(addr)
	if err != nil {
		flag = "-6"
		if ip, err = validateAddr6(addr); err != nil {
			return err
		}
	}
	out, _ := a.Runner.Run(ctx, fmt.Sprintf("ping %s -n 1 -w 1000 %s", flag, ip))
	if !regexp.MustCompile(`Reply from ` + regexp.QuoteMeta(ip) + `: (bytes=|time)`).MatchString(out) {
		return fmt.Errorf("ping %s: no reply", ip)
	}
	return nil
}

// ResetLeases drops every lease row that is not a reservation, declined
// (BAD_ADDRESS) rows included; reservations stay.
func (a *WindowsAdapter) ResetLeases(ctx context.Context) error {
	_, err := a.run(ctx, winScope+`Get-DhcpServerv4Lease -ScopeId $sid | Where-Object { $_.AddressState -notlike '*Reservation' } | Remove-DhcpServerv4Lease`)
	return err
}

// restoreFn runs script and wraps an error with label.
func (a *WindowsAdapter) restoreFn(script, label string) func(context.Context) error {
	return func(ctx context.Context) error {
		if _, err := a.run(ctx, script); err != nil {
			return fmt.Errorf("windows: %s restore: %w", label, err)
		}
		return nil
	}
}

// doOrUndo runs do; on its failure it runs the restore at once, so a half
// applied change never outlives the call.
func (a *WindowsAdapter) doOrUndo(ctx context.Context, do string, restore func(context.Context) error) (func(context.Context) error, error) {
	if _, err := a.run(ctx, do); err != nil {
		return nil, errors.Join(err, restore(context.WithoutCancel(ctx)))
	}
	return restore, nil
}

// SetDNSOption sets option 6 with -Force: without it the cmdlet resolves
// the server and refuses an address that runs no DNS ("is not a valid DNS
// server", measured 2026-10-31, lab #14). Restore writes back the
// addresses read first.
func (a *WindowsAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	out, err := a.run(ctx, winScope+`$v = Get-DhcpServerv4OptionValue -ScopeId $sid | Where-Object { $_.OptionId -eq 6 }; if ($v) { $v.Value -join ',' } else { '-' }`)
	if err != nil {
		return nil, fmt.Errorf("windows: SetDNSOption: %w", err)
	}
	old := strings.TrimSpace(out)
	undo := winScope + `Remove-DhcpServerv4OptionValue -ScopeId $sid -OptionId 6`
	if old != "-" {
		var q []string
		for _, s := range strings.Split(old, ",") {
			v, err := validateAddr(s)
			if err != nil {
				return nil, fmt.Errorf("windows: SetDNSOption: cannot write %q back: %w", old, err)
			}
			q = append(q, "'"+v+"'")
		}
		undo = winScope + `Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId 6 -Force -Value ` + strings.Join(q, ",")
	}
	return a.doOrUndo(ctx, winScope+fmt.Sprintf(`Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId 6 -Force -Value '%s'`, ip), a.restoreFn(undo, "SetDNSOption"))
}

// ShortenLeaseTime sets the scope's lease duration; restore writes back
// the seconds read first.
func (a *WindowsAdapter) ShortenLeaseTime(ctx context.Context, seconds int) (func(context.Context) error, error) {
	if seconds < 1 {
		return nil, fmt.Errorf("windows: lease time %d s is not positive", seconds)
	}
	out, err := a.run(ctx, winScope+`[int64]$sc[0].LeaseDuration.TotalSeconds`)
	if err != nil {
		return nil, fmt.Errorf("windows: ShortenLeaseTime: %w", err)
	}
	old, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil || old < 1 {
		return nil, fmt.Errorf("windows: ShortenLeaseTime: lease duration %q is not a positive number of seconds", out)
	}
	set := func(s int64) string {
		return winScope + fmt.Sprintf(`Set-DhcpServerv4Scope -ScopeId $sid -LeaseDuration ([TimeSpan]::FromSeconds(%d))`, s)
	}
	return a.doOrUndo(ctx, set(int64(seconds)), a.restoreFn(set(old), "ShortenLeaseTime"))
}

// winRange is one address range as the scope reads read it.
type winRange struct {
	S string `json:"s"`
	E string `json:"e"`
}

type winScopeShape struct {
	Start string     `json:"start"`
	End   string     `json:"end"`
	Ex    []winRange `json:"ex"`
}

const winShapeCmd = winScope + `ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{ start = $sc[0].StartRange.IPAddressToString; end = $sc[0].EndRange.IPAddressToString; ` +
	`ex = @(Get-DhcpServerv4ExclusionRange -ScopeId $sid | ForEach-Object { [ordered]@{ s = $_.StartRange.IPAddressToString; e = $_.EndRange.IPAddressToString } }) })`

// shape reads the scope's range and exclusions, each address parsed, so
// nothing read back reaches a later command unchecked.
func (a *WindowsAdapter) shape(ctx context.Context) (netip.Addr, netip.Addr, [][2]netip.Addr, error) {
	out, err := a.run(ctx, winShapeCmd)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, nil, err
	}
	var s winScopeShape
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &s); err != nil {
		return netip.Addr{}, netip.Addr{}, nil, fmt.Errorf("scope read %q: %w", out, err)
	}
	start, end, err := validatePool(s.Start, s.End)
	if err != nil {
		return start, end, nil, fmt.Errorf("scope read: %w", err)
	}
	var ex [][2]netip.Addr
	for _, r := range s.Ex {
		f, l, err := validatePool(r.S, r.E)
		if err != nil {
			return start, end, nil, fmt.Errorf("scope read: exclusion: %w", err)
		}
		ex = append(ex, [2]netip.Addr{f, l})
	}
	sort.Slice(ex, func(i, j int) bool { return ex[i][0].Less(ex[j][0]) })
	return start, end, ex, nil
}

func winExclusion(verb string, r [2]netip.Addr) string {
	return fmt.Sprintf(`%s-DhcpServerv4ExclusionRange -ScopeId $sid -StartRange '%s' -EndRange '%s'; `, verb, r[0], r[1])
}

// narrowRanges is what NarrowPool excludes: the scope from its start to
// first-1 and from last+1 to the band the image already excludes; the
// policy range above that band serves class B5 clients only (lab #14).
func narrowRanges(start, end netip.Addr, ex [][2]netip.Addr, first, last netip.Addr) ([][2]netip.Addr, error) {
	top := end.Next()
	for _, r := range ex {
		if r[0].Compare(last) > 0 {
			top = r[0]
			break
		}
		return nil, fmt.Errorf("the scope already excludes %s-%s, at or below the narrowed pool's end", r[0], r[1])
	}
	if first.Less(start) || !last.Less(top) {
		return nil, fmt.Errorf("pool %s-%s is not inside %s-%s", first, last, start, top.Prev())
	}
	var add [][2]netip.Addr
	if start.Less(first) {
		add = append(add, [2]netip.Addr{start, first.Prev()})
	}
	if last.Next().Less(top) {
		add = append(add, [2]netip.Addr{last.Next(), top.Prev()})
	}
	return add, nil
}

// carveBand returns the exclusion that holds first..last whole, or the zero
// range when none does.
func carveBand(ex [][2]netip.Addr, first, last netip.Addr) [2]netip.Addr {
	for _, r := range ex {
		if !first.Less(r[0]) && !r[1].Less(last) {
			return r
		}
	}
	return [2]netip.Addr{}
}

func (a *WindowsAdapter) NarrowPool(ctx context.Context, first, last string) (func(context.Context) error, error) {
	f, l, err := validatePool(first, last)
	if err != nil {
		return nil, err
	}
	start, end, ex, err := a.shape(ctx)
	if err != nil {
		return nil, fmt.Errorf("windows: NarrowPool: %w", err)
	}
	band := carveBand(ex, f, l)
	var add [][2]netip.Addr
	do, undo := winScope, winScope+"$ErrorActionPreference = 'Continue'; "
	if band[0].IsValid() {
		// The pool sits in a band the image excludes (C8 asks for the
		// user-class pool's band): the band is replaced by the scope below the pool and
		// the band's rest above it (lab #14).
		if f.Less(start) || end.Less(l) {
			return nil, fmt.Errorf("windows: NarrowPool: pool %s-%s is not inside %s-%s", f, l, start, end)
		}
		do += winExclusion("Remove", band)
		add = append(add, [2]netip.Addr{start, f.Prev()})
		if l.Less(band[1]) {
			add = append(add, [2]netip.Addr{l.Next(), band[1]})
		}
		for _, r := range add {
			do += winExclusion("Add", r)
			undo += winExclusion("Remove", r)
		}
		undo += winExclusion("Add", band)
	} else {
		add, err = narrowRanges(start, end, ex, f, l)
		if err != nil {
			return nil, fmt.Errorf("windows: NarrowPool: %w", err)
		}
		for _, r := range add {
			do += winExclusion("Add", r)
			undo += winExclusion("Remove", r)
		}
	}
	// The undo runs on a failed do too, where a range may be missing.
	undo += winScope + "$true"
	return a.doOrUndo(ctx, strings.TrimSuffix(do, "; "), a.restoreFn(undo, "NarrowPool"))
}

// winImport re-creates scopes from the export the image's first logon
// wrote; -BackupPath must name a fresh directory.
func winImport(scopeArg string) string {
	return fmt.Sprintf(`if (Test-Path '%[1]s') { Remove-Item -Recurse -Force '%[1]s' }; New-Item -ItemType Directory -Path '%[1]s' | Out-Null; `+
		`Import-DhcpServer -File '%[2]s' -BackupPath '%[1]s'%[3]s -ScopeOverwrite -Force; `, winImportBak, winBaseline, scopeArg)
}

// winSetNIC moves the segment NIC to one address.
func winSetNIC(addr string, bits int) string {
	return fmt.Sprintf(`Get-NetIPAddress -InterfaceAlias '%[1]s' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false; `+
		`New-NetIPAddress -InterfaceAlias '%[1]s' -IPAddress '%[2]s' -PrefixLength %[3]d | Out-Null; `, winSegAlias, addr, bits)
}

const winNICRead = `$n = @(Get-NetIPAddress -InterfaceAlias '` + winSegAlias + `' -AddressFamily IPv4); if ($n.Count -ne 1) { throw ('the segment NIC has ' + $n.Count + ' IPv4 addresses') }; `

// Renumber moves the segment NIC and the scope to one plan; the router
// and DNS options name the source itself, as the image has them. Restore
// imports the image's scope again and writes back the lease time read
// first (lab #14).
func (a *WindowsAdapter) Renumber(ctx context.Context, subnet, addr, first, last string) (func(context.Context) error, error) {
	p, err := validateRenumber(subnet, addr, first, last)
	if err != nil {
		return nil, err
	}
	out, err := a.run(ctx, winScope+winNICRead+`$sid; $n[0].IPAddress; $n[0].PrefixLength; [int64]$sc[0].LeaseDuration.TotalSeconds`)
	if err != nil {
		return nil, fmt.Errorf("windows: Renumber: %w", err)
	}
	v := lines(out)
	if len(v) != 4 {
		return nil, fmt.Errorf("windows: Renumber: state read gave %q", out)
	}
	oldScope, err1 := validateAddr(v[0])
	oldAddr, err2 := validateAddr(v[1])
	oldBits, err3 := strconv.Atoi(v[2])
	secs, err4 := strconv.ParseInt(v[3], 10, 64)
	if err := errors.Join(err1, err2, err3, err4); err != nil || oldBits < 1 || oldBits > 30 || secs < 1 {
		return nil, fmt.Errorf("windows: Renumber: cannot write %q back: %v", out, err)
	}
	undo := `Get-DhcpServerv4Scope | Remove-DhcpServerv4Scope -Force; ` + winSetNIC(oldAddr, oldBits) + winImport(" -ScopeId '"+oldScope+"'") +
		fmt.Sprintf(`Set-DhcpServerv4Scope -ScopeId '%s' -LeaseDuration ([TimeSpan]::FromSeconds(%d)); `, oldScope, secs) +
		"Restart-Service -Name DHCPServer -Force; " + winWaitRunning
	net := p.subnet.Addr().String()
	do := winScope + `Remove-DhcpServerv4Scope -ScopeId $sid -Force; ` + winSetNIC(p.addr.String(), p.subnet.Bits()) +
		fmt.Sprintf(`Add-DhcpServerv4Scope -Name 'lab' -StartRange '%s' -EndRange '%s' -SubnetMask '%s' -State Active -LeaseDuration ([TimeSpan]::FromSeconds(%d)); `,
			p.first, p.last, p.netmask(), secs) +
		fmt.Sprintf(`Set-DhcpServerv4OptionValue -ScopeId '%[1]s' -OptionId 3 -Value '%[2]s'; Set-DhcpServerv4OptionValue -ScopeId '%[1]s' -OptionId 6 -Force -Value '%[2]s'; `, net, p.addr) +
		"Restart-Service -Name DHCPServer -Force; " + winWaitRunning
	return a.doOrUndo(ctx, do, a.restoreFn(undo, "Renumber"))
}

// EnableFeature adds labf-named classes, policies and option values;
// restore removes them by name (lab #14). Option 77 is matched on its raw
// bytes, so the class data carries RFC 3004's length byte as the lab's
// clients send it.
func (a *WindowsAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	v, err := validateFeature(f, p)
	if err != nil {
		return nil, err
	}
	const def108 = `if (-not (Get-DhcpServerv4OptionDefinition -OptionId 108 -ErrorAction SilentlyContinue)) { Add-DhcpServerv4OptionDefinition -Name '` + winFeature + `108' -OptionId 108 -Type DWord }; `
	const undef108 = `if (Get-DhcpServerv4OptionDefinition -OptionId 108 -ErrorAction SilentlyContinue) { Remove-DhcpServerv4OptionDefinition -OptionId 108 }; `
	var do, undo string
	switch f {
	case FeatureUserClassPool:
		start, end, ex, err := a.shape(ctx)
		if err != nil {
			return nil, fmt.Errorf("windows: %s: %w", f, err)
		}
		s, e := netip.MustParseAddr(v.start), netip.MustParseAddr(v.end)
		if s.Less(start) || end.Less(e) {
			return nil, fmt.Errorf("windows: %s: pool %s-%s is not inside the scope %s-%s", f, s, e, start, end)
		}
		// A policy range lies inside the scope; the band it takes leaves
		// the exclusion it sits in, so only matching clients reach it.
		var band [2]netip.Addr
		for _, r := range ex {
			if !s.Less(r[0]) && !r[1].Less(e) {
				band = r
			}
		}
		if !band[0].IsValid() {
			return nil, fmt.Errorf("windows: %s: pool %s-%s lies in no excluded band of the scope", f, s, e)
		}
		n := winFeature + "77"
		split := winExclusion("Remove", band)
		join := "$ErrorActionPreference = 'Continue'; "
		if band[0].Less(s) {
			split += winExclusion("Add", [2]netip.Addr{band[0], s.Prev()})
			join += winExclusion("Remove", [2]netip.Addr{band[0], s.Prev()})
		}
		if e.Less(band[1]) {
			split += winExclusion("Add", [2]netip.Addr{e.Next(), band[1]})
			join += winExclusion("Remove", [2]netip.Addr{e.Next(), band[1]})
		}
		do = winScope + split + fmt.Sprintf(`Add-DhcpServerv4Class -Name '%[1]s' -Type User -Data ([string][char]%[2]d + '%[3]s'); `+
			`Add-DhcpServerv4Policy -Name '%[1]s' -ScopeId $sid -Condition OR -UserClass EQ, '%[1]s'; `+
			`Add-DhcpServerv4PolicyIPRange -Name '%[1]s' -ScopeId $sid -StartRange '%[4]s' -EndRange '%[5]s'`, n, len(v.class), v.class, s, e)
		undo = winScope + join + fmt.Sprintf(`Remove-DhcpServerv4Policy -Name '%[1]s' -ScopeId $sid; Remove-DhcpServerv4Class -Name '%[1]s' -Type User; `, n) +
			"$ErrorActionPreference = 'Stop'; " + winExclusion("Add", band) + "$true"
	case FeatureOffer108:
		do = winScope + def108 + fmt.Sprintf(`Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId 108 -Value %d`, v.seconds)
		undo = winScope + "$ErrorActionPreference = 'Continue'; " + `Remove-DhcpServerv4OptionValue -ScopeId $sid -OptionId 108; ` + undef108 + "$true"
	case FeatureForce108:
		// A client-id policy carries the value; whether the server sends
		// an option the client did not ask for is the row's measurement.
		n := winFeature + "108f"
		do = winScope + def108 + fmt.Sprintf(`Add-DhcpServerv4Policy -Name '%[1]s' -ScopeId $sid -Condition OR -ClientId EQ, '%[2]s'; `+
			`Set-DhcpServerv4OptionValue -ScopeId $sid -PolicyName '%[1]s' -OptionId 108 -Value %[3]d`, n, winDash(v.clientID), v.seconds)
		undo = winScope + "$ErrorActionPreference = 'Continue'; " + fmt.Sprintf(`Remove-DhcpServerv4Policy -Name '%s' -ScopeId $sid; `, n) + undef108 + "$true"
	default:
		why, ok := map[Feature]Capability{FeatureRapidCommit4: CapRapidCommit4, FeatureForceRenewNonce: CapForceRenewNonce}[f]
		if ok {
			return nil, fmt.Errorf("windows: %s: %s", f, windowsNAReasons[why])
		}
		return nil, fmt.Errorf("windows: %s: %s", f, winV6Reason)
	}
	return a.doOrUndo(ctx, do, a.restoreFn(undo, string(f)))
}

// winStateCmd reads the server's configuration as sorted text lines:
// scope, exclusions, policies and their ranges, option values, classes,
// option definitions, the segment address and conflict detection. Leases
// and reservations are left out, so A and B rows never move it (lab #14).
const winStateCmd = `$o = New-Object System.Collections.Generic.List[string]; ` +
	`foreach ($s in @(Get-DhcpServerv4Scope)) { $id = $s.ScopeId.IPAddressToString; ` +
	`$o.Add(('scope {0} {1} {2}-{3} {4} {5}' -f $id, $s.SubnetMask, $s.StartRange, $s.EndRange, $s.State, $s.LeaseDuration)); ` +
	`foreach ($x in @(Get-DhcpServerv4ExclusionRange -ScopeId $id)) { $o.Add(('excl {0} {1}-{2}' -f $id, $x.StartRange, $x.EndRange)) }; ` +
	`foreach ($p in @(Get-DhcpServerv4Policy -ScopeId $id)) { $o.Add(('policy {0} {1} {2} {3} {4} vc={5} uc={6} cid={7}' -f $id, $p.Name, $p.Enabled, $p.ProcessingOrder, $p.Condition, ($p.VendorClass -join ','), ($p.UserClass -join ','), ($p.ClientId -join ','))); ` +
	`foreach ($r in @(Get-DhcpServerv4PolicyIPRange -ScopeId $id -Name $p.Name -ErrorAction SilentlyContinue)) { $o.Add(('prange {0} {1} {2}-{3}' -f $id, $p.Name, $r.StartRange, $r.EndRange)) }; ` +
	`foreach ($v in @(Get-DhcpServerv4OptionValue -ScopeId $id -PolicyName $p.Name -ErrorAction SilentlyContinue)) { $o.Add(('popt {0} {1} {2} {3}' -f $id, $p.Name, $v.OptionId, ($v.Value -join ','))) } }; ` +
	`foreach ($v in @(Get-DhcpServerv4OptionValue -ScopeId $id)) { $o.Add(('opt {0} {1} {2}' -f $id, $v.OptionId, ($v.Value -join ','))) } }; ` +
	`foreach ($c in @(Get-DhcpServerv4Class)) { $o.Add(('class {0} {1} {2}' -f $c.Type, $c.Name, $c.AsciiData)) }; ` +
	`foreach ($d in @(Get-DhcpServerv4OptionDefinition)) { $o.Add(('optdef {0} {1} {2}' -f $d.OptionId, $d.Name, $d.Type)) }; ` +
	`foreach ($n in @(Get-NetIPAddress -InterfaceAlias '` + winSegAlias + `' -AddressFamily IPv4)) { $o.Add(('nic {0}/{1}' -f $n.IPAddress, $n.PrefixLength)) }; ` +
	`$o.Add(('conflict {0}' -f (Get-DhcpServerSetting).ConflictDetectionAttempts)); ` +
	`$o | Sort-Object`

// winHealthCmd reads the bootstrap marker, the service state and the
// license: status 1 is licensed, 2, 3 and 6 grace, anything else (5 is
// the notification state of an expired evaluation) refuses.
const winHealthCmd = `(Get-Content -Raw '` + winLabDir + `\bootstrap-done').Trim(); (Get-Service -Name DHCPServer).Status.ToString(); ` +
	`$lic = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"); ` +
	`if ($lic.Count -lt 1) { throw 'no Windows license product carries a key' }; ('{0} {1}' -f $lic[0].LicenseStatus, $lic[0].GracePeriodRemaining)`

// Ready holds the server to a finished first logon, a running service, a
// live license, a readable lease table, and the configuration the first
// Ready saw (lab #14).
func (a *WindowsAdapter) Ready(ctx context.Context) error {
	out, err := a.run(ctx, winHealthCmd)
	if err != nil {
		return err
	}
	st := lines(out)
	if len(st) != 3 {
		return fmt.Errorf("windows: state read gave %q", out)
	}
	if st[0] == "" {
		return errors.New("windows: the bootstrap marker is empty: the first logon did not finish")
	}
	if st[1] != "Running" {
		return fmt.Errorf("windows: DHCPServer is %s, not Running", st[1])
	}
	if err := winLicenseOK(st[2]); err != nil {
		return err
	}
	if _, err := a.Leases(ctx); err != nil {
		return fmt.Errorf("lease table not readable: %w", err)
	}
	cfg, err := a.run(ctx, winStateCmd)
	if err != nil {
		return err
	}
	a.base.mu.Lock()
	defer a.base.mu.Unlock()
	if !a.base.taken {
		a.base.taken, a.base.cfg = true, cfg
		return nil
	}
	if cfg != a.base.cfg {
		return fmt.Errorf("windows: the server configuration differs from the one taken at the first readiness check:\n%s", lineDiff(a.base.cfg, cfg))
	}
	return nil
}

// winLicenseOK reads "<LicenseStatus> <GracePeriodRemaining minutes>".
func winLicenseOK(s string) error {
	f := strings.Fields(s)
	if len(f) != 2 {
		return fmt.Errorf("windows: license read gave %q", s)
	}
	status, err1 := strconv.Atoi(f[0])
	mins, err2 := strconv.ParseInt(f[1], 10, 64)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("windows: license read gave %q", s)
	}
	switch status {
	case 1, 2, 3, 6:
		if status != 1 && mins <= 0 {
			return fmt.Errorf("windows: the license grace period is over (status %d); rebuild with scripts/build-windows-image.sh or restore the dated copy", status)
		}
		return nil
	}
	return fmt.Errorf("windows: license status %d, not licensed or in grace: the evaluation has expired; rebuild with scripts/build-windows-image.sh or restore the dated copy", status)
}

// lineDiff names the lines only one side has.
func lineDiff(was, now string) string {
	in := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range lines(s) {
			m[l] = true
		}
		return m
	}
	w, n := in(was), in(now)
	var b strings.Builder
	for _, l := range lines(was) {
		if !n[l] {
			b.WriteString("- " + l + "\n")
		}
	}
	for _, l := range lines(now) {
		if !w[l] {
			b.WriteString("+ " + l + "\n")
		}
	}
	return b.String()
}

// Recover removes every scope and labf object, puts the segment NIC back
// through the image's own boot script, imports the image's export again
// and restarts the service (lab #14).
func (a *WindowsAdapter) Recover(ctx context.Context) error {
	_, err := a.run(ctx, `Get-DhcpServerv4Scope | Remove-DhcpServerv4Scope -Force; `+
		`Get-DhcpServerv4Policy | Where-Object { $_.Name -like '`+winFeature+`*' } | Remove-DhcpServerv4Policy; `+
		`Get-DhcpServerv4Class | Where-Object { $_.Name -like '`+winFeature+`*' } | ForEach-Object { Remove-DhcpServerv4Class -Name $_.Name -Type $_.Type }; `+
		`if (Get-DhcpServerv4OptionDefinition -OptionId 108 -ErrorAction SilentlyContinue) { Remove-DhcpServerv4OptionDefinition -OptionId 108 }; `+
		`& powershell.exe -NoProfile -ExecutionPolicy Bypass -File '`+winLabDir+`\netconfig.ps1'; if ($LASTEXITCODE -ne 0) { throw 'netconfig.ps1 failed' }; `+
		winImport("")+`Set-DhcpServerSetting -ConflictDetectionAttempts 0; Restart-Service -Name DHCPServer -Force; `+winWaitRunning)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	return nil
}

// Leases6, SetRA and StopV6Server are refused: the cell serves DHCPv4 only.
func (a *WindowsAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	return nil, errors.New("windows: " + winV6Reason)
}

func (a *WindowsAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return nil, errors.New("windows: " + winV6Reason)
}

func (a *WindowsAdapter) StopV6Server(context.Context) (func(context.Context) error, error) {
	return nil, errors.New("windows: " + winV6Reason)
}

// Impair, Squat, StartRogue, RogueLeases and SendForceRenew need the
// source-side actor tools; needPortable refuses before any command.
func (a *WindowsAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return nil, a.host().needPortable("Impair")
}

func (a *WindowsAdapter) Squat(ctx context.Context, addr string, announce bool) (func(context.Context) error, error) {
	return nil, a.host().needPortable("Squat")
}

func (a *WindowsAdapter) StartRogue(ctx context.Context, serverAddr, first, last string) (func(context.Context) error, error) {
	return nil, a.host().needPortable("StartRogue")
}

func (a *WindowsAdapter) RogueLeases(ctx context.Context) ([]Lease, error) {
	return nil, a.host().needPortable("RogueLeases")
}

func (a *WindowsAdapter) SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error) {
	return "", a.host().needPortable("SendForceRenew")
}

func (a *WindowsAdapter) ServerEvents(ctx context.Context, since time.Time, mac string) ([]ServerEvent, error) {
	return serverEventsRefused("windows")
}

var _ Adapter = (*WindowsAdapter)(nil)
