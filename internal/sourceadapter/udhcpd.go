package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	udhcpdConf      = "/etc/udhcpd.conf"
	udhcpdLeaseFile = "/var/lib/misc/udhcpd.leases"
)

// UdhcpdAdapter drives busybox udhcpd 1.37 (Debian package udhcpd) over
// ssh (DESIGN-910 3.1, lab #10). The measurements behind each choice are
// in the PR that added it (M1, 2026-10-09).
type UdhcpdAdapter struct {
	Runner Runner
	base   baseline
}

func (a *UdhcpdAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease, CapOptionChange, CapImpair, CapSquatter, CapRogueServer, CapNarrowPool, CapRenumber}
}

// udhcpdNAReasons say why the capabilities udhcpd lacks are absent; they
// reach the matrix through NAExplainer (DESIGN-910 3.1).
var udhcpdNAReasons = map[Capability]string{
	CapReserveClientID: "udhcpd keys leases by MAC only: two clients with one MAC and different client identifiers get one lease (lookup is find_lease_by_mac), so an ipvlan shape that shares a parent MAC is the server's behaviour, not a plugin fault",
	CapVendorClassPool: "udhcpd has one global pool and no per-class selection",
	CapUserClassPool:   "udhcpd has one global pool and no per-class selection",
	CapOption108:       "udhcpd has no per-request option selection",
	CapDNSRegistration: "udhcpd serves no DNS",
	CapRapidCommit4:    "udhcpd does not implement rapid commit (RFC 4039)",
	CapForceRenewNonce: "udhcpd does not implement FORCERENEW (RFC 3203/6704)",
	CapV6:              "udhcpd is DHCPv4 only",
}

func (a *UdhcpdAdapter) NAReason(c Capability) (string, bool) {
	why, ok := udhcpdNAReasons[c]
	return why, ok
}

// NAShapeReason: udhcpd keys leases by MAC only and its table carries no
// client identifier. The ipvlan shape shares one parent MAC and is judged by
// client-id, and A2 on the IPAM shapes looks the restarted container up by
// the client identifier its lease carried, so those runs cannot be judged on
// this source (D1, lab #10).
func (a *UdhcpdAdapter) NAShapeReason(shape, scenario string) string {
	switch {
	case shape == "ipvlan":
		return "udhcpd keys leases by MAC only and its table has no client identifiers, which the ipvlan shape needs because its containers share one parent MAC; this is the server's behaviour, not a plugin fault"
	case strings.HasPrefix(scenario, "A2-") && (shape == "bridge-ipam" || shape == "macvlan-ipam"):
		return "udhcpd's table has no client identifiers, so a restarted container cannot be looked up by the identifier the plugin re-sends; this is the server's behaviour, not a plugin fault"
	}
	return ""
}

// udhcpdLeasesCmd sends USR1 and waits for the lease file's mtime to move
// before dumpleases reads it. The file is binary and udhcpd writes it on
// USR1, SIGTERM or every auto_time (7200 s); without the signal it is
// absent or stale, and a 0-byte file makes dumpleases fail with "short
// read" (M1, lab #10). TZ=UTC pins the expiry column, which prints no zone.
// The wait covers a burst of fresh OFFERs: udhcpd handles USR1 between
// packets and each fresh OFFER blocks about 2.1 s in its ARP probe (M1), so
// 400 tries of 50 ms (20 s) outlast nine of them back to back.
const udhcpdLeasesCmd = `m0=$(sudo stat -c %%.9Y %[1]s 2>/dev/null || echo 0); ` +
	`%[2]s && ` +
	`for i in $(seq 1 400); do m1=$(sudo stat -c %%.9Y %[1]s 2>/dev/null || echo 0); [ "$m1" != "$m0" ] && break; sleep 0.05; done; ` +
	`[ "$m1" != "$m0" ] || { echo "udhcpd did not rewrite %[1]s after USR1" >&2; exit 1; }; ` +
	`sudo env TZ=UTC busybox dumpleases -a -f %[1]s`

func (a *UdhcpdAdapter) Leases(ctx context.Context) ([]Lease, error) {
	usr1, err := a.host().svc().kill("USR1")
	if err != nil {
		return nil, fmt.Errorf("udhcpd: read leases: %w", err)
	}
	out, err := a.Runner.Run(ctx, fmt.Sprintf(udhcpdLeasesCmd, udhcpdLeaseFile, usr1))
	if err != nil {
		return nil, fmt.Errorf("udhcpd: read leases (USR1 then dumpleases): %w", err)
	}
	return parseUdhcpdLeases(out)
}

// parseUdhcpdLeases reads `dumpleases -a`: a header line, then one row per
// lease, "MAC IP [hostname] <ctime>" where the ctime is five fields
// ("Fri Oct  9 23:19:03 2026") or the word "expired" for a lease past its
// end, which is not active and is dropped. The hostname column is blank
// when the client sent none, so the expiry is read from the right (M1,
// lab #10).
func parseUdhcpdLeases(raw string) ([]Lease, error) {
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(strings.TrimSpace(lines[0]), "Mac Address") {
		return nil, fmt.Errorf("udhcpd: dumpleases output does not start with its header: %q", raw)
	}
	leases := []Lease{}
	for i, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 3 {
			return nil, fmt.Errorf("udhcpd: lease line %d has %d field(s), want at least 3: %q", i+1, len(fields), line)
		}
		mac, err := validateMAC(fields[0])
		if err != nil {
			return nil, fmt.Errorf("udhcpd: lease line %d: %w", i+1, err)
		}
		ip, err := validateAddr(fields[1])
		if err != nil {
			return nil, fmt.Errorf("udhcpd: lease line %d: %w", i+1, err)
		}
		l := Lease{MAC: mac, Address: ip}
		if fields[len(fields)-1] == "expired" {
			continue
		}
		if len(fields) < 7 {
			return nil, fmt.Errorf("udhcpd: lease line %d has no expiry: %q", i+1, line)
		}
		exp := strings.Join(fields[len(fields)-5:], " ")
		t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", exp, time.UTC)
		if err != nil {
			return nil, fmt.Errorf("udhcpd: lease line %d: expiry %q: %w", i+1, exp, err)
		}
		l.Expires = t
		if len(fields) > 7 {
			l.Hostname = strings.Join(fields[2:len(fields)-5], " ")
		}
		leases = append(leases, l)
	}
	return leases, nil
}

// ReserveMAC writes `static_lease MAC IP` and restarts; udhcpd reads
// static leases only at start. A static lease also wins over a lease the
// MAC already holds (M1, lab #10). The reservation lives in the same file the
// Ready baseline holds, so the baseline takes it up too; otherwise the next
// scenario sees drift and Recover restarts the source (lab #10).
func (a *UdhcpdAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf(`sudo sed -i '/^static_lease[[:space:]]\+%s[[:space:]]/Id' %s && echo 'static_lease %s %s' | sudo tee -a %s >/dev/null && %s`, hw, udhcpdConf, hw, ip, udhcpdConf, a.host().svc().restart)
	if _, err := a.Runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("udhcpd: reserve %s -> %s: %w", hw, ip, err)
	}
	return a.retakeBaseline(ctx)
}

// retakeBaseline re-reads the running config into the Ready baseline once
// a baseline exists, so a reservation is part of it and not drift (lab #10).
func (a *UdhcpdAdapter) retakeBaseline(ctx context.Context) error {
	a.base.mu.Lock()
	taken := a.base.taken
	a.base.mu.Unlock()
	if !taken {
		return nil
	}
	cur, err := a.Runner.Run(ctx, "sudo cat "+udhcpdConf)
	if err != nil {
		return fmt.Errorf("udhcpd: read %s after the reservation: %w", udhcpdConf, err)
	}
	a.base.mu.Lock()
	a.base.cfg = cur
	a.base.mu.Unlock()
	return nil
}

// Leases6 and SetRA are refused: udhcpd is DHCPv4 only and sends no RAs
// (lab #10, DESIGN-910 3.1).
func (a *UdhcpdAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	return nil, errors.New("udhcpd: " + udhcpdNAReasons[CapV6])
}

func (a *UdhcpdAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return nil, errors.New("udhcpd: " + udhcpdNAReasons[CapV6])
}

// ReserveClientID is refused: udhcpd has no client-id handling (lab #10,
// DESIGN-910 3.1).
func (a *UdhcpdAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	return errors.New("udhcpd: " + udhcpdNAReasons[CapReserveClientID])
}

func (a *UdhcpdAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	return nil, fmt.Errorf("udhcpd: feature %q is not supported: one global pool, no per-request options", f)
}

func (a *UdhcpdAdapter) SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error) {
	return "", errors.New("udhcpd: " + udhcpdNAReasons[CapForceRenewNonce])
}

func (a *UdhcpdAdapter) Restart(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "restart", "udhcpd")
}
func (a *UdhcpdAdapter) Stop(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "stop", "udhcpd")
}
func (a *UdhcpdAdapter) Start(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "start", "udhcpd")
}

// host is this source's userland: Debian with systemd, eth1 and
// /usr/sbin/tc; busybox udhcpd runs as the udhcpd unit (#9, #10).
func (a *UdhcpdAdapter) host() host { return debianHost("udhcpd") }

func (a *UdhcpdAdapter) Reachable(ctx context.Context, addr string) error {
	return reachable(ctx, a.Runner, addr)
}

// ResetLeases stops udhcpd (SIGTERM writes the file), truncates it and
// starts again; a 0-byte file starts cleanly (M1, lab #10).
func (a *UdhcpdAdapter) ResetLeases(ctx context.Context) error {
	return resetLeasesViaTruncate(ctx, a.Runner, udhcpdLeaseFile, nil, a.host().svc(), "udhcpd")
}

var (
	// udhcpdLeaseTimeRE matches both `option lease N` and `min_lease N`.
	// udhcpd raises a lease a client asks for to min_lease (default 60,
	// M1: a 40 s request got 60) but not the server's own `option lease`,
	// so A14 sets both and a 40 s lease is real whether or not the client
	// asks for one (lab #10).
	udhcpdLeaseTimeRE     = regexp.MustCompile(`(?m)^((?:option[ \t]+lease|min_lease)[ \t]+)[0-9]+$`)
	udhcpdOptionLeaseRE   = regexp.MustCompile(`(?m)^option[ \t]+lease[ \t]+[0-9]+$`)
	udhcpdMinLeaseRE      = regexp.MustCompile(`(?m)^min_lease[ \t]+[0-9]+$`)
	udhcpdRouterOptionRE  = regexp.MustCompile(`(?m)^(option[ \t]+router[ \t]+[^\n]*)$`)
	udhcpdStartRE         = regexp.MustCompile(`(?m)^(start[ \t]+)\S+$`)
	udhcpdEndRE           = regexp.MustCompile(`(?m)^(end[ \t]+)\S+$`)
	udhcpdInterfaceRE     = regexp.MustCompile(`(?m)^interface[ \t]+\S+$`)
	udhcpdLeaseFileLineRE = regexp.MustCompile(`(?m)^lease_file[ \t]+\S+$`)
	udhcpdAutoTimeRE      = regexp.MustCompile(`(?m)^auto_time[ \t]+[0-9]+$`)
)

// ShortenLeaseTime sets `option lease` and `min_lease` to seconds in the
// RUNNING config and restarts (A14, D3, lab #10). Both lines must be present.
func (a *UdhcpdAdapter) ShortenLeaseTime(ctx context.Context, seconds int) (func(context.Context) error, error) {
	if seconds <= 0 {
		return nil, fmt.Errorf("udhcpd: lease time must be positive, got %d", seconds)
	}
	cur, err := a.Runner.Run(ctx, "sudo cat "+udhcpdConf)
	if err != nil {
		return nil, fmt.Errorf("udhcpd: read %s before shortening lease time: %w", udhcpdConf, err)
	}
	if !udhcpdOptionLeaseRE.MatchString(cur) || !udhcpdMinLeaseRE.MatchString(cur) {
		return nil, fmt.Errorf("udhcpd: %s lacks an `option lease` or a `min_lease` line; refusing to shorten with one of them unset", udhcpdConf)
	}
	return shortenLeaseTimeViaSubstitution(ctx, a.Runner, udhcpdConf, udhcpdLeaseTimeRE, fmt.Sprintf("${1}%d", seconds),
		func(ctx context.Context) error { return a.Restart(ctx) }, "udhcpd")
}

// SetDNSOption adds `option dns` after the router option and restarts
// (B6, lab #10); without it udhcpd hands out no DNS server.
func (a *UdhcpdAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	return setDNSOptionViaSubstitution(ctx, a.Runner, udhcpdConf, udhcpdRouterOptionRE,
		fmt.Sprintf("${1}\noption dns %s", ip), "option dns",
		func(ctx context.Context) error { return a.Restart(ctx) }, "udhcpd")
}

// NarrowPool rewrites the `start` and `end` lines (C8, lab #10).
func (a *UdhcpdAdapter) NarrowPool(ctx context.Context, first, last string) (func(context.Context) error, error) {
	f, l, err := validatePool(first, last)
	if err != nil {
		return nil, fmt.Errorf("udhcpd: %w", err)
	}
	return enableFeatureViaSubstitution(ctx, a.Runner, udhcpdConf, fmt.Sprintf("start %s\nend %s", f, l),
		[]configEdit{
			{udhcpdStartRE, "${1}" + f.String(), "the start line"},
			{udhcpdEndRE, "${1}" + l.String(), "the end line"},
		}, func(ctx context.Context) error { return a.Restart(ctx) }, "udhcpd")
}

// Renumber moves the segment to subnet (C9). The old leases stay in the
// lease file and are dropped at start because they lie outside the new
// range (M1, lab #10).
func (a *UdhcpdAdapter) Renumber(ctx context.Context, subnet, addr, first, last string) (func(context.Context) error, error) {
	p, err := validateRenumber(subnet, addr, first, last)
	if err != nil {
		return nil, err
	}
	return a.host().renumberVia(ctx, a.Runner, udhcpdConf, p, renderUdhcpdRenumbered,
		func(ctx context.Context) error { return a.Restart(ctx) }, "udhcpd")
}

// renderUdhcpdRenumbered keeps interface, lease times, lease_file and
// auto_time, and drops static_lease and option dns lines (lab #10, C9).
func renderUdhcpdRenumbered(orig string, p renumberPlan) (string, error) {
	var keep [4]string
	for i, x := range []struct {
		re   *regexp.Regexp
		what string
	}{{udhcpdInterfaceRE, "interface lines"}, {udhcpdOptionLeaseRE, "option lease lines"}, {udhcpdMinLeaseRE, "min_lease lines"}, {udhcpdLeaseFileLineRE, "lease_file lines"}} {
		m, err := onlyMatch(x.re, orig, x.what)
		if err != nil {
			return "", err
		}
		keep[i] = m
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nstart %s\nend %s\noption subnet %s\noption router %s\n%s\n%s\n%s\n", keep[0], p.first, p.last, p.netmask(), p.addr, keep[1], keep[2], keep[3])
	if m := udhcpdAutoTimeRE.FindString(orig); m != "" {
		b.WriteString(m + "\n")
	}
	return b.String(), nil
}

func (a *UdhcpdAdapter) Squat(ctx context.Context, addr string, announce bool) (func(context.Context) error, error) {
	return a.host().squat(ctx, a.Runner, addr, announce)
}

func (a *UdhcpdAdapter) StartRogue(ctx context.Context, serverAddr, first, last string) (func(context.Context) error, error) {
	return a.host().startRogue(ctx, a.Runner, serverAddr, first, last)
}

func (a *UdhcpdAdapter) RogueLeases(ctx context.Context) ([]Lease, error) {
	return a.host().rogueLeases(ctx, a.Runner)
}

// Ready, Recover and Impair: the shared group C bodies (readiness.go, #23).
func (a *UdhcpdAdapter) units() sourceUnits {
	return sourceUnits{service: "udhcpd", cfgPath: udhcpdConf}
}

func (a *UdhcpdAdapter) Ready(ctx context.Context) error {
	return a.host().sourceReady(ctx, a.Runner, a.units(), a.Leases, &a.base)
}

func (a *UdhcpdAdapter) Recover(ctx context.Context) error {
	return a.host().sourceRecover(ctx, a.Runner, a.units(), &a.base)
}

func (a *UdhcpdAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return a.host().impair(ctx, a.Runner, delay, lossPct)
}

var _ Adapter = (*UdhcpdAdapter)(nil)
var _ NAExplainer = (*UdhcpdAdapter)(nil)
var _ ShapeNAReasoner = (*UdhcpdAdapter)(nil)
