package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The names the CHR seed (routeros/lab-baseline.tmpl.rsc) gives its
// objects; scenario objects all start with rosFeature so the baseline
// script removes them again (#9).
const (
	rosServer   = "lab"
	rosIdentity = "lab-ready"
	rosBaseline = "lab-baseline.rsc"
	rosFeature  = "labf"
)

const rosNoShell = "the CHR runs RouterOS, with no shell, iproute2 netns, tc or python3 for the lab's source-side actors"

// rosV6Reason is why the cell serves no DHCPv6: the seed configures no
// /ipv6 dhcp-server (#9).
const rosV6Reason = "the CHR seed configures no /ipv6 dhcp-server, so the cell is DHCPv4 only."

var routerosNAReasons = map[Capability]string{
	CapImpair:          "Impair puts netem on the source's segment leg; " + rosNoShell + ".",
	CapSquatter:        "the squatter is a netns actor on the source; " + rosNoShell + ".",
	CapRogueServer:     "the rogue server is a netns actor on the source; " + rosNoShell + ".",
	CapForceRenewNonce: "SendForceRenew runs the lab's sender on the source; " + rosNoShell + ". The lab does not drive RouterOS's own use-reconfigure.",
	CapRapidCommit4:    "RouterOS 7.24.5's /ip dhcp-server has no rapid-commit setting (M3, #9).",
	CapDNSRegistration: "the CHR's resolver refuses remote queries in its stock config (allow-remote-requests=no, M3) and the lab keeps it that way.",
	CapV6:              rosV6Reason,
}

// NAReason names why a capability is absent (DESIGN-910 5.2, #9).
func (a *RouterOSAdapter) NAReason(c Capability) (string, bool) {
	why, ok := routerosNAReasons[c]
	return why, ok
}

// RouterOSAdapter drives a MikroTik CHR over its CLI as user lab: every
// command is RouterOS script text, never a shell line (#9). Objects are
// named, not found, wherever RouterOS allows it: a set on an empty [find]
// succeeds silently, a set by a missing name fails (M3).
type RouterOSAdapter struct {
	Runner Runner
	base   baseline
}

func (a *RouterOSAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapReserveClientID, CapRestart, CapShortLease, CapOptionChange, CapVendorClassPool, CapUserClassPool, CapOption108, CapNarrowPool, CapRenumber}
}

// routerosService is the dhcp-server lab's command set; isActive raises a
// script error, which exits ssh 1 (M3), while the server is disabled (#9).
var routerosService = service{
	name:     "dhcp-server " + rosServer,
	isActive: `:if ([/ip dhcp-server get ` + rosServer + ` disabled]) do={:error "dhcp-server ` + rosServer + ` is disabled"}`,
	stop:     "/ip dhcp-server disable " + rosServer,
	start:    "/ip dhcp-server enable " + rosServer,
	restart:  "/ip dhcp-server disable " + rosServer + "; /ip dhcp-server enable " + rosServer,
}

// host is this source's userland for needPortable: no actor tools (#9).
func (a *RouterOSAdapter) host() host {
	return host{unit: func(string) service { return routerosService }, main: "routeros", portable: false}
}

// rosErrorRE matches the CLI's own error lines. A parse error still
// exits ssh 0 (M3), so run treats these lines as a failure too (#9).
var rosErrorRE = regexp.MustCompile(`(?m)^(bad command name|syntax error|expected |missing value|input does not match|invalid value|no such item|failure:|Script Error)`)

// run sends one RouterOS command and drops the CLI's carriage returns (#9).
func (a *RouterOSAdapter) run(ctx context.Context, cmd string) (string, error) {
	out, err := a.Runner.Run(ctx, cmd)
	out = strings.ReplaceAll(out, "\r", "")
	if err != nil {
		return out, fmt.Errorf("routeros: %s: %w", cmd, err)
	}
	if m := rosErrorRE.FindStringIndex(out); m != nil {
		line, _, _ := strings.Cut(out[m[0]:], "\n")
		return out, fmt.Errorf("routeros: %s: %s", cmd, line)
	}
	return out, nil
}

// lines is out's non-empty lines, trimmed (#9).
func lines(out string) []string {
	var l []string
	for _, s := range strings.Split(out, "\n") {
		if s = strings.TrimSpace(s); s != "" {
			l = append(l, s)
		}
	}
	return l
}

// rosLeaseCmd prints one "key=value;..." line per bound lease of server
// lab; print as-value leaves out client-id and expires-after (M3, #9).
const rosLeaseCmd = `:foreach i in=[/ip dhcp-server lease find where server=` + rosServer + ` and status=bound] do={:put [/ip dhcp-server lease get $i]}`

func (a *RouterOSAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.run(ctx, rosLeaseCmd)
	if err != nil {
		return nil, fmt.Errorf("routeros: read leases: %w", err)
	}
	return parseRouterOSLeases(out, time.Now())
}

// parseRouterOSLeases reads rosLeaseCmd's output. A static lease made by
// client-id carries no mac-address, so the active-* fields win (M3, #9).
func parseRouterOSLeases(out string, now time.Time) ([]Lease, error) {
	var leases []Lease
	for _, line := range lines(out) {
		f := parseAsValue(line)
		addr := first(f["active-address"], f["address"])
		if _, err := validateAddr(addr); err != nil {
			return nil, fmt.Errorf("routeros: lease line %q: %w", line, err)
		}
		l := Lease{Address: addr, Hostname: f["host-name"], ClientID: rosClientID(first(f["active-client-id"], f["client-id"]))}
		if mac := first(f["active-mac-address"], f["mac-address"]); mac != "" {
			hw, err := validateMAC(mac)
			if err != nil {
				return nil, fmt.Errorf("routeros: lease line %q: %w", line, err)
			}
			l.MAC = hw
		}
		if d, ok := rosDuration(f["expires-after"]); ok {
			l.Expires = now.Add(d)
		}
		leases = append(leases, l)
	}
	return leases, nil
}

// first is the first non-empty value of s (#9).
func first(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

var asValueKeyRE = regexp.MustCompile(`^[.a-z][a-z0-9-]*$`)

// parseAsValue splits one "key=value;key=value" line. get prints a ';'
// inside a value bare (dynamic-lease-identifiers=client-mac;client-id,
// comment=a;b=c, M3), so a piece without a new key=... head joins the
// value before it. Keys come sorted and the first one stands, so a
// client's host-name cannot replace an address or MAC printed before it (#9).
func parseAsValue(line string) map[string]string {
	f := map[string]string{}
	last := ""
	for _, p := range strings.Split(line, ";") {
		k, v, ok := strings.Cut(p, "=")
		if _, seen := f[k]; ok && !seen && asValueKeyRE.MatchString(k) {
			f[k], last = unquote(v), k
			continue
		}
		if last != "" {
			f[last] += ";" + p
		}
	}
	return f
}

// unquote drops one pair of surrounding double quotes (#9).
func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

var rosDurationRE = regexp.MustCompile(`^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+):(\d+):(\d+)|(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?)$`)

// rosDuration reads a RouterOS time: "1w2d03:04:05" from get, or
// "1w2d3h4m5s" from print (M3, #9).
func rosDuration(s string) (time.Duration, bool) {
	m := rosDurationRE.FindStringSubmatch(s)
	if s == "" || m == nil {
		return 0, false
	}
	unit := []time.Duration{7 * 24 * time.Hour, 24 * time.Hour, time.Hour, time.Minute, time.Second, time.Hour, time.Minute, time.Second}
	var d time.Duration
	for i, u := range unit {
		if m[i+1] != "" {
			n, err := strconv.Atoi(m[i+1])
			if err != nil {
				return 0, false
			}
			d += time.Duration(n) * u
		}
	}
	return d, true
}

var rosHexByteRE = regexp.MustCompile(`^[0-9a-fA-F]{1,2}$`)

// rosClientID turns RouterOS's client-id ("1:52:54:0:12:34:56", no
// leading zeros on a dynamic lease, M3) into lowercase colon-hex (#9).
func rosClientID(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Split(s, ":")
	b := make([]byte, 0, len(parts))
	for _, p := range parts {
		if !rosHexByteRE.MatchString(p) {
			return hexColon([]byte(s))
		}
		n, _ := strconv.ParseUint(p, 16, 8)
		b = append(b, byte(n))
	}
	return hexColon(b)
}

// rosShortHex is colon-hex as RouterOS shows it on a dynamic lease (#9).
func rosShortHex(id string) string {
	parts := strings.Split(id, ":")
	for i, p := range parts {
		if t := strings.TrimLeft(p, "0"); t != "" {
			parts[i] = t
		} else {
			parts[i] = "0"
		}
	}
	return strings.Join(parts, ":")
}

// ReserveMAC drops any lease of server lab on the address or the MAC,
// then adds the static one. find compares the MAC as text, and RouterOS
// keeps it in upper case (M3, #9).
func (a *RouterOSAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	up := strings.ToUpper(hw)
	_, err = a.run(ctx, fmt.Sprintf(`/ip dhcp-server lease remove [find where server=%s and (address=%s or mac-address="%s")]; /ip dhcp-server lease add server=%s mac-address=%s address=%s`, rosServer, ip, up, rosServer, up, ip))
	return err
}

// ReserveClientID is ReserveMAC by client-id. A static lease keeps the
// text it was given, a dynamic one drops leading zeros (M3), so the
// remove names both spellings (#9).
func (a *RouterOSAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	id, err := validateClientID(clientID)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	_, err = a.run(ctx, fmt.Sprintf(`/ip dhcp-server lease remove [find where server=%s and (address=%s or client-id="%s" or client-id="%s")]; /ip dhcp-server lease add server=%s client-id=%s address=%s`, rosServer, ip, id, rosShortHex(id), rosServer, id, ip))
	return err
}

func (a *RouterOSAdapter) Restart(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "restart", "routeros")
}
func (a *RouterOSAdapter) Stop(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "stop", "routeros")
}
func (a *RouterOSAdapter) Start(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "start", "routeros")
}

// Reachable pings from the CHR; /ping returns the reply count after its
// table, on the last line (M3, #9).
func (a *RouterOSAdapter) Reachable(ctx context.Context, addr string) error {
	ip, err := validateAddr(addr)
	if err != nil {
		if ip, err = validateAddr6(addr); err != nil {
			return err
		}
	}
	out, err := a.run(ctx, ":put [/ping "+ip+" count=1]")
	if err != nil {
		return err
	}
	l := lines(out)
	if len(l) == 0 || l[len(l)-1] == "0" {
		return fmt.Errorf("ping %s: no reply", ip)
	}
	if _, err := strconv.Atoi(l[len(l)-1]); err != nil {
		return fmt.Errorf("ping %s: unexpected answer %q", ip, l[len(l)-1])
	}
	return nil
}

// ResetLeases drops server lab's dynamic leases; reservations stay (#9).
func (a *RouterOSAdapter) ResetLeases(ctx context.Context) error {
	_, err := a.run(ctx, "/ip dhcp-server lease remove [find where server="+rosServer+" and dynamic=yes]")
	return err
}

// get reads each RouterOS expression on one line of its own (#9).
func (a *RouterOSAdapter) get(ctx context.Context, exprs ...string) ([]string, error) {
	cmd := ""
	for i, e := range exprs {
		if i > 0 {
			cmd += "; "
		}
		cmd += `:put ("=" . [` + e + `])`
	}
	out, err := a.run(ctx, cmd)
	if err != nil {
		return nil, err
	}
	var vals []string
	for _, s := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimRight(s, " "), "="); ok {
			vals = append(vals, v)
		}
	}
	if len(vals) != len(exprs) {
		return nil, fmt.Errorf("routeros: read %d values, got %q", len(exprs), out)
	}
	return vals, nil
}

var rosSafeValueRE = regexp.MustCompile(`^[0-9A-Za-z.:/,-]*$`)

// restoreFn runs cmd and wraps an error with label (#9).
func (a *RouterOSAdapter) restoreFn(cmd, label string) func(context.Context) error {
	return func(ctx context.Context) error {
		if _, err := a.run(ctx, cmd); err != nil {
			return fmt.Errorf("routeros: %s restore: %w", label, err)
		}
		return nil
	}
}

// capture reads exprs and refuses a value it could not write back as is (#9).
func (a *RouterOSAdapter) capture(ctx context.Context, label string, exprs ...string) ([]string, error) {
	vals, err := a.get(ctx, exprs...)
	if err != nil {
		return nil, fmt.Errorf("routeros: %s: %w", label, err)
	}
	for _, v := range vals {
		if !rosSafeValueRE.MatchString(v) {
			return nil, fmt.Errorf("routeros: %s: cannot write %q back", label, v)
		}
	}
	return vals, nil
}

// SetDNSOption sets the network's dns-server; restore writes back the
// value read first (empty in the seed) (#9).
func (a *RouterOSAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	v, err := a.capture(ctx, "SetDNSOption", "/ip dhcp-server network get [find] dns-server")
	if err != nil {
		return nil, err
	}
	if _, err := a.run(ctx, "/ip dhcp-server network set [find] dns-server="+ip); err != nil {
		return nil, err
	}
	return a.restoreFn(`/ip dhcp-server network set [find] dns-server="`+v[0]+`"`, "SetDNSOption"), nil
}

// ShortenLeaseTime sets server lab's lease-time; restore writes back the
// value read first (#9).
func (a *RouterOSAdapter) ShortenLeaseTime(ctx context.Context, seconds int) (func(context.Context) error, error) {
	if seconds < 1 {
		return nil, fmt.Errorf("routeros: lease time %d s is not positive", seconds)
	}
	v, err := a.capture(ctx, "ShortenLeaseTime", "/ip dhcp-server get "+rosServer+" lease-time")
	if err != nil {
		return nil, err
	}
	if _, ok := rosDuration(v[0]); !ok {
		return nil, fmt.Errorf("routeros: ShortenLeaseTime: lease-time %q is not a RouterOS time", v[0])
	}
	if _, err := a.run(ctx, fmt.Sprintf("/ip dhcp-server set %s lease-time=%ds", rosServer, seconds)); err != nil {
		return nil, err
	}
	return a.restoreFn("/ip dhcp-server set "+rosServer+" lease-time="+v[0], "ShortenLeaseTime"), nil
}

// NarrowPool sets pool lab to one range; restore writes back the ranges
// read first (#9).
func (a *RouterOSAdapter) NarrowPool(ctx context.Context, first, last string) (func(context.Context) error, error) {
	f, l, err := validatePool(first, last)
	if err != nil {
		return nil, err
	}
	v, err := a.capture(ctx, "NarrowPool", "/ip pool get "+rosServer+" ranges")
	if err != nil {
		return nil, err
	}
	if _, err := a.run(ctx, fmt.Sprintf("/ip pool set %s ranges=%s-%s", rosServer, f, l)); err != nil {
		return nil, err
	}
	return a.restoreFn("/ip pool set "+rosServer+" ranges="+v[0], "NarrowPool"), nil
}

// rosRenumberCmd moves ether2, pool lab and the network to one plan; the
// gateway is the source itself, as the seed has it (#9).
func rosRenumberCmd(cidr, ranges, subnet, gw string) string {
	return fmt.Sprintf("/ip address remove [find interface=ether2]; /ip address add interface=ether2 address=%s; /ip pool set %s ranges=%s; /ip dhcp-server network set [find] address=%s gateway=%s",
		cidr, rosServer, ranges, subnet, gw)
}

func (a *RouterOSAdapter) Renumber(ctx context.Context, subnet, addr, first, last string) (func(context.Context) error, error) {
	p, err := validateRenumber(subnet, addr, first, last)
	if err != nil {
		return nil, err
	}
	v, err := a.capture(ctx, "Renumber", "/ip address get [find interface=ether2] address", "/ip pool get "+rosServer+" ranges",
		"/ip dhcp-server network get [find] address", "/ip dhcp-server network get [find] gateway")
	if err != nil {
		return nil, err
	}
	restore := a.restoreFn(rosRenumberCmd(v[0], v[1], v[2], v[3]), "Renumber")
	if _, err := a.run(ctx, rosRenumberCmd(netip.PrefixFrom(p.addr, p.subnet.Bits()).String(), p.first.String()+"-"+p.last.String(), p.subnet.String(), p.addr.String())); err != nil {
		return nil, errors.Join(err, restore(context.WithoutCancel(ctx)))
	}
	return restore, nil
}

// rosHex is colon-hex as a RouterOS 0x value (#9).
func rosHex(colonHex string) string { return "0x" + strings.ReplaceAll(colonHex, ":", "") }

// EnableFeature adds labf-named matchers, options and pools; restore
// removes them by name (M3: a code 77 matcher takes the 0x value with the
// length byte, a forced option reaches one client through a code 61
// matcher's option-set) (#9).
func (a *RouterOSAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	v, err := validateFeature(f, p)
	if err != nil {
		return nil, err
	}
	var do, undo string
	switch f {
	case FeatureUserClassPool:
		n := rosFeature + "77"
		do = fmt.Sprintf("/ip pool add name=%[1]s ranges=%[2]s-%[3]s; /ip dhcp-server matcher add server=%[4]s name=%[1]s code=77 value=%[5]s matching-type=exact address-pool=%[1]s", n, v.start, v.end, rosServer, rosHex(v.classHex()))
		undo = fmt.Sprintf("/ip dhcp-server matcher remove [find name=%[1]s]; /ip pool remove [find name=%[1]s]", n)
	case FeatureOffer108:
		n := rosFeature + "108"
		do = fmt.Sprintf("/ip dhcp-server option add name=%[1]s code=108 value=%[2]s; /ip dhcp-server network set [find] dhcp-option=%[1]s", n, rosHex(v.hex108()))
		undo = fmt.Sprintf(`/ip dhcp-server network set [find] dhcp-option=""; /ip dhcp-server option remove [find name=%s]`, n)
	case FeatureForce108:
		n := rosFeature + "108f"
		do = fmt.Sprintf("/ip dhcp-server option add name=%[1]s code=108 value=%[2]s force=yes; /ip dhcp-server option sets add name=%[1]s options=%[1]s; /ip dhcp-server matcher add server=%[3]s name=%[1]s code=61 value=%[4]s matching-type=exact address-pool=%[3]s option-set=%[1]s", n, rosHex(v.hex108()), rosServer, rosHex(v.clientID))
		undo = fmt.Sprintf("/ip dhcp-server matcher remove [find name=%[1]s]; /ip dhcp-server option sets remove [find name=%[1]s]; /ip dhcp-server option remove [find name=%[1]s]", n)
	default:
		why, ok := map[Feature]Capability{FeatureRapidCommit4: CapRapidCommit4, FeatureForceRenewNonce: CapForceRenewNonce}[f]
		if ok {
			return nil, fmt.Errorf("routeros: %s: %s", f, routerosNAReasons[why])
		}
		return nil, fmt.Errorf("routeros: %s: %s", f, rosV6Reason)
	}
	restore := a.restoreFn(undo, string(f))
	if _, err := a.run(ctx, do); err != nil {
		return nil, errors.Join(err, restore(context.WithoutCancel(ctx)))
	}
	return restore, nil
}

// rosStateCmd reads the three things a seeded CHR keeps: identity
// lab-ready (the seed's last line), server lab enabled, admin disabled (#9).
const rosStateCmd = `:put [/system identity get name]; :put [/ip dhcp-server get ` + rosServer + ` disabled]; :put [/user get admin disabled]`

// normalizeExport drops /export's leading "#" lines (date, RouterOS
// version, system id: D12) and the /ip dhcp-server lease section, where
// reservations live, so B1/B2 do not move the baseline (#9).
func normalizeExport(out string) string {
	var b strings.Builder
	head, inLease := true, false
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		if head && (strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "") {
			continue
		}
		head = false
		if strings.HasPrefix(l, "/") {
			inLease = l == "/ip dhcp-server lease"
		}
		if !inLease {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// Ready holds the CHR to its seeded state and to the export the first
// Ready saw (#9).
func (a *RouterOSAdapter) Ready(ctx context.Context) error {
	out, err := a.run(ctx, rosStateCmd)
	if err != nil {
		return err
	}
	st := lines(out)
	if len(st) != 3 {
		return fmt.Errorf("routeros: state read gave %q", out)
	}
	if st[0] != rosIdentity {
		return fmt.Errorf("routeros: identity is %q, not %s: the seed did not finish", st[0], rosIdentity)
	}
	if st[1] != "false" {
		return fmt.Errorf("routeros: dhcp-server %s is not active (disabled=%s)", rosServer, st[1])
	}
	if st[2] != "true" {
		return fmt.Errorf("routeros: user admin is not disabled (disabled=%s)", st[2])
	}
	if _, err := a.Leases(ctx); err != nil {
		return fmt.Errorf("lease table not readable: %w", err)
	}
	exp, err := a.run(ctx, "/export")
	if err != nil {
		return err
	}
	cfg := normalizeExport(exp)
	a.base.mu.Lock()
	defer a.base.mu.Unlock()
	if !a.base.taken {
		a.base.taken, a.base.cfg = true, cfg
		return nil
	}
	if cfg != a.base.cfg {
		return errors.New("routeros: /export differs from the one taken at the first readiness check")
	}
	return nil
}

// Recover imports the seed's baseline script again, which removes every
// labf object and resets pool, server, network and ether2, then restarts
// server lab (#9).
func (a *RouterOSAdapter) Recover(ctx context.Context) error {
	out, err := a.run(ctx, "/import file-name="+rosBaseline)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	if !strings.Contains(out, "executed successfully") {
		return fmt.Errorf("recover: /import %s answered %q", rosBaseline, out)
	}
	return a.Restart(ctx)
}

// Leases6 and SetRA are refused: the cell serves DHCPv4 only (#9).
func (a *RouterOSAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	return nil, errors.New("routeros: " + rosV6Reason)
}

func (a *RouterOSAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return nil, errors.New("routeros: " + rosV6Reason)
}

// Impair, Squat, StartRogue, RogueLeases and SendForceRenew need the
// source-side actor tools; needPortable refuses before any command (#9).
func (a *RouterOSAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return nil, a.host().needPortable("Impair")
}

func (a *RouterOSAdapter) Squat(ctx context.Context, addr string, announce bool) (func(context.Context) error, error) {
	return nil, a.host().needPortable("Squat")
}

func (a *RouterOSAdapter) StartRogue(ctx context.Context, serverAddr, first, last string) (func(context.Context) error, error) {
	return nil, a.host().needPortable("StartRogue")
}

func (a *RouterOSAdapter) RogueLeases(ctx context.Context) ([]Lease, error) {
	return nil, a.host().needPortable("RogueLeases")
}

func (a *RouterOSAdapter) SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error) {
	return "", a.host().needPortable("SendForceRenew")
}

var _ Adapter = (*RouterOSAdapter)(nil)
