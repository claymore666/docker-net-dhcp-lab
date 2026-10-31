package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// The OpenWrt cell's files (lab #9, DESIGN-910 3.4). dnsmasq.init builds
// dnsmasq's config from the uci dhcp file and names openwrtLabConf at its
// head (conf-file=, read first); the procd jail mounts that file and the
// lease file.
const (
	openwrtDHCPConf  = "/etc/config/dhcp"
	openwrtNetConf   = "/etc/config/network"
	openwrtLabConf   = "/etc/dnsmasq.conf"
	openwrtLeaseFile = "/tmp/dhcp.leases"
	openwrtUCI       = "sudo /sbin/uci"
)

// openwrtNAReason is the DESIGN-910 3.4 text for the four group C
// capabilities the image does not carry the tools for; the image runs
// dnsmasq 2.93, the dnsmasq cell 2.91 (lab #9).
const openwrtNAReason = "not built: OpenWrt runs dnsmasq 2.93, the dnsmasq cell 2.91 runs them; needs tc-full, kmod-netem, kmod-macvlan and python3 in the image"

// openwrtV6Reason: the image disables odhcpd's RA and DHCPv6 (lab #9).
const openwrtV6Reason = "the OpenWrt cell is DHCPv4 only: its image turns odhcpd's RA and DHCPv6 off on every interface."

var openwrtNAReasons = map[Capability]string{
	CapImpair:          openwrtNAReason,
	CapSquatter:        openwrtNAReason,
	CapRogueServer:     openwrtNAReason,
	CapForceRenewNonce: openwrtNAReason,
	CapServerEvents:    serverEventsNA,
	CapVLANPool:        vlanPoolNA,
	CapV6:              openwrtV6Reason,
}

// OpenwrtAdapter drives the dnsmasq of an OpenWrt image built by
// scripts/build-openwrt-image.sh: no systemd, no iproute2 netns, so a
// non-portable host with procd init scripts (lab #9). A scenario edit
// goes through uci where OpenWrt has a key, else to openwrtLabConf.
type OpenwrtAdapter struct {
	Runner Runner
	base   baseline
}

func (a *OpenwrtAdapter) NAReason(c Capability) (string, bool) {
	why, ok := openwrtNAReasons[c]
	return why, ok
}

func (a *OpenwrtAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease, CapReserveClientID, CapDNSRegistration, CapVendorClassPool, CapOptionChange, CapUserClassPool, CapOption108, CapRapidCommit4, CapNarrowPool, CapRenumber}
}

// openwrtService is a procd init script's command set; network reloads
// rather than restarts, which would take the management link down too (lab #9).
func openwrtService(name string) service {
	initd := "sudo /etc/init.d/" + name
	restart := initd + " restart"
	if name == "network" {
		restart = initd + " reload"
	}
	return service{name: name, isActive: initd + " running", stop: initd + " stop", start: initd + " start", restart: restart}
}

func (a *OpenwrtAdapter) host() host {
	return host{unit: openwrtService, main: "dnsmasq", label: "openwrt", nic: segmentNIC}
}

func (a *OpenwrtAdapter) units() sourceUnits {
	return sourceUnits{service: "dnsmasq", cfgPath: openwrtDHCPConf,
		extra: []extraConf{{openwrtNetConf, "network"}, {openwrtLabConf, "dnsmasq"}}}
}

func (a *OpenwrtAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	return nil, errors.New("openwrt: " + openwrtV6Reason)
}

func (a *OpenwrtAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return nil, errors.New("openwrt: " + openwrtV6Reason)
}

func (a *OpenwrtAdapter) StopV6Server(context.Context) (func(context.Context) error, error) {
	return nil, errors.New("openwrt: " + openwrtV6Reason)
}

func (a *OpenwrtAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+openwrtLeaseFile)
	if err != nil {
		return nil, fmt.Errorf("openwrt: read dhcp.leases: %w", err)
	}
	return parseDnsmasqLeases(out)
}

func (a *OpenwrtAdapter) Restart(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "restart", "openwrt")
}
func (a *OpenwrtAdapter) Stop(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "stop", "openwrt")
}
func (a *OpenwrtAdapter) Start(ctx context.Context) error {
	return a.host().svc().do(ctx, a.Runner, "start", "openwrt")
}

func (a *OpenwrtAdapter) Reachable(ctx context.Context, addr string) error {
	return reachableAs(ctx, a.Runner, addr, "sudo ")
}

func (a *OpenwrtAdapter) ResetLeases(ctx context.Context) error {
	return resetLeasesViaTruncate(ctx, a.Runner, openwrtLeaseFile, nil, a.host().svc(), "openwrt")
}

// uciCmd quotes each argument; every value reaching it was validated (lab #9).
func uciCmd(args ...string) string {
	return openwrtUCI + " '" + strings.Join(args, "' '") + "'"
}

// ReserveMAC writes a uci host section named after the MAC, so a second
// call replaces the first (dnsmasq.init dhcp_host_add).
func (a *OpenwrtAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	sec := "dhcp.labres_" + strings.ReplaceAll(strings.ToLower(hw), ":", "")
	cmd := strings.Join([]string{uciCmd("set", sec+"=host"), uciCmd("set", sec+".mac="+hw), uciCmd("set", sec+".ip="+ip),
		uciCmd("commit", "dhcp"), a.host().svc().restart}, " && ")
	return a.reserve(ctx, openwrtDHCPConf, cmd, "reserve "+hw+" -> "+ip)
}

// ReserveClientID goes to openwrtLabConf: a uci host has no DHCPv4
// client-id key (dnsmasq.init dhcp_host_add reads duid for v6 only).
func (a *OpenwrtAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	id, err := validateClientID(clientID)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf(`sudo sed -i '/^dhcp-host=id:%s,/d' %s && echo 'dhcp-host=id:%s,%s' | sudo tee -a %s >/dev/null && %s`,
		id, openwrtLabConf, id, ip, openwrtLabConf, a.host().svc().restart)
	return a.reserve(ctx, openwrtLabConf, cmd, "reserve id:"+id+" -> "+ip)
}

// reserve runs cmd and moves Ready's copy of path along with it, but
// only when path held exactly that copy before: the other cells keep
// reservations outside the files Ready compares (lab #9 defeat N6).
func (a *OpenwrtAdapter) reserve(ctx context.Context, path, cmd, what string) error {
	before, err := a.Runner.Run(ctx, "sudo cat "+path)
	if err != nil {
		return fmt.Errorf("openwrt: %s: read %s: %w", what, path, err)
	}
	if _, err := a.Runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("openwrt: %s: %w", what, err)
	}
	after, err := a.Runner.Run(ctx, "sudo cat "+path)
	if err != nil {
		return fmt.Errorf("openwrt: %s: read %s back: %w", what, path, err)
	}
	a.base.mu.Lock()
	defer a.base.mu.Unlock()
	if !a.base.taken {
		return nil
	}
	if path == openwrtDHCPConf && a.base.cfg == before {
		a.base.cfg = after
	} else if path != openwrtDHCPConf && a.base.extra[path] == before {
		a.base.extra[path] = after
	}
	return nil
}

// owEdit is one scenario edit (lab #9 D14): uci commands, then
// substitutions on openwrtLabConf; nothing else is written. already
// refuses a second application, found in either file.
type owEdit struct {
	uci     [][]string
	conf    []configEdit
	already string
}

// apply captures both files, applies e and restarts dnsmasq; restore
// writes the captured bytes back in place and restarts again (lab #9).
func (a *OpenwrtAdapter) apply(ctx context.Context, what string, e owEdit) (func(context.Context) error, error) {
	orig := map[string]string{}
	for _, p := range []string{openwrtDHCPConf, openwrtLabConf} {
		s, err := a.Runner.Run(ctx, "sudo cat "+p)
		if err != nil {
			return nil, fmt.Errorf("openwrt: %s: read %s: %w", what, p, err)
		}
		if !strings.HasSuffix(s, "\n") {
			return nil, fmt.Errorf("openwrt: %s: %s does not end in a newline, cannot write it back byte for byte", what, p)
		}
		if e.already != "" && strings.Contains(s, e.already) {
			return nil, fmt.Errorf("openwrt: %s: %s already carries %q; refusing to add it twice (Recover puts the baseline back)", what, p, e.already)
		}
		orig[p] = s
	}
	conf := orig[openwrtLabConf]
	for _, c := range e.conf {
		next := c.re.ReplaceAllString(conf, c.repl)
		if next == conf {
			return nil, fmt.Errorf("openwrt: %s: anchor for %s not found in %s; refusing to change it blindly", what, c.what, openwrtLabConf)
		}
		conf = next
	}
	restore := func(ctx context.Context) error {
		var errs []error
		if len(e.uci) > 0 {
			errs = append(errs, writeRemoteConfig(ctx, a.Runner, openwrtDHCPConf, orig[openwrtDHCPConf]))
		}
		if len(e.conf) > 0 {
			errs = append(errs, writeRemoteConfig(ctx, a.Runner, openwrtLabConf, orig[openwrtLabConf]))
		}
		errs = append(errs, a.Restart(ctx))
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("openwrt: %s: restore: %w", what, err)
		}
		return nil
	}
	undo := func(err error) (func(context.Context) error, error) {
		return nil, errors.Join(fmt.Errorf("openwrt: %s: %w", what, err), restore(context.WithoutCancel(ctx)))
	}
	if len(e.conf) > 0 {
		if err := writeRemoteConfig(ctx, a.Runner, openwrtLabConf, conf); err != nil {
			return undo(err)
		}
	}
	if len(e.uci) > 0 {
		var cmds []string
		for _, u := range e.uci {
			cmds = append(cmds, uciCmd(u...))
		}
		cmds = append(cmds, uciCmd("commit", "dhcp"))
		if _, err := a.Runner.Run(ctx, strings.Join(cmds, " && ")); err != nil {
			return undo(err)
		}
	}
	if err := a.Restart(ctx); err != nil {
		return undo(err)
	}
	return restore, nil
}

func (a *OpenwrtAdapter) ShortenLeaseTime(ctx context.Context, seconds int) (func(context.Context) error, error) {
	if seconds <= 0 {
		return nil, fmt.Errorf("openwrt: lease time must be positive, got %d", seconds)
	}
	return a.apply(ctx, "shorten lease time", owEdit{uci: [][]string{{"set", fmt.Sprintf("dhcp.lan.leasetime=%d", seconds)}}})
}

func (a *OpenwrtAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	return a.apply(ctx, "set the DNS option", owEdit{already: "dhcp-option=6,",
		conf: []configEdit{{dnsmasqRouterOptionRE, fmt.Sprintf("${1}\ndhcp-option=6,%s", ip), "the router option"}}})
}

func (a *OpenwrtAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	v, err := validateFeature(f, p)
	if err != nil {
		return nil, err
	}
	var e owEdit
	switch f {
	case FeatureUserClassPool:
		e = owEdit{already: "dhcp-userclass=set:f1,", uci: [][]string{{"add_list", "dhcp.lan.tag=!f1"}},
			conf: []configEdit{{dnsmasqClassRangeRE, fmt.Sprintf("${1}\ndhcp-userclass=set:f1,%s\ndhcp-range=tag:f1,%s,%s,12h", v.class, v.start, v.end), "the class range"}}}
	case FeatureOffer108:
		e = owEdit{already: "dhcp-option=108,", conf: []configEdit{{dnsmasqRouterOptionRE, fmt.Sprintf("${1}\ndhcp-option=108,%s", v.hex108()), "the router option"}}}
	case FeatureForce108:
		e = owEdit{already: "set:f2b", conf: []configEdit{{dnsmasqRouterOptionRE, fmt.Sprintf("${1}\ndhcp-host=id:%s,set:f2b\ndhcp-option-force=tag:f2b,108,%s", v.clientID, v.hex108()), "the router option"}}}
	case FeatureRapidCommit4:
		e = owEdit{already: "rapidcommit", uci: [][]string{{"set", "dhcp.@dnsmasq[0].rapidcommit=1"}}}
	case FeatureForceRenewNonce:
		return nil, fmt.Errorf("openwrt: %s: %s", f, openwrtNAReason)
	default:
		return nil, fmt.Errorf("openwrt: %s: %s", f, openwrtV6Reason)
	}
	return a.apply(ctx, "enable "+string(f), e)
}

// NarrowPool sets the uci pool, start as an offset into eth1's subnet
// and limit as its size (dnsmasq.init dhcp_add, ipcalc).
func (a *OpenwrtAdapter) NarrowPool(ctx context.Context, first, last string) (func(context.Context) error, error) {
	f, l, err := validatePool(first, last)
	if err != nil {
		return nil, fmt.Errorf("openwrt: %w", err)
	}
	seg, err := a.host().segmentPrefix(ctx, a.Runner)
	if err != nil {
		return nil, fmt.Errorf("openwrt: %w", err)
	}
	if err := onSegment(seg, f.String(), l.String()); err != nil {
		return nil, fmt.Errorf("openwrt: %w", err)
	}
	start := addrOffset(seg.Masked().Addr(), f)
	size := addrOffset(f, l) + 1
	return a.apply(ctx, "narrow the pool", owEdit{uci: [][]string{
		{"set", fmt.Sprintf("dhcp.lan.start=%d", start)}, {"set", fmt.Sprintf("dhcp.lan.limit=%d", size)}}})
}

func addrOffset(from, to netip.Addr) uint32 {
	a, b := from.As4(), to.As4()
	return (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) -
		(uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]))
}

// openwrtGenConf is where dnsmasq.init writes the config it generates
// from uci and netifd's view of lan (the file name carries a section id).
const openwrtGenConf = "/var/etc/dnsmasq.conf.*"

var openwrtRangeRE = regexp.MustCompile(`(?m)^dhcp-range=(.*)$`)

// openwrtLabRange marks the lab conf's vendor-class pool, which is not
// the lan pool and keeps the first subnet.
const openwrtLabRange = "tag:b5"

// Renumber moves lan through uci and netifd, so that netifd, the uci
// dhcp section and dnsmasq.init agree on the new subnet (lab #127). The
// hand-made eth1 move of run 4 left netifd's view of lan on the old
// subnet and the source kept serving it. The lab conf keeps its lines
// and only its router option changes. Before it returns, the source is
// read back: eth1 carries exactly the new address, the generated dnsmasq
// config names the pool in the new subnet and no other, and the router
// option is the new address; any other state is an error, never a
// judged scenario. Only network.lan changes, because the management
// link shares netifd (lab #9).
func (a *OpenwrtAdapter) Renumber(ctx context.Context, subnet, addr, first, last string) (func(context.Context) error, error) {
	p, err := validateRenumber(subnet, addr, first, last)
	if err != nil {
		return nil, err
	}
	h := a.host()
	oldAddrs, err := h.segmentAddrs(ctx, a.Runner)
	if err != nil {
		return nil, fmt.Errorf("openwrt: %w", err)
	}
	if len(oldAddrs) == 0 {
		return nil, fmt.Errorf("openwrt: %s carries no IPv4 address to restore later", h.nic)
	}
	files := []string{openwrtNetConf, openwrtDHCPConf, openwrtLabConf}
	orig := map[string]string{}
	for _, f := range files {
		s, err := a.Runner.Run(ctx, "sudo cat "+f)
		if err != nil {
			return nil, fmt.Errorf("openwrt: read %s before renumbering: %w", f, err)
		}
		if !strings.HasSuffix(s, "\n") {
			return nil, fmt.Errorf("openwrt: %s does not end in a newline, cannot write it back byte for byte", f)
		}
		orig[f] = s
	}
	if _, err := onlyMatch(dnsmasqRouterOptionRE, orig[openwrtLabConf], "router options"); err != nil {
		return nil, fmt.Errorf("openwrt: %w", err)
	}
	conf := dnsmasqRouterOptionRE.ReplaceAllString(orig[openwrtLabConf], "dhcp-option=3,"+p.addr.String())
	start := addrOffset(p.subnet.Addr(), p.first)
	limit := addrOffset(p.first, p.last) + 1
	cidr := netip.PrefixFrom(p.addr, p.subnet.Bits())

	restore := func(ctx context.Context) error {
		var errs []error
		for _, f := range files {
			errs = append(errs, writeRemoteConfig(ctx, a.Runner, f, orig[f]))
		}
		errs = append(errs, a.reloadNetwork(ctx, oldAddrs), a.Restart(ctx))
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("openwrt: renumber restore: %w", err)
		}
		return nil
	}
	undo := func(err error) (func(context.Context) error, error) {
		return nil, errors.Join(fmt.Errorf("openwrt: renumber to %s: %w", p.subnet, err), restore(context.WithoutCancel(ctx)))
	}
	uci := strings.Join([]string{
		uciCmd("delete", "network.lan.ipaddr"), uciCmd("add_list", "network.lan.ipaddr="+cidr.String()),
		uciCmd("set", fmt.Sprintf("dhcp.lan.start=%d", start)), uciCmd("set", fmt.Sprintf("dhcp.lan.limit=%d", limit)),
		uciCmd("commit", "network"), uciCmd("commit", "dhcp")}, " && ")
	if _, err := a.Runner.Run(ctx, uci); err != nil {
		return undo(fmt.Errorf("uci: %w", err))
	}
	if err := writeRemoteConfig(ctx, a.Runner, openwrtLabConf, conf); err != nil {
		return undo(err)
	}
	if err := a.reloadNetwork(ctx, []netip.Prefix{cidr}); err != nil {
		return undo(err)
	}
	if err := a.Restart(ctx); err != nil {
		return undo(err)
	}
	// A settle: netifd must not put the old address back behind us.
	if _, err := a.Runner.Run(ctx, "sleep 2"); err != nil {
		return undo(err)
	}
	if err := a.verifyRenumber(ctx, p, cidr); err != nil {
		return undo(err)
	}
	return restore, nil
}

// reloadNetwork reloads netifd (the changed lan only) and waits until
// eth1 carries exactly want.
func (a *OpenwrtAdapter) reloadNetwork(ctx context.Context, want []netip.Prefix) error {
	if _, err := a.Runner.Run(ctx, openwrtService("network").restart); err != nil {
		return fmt.Errorf("network reload: %w", err)
	}
	var got []netip.Prefix
	var err error
	for i := 0; i < 20; i++ {
		if got, err = a.host().segmentAddrs(ctx, a.Runner); err == nil && fmt.Sprint(got) == fmt.Sprint(want) {
			return nil
		}
		if _, serr := a.Runner.Run(ctx, "sleep 1"); serr != nil {
			return serr
		}
	}
	return fmt.Errorf("%s carries %v 20 s after the network reload, want %v (%v)", segmentNIC, got, want, err)
}

// verifyRenumber reads the source's own state: the address on eth1, the
// pool dnsmasq.init generated, and the router option (lab #127).
func (a *OpenwrtAdapter) verifyRenumber(ctx context.Context, p renumberPlan, cidr netip.Prefix) error {
	got, err := a.host().segmentAddrs(ctx, a.Runner)
	if err != nil {
		return err
	}
	if fmt.Sprint(got) != fmt.Sprint([]netip.Prefix{cidr}) {
		return fmt.Errorf("source check: %s carries %v, want only %v", segmentNIC, got, cidr)
	}
	gen, err := a.Runner.Run(ctx, "sudo cat "+openwrtGenConf)
	if err != nil {
		return fmt.Errorf("source check: read the generated dnsmasq config: %w", err)
	}
	served := false
	for _, m := range openwrtRangeRE.FindAllStringSubmatch(gen, -1) {
		if strings.Contains(m[1], openwrtLabRange) {
			continue
		}
		var ips []netip.Addr
		for _, f := range strings.Split(m[1], ",") {
			if ip, err := netip.ParseAddr(f); err == nil && ip.Is4() {
				ips = append(ips, ip)
			}
		}
		if len(ips) < 2 {
			continue
		}
		if !p.subnet.Contains(ips[0]) || !p.subnet.Contains(ips[1]) {
			return fmt.Errorf("source check: dnsmasq still serves %s - %s, outside %s", ips[0], ips[1], p.subnet)
		}
		served = served || ips[0] == p.first
	}
	if !served {
		return fmt.Errorf("source check: the generated dnsmasq config has no pool starting at %s", p.first)
	}
	lab, err := a.Runner.Run(ctx, "sudo cat "+openwrtLabConf)
	if err != nil {
		return fmt.Errorf("source check: read %s: %w", openwrtLabConf, err)
	}
	if r, err := onlyMatch(dnsmasqRouterOptionRE, lab, "router options"); err != nil || r != "dhcp-option=3,"+p.addr.String() {
		return fmt.Errorf("source check: router option is %q (%v), want %s", r, err, p.addr)
	}
	return nil
}

func (a *OpenwrtAdapter) Ready(ctx context.Context) error {
	return a.host().sourceReady(ctx, a.Runner, a.units(), a.Leases, &a.base)
}

func (a *OpenwrtAdapter) Recover(ctx context.Context) error {
	return a.host().sourceRecover(ctx, a.Runner, a.units(), &a.base)
}

// The group C actors need netns, tc and python3; host() refuses them
// through needPortable before any command is sent (lab #9 D15).
func (a *OpenwrtAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return a.host().impair(ctx, a.Runner, delay, lossPct)
}

func (a *OpenwrtAdapter) Squat(ctx context.Context, addr string, announce bool) (func(context.Context) error, error) {
	return a.host().squat(ctx, a.Runner, addr, announce)
}

func (a *OpenwrtAdapter) StartRogue(ctx context.Context, serverAddr, first, last string) (func(context.Context) error, error) {
	return a.host().startRogue(ctx, a.Runner, serverAddr, first, last)
}

func (a *OpenwrtAdapter) RogueLeases(ctx context.Context) ([]Lease, error) {
	return a.host().rogueLeases(ctx, a.Runner)
}

func (a *OpenwrtAdapter) ServerEvents(ctx context.Context, since time.Time, mac string) ([]ServerEvent, error) {
	return serverEventsRefused("openwrt")
}

func (a *OpenwrtAdapter) SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error) {
	return a.host().sendForceRenew(ctx, a.Runner, script, p)
}
