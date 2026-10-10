package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	piholeService   = "pihole-FTL"
	piholeLabConf   = "/etc/dnsmasq.d/90-lab.conf"
	piholeLeaseFile = "/etc/pihole/dhcp.leases"
	// piholeLabHeader is the one line cloud-init/pihole-user-data.tmpl.yaml
	// seeds into piholeLabConf; every scenario edit anchors on it (#10).
	piholeLabHeader = "# lab-owned scenario overrides"
)

// piholeNAReason is why ShortLease, NarrowPool, Renumber, VendorClassPool
// and UserClassPool are not declared (D11, FTL v6.7.1, #10).
const piholeNAReason = "Pi-hole's FTL owns dhcp-range and lease time in pihole.toml; the lab does not edit the toml."

// piholeV6Reason is why the cell serves no DHCPv6: FTL's v6 server is a
// pihole.toml setting and the lab never edits the toml (#10).
const piholeV6Reason = "Pi-hole's DHCPv6 is a pihole.toml setting and the lab does not edit the toml, so the cell is DHCPv4 only."

var piholeNAReasons = map[Capability]string{
	CapShortLease:      piholeNAReason,
	CapNarrowPool:      piholeNAReason,
	CapRenumber:        piholeNAReason,
	CapVendorClassPool: piholeNAReason,
	CapUserClassPool:   piholeNAReason,
	CapV6:              piholeV6Reason,
}

// NAReason names why a capability is absent; scenario.Applicable shows it
// in the matrix (DESIGN-910 5.2).
func (a *PiholeAdapter) NAReason(c Capability) (string, bool) {
	why, ok := piholeNAReasons[c]
	return why, ok
}

var piholeAnchorRE = regexp.MustCompile(`(?m)^(` + regexp.QuoteMeta(piholeLabHeader) + `[^\n]*)$`)

// PiholeAdapter drives Pi-hole's FTL, an embedded dnsmasq. FTL writes
// /etc/pihole/dnsmasq.conf from pihole.toml on every start, so every
// scenario edit goes to piholeLabConf, which FTL reads through
// misc.etc_dnsmasq_d (#10).
type PiholeAdapter struct {
	Runner Runner
	base   baseline
}

func (a *PiholeAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart, CapReserveClientID, CapDNSRegistration, CapOptionChange, CapImpair, CapOption108, CapRapidCommit4, CapForceRenewNonce, CapSquatter, CapRogueServer}
}

// Leases6 and SetRA are refused: the cell serves DHCPv4 only (#10).
func (a *PiholeAdapter) Leases6(ctx context.Context) ([]Lease6, error) {
	return nil, errors.New("pihole: " + piholeV6Reason)
}

func (a *PiholeAdapter) SetRA(ctx context.Context, p RAParams) (func(context.Context) error, error) {
	return nil, errors.New("pihole: " + piholeV6Reason)
}

func (a *PiholeAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+piholeLeaseFile)
	if err != nil {
		return nil, fmt.Errorf("pihole: read dhcp.leases: %w", err)
	}
	return parseDnsmasqLeases(out)
}

// ReserveMAC reserves ip for the MAC in the lab-owned reservations file,
// not in piholeLabConf, so Ready's baseline does not move (#10).
func (a *PiholeAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return reserveViaDhcpHost(ctx, a.Runner, hw, ip, piholeService)
}

func (a *PiholeAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	id, err := validateClientID(clientID)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return reserveViaDhcpHost(ctx, a.Runner, "id:"+id, ip, piholeService)
}

func (a *PiholeAdapter) Restart(ctx context.Context) error { return a.systemctl(ctx, "restart") }
func (a *PiholeAdapter) Stop(ctx context.Context) error    { return a.systemctl(ctx, "stop") }
func (a *PiholeAdapter) Start(ctx context.Context) error   { return a.systemctl(ctx, "start") }

func (a *PiholeAdapter) systemctl(ctx context.Context, action string) error {
	if _, err := a.Runner.Run(ctx, "sudo systemctl "+action+" "+piholeService); err != nil {
		return fmt.Errorf("pihole: systemctl %s: %w", action, err)
	}
	return nil
}

func (a *PiholeAdapter) Reachable(ctx context.Context, addr string) error {
	return reachable(ctx, a.Runner, addr)
}

func (a *PiholeAdapter) ResetLeases(ctx context.Context) error {
	return resetLeasesViaTruncate(ctx, a.Runner, piholeLeaseFile, nil, piholeService, "pihole")
}

// SetDNSOption adds dhcp-option=6 to piholeLabConf, which FTL's generated
// config reads last; with FTL v6.7.1 the OFFER then carries it (#10).
func (a *PiholeAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	return setDNSOptionViaSubstitution(ctx, a.Runner, piholeLabConf,
		piholeAnchorRE, fmt.Sprintf("${1}\ndhcp-option=6,%s", ip), "dhcp-option=6,",
		func(ctx context.Context) error { return a.Restart(ctx) }, "pihole")
}

// EnableFeature appends plain dnsmasq directives to piholeLabConf (#10).
func (a *PiholeAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	v, err := validateFeature(f, p)
	if err != nil {
		return nil, err
	}
	var already, repl string
	switch f {
	case FeatureOffer108:
		already = "dhcp-option=108,"
		repl = fmt.Sprintf("${1}\ndhcp-option=108,%s", v.hex108())
	case FeatureForce108:
		already = "set:f2b"
		repl = fmt.Sprintf("${1}\ndhcp-host=id:%s,set:f2b\ndhcp-option-force=tag:f2b,108,%s", v.clientID, v.hex108())
	case FeatureForceRenewNonce:
		already = "set:f8"
		repl = fmt.Sprintf("${1}\ndhcp-host=id:%s,set:f8\ndhcp-match=set:f8sel,option:requested-address\ndhcp-option-force=tag:f8,145,01\ndhcp-option-force=tag:f8,tag:f8sel,90,%s", v.clientID, v.auth90Hex())
	case FeatureRapidCommit4:
		already = "dhcp-rapid-commit"
		repl = "${1}\ndhcp-rapid-commit"
	default:
		return nil, fmt.Errorf("pihole: %s is not supported: %s", f, piholeNAReason)
	}
	return enableFeatureViaSubstitution(ctx, a.Runner, piholeLabConf, already,
		[]configEdit{{piholeAnchorRE, repl, "the lab header line"}},
		func(ctx context.Context) error { return a.Restart(ctx) }, "pihole")
}

// ShortenLeaseTime, NarrowPool and Renumber would edit dhcp-range, which
// a second dhcp-range in piholeLabConf does not override (FTL v6.7.1,
// #10); they refuse rather than give a verdict on an unchanged server.
func (a *PiholeAdapter) ShortenLeaseTime(context.Context, int) (func(context.Context) error, error) {
	return nil, fmt.Errorf("pihole: ShortenLeaseTime: %s", piholeNAReason)
}

func (a *PiholeAdapter) NarrowPool(context.Context, string, string) (func(context.Context) error, error) {
	return nil, fmt.Errorf("pihole: NarrowPool: %s", piholeNAReason)
}

func (a *PiholeAdapter) Renumber(context.Context, string, string, string, string) (func(context.Context) error, error) {
	return nil, fmt.Errorf("pihole: Renumber: %s", piholeNAReason)
}

func (a *PiholeAdapter) units() sourceUnits {
	return sourceUnits{service: piholeService, cfgPath: piholeLabConf}
}

func (a *PiholeAdapter) Ready(ctx context.Context) error {
	return sourceReady(ctx, a.Runner, a.units(), a.Leases, &a.base)
}

func (a *PiholeAdapter) Recover(ctx context.Context) error {
	return sourceRecover(ctx, a.Runner, a.units(), &a.base)
}

func (a *PiholeAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return impair(ctx, a.Runner, delay, lossPct)
}

func (a *PiholeAdapter) Squat(ctx context.Context, addr string, announce bool) (func(context.Context) error, error) {
	return squat(ctx, a.Runner, addr, announce)
}

func (a *PiholeAdapter) StartRogue(ctx context.Context, serverAddr, first, last string) (func(context.Context) error, error) {
	return startRogue(ctx, a.Runner, serverAddr, first, last)
}

func (a *PiholeAdapter) RogueLeases(ctx context.Context) ([]Lease, error) {
	return rogueLeases(ctx, a.Runner)
}

func (a *PiholeAdapter) SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error) {
	return sendForceRenew(ctx, a.Runner, script, p)
}
