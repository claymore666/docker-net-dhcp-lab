// Package sourceadapter is the one interface issue #2 asks for: read
// leases, reserve by MAC, restart, stop, start, capabilities, one
// implementation per IP source, each reading lease evidence through that
// source's own interface (control agent API, leases file, lease file)
// rather than anything the plugin reports.
package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Capability is a source's declared ability. A declared capability is a
// claim until a real run against that source exercises it; see each
// adapter's own comment for what has actually been measured so far.
type Capability string

const (
	CapV4         Capability = "v4"
	CapReserveMAC Capability = "reserve-mac"
	CapRestart    Capability = "restart"
	// CapShortLease declares ShortenLeaseTime: a source that can run
	// with a short-lived lease for one scenario, then be restored to
	// its stock lease time (issue #3, A14). A declared capability is a
	// claim until measured, the same as every other Capability here.
	CapShortLease Capability = "short-lease"
	// CapReserveClientID declares ReserveClientID (group B, B2, #23).
	CapReserveClientID Capability = "reserve-client-id"
	// CapDNSRegistration declares that the source itself serves DNS
	// from its leases, so a registered hostname can be queried back
	// from it (B3, #23). Only dnsmasq does that out of the box; Kea and
	// ISC would need a separate DNS server beside the stock install.
	CapDNSRegistration Capability = "dns-registration"
	// CapVendorClassPool declares that the cloud-init config carries a
	// class pool served only to option 60 "lab-class-b5" (B5, #23).
	CapVendorClassPool Capability = "vendor-class-pool"
	// CapOptionChange declares SetDNSOption (B6, #23).
	CapOptionChange Capability = "option-change"
	// CapImpair declares Impair: netem on the source's segment leg (C10, #23).
	CapImpair Capability = "impair"
	// CapFailoverPair and CapRelay are declared by no adapter until a
	// failover-pair cell (lab #12) and a relay cell (lab #11) exist; C5
	// and C12 stay N/A through Applicable until then (#23).
	CapFailoverPair Capability = "failover-pair"
	CapRelay        Capability = "relay"
	// CapUserClassPool declares EnableFeature(FeatureUserClassPool): a
	// pool served only to option 77 clients of one class (group F, #20).
	CapUserClassPool Capability = "user-class-pool"
	// CapOption108 declares EnableFeature(FeatureOffer108) and
	// EnableFeature(FeatureForce108) (RFC 8925, F2a and F2b, #20).
	CapOption108 Capability = "option-108"
	// CapRapidCommit4 declares EnableFeature(FeatureRapidCommit4): the
	// source answers a DHCPv4 DISCOVER that carries option 80 with an
	// ACK (RFC 4039; dnsmasq only, #20).
	CapRapidCommit4 Capability = "rapid-commit-4"
	// CapForceRenewNonce declares EnableFeature(FeatureForceRenewNonce)
	// and SendForceRenew (F8-forcerenew, RFC 6704, #21).
	CapForceRenewNonce Capability = "forcerenew-nonce"
	// CapSquatter declares Squat, CapRogueServer StartRogue and
	// RogueLeases, CapNarrowPool NarrowPool, CapRenumber Renumber (C6 to
	// C9, #23).
	CapSquatter    Capability = "squatter"
	CapRogueServer Capability = "rogue-server"
	CapNarrowPool  Capability = "narrow-pool"
	CapRenumber    Capability = "renumber"
	// CapV6 declares the IPv6 segment: a DHCPv6 server answering IA_NA
	// on eth1 and RAs at the M=1 A=1 baseline, Leases6 and SetRA Off
	// (#23 group D).
	CapV6 Capability = "v6"
	// CapRapidCommit6 declares EnableFeature(FeatureRapidCommit6): a
	// Solicit carrying option 14 is answered by a Reply (RFC 8415
	// section 18.3.1).
	CapRapidCommit6 Capability = "rapid-commit-6"
	// CapTemporary6 declares that the server grants an IA_TA (RFC 8415
	// section 21.5) once EnableFeature(FeatureTemporary6) ran.
	CapTemporary6 Capability = "temporary-6"
	// CapPD and CapPref64 are declared by no adapter until #23 group D
	// part 2 adds delegation and PREF64 to the sources.
	CapPD     Capability = "pd"
	CapPref64 Capability = "pref64"
)

// Lease is one entry from a source's own table, normalized across the
// three source shapes (JSON, dhcpd.leases, dnsmasq.leases). ClientID is
// DHCP option 61, normalized to lowercase colon-hex across all three
// (Kea's own "client-id" field, ISC's "uid", dnsmasq's fifth lease-line
// field) -- empty when the row carries none. ipvlan slaves share the
// parent NIC's MAC (docs/reference.md "DHCP identity"), so ClientID is
// the only field that identifies one slave's lease from another's
// (#3). Expires is the lease's end as the source's own table states it,
// zero when the source gives none (dnsmasq "0" = infinite) or the field
// did not parse; B6 compares two reads of it (#23).
type Lease struct {
	MAC      string
	Address  string
	Hostname string
	ClientID string
	Expires  time.Time
}

// hexColon renders raw bytes as lowercase colon-hex, the shape every
// adapter normalizes its own client-id encoding into.
func hexColon(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

// Adapter is the interface issue #2 asks for. Every method reads or
// changes the source through its own management interface, over the
// runner it was built with; none of them ever touch the plugin.
type Adapter interface {
	Capabilities() []Capability
	// Leases returns ACTIVE leases only: an entry the source marks
	// released, free, expired-reclaimed or declined is dropped by each
	// adapter's parser, so "the table no longer shows X" (B7, #23) means
	// the same thing on all three sources.
	Leases(ctx context.Context) ([]Lease, error)
	// Leases6 returns the active IA_NA and IA_TA addresses of the
	// source's DHCPv6 table, the same "active only" rule as Leases (#23
	// group D).
	Leases6(ctx context.Context) ([]Lease6, error)
	// SetRA changes what the segment's router advertisements say and
	// returns the restore that puts the baseline (M=1, A=1) back (#23
	// group D). Only RAParams.Off is implemented.
	SetRA(ctx context.Context, p RAParams) (restore func(ctx context.Context) error, err error)
	ReserveMAC(ctx context.Context, mac, addr string) error
	// ReserveClientID reserves addr for a DHCP option 61 value given as
	// colon-hex (B2, #23). Idempotent: a second call for the same id
	// replaces the first.
	ReserveClientID(ctx context.Context, clientID, addr string) error
	// SetDNSOption makes the source hand out addr as DHCP option 6 and
	// restarts it; the returned restore func writes the captured running
	// config back byte for byte (B6, #23). Call restores in reverse
	// order of the calls that made them.
	SetDNSOption(ctx context.Context, addr string) (restore func(ctx context.Context) error, err error)
	Restart(ctx context.Context) error
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
	// Reachable reports whether addr answers from the source's own
	// vantage point on the cell's segment (issue #3): A4/A5's PASS bar
	// needs proof the container can still be reached, not only that the
	// source's lease table still lists it.
	Reachable(ctx context.Context, addr string) error
	// ShortenLeaseTime installs a short-lived-lease config over the
	// source's own stock config and restarts it, so a scenario can run
	// past a lease's renewal point in bounded wall time (issue #3,
	// A14). The returned restore func puts the stock config straight
	// back and restarts again; a caller that never gets a restore func
	// (a non-nil error) has made no change to restore. Scoped to A14
	// alone: every other scenario's timing assumes the stock lease
	// time, never this one's.
	ShortenLeaseTime(ctx context.Context, seconds int) (restore func(ctx context.Context) error, err error)
	// ResetLeases stops the source, clears every lease file it reloads at start,
	// and starts it again (issue #3 part 2). The plugin's own
	// default is release_lease=never (docs/reference.md), so nothing
	// else ever frees a lease between shapes: five shapes of fresh
	// MACs/client-ids on the one small pool this lab uses run it out
	// unless the runner resets the source before every shape, which is
	// what this is for.
	ResetLeases(ctx context.Context) error
	// Ready reports whether the source is in the state a scenario may
	// start from: service active, table readable, no labc-* netns, no
	// netem on its segment leg, segment addresses and main config equal
	// to the copy taken at the first Ready (group C, #23). Recover puts
	// it back there; the scenario runner calls Ready, then Recover once.
	Ready(ctx context.Context) error
	Recover(ctx context.Context) error
	// Impair delays and drops the source's segment egress (its replies);
	// restore removes the qdisc (C10, #23).
	Impair(ctx context.Context, delay time.Duration, lossPct int) (restore func(ctx context.Context) error, err error)
	// EnableFeature changes the running config for one group F scenario
	// (#20) and restarts the source. A non-nil error means the config was
	// put back before returning; a nil error hands over a restore func
	// that writes the captured bytes back and restarts, and may be
	// called again after a failure. The caller defers it on every path.
	EnableFeature(ctx context.Context, f Feature, p FeatureParams) (restore func(ctx context.Context) error, err error)
	// SendForceRenew sends one FORCERENEW frame from the source's segment
	// leg with script, the repo's scripts/forcerenew-send.py, and returns
	// its one-line record (F8-forcerenew, #21). It claims no address and binds no
	// port, so the server itself is untouched.
	SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error)
	// Squat holds addr on the segment from netns labc-squat, a macvlan
	// child of eth1 with its own MAC: it answers ARP for addr, ignores
	// ping, and with announce sends three gratuitous ARPs (C6, C6b, #23).
	Squat(ctx context.Context, addr string, announce bool) (stop func(ctx context.Context) error, err error)
	// StartRogue runs a second DHCP server, dnsmasq with server id
	// serverAddr and pool first-last, in netns labc-rogue (C7, #23).
	StartRogue(ctx context.Context, serverAddr, first, last string) (stop func(ctx context.Context) error, err error)
	// RogueLeases reads the running rogue's own lease file.
	RogueLeases(ctx context.Context) ([]Lease, error)
	// NarrowPool sets the main pool to first-last and restarts (C8, #23).
	NarrowPool(ctx context.Context, first, last string) (restore func(ctx context.Context) error, err error)
	// Renumber moves the source to subnet: eth1 carries addr alone and a
	// minimal config serves first-last with addr as router at the
	// current lease time; restore puts eth1's addresses and the config
	// back byte for byte and restarts (C9, #23).
	Renumber(ctx context.Context, subnet, addr, first, last string) (restore func(ctx context.Context) error, err error)
}

// Runner executes one command on the source VM's own management
// connection and returns its stdout. SSHRunner is the real
// implementation; tests supply a fake so the adapters are unit-testable
// with no network at all.
type Runner interface {
	Run(ctx context.Context, remoteCmd string) (string, error)
}

// validateMAC and validateAddr are the injection guard issue #2 asks for:
// ReserveMAC's arguments reach a remote shell/JSON command only after
// they round-trip through Go's own MAC/IP parsers, which accept nothing
// but a MAC or an IPv4 literal -- no quote, brace or shell metacharacter
// can survive that round trip, so the value that reaches the command
// line was never attacker-controlled text, it is stdlib's own
// normalized form of a real MAC or address (issue #2).
func validateMAC(mac string) (string, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return "", fmt.Errorf("invalid MAC %q: %w", mac, err)
	}
	return hw.String(), nil
}

var clientIDRE = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})*$`)

// validateClientID is validateMAC's counterpart for option 61 values:
// only colon-hex survives, lower-cased, so nothing else reaches a remote
// shell or JSON string (B2, #23).
func validateClientID(id string) (string, error) {
	if !clientIDRE.MatchString(id) {
		return "", fmt.Errorf("invalid client id %q: want colon-separated hex bytes", id)
	}
	return strings.ToLower(id), nil
}

func validateAddr(addr string) (string, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if !a.Is4() {
		return "", fmt.Errorf("address %q is not IPv4", addr)
	}
	return a.String(), nil
}

// reachable pings addr from the source VM, which already sits on the
// cell's own segment beside every shape's containers -- the practical
// stand-in for "the observer can reach the container" (issue #3): the
// repo's packet-capture observer is passive-only and cannot probe
// anything itself. addr round-trips
// through validateAddr first, so it is stdlib's own normalized form
// before it ever reaches the command line.
func reachable(ctx context.Context, r Runner, addr string) error {
	ping := "ping -c1 -W2 "
	ip, err := validateAddr(addr)
	if err != nil {
		if ip, err = validateAddr6(addr); err != nil {
			return err
		}
		ping = "ping -6 -c1 -W2 "
	}
	if _, err := r.Run(ctx, ping+ip); err != nil {
		return fmt.Errorf("ping %s: %w", ip, err)
	}
	return nil
}

// writeRemoteConfig overwrites path on r with content via a single
// heredoc, the same one-command idiom internal/scenario's own
// writeRemoteFile already uses -- no shell metacharacter in content is
// ever interpreted, since content here is always a config file just
// read back from this same host, never caller-supplied text.
func writeRemoteConfig(ctx context.Context, r Runner, path, content string) error {
	cmd := fmt.Sprintf("sudo tee %s >/dev/null <<'LABEOF'\n%sLABEOF\n", path, content)
	_, err := r.Run(ctx, cmd)
	return err
}

// shortenLeaseTimeViaSubstitution is every adapter's ShortenLeaseTime
// body (issue #3, A14): capture the source's own currently RUNNING
// config, apply re/repl once, write it back and restart, and hand the
// caller a restore closure that puts the exact bytes it captured back
// and restarts again -- so a reservation ReserveMAC already made before
// this call survives the round trip untouched, and a re-run never drifts
// further from the running config than one lease-time field.
func shortenLeaseTimeViaSubstitution(ctx context.Context, r Runner, path string, re *regexp.Regexp, repl string, restart func(context.Context) error, label string) (func(context.Context) error, error) {
	orig, err := r.Run(ctx, "sudo cat "+path)
	if err != nil {
		return nil, fmt.Errorf("%s: read %s before shortening lease time: %w", label, path, err)
	}
	short := re.ReplaceAllString(orig, repl)
	if short == orig {
		return nil, fmt.Errorf("%s: lease-time pattern not found in the running config at %s; refusing to shorten blindly", label, path)
	}
	if err := writeRemoteConfig(ctx, r, path, short); err != nil {
		return nil, fmt.Errorf("%s: write shortened lease time to %s: %w", label, path, err)
	}
	if err := restart(ctx); err != nil {
		return nil, fmt.Errorf("%s: restart after shortening lease time: %w", label, err)
	}
	restore := func(ctx context.Context) error {
		if err := writeRemoteConfig(ctx, r, path, orig); err != nil {
			return fmt.Errorf("%s: restore original config to %s: %w", label, path, err)
		}
		return restart(ctx)
	}
	return restore, nil
}

// resetLeasesViaTruncate stops the service, truncates leaseFile, removes
// every other file the source reloads at start (Kea's LFC copies), and
// starts the service again, in one chained command (issue #3 part 2;
// C4 defeat 2, #23). truncate creates a missing file, rm -f ignores one.
func resetLeasesViaTruncate(ctx context.Context, r Runner, leaseFile string, reloaded []string, svc service, label string) error {
	rm := ""
	if len(reloaded) > 0 {
		rm = " && sudo rm -f -- " + strings.Join(reloaded, " ")
	}
	cmd := svc.stop + " && sudo truncate -s 0 " + leaseFile + rm + " && " + svc.start
	if _, err := r.Run(ctx, cmd); err != nil {
		return fmt.Errorf("%s: reset leases (stop %s, clear %s, start %s): %w", label, svc.name, leaseFile, svc.name, err)
	}
	return nil
}

// setDNSOptionViaSubstitution is every adapter's SetDNSOption body (B6,
// #23): the same capture, rewrite, restart and byte-exact restore as
// shortenLeaseTimeViaSubstitution, for a pattern that must match once
// and a config that must not already carry a DNS option.
func setDNSOptionViaSubstitution(ctx context.Context, r Runner, path string, re *regexp.Regexp, repl, already string, restart func(context.Context) error, label string) (func(context.Context) error, error) {
	orig, err := r.Run(ctx, "sudo cat "+path)
	if err != nil {
		return nil, fmt.Errorf("%s: read %s before setting the DNS option: %w", label, path, err)
	}
	if strings.Contains(orig, already) {
		return nil, fmt.Errorf("%s: %s already carries a DNS option (%q); refusing to add a second one", label, path, already)
	}
	changed := re.ReplaceAllString(orig, repl)
	if changed == orig {
		return nil, fmt.Errorf("%s: DNS-option anchor not found in the running config at %s; refusing to change it blindly", label, path)
	}
	if err := writeRemoteConfig(ctx, r, path, changed); err != nil {
		return nil, fmt.Errorf("%s: write DNS option to %s: %w", label, path, err)
	}
	if err := restart(ctx); err != nil {
		return nil, fmt.Errorf("%s: restart after setting the DNS option: %w", label, err)
	}
	restore := func(ctx context.Context) error {
		if err := writeRemoteConfig(ctx, r, path, orig); err != nil {
			return fmt.Errorf("%s: restore original config to %s: %w", label, path, err)
		}
		return restart(ctx)
	}
	return restore, nil
}

// The group C actors live in network namespaces named labc-*, each on a
// macvlan child of eth1 with a kernel-chosen MAC; Ready and Recover find
// leftovers by that prefix (readiness.go, #23).
const (
	squatNetns     = "labc-squat"
	squatLink      = "labc-sq0"
	probeNetns     = "labc-probe"
	probeLink      = "labc-pr0"
	rogueNetns     = "labc-rogue"
	rogueLink      = "labc-rg0"
	rogueLeaseFile = "/run/labc-rogue.leases"
	rogueLogFile   = "/run/labc-rogue.log"
	roguePIDFile   = "/run/labc-rogue.pid"
)

func (h host) segAddrCmd() string { return "ip -4 -o addr show dev " + h.nic + " | awk '{print $4}'" }

// segmentAddrs reads every IPv4 prefix on eth1, each parsed, so nothing
// read back from the source reaches a later command unchecked.
func (h host) segmentAddrs(ctx context.Context, r Runner) ([]netip.Prefix, error) {
	out, err := r.Run(ctx, h.segAddrCmd())
	if err != nil {
		return nil, fmt.Errorf("read %s addresses: %w", h.nic, err)
	}
	var ps []netip.Prefix
	for _, f := range strings.Fields(out) {
		p, err := netip.ParsePrefix(f)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("%s carries %q, not an IPv4 prefix", h.nic, f)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// segmentPrefix is eth1's one address; an actor joins only a segment
// the source holds exactly one address on.
func (h host) segmentPrefix(ctx context.Context, r Runner) (netip.Prefix, error) {
	ps, err := h.segmentAddrs(ctx, r)
	if err != nil {
		return netip.Prefix{}, err
	}
	if len(ps) != 1 {
		return netip.Prefix{}, fmt.Errorf("%s carries %d IPv4 addresses, want 1", h.nic, len(ps))
	}
	return ps[0], nil
}

// onSegment refuses an address outside the source's segment subnet or
// equal to the source's own address.
func onSegment(seg netip.Prefix, addrs ...string) error {
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", a, err)
		}
		if !seg.Masked().Contains(ip) {
			return fmt.Errorf("%s is outside the segment %s", ip, seg.Masked())
		}
		if ip == seg.Addr() {
			return fmt.Errorf("%s is the source's own segment address", ip)
		}
	}
	return nil
}

// setSegmentAddrs replaces eth1's IPv4 addresses with want and reads
// them back; "brd +" sets the broadcast the subnet implies.
func (h host) setSegmentAddrs(ctx context.Context, r Runner, want []netip.Prefix) error {
	cmd := "sudo ip -4 addr flush dev " + h.nic
	for _, p := range want {
		cmd += fmt.Sprintf(" && sudo ip addr add %s brd + dev %s", p, h.nic)
	}
	if _, err := r.Run(ctx, cmd); err != nil {
		return fmt.Errorf("set %s addresses to %v: %w", h.nic, want, err)
	}
	got, err := h.segmentAddrs(ctx, r)
	if err != nil {
		return err
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Errorf("%s carries %v after the change, want %v", h.nic, got, want)
	}
	return nil
}

// netnsUpCmd makes netns ns with a macvlan child link of eth1, IPv6 off
// on it (no router solicitations from the actor), cidr on it if given.
func (h host) netnsUpCmd(ns, link, cidr string, ignorePing bool) string {
	cmd := fmt.Sprintf("sudo ip netns add %[1]s && sudo ip link add %[2]s link %[3]s type macvlan mode bridge && sudo ip link set %[2]s netns %[1]s && "+
		"{ sudo ip netns exec %[1]s sysctl -qw net.ipv6.conf.%[2]s.disable_ipv6=1 2>/dev/null || true; }", ns, link, h.nic)
	if ignorePing {
		cmd += fmt.Sprintf(" && sudo ip netns exec %s sysctl -qw net.ipv4.icmp_echo_ignore_all=1", ns)
	}
	if cidr != "" {
		cmd += fmt.Sprintf(" && sudo ip netns exec %s ip addr add %s dev %s", ns, cidr, link)
	}
	return cmd + fmt.Sprintf(" && sudo ip netns exec %s ip link set %s up", ns, link)
}

// netnsDownCmd kills every process in ns before deleting it: a deleted
// netns lives on, link and all, while a process still runs in it
// (ip-netns(8)). It exits nonzero if ns is still listed.
func netnsDownCmd(ns, link string) string {
	return fmt.Sprintf(`if ip netns list | awk '$1 == "%[1]s" {f=1} END {exit !f}'; then `+
		`for i in 1 2 3 4 5 6; do p=$(sudo ip netns pids %[1]s); [ -z "$p" ] && break; sudo kill $p; sleep 0.5; done; `+
		`p=$(sudo ip netns pids %[1]s); [ -z "$p" ] || sudo kill -9 $p; sudo ip netns del %[1]s; fi; `+
		`sudo ip link del %[2]s 2>/dev/null; ip netns list | awk '$1 == "%[1]s" {f=1} END {exit f}'`, ns, link)
}

func actorStop(r Runner, ns, link, label string) func(context.Context) error {
	return func(ctx context.Context) error {
		if _, err := r.Run(ctx, netnsDownCmd(ns, link)); err != nil {
			return fmt.Errorf("%s: remove %s: %w", label, ns, err)
		}
		return nil
	}
}

// squat is every adapter's Squat body (C6, C6b, #23).
func (h host) squat(ctx context.Context, r Runner, addr string, announce bool) (func(context.Context) error, error) {
	if err := h.needPortable("squatter"); err != nil {
		return nil, err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	seg, err := h.segmentPrefix(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("squatter: %w", err)
	}
	if err := onSegment(seg, ip); err != nil {
		return nil, fmt.Errorf("squatter: %w", err)
	}
	stop := actorStop(r, squatNetns, squatLink, "squatter")
	undo := func(err error) (func(context.Context) error, error) {
		return nil, errors.Join(err, stop(context.WithoutCancel(ctx)))
	}
	cidr := fmt.Sprintf("%s/%d", ip, seg.Bits())
	if _, err := r.Run(ctx, h.netnsUpCmd(squatNetns, squatLink, cidr, true)); err != nil {
		return undo(fmt.Errorf("squatter: set up %s with %s: %w", squatNetns, cidr, err))
	}
	if err := h.probeSquatter(ctx, r, ip); err != nil {
		return undo(err)
	}
	if announce {
		if _, err := r.Run(ctx, fmt.Sprintf("sudo ip netns exec %s arping -q -U -c 3 -I %s %s", squatNetns, squatLink, ip)); err != nil {
			return undo(fmt.Errorf("squatter: gratuitous ARP for %s: %w", ip, err))
		}
	}
	return stop, nil
}

var arpReplyMACRE = regexp.MustCompile(`\[([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\]`)

// probeSquatter checks the squatter from a second macvlan child: an
// RFC 5227 probe (arping -D, sender 0.0.0.0, the plugin's conflict
// check) for ip is answered by the squatter's MAC, and ping is off in
// its netns, so the server's own ping check cannot do the plugin's job.
func (h host) probeSquatter(ctx context.Context, r Runner, ip string) error {
	defer func() { _, _ = r.Run(context.WithoutCancel(ctx), netnsDownCmd(probeNetns, probeLink)) }()
	if _, err := r.Run(ctx, h.netnsUpCmd(probeNetns, probeLink, "", false)); err != nil {
		return fmt.Errorf("squatter probe: set up %s: %w", probeNetns, err)
	}
	out, err := r.Run(ctx, fmt.Sprintf(`printf 'arp:'; sudo ip netns exec %[1]s arping -D -c 2 -w 3 -I %[2]s %[3]s 2>&1 | tr '\n' ' '; echo; `+
		`printf 'mac:'; sudo ip netns exec %[4]s cat /sys/class/net/%[5]s/address; `+
		`printf 'icmp:'; sudo ip netns exec %[4]s sysctl -n net.ipv4.icmp_echo_ignore_all`, probeNetns, probeLink, ip, squatNetns, squatLink))
	if err != nil {
		return fmt.Errorf("squatter probe: %w", err)
	}
	return judgeSquatProbe(out, ip)
}

func judgeSquatProbe(out, ip string) error {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && (k == "arp" || k == "mac" || k == "icmp") {
			kv[k] = strings.TrimSpace(v)
		}
	}
	mac, err := net.ParseMAC(kv["mac"])
	if err != nil {
		return fmt.Errorf("squatter probe: unreadable squatter MAC %q", kv["mac"])
	}
	m := arpReplyMACRE.FindStringSubmatch(kv["arp"])
	if m == nil {
		return fmt.Errorf("squatter probe: no ARP reply for %s to a probe: %q", ip, kv["arp"])
	}
	if !strings.EqualFold(m[1], mac.String()) {
		return fmt.Errorf("squatter probe: %s answered by %s, not the squatter's %s", ip, m[1], mac)
	}
	if kv["icmp"] != "1" {
		return fmt.Errorf("squatter probe: icmp_echo_ignore_all is %q in %s, want 1", kv["icmp"], squatNetns)
	}
	return nil
}

// startRogue is every adapter's StartRogue body (C7, #23): dnsmasq in
// labc-rogue, DNS off (--port=0), no config file (/etc/dnsmasq.conf is
// the real server's on the dnsmasq source), no ping before an offer,
// not authoritative, so it never NAKs the real server's clients, and
// its own lease file read by RogueLeases.
func (h host) startRogue(ctx context.Context, r Runner, serverAddr, first, last string) (func(context.Context) error, error) {
	if err := h.needPortable("rogue"); err != nil {
		return nil, err
	}
	var ips [3]string
	for i, a := range []string{serverAddr, first, last} {
		ip, err := validateAddr(a)
		if err != nil {
			return nil, err
		}
		ips[i] = ip
	}
	srv, f, l := netip.MustParseAddr(ips[0]), netip.MustParseAddr(ips[1]), netip.MustParseAddr(ips[2])
	if f.Compare(l) > 0 {
		return nil, fmt.Errorf("rogue: pool %s - %s is backwards", f, l)
	}
	if srv.Compare(f) >= 0 && srv.Compare(l) <= 0 {
		return nil, fmt.Errorf("rogue: server address %s lies inside its own pool %s - %s", srv, f, l)
	}
	seg, err := h.segmentPrefix(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("rogue: %w", err)
	}
	if err := onSegment(seg, ips[:]...); err != nil {
		return nil, fmt.Errorf("rogue: %w", err)
	}
	stop := actorStop(r, rogueNetns, rogueLink, "rogue")
	undo := func(err error) (func(context.Context) error, error) {
		return nil, errors.Join(err, stop(context.WithoutCancel(ctx)))
	}
	cidr := fmt.Sprintf("%s/%d", srv, seg.Bits())
	if _, err := r.Run(ctx, h.netnsUpCmd(rogueNetns, rogueLink, cidr, false)); err != nil {
		return undo(fmt.Errorf("rogue: set up %s with %s: %w", rogueNetns, cidr, err))
	}
	run := fmt.Sprintf("sudo rm -f %[2]s %[3]s %[4]s && sudo ip netns exec %[1]s dnsmasq --conf-file=/dev/null --port=0 --no-resolv --no-hosts "+
		"--interface=%[5]s --bind-interfaces --no-ping --dhcp-range=%[6]s,%[7]s,2m --dhcp-leasefile=%[2]s --pid-file=%[4]s "+
		"--log-dhcp --log-facility=%[3]s --user=root && sleep 1 && sudo ip netns pids %[1]s | grep -q .",
		rogueNetns, rogueLeaseFile, rogueLogFile, roguePIDFile, rogueLink, f, l)
	if _, err := r.Run(ctx, run); err != nil {
		return undo(fmt.Errorf("rogue: dnsmasq in %s not running: %w", rogueNetns, err))
	}
	return stop, nil
}

func (h host) rogueLeases(ctx context.Context, r Runner) ([]Lease, error) {
	if err := h.needPortable("rogue"); err != nil {
		return nil, err
	}
	out, err := r.Run(ctx, "sudo cat "+rogueLeaseFile)
	if err != nil {
		return nil, fmt.Errorf("rogue: read %s: %w", rogueLeaseFile, err)
	}
	return parseDnsmasqLeases(out)
}

// renumberPlan is a validated Renumber target.
type renumberPlan struct {
	subnet            netip.Prefix
	addr, first, last netip.Addr
}

func (p renumberPlan) netmask() string {
	return net.IP(net.CIDRMask(p.subnet.Bits(), 32)).String()
}

func validateRenumber(subnet, addr, first, last string) (renumberPlan, error) {
	var p renumberPlan
	s, err := netip.ParsePrefix(subnet)
	if err != nil || !s.Addr().Is4() || s != s.Masked() {
		return p, fmt.Errorf("renumber: %q is not an IPv4 network prefix", subnet)
	}
	p.subnet = s
	for i, a := range []string{addr, first, last} {
		ip, err := validateAddr(a)
		if err != nil {
			return p, err
		}
		x := netip.MustParseAddr(ip)
		if !s.Contains(x) || x == s.Addr() {
			return p, fmt.Errorf("renumber: %s is not a host address in %s", x, s)
		}
		*[]*netip.Addr{&p.addr, &p.first, &p.last}[i] = x
	}
	if p.first.Compare(p.last) > 0 {
		return p, fmt.Errorf("renumber: pool %s - %s is backwards", p.first, p.last)
	}
	if p.addr.Compare(p.first) >= 0 && p.addr.Compare(p.last) <= 0 {
		return p, fmt.Errorf("renumber: source address %s lies inside the pool %s - %s", p.addr, p.first, p.last)
	}
	return p, nil
}

// renumberVia is every adapter's Renumber body (C9, #23): eth1 moves
// first, so a server that needs a subnet matching its interface (ISC)
// starts on the new config; restore moves the addresses back, then the
// config, then restarts.
func (h host) renumberVia(ctx context.Context, r Runner, path string, plan renumberPlan, render func(orig string, p renumberPlan) (string, error), restart func(context.Context) error, label string) (func(context.Context) error, error) {
	addrs, err := h.segmentAddrs(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s: %s carries no IPv4 address to restore later", label, h.nic)
	}
	orig, err := r.Run(ctx, "sudo cat "+path)
	if err != nil {
		return nil, fmt.Errorf("%s: read %s before renumbering: %w", label, path, err)
	}
	if !strings.HasSuffix(orig, "\n") {
		return nil, fmt.Errorf("%s: %s does not end in a newline, cannot write it back byte for byte", label, path)
	}
	next, err := render(orig, plan)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	restore := func(ctx context.Context) error {
		aerr := h.setSegmentAddrs(ctx, r, addrs)
		werr := writeRemoteConfig(ctx, r, path, orig)
		if werr != nil {
			werr = fmt.Errorf("restore original config to %s: %w", path, werr)
		}
		rerr := restart(ctx)
		if err := errors.Join(aerr, werr, rerr); err != nil {
			return fmt.Errorf("%s: renumber restore: %w", label, err)
		}
		return nil
	}
	undo := func(err error) (func(context.Context) error, error) {
		return nil, errors.Join(err, restore(context.WithoutCancel(ctx)))
	}
	if err := h.setSegmentAddrs(ctx, r, []netip.Prefix{netip.PrefixFrom(plan.addr, plan.subnet.Bits())}); err != nil {
		return undo(fmt.Errorf("%s: %w", label, err))
	}
	if err := writeRemoteConfig(ctx, r, path, next); err != nil {
		return undo(fmt.Errorf("%s: write renumbered config to %s: %w", label, path, err))
	}
	if err := restart(ctx); err != nil {
		return undo(fmt.Errorf("%s: restart on the renumbered config: %w", label, err))
	}
	return restore, nil
}

// onlyMatch returns re's one match in s, refusing none or several.
func onlyMatch(re *regexp.Regexp, s, what string) (string, error) {
	m := re.FindAllString(s, -1)
	if len(m) != 1 {
		return "", fmt.Errorf("found %d %s in the running config, want 1", len(m), what)
	}
	return m[0], nil
}
