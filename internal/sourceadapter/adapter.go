// Package sourceadapter is the one interface issue #2 asks for: read
// leases, reserve by MAC, restart, stop, start, capabilities, one
// implementation per IP source, each reading lease evidence through that
// source's own interface (control agent API, leases file, lease file)
// rather than anything the plugin reports.
package sourceadapter

import (
	"context"
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
	// ResetLeases stops the source, truncates its lease file to zero
	// bytes, and starts it again (issue #3 part 2). The plugin's own
	// default is release_lease=never (docs/reference.md), so nothing
	// else ever frees a lease between shapes: five shapes of fresh
	// MACs/client-ids on the one small pool this lab uses run it out
	// unless the runner resets the source before every shape, which is
	// what this is for.
	ResetLeases(ctx context.Context) error
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
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	if _, err := r.Run(ctx, "ping -c1 -W2 "+ip); err != nil {
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

// resetLeasesViaTruncate stops the service, truncates leaseFile to zero
// bytes, and starts the service again, in one chained remote command
// (issue #3 part 2) -- the same single-command idiom ReserveMAC's own
// write-then-restart already uses on each adapter. GNU truncate creates
// a missing file rather than erroring on one (coreutils truncate(1)),
// so this works whether or not the source has ever written the file
// yet. If the truncate or the start fails, the chain stops there and
// the error names which step failed; the caller treats it as an
// infrastructure error, the same as any other failed Restart/Stop/
// Start.
func resetLeasesViaTruncate(ctx context.Context, r Runner, leaseFile, service, label string) error {
	cmd := fmt.Sprintf("sudo systemctl stop %s && sudo truncate -s 0 %s && sudo systemctl start %s", service, leaseFile, service)
	if _, err := r.Run(ctx, cmd); err != nil {
		return fmt.Errorf("%s: reset leases (stop %s, truncate %s, start %s): %w", label, service, leaseFile, service, err)
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
