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
	"strings"
)

// Capability is a source's declared ability. A declared capability is a
// claim until a real run against that source exercises it; see each
// adapter's own comment for what has actually been measured so far.
type Capability string

const (
	CapV4         Capability = "v4"
	CapReserveMAC Capability = "reserve-mac"
	CapRestart    Capability = "restart"
)

// Lease is one entry from a source's own table, normalized across the
// three source shapes (JSON, dhcpd.leases, dnsmasq.leases). ClientID is
// DHCP option 61, normalized to lowercase colon-hex across all three
// (Kea's own "client-id" field, ISC's "uid", dnsmasq's fifth lease-line
// field) -- empty when the row carries none. ipvlan slaves share the
// parent NIC's MAC (docs/reference.md "DHCP identity"), so ClientID is
// the only field that identifies one slave's lease from another's
// (#3).
type Lease struct {
	MAC      string
	Address  string
	Hostname string
	ClientID string
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
	Leases(ctx context.Context) ([]Lease, error)
	ReserveMAC(ctx context.Context, mac, addr string) error
	Restart(ctx context.Context) error
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
	// Reachable reports whether addr answers from the source's own
	// vantage point on the cell's segment (issue #3): A4/A5's PASS bar
	// needs proof the container can still be reached, not only that the
	// source's lease table still lists it.
	Reachable(ctx context.Context, addr string) error
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
