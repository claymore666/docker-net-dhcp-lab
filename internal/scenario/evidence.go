package scenario

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// writeLeaseSnapshot reads the source's own table and writes it to a
// plain text file, always at least the header line even when the table
// is empty: Write's non-empty-evidence rule (issue #3 defeat list) must
// never be satisfied by a file that only looks non-empty by accident.
func writeLeaseSnapshot(ctx context.Context, a sourceadapter.Adapter, path string) ([]sourceadapter.Lease, error) {
	leases, err := a.Leases(ctx)
	if err != nil {
		return nil, fmt.Errorf("leases: %w", err)
	}
	sorted := make([]sourceadapter.Lease, len(leases))
	copy(sorted, leases)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Address < sorted[j].Address })

	var b strings.Builder
	fmt.Fprintf(&b, "# lease snapshot, %s, %d entries\n", time.Now().UTC().Format(time.RFC3339), len(sorted))
	for _, l := range sorted {
		fmt.Fprintf(&b, "%s %s %s %s\n", l.MAC, l.Address, l.Hostname, l.ClientID)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return nil, fmt.Errorf("write snapshot %s: %w", path, err)
	}
	return leases, nil
}

// findLease matches a lease row by MAC and address together. Correct for
// bridge and macvlan, where each container gets its own MAC; never used
// for ipvlan, whose slaves share the parent's MAC (issue #3 defeat list).
func findLease(leases []sourceadapter.Lease, mac, addr string) (sourceadapter.Lease, bool) {
	mac = strings.ToLower(mac)
	for _, l := range leases {
		if strings.ToLower(l.MAC) == mac && l.Address == addr {
			return l, true
		}
	}
	return sourceadapter.Lease{}, false
}

// findLeaseByAddr matches by leased address alone. Required for ipvlan
// (every slave shares the parent NIC's MAC, so a MAC match would
// attribute one container's lease to another -- issue #3 defeat list);
// also usable wherever only the address survived an event (e.g. a
// restart that keeps the address but not necessarily the same reported
// MAC on the source's side).
func findLeaseByAddr(leases []sourceadapter.Lease, addr string) (sourceadapter.Lease, bool) {
	for _, l := range leases {
		if l.Address == addr {
			return l, true
		}
	}
	return sourceadapter.Lease{}, false
}

// findLeaseByClientID matches by DHCP client-id (option 61) alone: the
// only field that survives ipvlan's shared parent MAC (issue #3, lead
// directive 2026-09-26, item 3). Comparison is case-insensitive; both
// sides are already lowercase colon-hex by construction, but a raw
// source field is not guaranteed to be.
func findLeaseByClientID(leases []sourceadapter.Lease, clientID string) (sourceadapter.Lease, bool) {
	want := strings.ToLower(clientID)
	for _, l := range leases {
		if l.ClientID != "" && strings.ToLower(l.ClientID) == want {
			return l, true
		}
	}
	return sourceadapter.Lease{}, false
}

// ipvlanClientID derives the DHCP client-id (option 61) the plugin
// documents for ipvlan mode: type byte 0x00 followed by the first 8
// bytes of the Docker endpoint id, lowercase colon-hex (issue #3, lead
// directive 2026-09-26, item 3; docs/parent-attached-modes.md). Measured
// live against a Kea lease: endpoint id
// 97ce0dfd016fae55148e376d84988fc42e5f0690900ec178ca415a056ac6236a
// produced client-id 00:97:ce:0d:fd:01:6f:ae:55.
func ipvlanClientID(endpointID string) (string, error) {
	const wantBytes = 8
	if len(endpointID) < wantBytes*2 {
		return "", fmt.Errorf("endpoint id %q is shorter than the %d bytes the client-id needs", endpointID, wantBytes)
	}
	raw, err := hex.DecodeString(endpointID[:wantBytes*2])
	if err != nil {
		return "", fmt.Errorf("endpoint id %q is not hex: %w", endpointID, err)
	}
	return hexColonID(append([]byte{0x00}, raw...)), nil
}

func hexColonID(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

// lookupLease snapshots the source's table to path, then resolves the
// container's lease by the matching rule for shape: MAC+address for
// bridge/macvlan, client-id for ipvlan (issue #3, lead directive
// 2026-09-26, item 3) -- an address-only match let one ipvlan
// container's verdict silently read another's lease when both held the
// same address at different times within one snapshot's staleness
// window; client-id does not have that collision.
func lookupLease(ctx context.Context, a sourceadapter.Adapter, shape Shape, mac, addr, endpointID, snapshotPath string) (sourceadapter.Lease, []sourceadapter.Lease, bool, error) {
	leases, err := writeLeaseSnapshot(ctx, a, snapshotPath)
	if err != nil {
		return sourceadapter.Lease{}, nil, false, err
	}
	if shape == ShapeIpvlan {
		clientID, err := ipvlanClientID(endpointID)
		if err != nil {
			return sourceadapter.Lease{}, leases, false, err
		}
		l, ok := findLeaseByClientID(leases, clientID)
		return l, leases, ok, nil
	}
	l, ok := findLease(leases, mac, addr)
	return l, leases, ok, nil
}

// reachabilityWindow bounds reachableWithRetry: a single ping taken
// right after a lease is confirmed can race the container's network
// attach (project note: Join returns before the attach lands). The lead
// set this window as a definition, not a value tuned to any one result
// (lab lead, 2026-09-26); a dig at 98b3478 measured 0.7s to first reply
// on a clean isc-dhcp/bridge host reboot, well inside it.
const reachabilityWindow = 10 * time.Second

// reachableWithRetry pings addr through the source once per second,
// starting as soon as the caller has a confirmed lease, until the first
// reply or reachabilityWindow elapses. It always returns the whole
// seconds elapsed, on success or on timeout, so every verdict this
// backs records how long the check took either way (lab lead,
// 2026-09-26).
func reachableWithRetry(ctx context.Context, a sourceadapter.Adapter, addr string) (int, error) {
	start := time.Now()
	var lastErr error
	for {
		if lastErr = a.Reachable(ctx, addr); lastErr == nil {
			return int(time.Since(start).Round(time.Second) / time.Second), nil
		}
		if time.Since(start) >= reachabilityWindow {
			return int(reachabilityWindow / time.Second), lastErr
		}
		select {
		case <-ctx.Done():
			return int(time.Since(start).Round(time.Second) / time.Second), ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func leaseFailReason(shape Shape, mac, addr, endpointID string) string {
	if shape == ShapeIpvlan {
		clientID, err := ipvlanClientID(endpointID)
		if err != nil {
			return fmt.Sprintf("could not derive the ipvlan client-id from endpoint id %s: %v", endpointID, err)
		}
		return fmt.Sprintf("no lease for client-id %s (address %s) in the source's own table", clientID, addr)
	}
	return fmt.Sprintf("no lease for mac %s address %s in the source's own table", mac, addr)
}

func pass(scenario, cell string, shape Shape, reason string, evidence map[string]string, gitSHA string) Verdict {
	return Verdict{
		Scenario: scenario, Cell: cell, Shape: shape,
		Result: PASS, Reason: reason, Evidence: evidence,
		GitSHA: gitSHA, Timestamp: time.Now(),
	}
}

func fail(scenario, cell string, shape Shape, reason string, evidence map[string]string, gitSHA string) Verdict {
	return Verdict{
		Scenario: scenario, Cell: cell, Shape: shape,
		Result: FAIL, Reason: reason, Evidence: evidence,
		GitSHA: gitSHA, Timestamp: time.Now(),
	}
}

func na(scenario, cell string, shape Shape, reason, gitSHA string) Verdict {
	return Verdict{
		Scenario: scenario, Cell: cell, Shape: shape,
		Result: NA, Reason: reason, Evidence: nil,
		GitSHA: gitSHA, Timestamp: time.Now(),
	}
}

// blocked marks a scenario that never reached a known plugin state
// (issue #3, lead directive 2026-09-26): the precondition check itself
// failed, or a previous scenario's failure could not be restored, so
// this scenario never ran and carries no evidence, the same discipline
// na already applies.
func blocked(scenario, cell string, shape Shape, reason, gitSHA string) Verdict {
	return Verdict{
		Scenario: scenario, Cell: cell, Shape: shape,
		Result: BLOCKED, Reason: reason, Evidence: nil,
		GitSHA: gitSHA, Timestamp: time.Now(),
	}
}
