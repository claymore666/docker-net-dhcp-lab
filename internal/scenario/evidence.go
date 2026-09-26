package scenario

import (
	"context"
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
		fmt.Fprintf(&b, "%s %s %s\n", l.MAC, l.Address, l.Hostname)
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

// lookupLease snapshots the source's table to path, then resolves the
// container's lease by the matching rule for shape: MAC+address for
// bridge/macvlan, address-only for ipvlan.
func lookupLease(ctx context.Context, a sourceadapter.Adapter, shape Shape, mac, addr, snapshotPath string) (sourceadapter.Lease, []sourceadapter.Lease, bool, error) {
	leases, err := writeLeaseSnapshot(ctx, a, snapshotPath)
	if err != nil {
		return sourceadapter.Lease{}, nil, false, err
	}
	if shape == ShapeIpvlan {
		l, ok := findLeaseByAddr(leases, addr)
		return l, leases, ok, nil
	}
	l, ok := findLease(leases, mac, addr)
	return l, leases, ok, nil
}

func leaseFailReason(shape Shape, mac, addr string) string {
	if shape == ShapeIpvlan {
		return fmt.Sprintf("no lease for address %s in the source's own table", addr)
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
