package main

import "testing"

// The pre-shape pool capacity check exists because the plugin's own
// default is release_lease=never (docs/reference.md) -- nothing frees
// a lease between shapes on its own, so a run only stays sound if the
// pool the cell's source hands out can actually cover one shape's
// worst case (#3). These two functions are the pure core of that
// check; the rest of cmdRun is the plumbing that calls them and cannot
// run without a real source VM.

func TestPoolCapacityCountsInclusive(t *testing.T) {
	cases := []struct {
		name, start, end string
		want             int
	}{
		{"kea pool", "10.200.1.100", "10.200.1.200", 101},
		{"isc-dhcp pool", "10.200.2.100", "10.200.2.200", 101},
		{"dnsmasq pool", "10.200.3.100", "10.200.3.200", 101},
		{"single address", "10.200.1.100", "10.200.1.100", 1},
		{"crosses a byte boundary", "10.200.1.250", "10.200.2.5", 12},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := poolCapacity(c.start, c.end)
			if err != nil {
				t.Fatalf("poolCapacity(%q, %q): %v", c.start, c.end, err)
			}
			if got != c.want {
				t.Fatalf("poolCapacity(%q, %q) = %d, want %d", c.start, c.end, got, c.want)
			}
		})
	}
}

func TestPoolCapacityRejectsBadInput(t *testing.T) {
	cases := []struct {
		name, start, end string
	}{
		{"not an address", "not-an-ip", "10.200.1.200"},
		{"end before start", "10.200.1.200", "10.200.1.100"},
		{"ipv6", "fe80::1", "fe80::2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := poolCapacity(c.start, c.end); err == nil {
				t.Fatalf("poolCapacity(%q, %q): want an error, got none", c.start, c.end)
			}
		})
	}
}

// TestPoolHasCapacityForMatchesMinPoolAddresses pins the check against
// scenario.MinPoolAddresses's own value (38, catalog.go) rather than a
// number restated here: a pool exhausted by four prior shapes' worth of
// held leases must abort the fifth, and a fresh 101-address pool must
// clear every shape (five shapes x 38 is exactly the case that
// exhausted the pool on A15/A16 before this fix, #3).
func TestPoolHasCapacityForMatchesMinPoolAddresses(t *testing.T) {
	const need = 38 // scenario.MinPoolAddresses

	if ok, reason := poolHasCapacityFor(101, 0, need); !ok {
		t.Fatalf("a fresh 101-address pool must cover one shape's run: %s", reason)
	}
	if ok, _ := poolHasCapacityFor(101, 4*need, need); ok {
		t.Fatalf("a pool already holding four shapes' worth of leases must not clear a fifth")
	}
	if ok, _ := poolHasCapacityFor(101, 101-need+1, need); ok {
		t.Fatalf("one address short of the requirement must not pass")
	}
	if ok, reason := poolHasCapacityFor(101, 101-need, need); !ok {
		t.Fatalf("exactly enough free addresses must pass: %s", reason)
	}
}

func TestPoolHasCapacityForReasonNamesTheShortfall(t *testing.T) {
	ok, reason := poolHasCapacityFor(101, 70, 38)
	if ok {
		t.Fatalf("101 capacity, 70 held, need 38: want insufficient, got ok")
	}
	if reason == "" {
		t.Fatal("want a non-empty reason describing the shortfall")
	}
}
