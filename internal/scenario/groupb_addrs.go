package scenario

import (
	"fmt"
	"net/netip"
)

// Group B picks every address it reserves, serves from a class pool or
// advertises as DNS from fixed host octets of the cell's /24, all above
// the main pool (.100-.200 in lab.yaml, .80-.200 on the two failover pairs) so the source can
// never hand one to another client first (#23). classPoolFirstHost and
// classPoolLastHost must equal class_first_host and class_last_host in
// scripts/up-source.sh, which bakes the class pool into the source VM;
// TestClassPoolBandMatchesUpSource reads them out of that script.
const (
	reserveBaseHost    = 211 // B1 takes 211+shape index, B2 216+shape index
	classPoolFirstHost = 221
	classPoolLastHost  = 230
	dnsOptionHost      = 253
	// Group F's user-class pool (user class, #20) is added to the source at run
	// time, not baked in; it sits below the reservations and clear of the
	// main pool and the class pool.
	userClassFirstHost = 203
	userClassLastHost  = 210
)

// shapeIndex is the shape's position in Shapes, so two shapes of one
// cell never reserve the same address on the one persistent source.
func shapeIndex(shape Shape) (int, error) {
	for i, s := range Shapes {
		if s == shape {
			return i, nil
		}
	}
	return 0, fmt.Errorf("unknown shape %q", shape)
}

// groupBAddr returns host octet host of the cell's segment, refusing any
// address the source could hand out of the main pool or already owns.
func groupBAddr(e Env, host int) (string, error) {
	subnet, err := netip.ParsePrefix(e.SegSubnet)
	if err != nil {
		return "", fmt.Errorf("segment subnet %q: %w", e.SegSubnet, err)
	}
	if !subnet.Addr().Is4() || subnet.Bits() != 24 {
		return "", fmt.Errorf("segment subnet %s is not an IPv4 /24", subnet)
	}
	if host < 1 || host > 254 {
		return "", fmt.Errorf("host octet %d is outside 1..254", host)
	}
	b := subnet.Masked().Addr().As4()
	b[3] = byte(host)
	addr := netip.AddrFrom4(b)
	start, err := netip.ParseAddr(e.PoolStart)
	if err != nil {
		return "", fmt.Errorf("pool start %q: %w", e.PoolStart, err)
	}
	end, err := netip.ParseAddr(e.PoolEnd)
	if err != nil {
		return "", fmt.Errorf("pool end %q: %w", e.PoolEnd, err)
	}
	if addr.Compare(start) >= 0 && addr.Compare(end) <= 0 {
		return "", fmt.Errorf("%s lies inside the main pool %s-%s, where the source may hand it to any client", addr, start, end)
	}
	if addr.String() == e.SegGateway {
		return "", fmt.Errorf("%s is the segment gateway address", addr)
	}
	return addr.String(), nil
}

// reservationAddr is the address B1 or B2 reserves for this shape.
func reservationAddr(e Env, scenario string) (string, error) {
	i, err := shapeIndex(e.Shape)
	if err != nil {
		return "", err
	}
	switch scenario {
	case NameB1:
		return groupBAddr(e, reserveBaseHost+i)
	case NameB2:
		return groupBAddr(e, reserveBaseHost+len(Shapes)+i)
	}
	return "", fmt.Errorf("%s reserves no address", scenario)
}

// classPool returns the first and last address of B5's class pool.
func classPool(e Env) (first, last netip.Addr, err error) {
	f, err := groupBAddr(e, classPoolFirstHost)
	if err != nil {
		return first, last, err
	}
	l, err := groupBAddr(e, classPoolLastHost)
	if err != nil {
		return first, last, err
	}
	return netip.MustParseAddr(f), netip.MustParseAddr(l), nil
}

// inClassPool reports whether addr is one of B5's class pool addresses.
func inClassPool(e Env, addr string) (bool, error) {
	first, last, err := classPool(e)
	if err != nil {
		return false, err
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false, fmt.Errorf("address %q: %w", addr, err)
	}
	return a.Compare(first) >= 0 && a.Compare(last) <= 0, nil
}

// userClassPool returns the first and last address of the user-class pool.
func userClassPool(e Env) (first, last netip.Addr, err error) {
	f, err := groupBAddr(e, userClassFirstHost)
	if err != nil {
		return first, last, err
	}
	l, err := groupBAddr(e, userClassLastHost)
	if err != nil {
		return first, last, err
	}
	return netip.MustParseAddr(f), netip.MustParseAddr(l), nil
}

// inUserClassPool reports whether addr is one of the user-class pool addresses.
func inUserClassPool(e Env, addr string) (bool, error) {
	first, last, err := userClassPool(e)
	if err != nil {
		return false, err
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false, fmt.Errorf("address %q: %w", addr, err)
	}
	return a.Compare(first) >= 0 && a.Compare(last) <= 0, nil
}
