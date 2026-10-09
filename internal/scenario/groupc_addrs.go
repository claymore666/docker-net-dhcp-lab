package scenario

import (
	"fmt"
	"net/netip"
)

// Group C's actors take fixed host octets of the cell's /24 clear of the
// main pool and of every group B and F band (#23 defeat 13): C8's
// narrowed pool .201-.202, C6's reserved squat target .231+shape index,
// C7's rogue server .240 with its pool .241-.250.
const (
	c8FirstHost    = 201
	c8LastHost     = 202
	c6BaseHost     = 231
	rogueHost      = 240
	rogueFirstHost = 241
	rogueLastHost  = 250
	// c9OctetShift is how far C9 moves the third octet of the cell's
	// /24; every lab.yaml cell sits on 10.200.0-7.0/24 (#23).
	c9OctetShift = 100
)

// groupCAddr is groupBAddr that also refuses the user-class pool, the
// group B reservations, the class pool and the DNS address.
func groupCAddr(e Env, host int) (string, error) {
	bands := []struct {
		first, last int
		what        string
	}{
		{userClassFirstHost, userClassLastHost, "the user-class pool"},
		{reserveBaseHost, reserveBaseHost + 2*len(Shapes) - 1, "the group B reservations"},
		{classPoolFirstHost, classPoolLastHost, "the class pool"},
		{dnsOptionHost, dnsOptionHost, "the DNS option address"},
	}
	for _, b := range bands {
		if host >= b.first && host <= b.last {
			return "", fmt.Errorf("host octet %d lies in %s (.%d-.%d)", host, b.what, b.first, b.last)
		}
	}
	return groupBAddr(e, host)
}

// c9Target is C9's new segment: the cell's /24 with its third octet
// moved by c9OctetShift, the source's own host octet and the main
// pool's host octets on it.
func c9Target(e Env) (subnet, addr, first, last string, err error) {
	s, err := netip.ParsePrefix(e.SegSubnet)
	if err != nil || !s.Addr().Is4() || s.Bits() != 24 {
		return "", "", "", "", fmt.Errorf("segment subnet %q is not an IPv4 /24", e.SegSubnet)
	}
	b := s.Masked().Addr().As4()
	if int(b[2])+c9OctetShift > 254 {
		return "", "", "", "", fmt.Errorf("%s moved by %d leaves the third octet's range", s, c9OctetShift)
	}
	b[2] += c9OctetShift
	moved := func(a string) (string, error) {
		ip, err := netip.ParseAddr(a)
		if err != nil || !s.Contains(ip) {
			return "", fmt.Errorf("%q is not an address in %s", a, s)
		}
		x := b
		x[3] = ip.As4()[3]
		return netip.AddrFrom4(x).String(), nil
	}
	if addr, err = moved(e.SourceAddr); err != nil {
		return "", "", "", "", err
	}
	if first, err = moved(e.PoolStart); err != nil {
		return "", "", "", "", err
	}
	if last, err = moved(e.PoolEnd); err != nil {
		return "", "", "", "", err
	}
	return netip.PrefixFrom(netip.AddrFrom4(b), 24).String(), addr, first, last, nil
}

// inMainPool reports whether addr lies in the cell's main pool.
func inMainPool(e Env, addr string) bool {
	a, err1 := netip.ParseAddr(addr)
	s, err2 := netip.ParseAddr(e.PoolStart)
	l, err3 := netip.ParseAddr(e.PoolEnd)
	return err1 == nil && err2 == nil && err3 == nil && a.Compare(s) >= 0 && a.Compare(l) <= 0
}
