package scenario

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group D part 2 judges (#23): D3 (ipv6_mode=auto against the RA's M and
// A bits), D4 (two prefixes), prefix delegation and PREF64.
// Every flag and prefix is read from the capture, never from the RAParams
// the row asked for (design defeat 6).

// autoPrefixes is the distinct autonomous prefixes of ras, in wire order (RFC 4861 section 4.6.2).
func autoPrefixes(ras []RAMsg) []netip.Prefix {
	var out []netip.Prefix
	for _, ra := range ras {
		for _, p := range ra.PIOs {
			if p.Auto && !slices.Contains(out, p.Prefix) {
				out = append(out, p.Prefix)
			}
		}
	}
	return out
}

func hasAutoPIO(ra RAMsg) bool {
	for _, p := range ra.PIOs {
		if p.Auto {
			return true
		}
	}
	return false
}

// judgeRAFlags proves the row's M and A bits on the wire: every captured
// RA must carry the managed flag and an autonomous PIO exactly as want
// says. A source that did not advertise them leaves the row BLOCKED (#23, RFC 4861 section 4.2).
func judgeRAFlags(ras []RAMsg, want sourceadapter.RAParams) (fOutcome, bool) {
	if len(ras) == 0 {
		return fBlocked("the capture shows no RA, so the row's M=%v A=%v is not proven on the wire", want.Managed, want.Autonomous), false
	}
	for _, ra := range ras {
		if ra.Managed != want.Managed || hasAutoPIO(ra) != want.Autonomous {
			return fBlocked("an RA from %s at %s carries M=%v and an autonomous PIO %v, the row needs M=%v A=%v; the source did not advertise the row's flags",
				ra.Src, ra.At.Format(time.RFC3339), ra.Managed, hasAutoPIO(ra), want.Managed, want.Autonomous), false
		}
	}
	return fOutcome{Result: PASS, Reason: wireFlags(ras)}, true
}

func wireFlags(ras []RAMsg) string {
	if len(ras) == 0 {
		return "no RA"
	}
	return "M=" + b01(ras[0].Managed) + " A=" + b01(hasAutoPIO(ras[0])) + " in all " + strconv.Itoa(len(ras)) + " RAs"
}

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// judgeD3cAuto -- ipv6_mode=auto on an M=1 A=1 link whose DHCPv6 server
// is stopped (plugin docs/reference.md, ipv6_mode): auto "falls back to
// the advertised prefix after half the router-discovery window". So the
// client solicits, nothing answers, and the prefix's address is formed;
// fallbacks is the dhcpv6_auto_fallbacks delta, corroboration only (#23 row D3c).
func judgeD3cAuto(o d2Obs, fallbacks string) fOutcome {
	sol := 0
	for _, m := range o.Msgs {
		if m.Type == "SOLICIT" {
			sol++
		}
		if m.Type == "REPLY" && HasAddr(m.NA) {
			return fBlocked("a Reply granted an IA_NA although StopV6Server ran; the source's DHCPv6 server was not silent")
		}
	}
	if sol == 0 {
		return fFail("the RA says DHCPv6 (M=1) and the container sent no Solicit under ipv6_mode=auto")
	}
	out := slaacFormed(o)
	if out.Result != PASS {
		return out
	}
	return fOK("%d Solicits unanswered, then %s; dhcpv6_auto_fallbacks %s (recorded)", sol, out.Reason, fallbacks)
}

// judgeD3cFails is D3c's strict and dhcp legs (docs: ipv6_auto_strict
// "fails the endpoint instead"; ipv6=true "on a segment that advertises
// one and then answers nothing it fails"). A started container is a FAIL,
// so a SLAAC address cannot pass (defeat E). A start error passes only
// when tied to the silent server: Solicits on the link with no Advertise
// or Reply, or the plugin's ErrNoV6Server text (#23).
func judgeD3cFails(opts string, startErr error, settled []addr6, msgs []DHCP6Msg) fOutcome {
	if startErr == nil {
		return fFail("the container started with %s on an M=1 link whose DHCPv6 server is silent (link carries %v); the docs fail the endpoint", opts, globals(settled))
	}
	sol := 0
	for _, m := range msgs {
		switch m.Type {
		case "SOLICIT":
			sol++
		case "ADVERTISE", "REPLY":
			return fBlocked("a DHCPv6 %s is on the link after the server was stopped, so the server is not silent; start error: %v", m.Type, startErr)
		}
	}
	if sol > 0 {
		return fOK("%s with a silent DHCPv6 server: %d Solicits unanswered, the endpoint failed (%v)", opts, sol, startErr)
	}
	if strings.Contains(startErr.Error(), d3cNoServer) {
		return fOK("%s with a silent DHCPv6 server: the endpoint failed naming it (%v)", opts, startErr)
	}
	return fBlocked("%s: the container did not start, but no Solicit is on the link and the error does not name DHCPv6 silence: %v", opts, startErr)
}

// d3cNoServer is the plugin's ErrNoV6Server text (plugin
// pkg/dhcp/v6failure.go, #23).
const d3cNoServer = "no DHCPv6 server answered"

// d4Obs is D4's reads; Main is ipv6_main_prefix (D4m), unset for D4 (#23 row D4).
type d4Obs struct {
	d2Obs
	Main netip.Prefix
}

// judgeD4 -- two autonomous prefixes under slaac (plugin
// docs/reference.md, ipv6_mode: "installs every address the
// advertisement forms" and inspect shows "the first advertised prefix's
// address by default"; ipv6_main_prefix names another). The first
// prefix is read from the capture by d4First (DESIGN-23d row D4).
func judgeD4(o d4Obs) fOutcome {
	for _, m := range o.Msgs {
		if isClient6(m.Type) {
			return fFail("the container sent a DHCPv6 %s although ipv6_mode=slaac sends no Solicit", m.Type)
		}
	}
	var before []RAMsg
	for _, ra := range o.RAs {
		if !ra.At.After(o.Settled.At) && hasAutoPIO(ra) {
			before = append(before, ra)
		}
	}
	ps := autoPrefixes(before)
	if len(ps) < 2 {
		return fBlocked("the capture shows %d autonomous prefixes before the settled read (%v), the row needs two", len(ps), ps)
	}
	var want []netip.Addr
	for _, p := range ps {
		a, err := eui64(p, o.MAC)
		if err != nil {
			return fBlocked("%v", err)
		}
		if _, ok := findAddr6(o.Settled.Addrs, a); !ok {
			return fFail("the container's link has no %s once settled; the RA advertised %s as autonomous", a, p)
		}
		want = append(want, a)
	}
	if extra, bad := leftover(o.Settled.Addrs, want...); bad {
		return fFail("the container's link also carries %s; the RAs formed only %v", extra, want)
	}
	if o.Main.IsValid() {
		if !slices.Contains(ps, o.Main) {
			return fBlocked("ipv6_main_prefix %s is not among the advertised prefixes %v", o.Main, ps)
		}
		m, _ := eui64(o.Main, o.MAC)
		if o.Inspect != m.String() {
			return fFail("docker inspect reports GlobalIPv6Address %q, ipv6_main_prefix=%s names %s", o.Inspect, o.Main, m)
		}
		return fOK("%v on the link, one per advertised prefix %v; inspect shows %s, ipv6_main_prefix's", want, ps, m)
	}
	first, how, ok := d4First(before, o.Start.At)
	if !ok {
		return fBlocked("%s", how)
	}
	a, _ := eui64(first, o.MAC)
	if o.Inspect != a.String() {
		return fFail("docker inspect reports GlobalIPv6Address %q, the first advertised prefix %s gives %s (%s)", o.Inspect, first, a, how)
	}
	return fOK("%v on the link, one per advertised prefix %v; inspect shows %s, the first advertised prefix's (%s)", want, ps, o.Inspect, how)
}

// firstAuto is ra's first autonomous PIO in wire order (DESIGN-23d defeat 7).
func firstAuto(ra RAMsg) (netip.Prefix, bool) {
	for _, p := range ra.PIOs {
		if p.Auto {
			return p.Prefix, true
		}
	}
	return netip.Prefix{}, false
}

// d4First is the prefix the plugin had to name first (DESIGN-23d defeat
// 7): the first autonomous PIO of the last RA captured before the start
// read, which bounds the moment CreateEndpoint reported the address.
// dnsmasq turns its PIO order round between RAs (measured,
// scripts/testdata/v6/dnsmasq-pio-order-flips.pcap), so an earlier RA in
// that window that lists another prefix first leaves the row BLOCKED,
// never accepting either. With no RA before the start read, every RA
// before the settled read must agree.
func d4First(before []RAMsg, startAt time.Time) (netip.Prefix, string, bool) {
	var anchor []RAMsg
	for _, ra := range before {
		if !ra.At.After(startAt) {
			anchor = append(anchor, ra)
		}
	}
	how := "the last RA before the container's start read"
	if len(anchor) == 0 {
		anchor, how = before, "no RA before the start read, every RA before the settled read"
	}
	last, _ := firstAuto(anchor[len(anchor)-1])
	for _, ra := range anchor {
		if f, _ := firstAuto(ra); f != last {
			return netip.Prefix{}, fmt.Sprintf("the RAs before the address appeared list %s and %s first (the RA at %s and the one at %s); which one the plugin read is not on the wire",
				f, last, ra.At.Format(time.RFC3339Nano), anchor[len(anchor)-1].At.Format(time.RFC3339Nano)), false
		}
	}
	return last, fmt.Sprintf("%s, at %s, lists %s first", how, anchor[len(anchor)-1].At.Format(time.RFC3339Nano), last), true
}

// judgeD4bDrop -- the router stops advertising the second prefix: its
// address "is removed" (plugin docs/reference.md:967, ipv6_mode) and,
// from v2.2.3, the on-link route stays (docs/reference.md:1824-1828,
// #1088). DESIGN-23d row D4 says the address stays until its valid
// lifetime; the judge follows the docs and the host run decides
// (#23).
func judgeD4bDrop(after []RAMsg, addrs []addr6, routes string, first, second netip.Prefix, mac string, routeKept bool) fOutcome {
	if len(after) == 0 {
		return fBlocked("the capture shows no RA after the second prefix was dropped, so nothing told the container")
	}
	for _, ra := range after {
		for _, p := range ra.PIOs {
			if p.Prefix == second {
				return fBlocked("an RA at %s still carries %s after the drop; the source did not drop it", ra.At.Format(time.RFC3339), second)
			}
		}
	}
	a1, _ := eui64(first, mac)
	a2, _ := eui64(second, mac)
	if _, ok := findAddr6(addrs, a2); ok {
		return fFail("%s is still on the link after the router stopped advertising %s; %s", a2, second, d4bDocAddr)
	}
	if _, ok := findAddr6(addrs, a1); !ok {
		return fFail("%s left the link although %s is still advertised", a1, first)
	}
	if routeKept {
		if _, ok := routeFor(routes, second); !ok {
			return fFail("the on-link route for %s went with the prefix; %s", second, d4bDocRoute)
		}
		return fOK("%s removed after the drop, %s kept, the route for %s kept; %s; %s", a2, a1, second, d4bDocAddr, d4bDocRoute)
	}
	return fOK("%s removed after the drop, %s kept (route not judged before v2.2.3); %s", a2, a1, d4bDocAddr)
}

// The plugin doc lines judgeD4bDrop follows, named in its verdict reason
// (#23).
const (
	d4bDocAddr  = `plugin docs/reference.md:967 (ipv6_mode): an address "whose prefix the router stops advertising, is removed"`
	d4bDocRoute = `plugin docs/reference.md:1824-1828 (#1088): "an advertisement that leaves a prefix out keeps its route"`
)

// judgeD4bExpired -- the second prefix advertised with valid lifetime 0:
// "an RA with valid lifetime 0 removes" the route (#1088), and the
// address goes with it (RFC 4862 section 5.5.3 e).
func judgeD4bExpired(after []RAMsg, addrs []addr6, routes string, second netip.Prefix, mac string) fOutcome {
	seen := false
	for _, ra := range after {
		for _, p := range ra.PIOs {
			if p.Prefix == second && p.Valid == 0 {
				seen = true
			}
		}
	}
	if !seen {
		return fBlocked("the capture shows no RA advertising %s with valid lifetime 0", second)
	}
	a2, _ := eui64(second, mac)
	if _, ok := findAddr6(addrs, a2); ok {
		return fFail("%s is still on the link after %s was advertised with valid lifetime 0", a2, second)
	}
	if line, ok := routeFor(routes, second); ok {
		return fFail("the route %q is still in the container after %s was advertised with valid lifetime 0 (#1088)", line, second)
	}
	return fOK("%s advertised with valid lifetime 0: address and route gone", second)
}

// routeTypes is ip-route(8)'s TYPE keywords, which `ip -6 route show`
// prints before the destination of any route that is not unicast (#23).
var routeTypes = []string{"unicast", "unreachable", "blackhole", "prohibit", "local", "broadcast", "throw", "nat", "anycast", "multicast"}

// routeDst is the destination of one `ip -6 route show` line past its
// route type; ip prints a /128 as a bare address (ip-route(8)) (#23).
func routeDst(line string) (netip.Prefix, bool) {
	f := strings.Fields(line)
	if len(f) > 1 && slices.Contains(routeTypes, f[0]) {
		f = f[1:]
	}
	if len(f) == 0 {
		return netip.Prefix{}, false
	}
	if q, err := netip.ParsePrefix(f[0]); err == nil {
		return q, true
	}
	if a, err := netip.ParseAddr(f[0]); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// routeFor finds the `ip -6 route show` line whose destination is p (#23 rows D4b, F6-prefix-delegation).
func routeFor(out string, p netip.Prefix) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		if q, ok := routeDst(line); ok && q == p {
			return strings.TrimSpace(line), true
		}
	}
	return "", false
}

// judgeF6 -- prefix delegation (plugin docs/reference.md, ipv6_pd): an
// IA_PD in the Solicit and Request; a delegated prefix is routed as
// "`unreachable <prefix> proto dhcp`" and listed in delegated_prefixes;
// a server with none to give leaves the endpoint its address and no
// route. busybox ip may print the protocol as its number, 16 (#23 row F6-prefix-delegation, RFC 8415 section 6.3).
func judgeF6(o d1Obs, serverPD bool, pool netip.Prefix, routes string, h healthEndpoint, found bool) fOutcome {
	d1, x := judgeD1(o)
	if d1.Result != PASS {
		return d1
	}
	for _, m := range x.client() {
		if (m.Type == "SOLICIT" || m.Type == "REQUEST") && len(m.PD) == 0 {
			return fFail("a %s carries no IA_PD although the network sets ipv6_pd=64", m.Type)
		}
	}
	var pd netip.Prefix
	for _, ia := range x.Reply.PD {
		if ia.Prefix.IsValid() {
			pd = ia.Prefix
			break
		}
	}
	var held []string
	for _, p := range h.DelegatedPrefixes {
		held = append(held, p.Prefix)
	}
	if !pd.IsValid() {
		if serverPD {
			return fFail("the Reply delegates no prefix although the source has a PD pool %s", pool)
		}
		for _, line := range strings.Split(routes, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "unreachable") {
				return fFail("no prefix was delegated, the container still has %q", strings.TrimSpace(line))
			}
		}
		if len(held) > 0 {
			return fFail("no prefix was delegated, /Plugin.Health shows delegated_prefixes %v", held)
		}
		return fOK("%s; the source delegates no prefix: no route, no delegated_prefixes, the address kept", d1.Reason)
	}
	if !serverPD {
		return fBlocked("the source delegated %s though the lab declares no PD pool for it; the capability table is out of date", pd)
	}
	if pd.Bits() != 64 || !pool.Contains(pd.Addr()) {
		return fBlocked("the source delegated %s, outside its /64s from pool %s", pd, pool)
	}
	inTable := false
	for _, l := range o.Leases {
		if l.Type == sourceadapter.Lease6PD && l.DUID == x.DUID && l.Prefix == pd {
			inTable = true
		}
	}
	if !inTable {
		return fFail("the source's DHCPv6 table holds no IA_PD %s for DUID %s", pd, x.DUID)
	}
	line, ok := routeFor(routes, pd)
	if !ok || !strings.HasPrefix(line, "unreachable") || !(strings.Contains(line, "proto dhcp") || strings.Contains(line, "proto 16")) {
		return fFail("the container has no `unreachable %s proto dhcp` route (route %q)", pd, line)
	}
	if !found {
		return fFail("/Plugin.Health lists no entry for the endpoint")
	}
	if !slices.ContainsFunc(held, func(s string) bool { q, err := netip.ParsePrefix(s); return err == nil && q == pd }) {
		return fFail("/Plugin.Health shows delegated_prefixes %v, the Reply delegated %s", held, pd)
	}
	return fOK("%s; IA_PD %s delegated from %s, in the source's table, routed as %q, in delegated_prefixes", d1.Reason, pd, pool, line)
}

// f7Reads is what the PREF64 row reads inside the container and from the
// plugin: Base* before the source advertises PREF64, the rest after (#23 row F7-pref64).
type f7Reads struct {
	Addrs              []addr6
	BaseRoutes, Routes string
	BaseResolv, Resolv string
	Health             healthEndpoint
	Found              bool
}

// pref64s is the union of the PREF64 prefixes on the wire (RFC 8781 section 4).
func pref64s(ras []RAMsg) []netip.Prefix {
	var out []netip.Prefix
	for _, ra := range ras {
		for _, p := range ra.Pref64 {
			if !slices.Contains(out, p.Masked()) {
				out = append(out, p.Masked())
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// judgeF7 -- PREF64 (plugin docs/reference.md, NAT64 prefix):
// nat64_prefixes in CIDR form, "absent when the router advertises none",
// equal to what the RA carried; "Nothing is installed in the container",
// proven against routes and resolv.conf read before PREF64 was on the
// wire (RFC 8781 section 4, DESIGN-23d row F7-pref64).
func judgeF7(ras []RAMsg, serverPref64 bool, r f7Reads) fOutcome {
	if len(ras) == 0 {
		return fBlocked("the capture shows no RA after the baseline read, so nothing the RA carried is proven")
	}
	wire := pref64s(ras)
	if serverPref64 && len(wire) == 0 {
		return fBlocked("the source was set to advertise PREF64 and the capture shows no RA carrying it (%d RAs)", len(ras))
	}
	if !serverPref64 && len(wire) > 0 {
		return fBlocked("the RA carries PREF64 %v though the lab declares none for this source; the capability table is out of date", wire)
	}
	if !r.Found {
		if len(wire) > 0 {
			return fFail("/Plugin.Health lists no entry for the endpoint")
		}
		return fBlocked("/Plugin.Health lists no entry for the endpoint, so an absent nat64_prefixes proves nothing")
	}
	var health []netip.Prefix
	for _, s := range r.Health.NAT64Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fFail("/Plugin.Health nat64_prefixes holds %q, not a CIDR", s)
		}
		if !slices.Contains(health, p.Masked()) {
			health = append(health, p.Masked())
		}
	}
	slices.SortFunc(health, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	if !slices.Equal(health, wire) {
		return fFail("/Plugin.Health shows nat64_prefixes %v, the RA carried %v", health, wire)
	}
	for _, p := range wire {
		for _, a := range r.Addrs {
			if p.Contains(a.Addr) {
				return fFail("the container's link carries %s, inside PREF64 %s; the docs install nothing", a.Addr, p)
			}
		}
		for _, line := range strings.Split(r.Routes, "\n") {
			if q, ok := routeDst(line); ok && q.Overlaps(p) {
				return fFail("the container has the route %q, inside PREF64 %s", strings.TrimSpace(line), p)
			}
		}
		for _, f := range strings.Fields(r.Resolv) {
			if a, err := netip.ParseAddr(f); err == nil && p.Contains(a) {
				return fFail("resolv.conf names %s, inside PREF64 %s; propagate_dns does not change that (docs)", a, p)
			}
		}
	}
	if r.Resolv != r.BaseResolv {
		return fFail("resolv.conf changed after the PREF64 RAs arrived; the docs install nothing")
	}
	if !slices.Equal(routeKeys(r.BaseRoutes), routeKeys(r.Routes)) {
		return fFail("the container's IPv6 routes changed after the PREF64 RAs arrived (%v, then %v)", routeKeys(r.BaseRoutes), routeKeys(r.Routes))
	}
	if len(wire) == 0 {
		return fOK("the RA carries no PREF64; the endpoint's nat64_prefixes absent, nothing installed")
	}
	return fOK("nat64_prefixes %v equals the RA's PREF64; no address, route or resolver inside it, routes and resolv.conf as before PREF64 was advertised", wire)
}

// routeKeys is the type and destination of each `ip -6 route show`
// line, without the expires counters that change between two reads (#23).
func routeKeys(out string) []string {
	var d []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		typ := "unicast"
		if len(f) > 1 && slices.Contains(routeTypes, f[0]) {
			typ, f = f[0], f[1:]
		}
		d = append(d, typ+" "+f[0])
	}
	slices.Sort(d)
	return d
}
