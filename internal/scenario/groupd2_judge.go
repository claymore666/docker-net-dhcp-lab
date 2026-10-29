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
// one-shot client solicits, nothing answers, and the prefix's address is
// formed with the last PIO's finite lifetimes. The persistent client adds
// no Solicit transaction of its own (plugin #1369): a second transaction
// ID is a second exchange, a retransmission reuses its ID (RFC 8415
// section 15). fallbacks is the dhcpv6_auto_fallbacks delta,
// corroboration only (#23 row D3c).
func judgeD3cAuto(o d2Obs, fallbacks string) fOutcome {
	var xids []string
	sol := 0
	for _, m := range o.Msgs {
		if m.Type == "SOLICIT" {
			sol++
			if !slices.Contains(xids, m.XID) {
				xids = append(xids, m.XID)
			}
		}
		if m.Type == "REPLY" && HasAddr(m.NA) {
			return fBlocked("a Reply granted an IA_NA although StopV6Server ran; the source's DHCPv6 server was not silent")
		}
	}
	if sol == 0 {
		return fFail("the RA says DHCPv6 (M=1) and the container sent no Solicit under ipv6_mode=auto")
	}
	if len(xids) != 1 {
		return fFail("%d Solicit transactions (xids %s), want the one-shot's alone: the persistent client must not solicit again (plugin #1369)", len(xids), strings.Join(xids, " "))
	}
	out := slaacFormed(o)
	if out.Result != PASS {
		return out
	}
	pio, _, _, _, _ := lastAutoPIO(o)
	want, _ := eui64(pio.Prefix, o.MAC)
	s, _ := findAddr6(o.Settled.Addrs, want)
	if s.Valid > int64(pio.Valid) || s.Pref > int64(pio.Pref) {
		return fFail("%s carries valid %d preferred %d, above the last PIO's %d/%d (plugin #1369)", want, s.Valid, s.Pref, pio.Valid, pio.Pref)
	}
	return fOK("%d Solicits unanswered (one transaction), then %s; dhcpv6_auto_fallbacks %s (recorded)", sol, out.Reason, fallbacks)
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
		if asksForAddress6(m.Type) {
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
// address stays while its valid lifetime runs and counts down (plugin
// #1368, RFC 4862 section 5.5.3 e), and the on-link route stays (plugin
// docs/reference.md:1824-1828, #1088). reads are the container's address
// reads from the drop on, oldest first; the address may leave only when
// the lifetime the last read that held it showed has run out (#23).
func judgeD4bDrop(after []RAMsg, reads []d6Read, routes string, first, second netip.Prefix, mac string, routeKept bool) fOutcome {
	if len(after) == 0 {
		return fBlocked("the capture shows no RA after the second prefix was dropped, so nothing told the container")
	}
	if len(reads) == 0 {
		return fBlocked("no address read after the second prefix was dropped")
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
	last := reads[len(reads)-1]
	if _, ok := findAddr6(last.Addrs, a1); !ok {
		return fFail("%s left the link although %s is still advertised", a1, first)
	}
	var held string
	if x, ok := findAddr6(last.Addrs, a2); ok {
		if bad, ok := d4bCountsDown(reads, a2, x); !ok {
			return bad
		}
		held = fmt.Sprintf("%s stayed with valid %d, counting down", a2, x.Valid)
	} else {
		var seen *addr6
		var seenAt time.Time
		for _, r := range reads {
			if x, ok := findAddr6(r.Addrs, a2); ok {
				seen, seenAt = &x, r.At
			}
		}
		if seen == nil {
			return fFail("%s was gone at the first read after the drop; the address stays until its valid lifetime runs out, it is not removed when the prefix ceases (%s)", a2, d4bDoc)
		}
		if ran := last.sampled().Sub(seenAt); seen.Valid == forever || seen.Valid > int64(ran/time.Second)+lftSlack {
			return fFail("%s left the link with valid %d seconds still to run, %s after the read that showed it; it goes only at expiry (%s)", a2, seen.Valid, ran.Round(time.Second), d4bDoc)
		}
		held = fmt.Sprintf("%s left only as its valid lifetime ran out", a2)
	}
	if routeKept {
		if _, ok := routeFor(routes, second); !ok {
			return fFail("the on-link route for %s went with the prefix; %s", second, d4bDocRoute)
		}
		return fOK("%s, %s kept, the route for %s kept; %s; %s", held, a1, second, d4bDoc, d4bDocRoute)
	}
	return fOK("%s, %s kept (route not judged before v2.2.3); %s", held, a1, d4bDoc)
}

// d4bMinSpan is the least time between the first and last read for a
// count-down to be seen: kernel lifetimes are whole seconds and an ssh
// read is a few seconds wide (lab #102).
const d4bMinSpan = 6 * time.Second

// d4bCountsDown is true when a2's valid lifetime is finite and lower in
// the last read than in the first, else the verdict that says why not.
func d4bCountsDown(reads []d6Read, a2 netip.Addr, lastSeen addr6) (fOutcome, bool) {
	if lastSeen.Valid <= 0 {
		return fFail("%s is still on the link with valid lifetime %d (-1 is forever) after the prefix was withdrawn; %s", a2, lastSeen.Valid, d4bDoc), false
	}
	firstRead := reads[0]
	x, ok := findAddr6(firstRead.Addrs, a2)
	if !ok {
		return fFail("%s was missing from the first read after the drop and back later; %s", a2, d4bDoc), false
	}
	if span := reads[len(reads)-1].At.Sub(firstRead.sampled()); span < d4bMinSpan {
		return fBlocked("the address reads after the drop span %s, under %s; a count-down cannot be seen", span.Round(time.Second), d4bMinSpan), false
	}
	if lastSeen.Valid >= x.Valid {
		return fFail("%s valid lifetime %d at the last read, %d at the first %s earlier: it does not count down; %s", a2, lastSeen.Valid, x.Valid, reads[len(reads)-1].At.Sub(firstRead.At).Round(time.Second), d4bDoc), false
	}
	return fOutcome{}, true
}

// The plugin statement judgeD4bDrop follows, named in its verdict reason
// (plugin #1368), and the route doc line (#23).
const (
	d4bDoc      = "plugin #1368: a withdrawn prefix's address keeps its valid lifetime and counts down"
	d4bDocRoute = `plugin docs/reference.md:1824-1828 (#1088): "an advertisement that leaves a prefix out keeps its route"`
)

// d4bTwoHours is the valid lifetime a Prefix Information option with
// valid lifetime 0 cuts an address to when more is left (RFC 4862 section
// 5.5.3 e).
const d4bTwoHours = 7200

// judgeD4bExpired -- the second prefix advertised with valid lifetime 0:
// "an RA with valid lifetime 0 removes" the route (#1088). The address
// follows RFC 4862 section 5.5.3 e (plugin #1368): the option "cuts what
// is left to two hours when more is left and is otherwise ignored", so
// the address is either gone or still there, finite, with at most two
// hours left (lab #102).
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
	held := "address gone"
	if x, ok := findAddr6(addrs, a2); ok {
		if x.Valid == forever || x.Valid > d4bTwoHours {
			return fFail("%s carries valid %d (-1 is forever) after %s was advertised with valid lifetime 0; the option cuts what is left to two hours (plugin #1368)", a2, x.Valid, second)
		}
		held = fmt.Sprintf("address kept with valid %d, within the two hours", x.Valid)
	}
	if line, ok := routeFor(routes, second); ok {
		return fFail("the route %q is still in the container after %s was advertised with valid lifetime 0 (#1088)", line, second)
	}
	return fOK("%s advertised with valid lifetime 0: %s, route gone", second, held)
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
// route. The routes must come from iproute2: BusyBox ip (alpine:3.20,
// v1.36.1) prints no protocol at all, so only the container's netns read
// from the host can show proto dhcp (plugin #1370, RFC 8415 section 6.3).
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
	if !ok || !strings.HasPrefix(line, "unreachable") || !strings.Contains(line, "proto dhcp") {
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

// f7Reads is what the PREF64 row reads: Base* in the first container
// before the source advertises PREF64, the rest after it, and Bind* in a
// second container started once PREF64 is on the wire (#23 row F7-pref64).
type f7Reads struct {
	Addrs              []addr6
	BaseRoutes, Routes string
	BaseResolv, Resolv string
	Health             healthEndpoint
	Found              bool
	BindAddrs          []addr6
	BindRoutes         string
	BindResolv         string
	BindHealth         healthEndpoint
	BindFound          bool
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

// judgeF7 -- PREF64 against plugin docs/reference.md:2020-2033 (#1028):
// nat64_prefixes is "absent when the router advertises none", refreshed
// "on each lease event of the endpoint: a bind, ...", and "An
// advertisement whose only news is a PREF64 option is not an event of its
// own". So the second container's bind must show the wire's PREF64, the
// first container's field may still lag, and "Nothing is installed in the
// container" holds in both against the first one's pre-PREF64 reads
// (RFC 8781 section 4, DESIGN-23d row F7-pref64).
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
	if !r.BindFound {
		if len(wire) > 0 {
			return fFail("/Plugin.Health lists no entry for the endpoint bound after PREF64 was advertised")
		}
		return fBlocked("/Plugin.Health lists no entry for the endpoint bound after the RA, so an absent nat64_prefixes proves nothing")
	}
	bound, err := nat64Set(r.BindHealth)
	if err != nil {
		return fFail("%v", err)
	}
	if !slices.Equal(bound, wire) {
		return fFail("/Plugin.Health shows nat64_prefixes %v for the endpoint bound after PREF64 was advertised, the RA carried %v; a bind is a lease event (docs/reference.md:2027-2028)", bound, wire)
	}
	if r.Found {
		first, err := nat64Set(r.Health)
		if err != nil {
			return fFail("%v", err)
		}
		if len(first) > 0 && !slices.Equal(first, wire) {
			return fFail("/Plugin.Health shows nat64_prefixes %v for the first endpoint, the RA carried %v", first, wire)
		}
	}
	for _, c := range []struct {
		who            string
		addrs          []addr6
		routes, resolv string
	}{{"first", r.Addrs, r.Routes, r.Resolv}, {"second", r.BindAddrs, r.BindRoutes, r.BindResolv}} {
		for _, p := range wire {
			for _, a := range c.addrs {
				if p.Contains(a.Addr) {
					return fFail("the %s container's link carries %s, inside PREF64 %s; the docs install nothing", c.who, a.Addr, p)
				}
			}
			for _, line := range strings.Split(c.routes, "\n") {
				if q, ok := routeDst(line); ok && q.Overlaps(p) {
					return fFail("the %s container has the route %q, inside PREF64 %s", c.who, strings.TrimSpace(line), p)
				}
			}
			for _, f := range strings.Fields(c.resolv) {
				if a, err := netip.ParseAddr(f); err == nil && p.Contains(a) {
					return fFail("the %s container's resolv.conf names %s, inside PREF64 %s; propagate_dns does not change that (docs)", c.who, a, p)
				}
			}
		}
		if c.resolv != r.BaseResolv {
			return fFail("the %s container's resolv.conf differs from the first one's before PREF64 was advertised; the docs install nothing", c.who)
		}
		if !slices.Equal(routeKeys(r.BaseRoutes), routeKeys(c.routes)) {
			return fFail("the %s container's IPv6 routes changed against the first one's before PREF64 was advertised (%v, then %v)", c.who, routeKeys(r.BaseRoutes), routeKeys(c.routes))
		}
	}
	if len(wire) == 0 {
		return fOK("the RA carries no PREF64; the bound endpoint's nat64_prefixes absent, nothing installed")
	}
	return fOK("nat64_prefixes %v on the endpoint bound after PREF64 was advertised equals the RA's PREF64; no address, route or resolver inside it in either container, routes and resolv.conf as before PREF64 was advertised", wire)
}

// nat64Set is h's nat64_prefixes, masked, deduplicated and sorted (#23 row F7-pref64).
func nat64Set(h healthEndpoint) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range h.NAT64Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("/Plugin.Health nat64_prefixes holds %q, not a CIDR", s)
		}
		if !slices.Contains(out, p.Masked()) {
			out = append(out, p.Masked())
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
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
