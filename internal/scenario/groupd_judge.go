package scenario

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group D judges (#23): pure functions over what the capture, the
// source's table, the container's own netns, docker inspect and
// /Plugin.Health showed, so each rule has a fixture test.

// lftSlack is the seconds a read lifetime may sit below the expected
// count-down: the gap between the capture's timestamp and the read.
const lftSlack = 15

// d6Read is one read of the container's addresses and when it was taken.
type d6Read struct {
	At    time.Time
	Addrs []addr6
}

func isClient6(typ string) bool {
	switch typ {
	case "SOLICIT", "REQUEST", "CONFIRM", "RENEW", "REBIND", "RELEASE", "DECLINE", "INFORMATION-REQUEST":
		return true
	}
	return false
}

// d6Exchange is one client's messages and the server's answers to it,
// keyed on the DUID the client itself sent (design: "never by a DUID
// computed from the MAC").
type d6Exchange struct {
	DUID     string
	Msgs     []DHCP6Msg
	Reply    DHCP6Msg
	HasReply bool
}

func (x d6Exchange) client() []DHCP6Msg {
	var out []DHCP6Msg
	for _, m := range x.Msgs {
		if isClient6(m.Type) {
			out = append(out, m)
		}
	}
	return out
}

func (x d6Exchange) types() []string {
	var t []string
	for _, m := range x.Msgs {
		t = append(t, m.Type)
	}
	return collapse(t)
}

func exchange6(msgs []DHCP6Msg) (d6Exchange, fOutcome, bool) {
	var duids []string
	for _, m := range msgs {
		if isClient6(m.Type) && m.ClientDUID != "" && !slices.Contains(duids, m.ClientDUID) {
			duids = append(duids, m.ClientDUID)
		}
	}
	switch len(duids) {
	case 0:
		return d6Exchange{}, fFail("the capture shows no DHCPv6 message from the container (%d messages matched its MAC and link-local)", len(msgs)), false
	case 1:
	default:
		return d6Exchange{}, fBlocked("the capture shows %d client DUIDs for the container's MAC and link-local (%s); the lab cannot tell which one is the container", len(duids), strings.Join(duids, " ")), false
	}
	x := d6Exchange{DUID: duids[0]}
	for _, m := range msgs {
		if m.ClientDUID == x.DUID {
			x.Msgs = append(x.Msgs, m)
		}
	}
	sort.SliceStable(x.Msgs, func(i, j int) bool { return x.Msgs[i].At.Before(x.Msgs[j].At) })
	for _, m := range x.Msgs {
		if m.Type == "REPLY" && HasAddr(m.NA) {
			x.Reply, x.HasReply = m, true
		}
	}
	if !x.HasReply {
		return x, fFail("no Reply granted DUID %s an IA_NA address (exchange %s)", x.DUID, strings.Join(x.types(), " ")), false
	}
	return x, fOutcome{}, true
}

func firstAddr(ias []IA6) (IA6, bool) {
	for _, ia := range ias {
		if ia.Addr.IsValid() {
			return ia, true
		}
	}
	return IA6{}, false
}

// lftWithin: a read lifetime is finite, above zero, at most what the
// server or router stated, and no lower than that count-down allows.
func lftWithin(got int64, stated uint32, elapsed time.Duration) bool {
	lo := int64(stated) - int64(elapsed/time.Second) - lftSlack
	return got > 0 && got <= int64(stated) && got >= lo
}

// d1Obs is everything D1, D1b and the rapid commit and temporary address
// rows read for one container.
type d1Obs struct {
	Msgs     []DHCP6Msg
	RAs      []RAMsg
	Leases   []sourceadapter.Lease6
	Start    d6Read
	Settled  d6Read
	Inspect  string
	Route    netip.Addr
	HasRoute bool
	PingErr  error
	// ExtraTA is a temporary address the judge allows beside the lease.
	ExtraTA netip.Addr
}

// raBefore: some RA carrying prefix p as autonomous was on the wire by t.
func raBefore(ras []RAMsg, p netip.Prefix, t time.Time) bool {
	for _, ra := range ras {
		if ra.At.After(t) {
			continue
		}
		for _, x := range ra.PIOs {
			if x.Auto && x.Prefix == p {
				return true
			}
		}
	}
	return false
}

func leftover(as []addr6, allowed ...netip.Addr) (netip.Addr, bool) {
	for _, a := range globals(as) {
		if !slices.Contains(allowed, a.Addr) {
			return a.Addr, true
		}
	}
	return netip.Addr{}, false
}

// judgeD1 -- DHCPv6 lease (plugin docs/reference.md, ipv6): the IA_NA
// is in the source's table for the container's DUID, on the link as a
// /128 with the server's lifetimes ("`forever`" allowed only at start),
// docker inspect shows it, the default route goes via an advertising
// router's link-local source, and it answers the source.
func judgeD1(o d1Obs) (fOutcome, d6Exchange) {
	x, out, ok := exchange6(o.Msgs)
	if !ok {
		return out, x
	}
	na, _ := firstAddr(x.Reply.NA)
	found := false
	for _, l := range o.Leases {
		if l.Type == sourceadapter.Lease6NA && l.DUID == x.DUID && l.Address == na.Addr {
			found = true
		}
	}
	if !found {
		return fFail("the source's DHCPv6 table holds no IA_NA %s for DUID %s (%d rows)", na.Addr, x.DUID, len(o.Leases)), x
	}
	allowed := []netip.Addr{na.Addr}
	if o.ExtraTA.IsValid() {
		allowed = append(allowed, o.ExtraTA)
	}
	a, ok := findAddr6(o.Start.Addrs, na.Addr)
	if !ok {
		return fFail("right after docker run returned the container's link has no %s", na.Addr), x
	}
	if a.Bits != 128 {
		return fFail("%s is on the link as /%d, the docs install it as a /128", na.Addr, a.Bits), x
	}
	if (a.Valid != forever && a.Valid > int64(na.Valid)) || (a.Pref != forever && a.Pref > int64(na.Pref)) {
		return fFail("at start %s carries valid %d preferred %d, above the Reply's %d/%d", na.Addr, a.Valid, a.Pref, na.Valid, na.Pref), x
	}
	for _, r := range []d6Read{o.Start, o.Settled} {
		if extra, bad := leftover(r.Addrs, allowed...); bad {
			return fFail("the container's link also carries %s, which no Reply granted", extra), x
		}
	}
	s, ok := findAddr6(o.Settled.Addrs, na.Addr)
	if !ok {
		return fFail("%s was gone from the link once settled", na.Addr), x
	}
	elapsed := o.Settled.At.Sub(x.Reply.At)
	if s.Valid == forever || s.Pref == forever {
		return fFail("%s still carries valid %d preferred %d (-1 is forever) %s after the Reply; the docs install the server's lifetimes", na.Addr, s.Valid, s.Pref, elapsed.Round(time.Second)), x
	}
	if !lftWithin(s.Valid, na.Valid, elapsed) || !lftWithin(s.Pref, na.Pref, elapsed) {
		return fFail("%s carries valid %d preferred %d %s after a Reply that stated %d/%d", na.Addr, s.Valid, s.Pref, elapsed.Round(time.Second), na.Valid, na.Pref), x
	}
	if o.Inspect != na.Addr.String() {
		return fFail("docker inspect reports GlobalIPv6Address %q, the lease and the link hold %s", o.Inspect, na.Addr), x
	}
	var routers []netip.Addr
	for _, ra := range o.RAs {
		if ra.RouterLifetime > 0 && !slices.Contains(routers, ra.Src) {
			routers = append(routers, ra.Src)
		}
	}
	if len(routers) == 0 {
		return fBlocked("the capture shows no RA with a router lifetime above 0 (%d RAs), so the default route has nothing to be judged against", len(o.RAs)), x
	}
	if !o.HasRoute {
		return fFail("the container has no IPv6 default route; the RAs came from %v", routers), x
	}
	if !slices.Contains(routers, o.Route) {
		return fFail("the container's IPv6 default route goes via %s, the RAs came from %v", o.Route, routers), x
	}
	if o.PingErr != nil {
		return fFail("%s is leased but does not answer from the source: %v", na.Addr, o.PingErr), x
	}
	return fOK("IA_NA %s for DUID %s in the source's table; on the link as /128, valid %d preferred %d once settled (Reply %d/%d); inspect agrees; default route via %s; answers the source",
		na.Addr, x.DUID, s.Valid, s.Pref, na.Valid, na.Pref, o.Route), x
}

// judgeF4Wire -- DHCPv6 rapid commit (plugin docs/reference.md,
// rapid_commit): option 14 in every Solicit; a server that supports it
// answers the Reply and "the lease takes two messages instead of four".
// Before v2.4.0 the client sends no option 14 and the four follow.
func judgeF4Wire(present, serverRapid bool, x d6Exchange) fOutcome {
	types := x.types()
	seq := strings.Join(types, " ")
	sol := 0
	for _, m := range x.client() {
		if m.Type == "SOLICIT" {
			sol++
			if m.Rapid != present {
				return fFail("a Solicit carries option 14 = %v, want %v (exchange %s)", m.Rapid, present, seq)
			}
		}
	}
	if sol == 0 {
		return fFail("the capture holds no Solicit from DUID %s (exchange %s)", x.DUID, seq)
	}
	if present && serverRapid {
		if !slices.Equal(types, []string{"SOLICIT", "REPLY"}) {
			return fFail("rapid commit on both sides, the exchange was %s, want SOLICIT REPLY", seq)
		}
		if !x.Reply.Rapid {
			return fFail("the Reply to a rapid-commit Solicit carries no option 14 (RFC 8415 section 18.3.1)")
		}
		return fOK("two messages, Solicit and Reply both with option 14")
	}
	if !slices.Equal(types, []string{"SOLICIT", "ADVERTISE", "REQUEST", "REPLY"}) {
		return fFail("the exchange was %s, want SOLICIT ADVERTISE REQUEST REPLY", seq)
	}
	return fOK("four messages, Solicit option 14 = %v", present)
}

// judgeF5 -- temporary address (plugin docs/reference.md,
// ipv6_temporary): an IA_TA in every Solicit and Request; a granted one
// is on the link beside the stable address, "never the address Docker is
// told about", and shown on /Plugin.Health as ipv6_temporary_address. "A
// server that grants no temporary address answers the IA_NA alone and
// the endpoint runs as without the key."
func judgeF5(o d1Obs, present, serverTA, healthFound bool, healthTA string) fOutcome {
	x, out, ok := exchange6(o.Msgs)
	if !ok {
		return out
	}
	for _, m := range x.client() {
		if (m.Type == "SOLICIT" || m.Type == "REQUEST") && (len(m.TA) > 0) != present {
			return fFail("a %s carries an IA_TA = %v, want %v", m.Type, len(m.TA) > 0, present)
		}
	}
	ta, granted := firstAddr(x.Reply.TA)
	if granted && !(present && serverTA) {
		return fBlocked("the source granted IA_TA %s though the lab expects none (client asks %v, source declares a temporary pool %v); the capability table is out of date", ta.Addr, present, serverTA)
	}
	if present && serverTA && !granted {
		return fFail("the Reply grants no IA_TA address although the source has a temporary pool")
	}
	if granted {
		o.ExtraTA = ta.Addr
	}
	d1, _ := judgeD1(o)
	if d1.Result != PASS {
		return d1
	}
	if present && !healthFound {
		return fFail("/Plugin.Health lists no entry for the endpoint")
	}
	gotTA, _, _ := strings.Cut(healthTA, "/")
	if !granted {
		if gotTA != "" {
			return fFail("/Plugin.Health shows ipv6_temporary_address %s, no Reply granted one", healthTA)
		}
		return fOK("%s; no IA_TA granted, the endpoint runs as without the key", d1.Reason)
	}
	s, ok := findAddr6(o.Settled.Addrs, ta.Addr)
	if !ok {
		return fFail("the granted IA_TA %s is not on the container's link once settled", ta.Addr)
	}
	if !lftWithin(s.Valid, ta.Valid, o.Settled.At.Sub(x.Reply.At)) || !lftWithin(s.Pref, ta.Pref, o.Settled.At.Sub(x.Reply.At)) {
		return fFail("IA_TA %s carries valid %d preferred %d, the Reply stated %d/%d", ta.Addr, s.Valid, s.Pref, ta.Valid, ta.Pref)
	}
	inTable := false
	for _, l := range o.Leases {
		if l.Type == sourceadapter.Lease6TA && l.DUID == x.DUID && l.Address == ta.Addr {
			inTable = true
		}
	}
	if !inTable {
		return fFail("the source's DHCPv6 table holds no IA_TA %s for DUID %s", ta.Addr, x.DUID)
	}
	if gotTA != ta.Addr.String() {
		return fFail("/Plugin.Health shows ipv6_temporary_address %q, the Reply granted %s", healthTA, ta.Addr)
	}
	return fOK("%s; IA_TA %s granted, on the link, in the source's table and on /Plugin.Health", d1.Reason, ta.Addr)
}

// pioLft is lftWithin for an RA's lifetime: dnsmasq counts its PIO
// lifetimes down between RAs and the plugin refreshes on every RA
// (RFC 4861 section 6.2.1), so the ceiling is the largest PIO seen.
func pioLft(got int64, last, ceiling uint32, elapsed time.Duration) bool {
	return got > 0 && got <= int64(ceiling) && got >= int64(last)-int64(elapsed/time.Second)-lftSlack
}

// d2Obs is what D2 reads for one container.
type d2Obs struct {
	Msgs    []DHCP6Msg
	RAs     []RAMsg
	Leases  []sourceadapter.Lease6
	MAC     string
	Start   d6Read
	Settled d6Read
	Inspect string
}

// judgeD2 -- SLAAC (plugin docs/reference.md, ipv6_mode): `slaac` forms
// the address "from a router advertisement's autonomous prefix ... and
// sends no Solicit", the modified EUI-64 of the MAC by default
// (ipv6_iid), with the PIO's lifetimes. The prefix must be in an RA this
// scenario captured before the start read, and the address is the
// container's own MAC's, so a leftover address cannot pass (design
// defeat 5).
func judgeD2(o d2Obs) fOutcome {
	for _, m := range o.Msgs {
		if isClient6(m.Type) {
			return fFail("the container sent a DHCPv6 %s although ipv6_mode=slaac sends no Solicit", m.Type)
		}
	}
	return slaacFormed(o)
}

// slaacFormed is judgeD2 past its Solicit rule, shared with D3b and the
// fallback leg of D3c, where auto forms the same address (docs,
// ipv6_mode: "a clear flag means the prefix") (#23 rows D2, D3b).
func slaacFormed(o d2Obs) fOutcome {
	var pio PIO
	var last RAMsg
	var maxValid, maxPref uint32
	found := false
	for _, ra := range o.RAs {
		if ra.At.After(o.Settled.At) {
			continue
		}
		for _, p := range ra.PIOs {
			if !p.Auto || (found && p.Prefix != pio.Prefix) {
				continue
			}
			pio, last, found = p, ra, true
			maxValid, maxPref = max(maxValid, p.Valid), max(maxPref, p.Pref)
		}
	}
	if !found {
		return fBlocked("the capture shows no RA with an autonomous prefix before the settled read (%d RAs)", len(o.RAs))
	}
	want, err := eui64(pio.Prefix, o.MAC)
	if err != nil {
		return fBlocked("%v", err)
	}
	if _, ok := findAddr6(o.Start.Addrs, want); !ok {
		return fFail("right after docker run returned the container's link has no %s (%s plus the modified EUI-64 of %s)", want, pio.Prefix, o.MAC)
	}
	if !raBefore(o.RAs, pio.Prefix, o.Start.At) {
		return fFail("%s was on the link at the start read, but the capture shows no RA with %s before it", want, pio.Prefix)
	}
	for _, r := range []d6Read{o.Start, o.Settled} {
		if extra, bad := leftover(r.Addrs, want); bad {
			return fFail("the container's link also carries %s; the RA formed only %s", extra, want)
		}
	}
	s, ok := findAddr6(o.Settled.Addrs, want)
	if !ok {
		return fFail("%s was gone from the link once settled", want)
	}
	elapsed := o.Settled.At.Sub(last.At)
	if !pioLft(s.Valid, pio.Valid, maxValid, elapsed) || !pioLft(s.Pref, pio.Pref, maxPref, elapsed) {
		return fFail("%s carries valid %d preferred %d once settled, the last RA's PIO stated %d/%d %s before", want, s.Valid, s.Pref, pio.Valid, pio.Pref, elapsed.Round(time.Second))
	}
	if o.Inspect != want.String() {
		return fFail("docker inspect reports GlobalIPv6Address %q, the link holds %s", o.Inspect, want)
	}
	mac := strings.ToLower(o.MAC)
	for _, l := range o.Leases {
		if strings.HasSuffix(l.DUID, mac) {
			return fFail("the source's DHCPv6 table holds %s for DUID %s, which carries the container's MAC", l.Address, l.DUID)
		}
	}
	return fOK("%s formed from RA prefix %s (modified EUI-64 of %s), valid %d preferred %d once settled (PIO %d/%d); no Solicit, no lease; inspect agrees",
		want, pio.Prefix, o.MAC, s.Valid, s.Pref, pio.Valid, pio.Pref)
}

// judgeNoRA: SetRA Off is proven by the wire, not by the config: any RA
// captured after it leaves the row BLOCKED.
func judgeNoRA(ras []RAMsg) (fOutcome, bool) {
	if len(ras) > 0 {
		return fBlocked("%d RAs from %s on the wire after SetRA Off; the segment still advertises", len(ras), ras[0].Src), false
	}
	return fOutcome{}, true
}

// judgeD1c (plugin docs/reference.md, "Networks where DHCPv6 offers no
// address"): "Advertised nothing at all, on `ipv6_mode=dhcp` ... Starts
// the endpoint without a DHCPv6 address". The source's DHCPv6 server
// keeps running with its RAs off, and the docs add that "a server that is
// there answers a Solicit whether or not a router advertises", so a Reply
// on the wire puts the row outside that table: then the granted address
// must be on the link and in inspect, with nothing beyond it.
func judgeD1c(startErr error, msgs []DHCP6Msg, settled []addr6, inspect string) fOutcome {
	if startErr != nil {
		return fFail("the container did not start with no RA on the segment: %v", startErr)
	}
	solicits := 0
	var granted []netip.Addr
	for _, m := range msgs {
		switch {
		case m.Type == "SOLICIT":
			solicits++
		case m.Type == "REPLY":
			for _, ia := range m.NA {
				if ia.Addr.IsValid() {
					granted = append(granted, ia.Addr)
				}
			}
		}
	}
	if extra, bad := leftover(settled, granted...); bad {
		return fFail("with no RA on the segment the container's link carries %s, which no Reply granted", extra)
	}
	if len(granted) > 0 {
		var onLink netip.Addr
		for _, g := range granted {
			if _, ok := findAddr6(settled, g); ok {
				onLink = g
				break
			}
		}
		if !onLink.IsValid() {
			return fFail("with no RA on the segment a Reply granted %v, but the container's link carries none of it (link %v)", granted, globals(settled))
		}
		if inspect != onLink.String() {
			return fFail("with no RA on the segment docker inspect reports GlobalIPv6Address %q, the Reply and the link hold %s", inspect, onLink)
		}
		return fOK("no RA on the segment: the endpoint started; the source still answered the Solicit with %s, on the link and in inspect, so the docs' no-advertisement row does not apply (%d Solicits, recorded)", onLink, solicits)
	}
	if inspect != "" {
		return fFail("with no RA on the segment docker inspect reports GlobalIPv6Address %s", inspect)
	}
	return fOK("no RA on the segment: the endpoint started without an IPv6 address (%d Solicits on the wire, recorded)", solicits)
}

// judgeEndpointFails is D2b (docs: "Advertised nothing at all, on
// `ipv6_mode=slaac` ... **Fails the endpoint**").
func judgeEndpointFails(startErr error) fOutcome {
	if startErr == nil {
		return fFail("the container started with ipv6_mode=slaac and no RA on the segment; the docs fail the endpoint")
	}
	return fOK("no RA on the segment: the endpoint failed (%v)", startErr)
}

// judgeRefused is D2 on ipvlan (docs: "`slaac` and `auto` are refused
// in `mode=ipvlan`").
func judgeRefused(opt string, createErr error) fOutcome {
	if createErr == nil {
		return fFail("docker network create with %s on ipvlan succeeded; the docs refuse it", opt)
	}
	return fOK("docker network create with %s on ipvlan was refused (%v)", opt, createErr)
}
