package scenario

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

var (
	d6T0     = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	d6DUID   = "00:03:00:01:02:42:ac:11:00:02"
	d6NA     = netip.MustParseAddr("fd42:200:0:100::150")
	d6TA     = netip.MustParseAddr("fd42:200:0:100::210")
	d6Router = netip.MustParseAddr("fe80::1")
	d6LL     = addr6{Addr: netip.MustParseAddr("fe80::42:acff:fe11:2"), Bits: 64, Scope: "link", Valid: forever, Pref: forever}
)

func d6At(s float64) time.Time { return d6T0.Add(time.Duration(s * float64(time.Second))) }

func d6Msg(at float64, typ string, rapid bool, na, ta []IA6) DHCP6Msg {
	return DHCP6Msg{At: d6At(at), Type: typ, XID: "abc123", ClientDUID: d6DUID, Rapid: rapid, NA: na, TA: ta}
}

// confirmPair is the persistent client's Confirm and the server's Reply
// to it, which carries a Status Code and no IA (RFC 8415 section 18.2.12;
// synthetic, plugin #1369).
func confirmPair(at float64) []DHCP6Msg {
	return []DHCP6Msg{d6Msg(at, "CONFIRM", false, []IA6{{IAID: 1, Addr: d6NA}}, nil), d6Msg(at+0.1, "REPLY", false, nil, nil)}
}

func d6IA(a netip.Addr) []IA6 { return []IA6{{IAID: 1, Addr: a, Pref: 3600, Valid: 7200}} }

// goodD1 is a passing four-message D1 observation; each test breaks one
// thing in it.
func goodD1() d1Obs {
	return d1Obs{
		Msgs: []DHCP6Msg{
			d6Msg(0, "SOLICIT", false, []IA6{{IAID: 1}}, nil),
			d6Msg(0.1, "ADVERTISE", false, d6IA(d6NA), nil),
			d6Msg(0.2, "REQUEST", false, d6IA(d6NA), nil),
			d6Msg(0.3, "REPLY", false, d6IA(d6NA), nil),
		},
		RAs:    []RAMsg{{At: d6At(-1), Src: d6Router, Managed: true, RouterLifetime: 1800}},
		Leases: []sourceadapter.Lease6{{Type: sourceadapter.Lease6NA, Address: d6NA, DUID: d6DUID, IAID: 1}},
		Start: d6Read{At: d6At(1), Addrs: []addr6{d6LL,
			{Addr: d6NA, Bits: 128, Scope: "global", Valid: forever, Pref: forever}}},
		Settled: d6Read{At: d6At(21), Addrs: []addr6{d6LL,
			{Addr: d6NA, Bits: 128, Scope: "global", Valid: 7180, Pref: 3580}}},
		Inspect:  d6NA.String(),
		Route:    d6Router,
		HasRoute: true,
	}
}

func needF(t *testing.T, got fOutcome, want Result, sub string) {
	t.Helper()
	if got.Result != want || !strings.Contains(got.Reason, sub) {
		t.Errorf("got %s %q, want %s containing %q", got.Result, got.Reason, want, sub)
	}
}

func TestJudgeD1(t *testing.T) {
	cases := map[string]struct {
		mut  func(*d1Obs)
		want Result
		sub  string
	}{
		"good, forever at start":          {func(*d1Obs) {}, PASS, "default route via fe80::1"},
		"forever once settled":            {func(o *d1Obs) { o.Settled.Addrs[1].Valid = forever }, FAIL, "-1 is forever"},
		"settled above the Reply":         {func(o *d1Obs) { o.Settled.Addrs[1].Valid = 7300 }, FAIL, "stated 7200/3600"},
		"settled lifetime 0":              {func(o *d1Obs) { o.Settled.Addrs[1].Pref = 0 }, FAIL, "stated 7200/3600"},
		"settled below the count-down":    {func(o *d1Obs) { o.Settled.Addrs[1].Valid = 7000 }, FAIL, "stated 7200/3600"},
		"start above the Reply":           {func(o *d1Obs) { o.Start.Addrs[1].Valid = 9000 }, FAIL, "at start"},
		"start preferred above the Reply": {func(o *d1Obs) { o.Start.Addrs[1].Pref = 5000 }, FAIL, "at start"},
		"not a /128":                      {func(o *d1Obs) { o.Start.Addrs[1].Bits = 64 }, FAIL, "as /64"},
		"missing at start":                {func(o *d1Obs) { o.Start.Addrs = o.Start.Addrs[:1] }, FAIL, "right after docker run"},
		"gone once settled":               {func(o *d1Obs) { o.Settled.Addrs = o.Settled.Addrs[:1] }, FAIL, "gone from the link"},
		"leftover address": {func(o *d1Obs) {
			o.Settled.Addrs = append(o.Settled.Addrs, addr6{Addr: netip.MustParseAddr("fd42:200:0:100::99"), Bits: 128, Scope: "global", Valid: 10, Pref: 10})
		}, FAIL, "fd42:200:0:100::99"},
		"leftover only at start": {func(o *d1Obs) {
			o.Start.Addrs = append(o.Start.Addrs, addr6{Addr: netip.MustParseAddr("fd42:200:0:100::98"), Bits: 128, Scope: "global", Valid: 10, Pref: 10})
		}, FAIL, "fd42:200:0:100::98"},
		"inspect differs from the link": {func(o *d1Obs) { o.Inspect = "fd42:200:0:100::151" }, FAIL, "docker inspect"},
		"inspect empty":                 {func(o *d1Obs) { o.Inspect = "" }, FAIL, "docker inspect"},
		"no lease in the table":         {func(o *d1Obs) { o.Leases = nil }, FAIL, "holds no IA_NA"},
		"lease under another DUID":      {func(o *d1Obs) { o.Leases[0].DUID = "00:01" }, FAIL, "holds no IA_NA"},
		"no route":                      {func(o *d1Obs) { o.HasRoute = false }, FAIL, "no IPv6 default route"},
		"route via another router":      {func(o *d1Obs) { o.Route = netip.MustParseAddr("fe80::9") }, FAIL, "goes via fe80::9"},
		"RAs only with lifetime 0":      {func(o *d1Obs) { o.RAs[0].RouterLifetime = 0 }, BLOCKED, "router lifetime above 0"},
		"no RA":                         {func(o *d1Obs) { o.RAs = nil }, BLOCKED, "router lifetime above 0"},
		"ping fails":                    {func(o *d1Obs) { o.PingErr = errors.New("100% loss") }, FAIL, "does not answer"},
		"no Reply with an address":      {func(o *d1Obs) { o.Msgs = o.Msgs[:3] }, FAIL, "no Reply granted"},
		"no client message":             {func(o *d1Obs) { o.Msgs = nil }, FAIL, "no DHCPv6 message"},
		"two client DUIDs": {func(o *d1Obs) {
			m := o.Msgs[0]
			m.ClientDUID = "00:03:00:01:02:42:ac:11:00:03"
			o.Msgs = append(o.Msgs, m)
		}, BLOCKED, "2 client DUIDs"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o := goodD1()
			c.mut(&o)
			got, _ := judgeD1(o)
			needF(t, got, c.want, c.sub)
		})
	}
}

func rapidX(t *testing.T, msgs []DHCP6Msg) d6Exchange {
	t.Helper()
	x, out, ok := exchange6(msgs)
	if !ok {
		t.Fatalf("exchange6: %v", out)
	}
	return x
}

func TestJudgeF4Wire(t *testing.T) {
	two := []DHCP6Msg{d6Msg(0, "SOLICIT", true, []IA6{{IAID: 1}}, nil), d6Msg(0.1, "REPLY", true, d6IA(d6NA), nil)}
	four := goodD1().Msgs
	fourAsked := goodD1().Msgs
	fourAsked[0].Rapid = true
	twoNoOpt := []DHCP6Msg{two[0], two[1]}
	twoNoOpt[1].Rapid = false

	needF(t, judgeF4Wire(true, true, rapidX(t, two)), PASS, "two messages")
	needF(t, judgeF4Wire(false, false, rapidX(t, four)), PASS, "option 14 = false")
	needF(t, judgeF4Wire(true, false, rapidX(t, fourAsked)), PASS, "option 14 = true")
	needF(t, judgeF4Wire(true, true, rapidX(t, fourAsked)), FAIL, "want SOLICIT REPLY")
	needF(t, judgeF4Wire(true, true, rapidX(t, four)), FAIL, "option 14 = false, want true")
	needF(t, judgeF4Wire(false, false, rapidX(t, fourAsked)), FAIL, "option 14 = true, want false")
	needF(t, judgeF4Wire(false, false, rapidX(t, two)), FAIL, "option 14 = true, want false")
	needF(t, judgeF4Wire(true, false, rapidX(t, two)), FAIL, "want SOLICIT ADVERTISE REQUEST REPLY")
	needF(t, judgeF4Wire(true, true, rapidX(t, twoNoOpt)), FAIL, "carries no option 14")
}

// goodF5 is goodD1 with an IA_TA asked for and granted.
func goodF5() d1Obs {
	o := goodD1()
	for i := range o.Msgs {
		switch o.Msgs[i].Type {
		case "SOLICIT":
			o.Msgs[i].TA = []IA6{{IAID: 2}}
		default:
			o.Msgs[i].TA = d6IA(d6TA)
		}
	}
	o.Start.Addrs = append(o.Start.Addrs, addr6{Addr: d6TA, Bits: 128, Scope: "global", Valid: forever, Pref: forever})
	o.Settled.Addrs = append(o.Settled.Addrs, addr6{Addr: d6TA, Bits: 128, Scope: "global", Valid: 7180, Pref: 3580})
	o.Leases = append(o.Leases, sourceadapter.Lease6{Type: sourceadapter.Lease6TA, Address: d6TA, DUID: d6DUID, IAID: 2})
	return o
}

// keaF5 is the fallback: the client asks for an IA_TA, the Reply grants
// the IA_NA alone.
func keaF5() d1Obs {
	o := goodD1()
	for i := range o.Msgs {
		if isClient6(o.Msgs[i].Type) {
			o.Msgs[i].TA = []IA6{{IAID: 2}}
		}
	}
	return o
}

func TestJudgeF5(t *testing.T) {
	ta := d6TA.String() + "/128"
	needF(t, judgeF5(goodF5(), true, true, true, ta), PASS, "IA_TA "+d6TA.String()+" granted")
	needF(t, judgeF5(keaF5(), true, false, true, ""), PASS, "runs as without the key")
	needF(t, judgeF5(goodD1(), false, true, false, ""), PASS, "runs as without the key")

	needF(t, judgeF5(goodF5(), true, false, true, ta), BLOCKED, "capability table is out of date")
	needF(t, judgeF5(keaF5(), true, true, true, ""), FAIL, "grants no IA_TA")
	needF(t, judgeF5(goodD1(), true, true, true, ""), FAIL, "a SOLICIT carries an IA_TA = false")
	needF(t, judgeF5(keaF5(), false, false, false, ""), FAIL, "a SOLICIT carries an IA_TA = true")
	needF(t, judgeF5(keaF5(), true, false, false, ""), FAIL, "no entry for the endpoint")
	needF(t, judgeF5(keaF5(), true, false, true, ta), FAIL, "no Reply granted one")
	needF(t, judgeF5(goodF5(), true, true, true, "fd42:200:0:100::211/128"), FAIL, "/Plugin.Health shows")
	needF(t, judgeF5(goodF5(), true, true, true, ""), FAIL, "/Plugin.Health shows")

	noTA := goodF5()
	noTA.Settled.Addrs = noTA.Settled.Addrs[:2]
	needF(t, judgeF5(noTA, true, true, true, ta), FAIL, "not on the container's link")
	forever6 := goodF5()
	forever6.Settled.Addrs[2].Valid = forever
	needF(t, judgeF5(forever6, true, true, true, ta), FAIL, "carries valid -1")
	noRow := goodF5()
	noRow.Leases = noRow.Leases[:1]
	needF(t, judgeF5(noRow, true, true, true, ta), FAIL, "holds no IA_TA")
	inspTA := goodF5()
	inspTA.Inspect = d6TA.String()
	needF(t, judgeF5(inspTA, true, true, true, ta), FAIL, "docker inspect")
	// The TA is allowed beside the lease only when granted.
	extra := keaF5()
	extra.Settled.Addrs = append(extra.Settled.Addrs, addr6{Addr: d6TA, Bits: 128, Scope: "global", Valid: 100, Pref: 100})
	needF(t, judgeF5(extra, true, false, true, ""), FAIL, "which no Reply granted")
}

var d2MAC = "02:42:ac:11:00:02"

func goodD2(t *testing.T) (d2Obs, netip.Addr) {
	t.Helper()
	p := netip.MustParsePrefix("fd42:200:0:100::/64")
	want, err := eui64(p, d2MAC)
	if err != nil {
		t.Fatal(err)
	}
	return d2Obs{
		RAs: []RAMsg{
			{At: d6At(-5), Src: d6Router, RouterLifetime: 1800, PIOs: []PIO{{Prefix: p, Auto: true, Valid: 7200, Pref: 3600}}},
			{At: d6At(5), Src: d6Router, RouterLifetime: 1800, PIOs: []PIO{{Prefix: p, Auto: true, Valid: 7190, Pref: 3590}}},
		},
		MAC:     d2MAC,
		Start:   d6Read{At: d6At(1), Addrs: []addr6{d6LL, {Addr: want, Bits: 64, Scope: "global", Valid: 7200, Pref: 3600}}},
		Settled: d6Read{At: d6At(21), Addrs: []addr6{d6LL, {Addr: want, Bits: 64, Scope: "global", Valid: 7175, Pref: 3575}}},
		Inspect: want.String(),
	}, want
}

func TestJudgeD2(t *testing.T) {
	_, want := goodD2(t)
	if want.String() != "fd42:200:0:100:42:acff:fe11:2" {
		t.Fatalf("eui64 = %s", want)
	}
	cases := map[string]struct {
		mut  func(*d2Obs)
		want Result
		sub  string
	}{
		"good":  {func(*d2Obs) {}, PASS, "modified EUI-64"},
		"no RA": {func(o *d2Obs) { o.RAs = nil }, BLOCKED, "no RA with an autonomous prefix"},
		"RA after the settled read": {func(o *d2Obs) {
			for i := range o.RAs {
				o.RAs[i].At = d6At(30)
			}
		}, BLOCKED, "no RA with an autonomous prefix"},
		"RA only after the start read": {func(o *d2Obs) { o.RAs[0].At = d6At(3) }, FAIL, "no RA with fd42:200:0:100::/64 before it"},
		"only another prefix before the start read": {func(o *d2Obs) {
			o.RAs[0].At = d6At(3)
			o.RAs[1].At = d6At(-5)
			o.RAs[1].PIOs[0].Prefix = netip.MustParsePrefix("fd42:200:0:300::/64")
		}, FAIL, "no RA with fd42:200:0:100::/64 before it"},
		"A flag off": {func(o *d2Obs) {
			for i := range o.RAs {
				o.RAs[i].PIOs[0].Auto = false
			}
		}, BLOCKED, "no RA with an autonomous prefix"},
		"a Solicit": {func(o *d2Obs) { o.Msgs = []DHCP6Msg{d6Msg(0, "SOLICIT", false, nil, nil)} }, FAIL, "sends no Solicit"},
		"an Information-request alone (stateless network, lab #70 row 1)": {func(o *d2Obs) {
			o.Msgs = []DHCP6Msg{d6Msg(0, "INFORMATION-REQUEST", false, nil, nil)}
		}, PASS, "modified EUI-64"},
		"an Information-request then a Solicit": {func(o *d2Obs) {
			o.Msgs = []DHCP6Msg{d6Msg(0, "INFORMATION-REQUEST", false, nil, nil), d6Msg(1, "SOLICIT", false, nil, nil)}
		}, FAIL, "DHCPv6 SOLICIT"},
		"a Request": {func(o *d2Obs) { o.Msgs = []DHCP6Msg{d6Msg(0, "REQUEST", false, nil, nil)} }, FAIL, "DHCPv6 REQUEST"},
		"a Decline": {func(o *d2Obs) { o.Msgs = []DHCP6Msg{d6Msg(0, "DECLINE", false, nil, nil)} }, FAIL, "DHCPv6 DECLINE"},
		"a Release": {func(o *d2Obs) { o.Msgs = []DHCP6Msg{d6Msg(0, "RELEASE", false, nil, nil)} }, FAIL, "DHCPv6 RELEASE"},
		"leftover address only": {func(o *d2Obs) {
			other := addr6{Addr: netip.MustParseAddr("fd42:200:0:100::77"), Bits: 128, Scope: "global", Valid: 7000, Pref: 3000}
			o.Start.Addrs = []addr6{d6LL, other}
			o.Settled.Addrs = []addr6{d6LL, other}
			o.Inspect = other.Addr.String()
		}, FAIL, "right after docker run"},
		"leftover beside it": {func(o *d2Obs) {
			o.Settled.Addrs = append(o.Settled.Addrs, addr6{Addr: netip.MustParseAddr("fd42:200:0:100::77"), Bits: 128, Scope: "global", Valid: 70, Pref: 30})
		}, FAIL, "also carries fd42:200:0:100::77"},
		"forever once settled":  {func(o *d2Obs) { o.Settled.Addrs[1].Valid = forever }, FAIL, "once settled"},
		"lifetime 0":            {func(o *d2Obs) { o.Settled.Addrs[1].Pref = 0 }, FAIL, "once settled"},
		"above the largest PIO": {func(o *d2Obs) { o.Settled.Addrs[1].Valid = 7300 }, FAIL, "once settled"},
		"gone once settled":     {func(o *d2Obs) { o.Settled.Addrs = o.Settled.Addrs[:1] }, FAIL, "gone from the link"},
		"inspect differs":       {func(o *d2Obs) { o.Inspect = "" }, FAIL, "docker inspect"},
		"a lease for the MAC": {func(o *d2Obs) {
			o.Leases = []sourceadapter.Lease6{{Type: sourceadapter.Lease6NA, Address: d6NA, DUID: "00:03:00:01:" + d2MAC}}
		}, FAIL, "carries the container's MAC"},
		"bad MAC": {func(o *d2Obs) { o.MAC = "zz" }, BLOCKED, "not a 48-bit address"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o, _ := goodD2(t)
			c.mut(&o)
			needF(t, judgeD2(o), c.want, c.sub)
		})
	}
}

func TestJudgeNoRAAndTheNoRARows(t *testing.T) {
	if out, ok := judgeNoRA([]RAMsg{{Src: d6Router}}); ok || out.Result != BLOCKED {
		t.Errorf("an RA after SetRA Off: %v %v", ok, out)
	}
	if _, ok := judgeNoRA(nil); !ok {
		t.Errorf("no RA after SetRA Off was not accepted")
	}
	solicit := []DHCP6Msg{d6Msg(0, "SOLICIT", false, nil, nil), d6Msg(4, "SOLICIT", false, nil, nil)}
	answered := goodD1().Msgs
	naOnLink := []addr6{d6LL, {Addr: d6NA, Bits: 128, Scope: "global", Valid: 7190, Pref: 3590}}
	needF(t, judgeD1c(nil, solicit, []addr6{d6LL}, ""), PASS, "2 Solicits")
	needF(t, judgeD1c(errors.New("exit 125"), nil, nil, ""), FAIL, "did not start")
	needF(t, judgeD1c(errors.New("exit 125"), answered, nil, ""), FAIL, "did not start")
	needF(t, judgeD1c(nil, solicit, naOnLink, ""), FAIL, "which no Reply granted")
	needF(t, judgeD1c(nil, solicit, []addr6{d6LL}, d6NA.String()), FAIL, "docker inspect")
	needF(t, judgeD1c(nil, answered, naOnLink, d6NA.String()), PASS, "does not apply")
	needF(t, judgeD1c(nil, answered, []addr6{d6LL}, ""), FAIL, "carries none of it")
	needF(t, judgeD1c(nil, answered, []addr6{d6LL}, d6NA.String()), FAIL, "carries none of it")
	needF(t, judgeD1c(nil, answered, naOnLink, ""), FAIL, "docker inspect")
	needF(t, judgeD1c(nil, answered, naOnLink, "fd42:200:0:100::99"), FAIL, "docker inspect")
	other := append(append([]addr6{}, naOnLink...), addr6{Addr: netip.MustParseAddr("fd42:200:0:100::99"), Bits: 128, Scope: "global"})
	needF(t, judgeD1c(nil, answered, other, d6NA.String()), FAIL, "fd42:200:0:100::99")
	needF(t, judgeEndpointFails(errors.New("exit 125")), PASS, "endpoint failed")
	needF(t, judgeEndpointFails(nil), FAIL, "fail the endpoint")
	needF(t, judgeRefused("ipv6_mode=slaac", errors.New("refused")), PASS, "was refused")
	needF(t, judgeRefused("ipv6_mode=slaac", nil), FAIL, "succeeded")
}

func TestParseAddrs6(t *testing.T) {
	out := `1: lo    inet6 ::1/128 scope host noprefixroute \       valid_lft forever preferred_lft forever
42: eth0    inet6 fd42:200:0:100::150/128 scope global dynamic noprefixroute \       valid_lft 7180sec preferred_lft 3580sec
42: eth0    inet6 fe80::42:acff:fe11:2/64 scope link \       valid_lft forever preferred_lft forever`
	as, err := parseAddrs6(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 3 || len(globals(as)) != 1 {
		t.Fatalf("parsed %+v", as)
	}
	g := globals(as)[0]
	if g.Addr != d6NA || g.Bits != 128 || g.Valid != 7180 || g.Pref != 3580 {
		t.Errorf("global = %+v", g)
	}
	if ll, ok := linkLocal(as); !ok || ll != d6LL.Addr {
		t.Errorf("link-local = %v %v", ll, ok)
	}
	if as[0].Valid != forever {
		t.Errorf("forever read as %d", as[0].Valid)
	}
	for _, bad := range []string{
		"42: eth0    inet6 fd42:200:0:100::150/128 scope global",
		"42: eth0    inet6 fd42:200:0:100::150/128 valid_lft 1sec preferred_lft 1sec",
		"42: eth0    inet6 fd42:200:0:100::150/128 scope global valid_lft soon preferred_lft 1sec",
		"42: eth0    inet6 not-an-address scope global valid_lft 1sec preferred_lft 1sec",
	} {
		if _, err := parseAddrs6(bad); err == nil {
			t.Errorf("parseAddrs6(%q) accepted a line it cannot read", bad)
		}
	}
}

func TestParseDefaultRoute6(t *testing.T) {
	if gw, ok := parseDefaultRoute6("default via fe80::1 dev eth0 proto ra metric 1024 expires 1790sec hoplimit 64 pref medium\n"); !ok || gw != d6Router {
		t.Errorf("got %v %v", gw, ok)
	}
	for _, out := range []string{"", "fd42:200:0:100::/64 dev eth0 proto kernel metric 256", "default dev eth0 metric 1024"} {
		if _, ok := parseDefaultRoute6(out); ok {
			t.Errorf("parseDefaultRoute6(%q) found a route", out)
		}
	}
}

func TestParseHealthEndpoint(t *testing.T) {
	body := `{"endpoints":[{"endpoint":"0123456789abcdef0123","ipv6_temporary_address":"fd42:200:0:100::210/128"},{"endpoint":"fedcba9876543210"}]}`
	ep, ok, err := parseHealthEndpoint(body, "0123456789ab")
	if err != nil || !ok || ep.IPv6TemporaryAddress != "fd42:200:0:100::210/128" {
		t.Errorf("short id: %+v %v %v", ep, ok, err)
	}
	if ep, ok, _ := parseHealthEndpoint(body, "fedcba9876543210ffff"); !ok || ep.IPv6TemporaryAddress != "" {
		t.Errorf("long id against a short entry: %+v %v", ep, ok)
	}
	if _, ok, _ := parseHealthEndpoint(body, "aaaaaaaaaaaaaaaa"); ok {
		t.Errorf("an unknown endpoint was found")
	}
	if _, _, err := parseHealthEndpoint(body, "0123"); err == nil {
		t.Errorf("a 4-character id matched")
	}
	if _, _, err := parseHealthEndpoint("<html>", "0123456789ab"); err == nil {
		t.Errorf("a non-JSON body parsed")
	}
}

func TestEUI64(t *testing.T) {
	p := netip.MustParsePrefix("fd42:200:0:300::/64")
	got, err := eui64(p, "00:16:3E:AA:BB:CC")
	if err != nil || got.String() != "fd42:200:0:300:216:3eff:feaa:bbcc" {
		t.Errorf("got %v %v", got, err)
	}
	if _, err := eui64(netip.MustParsePrefix("fd42:200:0:300::/56"), "00:16:3e:aa:bb:cc"); err == nil {
		t.Errorf("a /56 was accepted")
	}
	if _, err := eui64(p, "00:16:3e:aa:bb:cc:dd:ee"); err == nil {
		t.Errorf("a 64-bit MAC was accepted")
	}
}

func TestV6IdentSkipsWhatIsMissing(t *testing.T) {
	for _, c := range []struct {
		mac  string
		ll   netip.Addr
		want string
	}{
		{"AA:BB:CC:00:00:01", d6LL.Addr, "aa:bb:cc:00:00:01,fe80::42:acff:fe11:2"},
		{"", d6LL.Addr, "fe80::42:acff:fe11:2"},
		{"aa:bb:cc:00:00:01", netip.Addr{}, "aa:bb:cc:00:00:01"},
		{"", netip.Addr{}, "-"},
	} {
		if got := v6Ident(c.mac, c.ll); got != c.want {
			t.Errorf("v6Ident(%q, %v) = %q, want %q", c.mac, c.ll, got, c.want)
		}
	}
}

// The Information-request stays a message from the container for the
// exchange reading and the DUID collection (lab #70 row 1): only the
// slaac judges stop counting it as a request for an address.
func TestInformationRequestStaysAClientMessageForTheExchange(t *testing.T) {
	if !isClient6("INFORMATION-REQUEST") || asksForAddress6("INFORMATION-REQUEST") {
		t.Fatal("isClient6 must count it, asksForAddress6 must not")
	}
	for _, typ := range []string{"SOLICIT", "REQUEST", "CONFIRM", "RENEW", "REBIND", "RELEASE", "DECLINE"} {
		if !asksForAddress6(typ) {
			t.Errorf("%s no longer counts as asking for an address", typ)
		}
	}
	msgs := []DHCP6Msg{d6Msg(0, "INFORMATION-REQUEST", false, nil, nil), d6Msg(1, "REPLY", false, d6IA(d6NA), nil)}
	x, _, ok := exchange6(msgs)
	if !ok || x.DUID != d6DUID {
		t.Errorf("exchange6 lost the DUID of an Information-request: %+v %v", x, ok)
	}
}

// Row 6: the lifetimes are read when the read returns; Start.At and
// Settled.At stay the cut-off for "existed before the read".
func TestD1bElapsedCountsASlowRead(t *testing.T) {
	stated := goodD1()
	stated.Settled.Addrs[1].Valid, stated.Settled.Addrs[1].Pref = 7124, 3524
	stated.Settled.At = d6At(21)
	stated.Settled.Got = d6At(76)
	if out, _ := judgeD1(stated); out.Result != PASS {
		t.Errorf("a 76 s read judged against 76 s: %s %q", out.Result, out.Reason)
	}
	stated.Settled.Got = time.Time{}
	if out, _ := judgeD1(stated); out.Result != FAIL {
		t.Errorf("a countdown of 76 s judged against 21 s must fail: %s %q", out.Result, out.Reason)
	}
}

func TestD1bSlowReadDoesNotRaiseTheCeilingOrAcceptAShortCountdown(t *testing.T) {
	o := goodD1()
	o.Settled.Got = d6At(76)
	o.Settled.Addrs[1].Valid = 7300
	if out, _ := judgeD1(o); out.Result != FAIL {
		t.Errorf("a lifetime above the stated one passed: %s", out.Reason)
	}
	o = goodD1()
	o.Settled.Got = d6At(76)
	o.Settled.Addrs[1].Valid, o.Settled.Addrs[1].Pref = 7000, 3400
	if out, _ := judgeD1(o); out.Result != FAIL {
		t.Errorf("a lifetime 200 s short of the count-down passed: %s", out.Reason)
	}
}

// A slow start read must not turn an RA that arrived during it into one
// that came before it (design defeat 5, lab #70 row 6).
func TestD2SlowStartReadKeepsTheRACutoff(t *testing.T) {
	o, _ := goodD2(t)
	o.RAs[0].At = d6At(3)
	o.Start.At = d6At(1)
	o.Start.Got = d6At(80)
	needF(t, judgeD2(o), FAIL, "no RA with fd42:200:0:100::/64 before it")
}

// The lines are synthetic, shaped as RFC 8415 section 18.2.12 and plugin
// #1371 describe them: the Reply to a Confirm carries a Status Code and no IA.
func TestJudgeF4WireAcceptsTheTrailingConfirm(t *testing.T) {
	confirm := confirmPair
	two := []DHCP6Msg{d6Msg(0, "SOLICIT", true, []IA6{{IAID: 1}}, nil), d6Msg(0.1, "REPLY", true, d6IA(d6NA), nil)}
	four := goodD1().Msgs
	asked := goodD1().Msgs
	asked[0].Rapid = true
	needF(t, judgeF4Wire(true, true, rapidX(t, append(slices.Clone(two), confirm(1)...))), PASS, "Confirm and its Reply")
	needF(t, judgeF4Wire(true, true, rapidX(t, append(slices.Clone(two), append(confirm(1), confirm(2)...)...))), FAIL, "at most one CONFIRM REPLY")
	needF(t, judgeF4Wire(false, false, rapidX(t, append(slices.Clone(four), confirm(1)...))), PASS, "Confirm and its Reply")
	needF(t, judgeF4Wire(true, false, rapidX(t, append(slices.Clone(asked), confirm(1)...))), PASS, "Confirm and its Reply")
	// ADVERTISE and REQUEST stay refused under rapid commit, Confirm or not.
	needF(t, judgeF4Wire(true, true, rapidX(t, append(slices.Clone(asked), confirm(1)...))), FAIL, "want SOLICIT REPLY")
	// A Confirm nothing answers is not the persistent client's pair.
	needF(t, judgeF4Wire(true, true, rapidX(t, append(slices.Clone(two), confirm(1)[0]))), FAIL, "want SOLICIT REPLY")
	needF(t, judgeF4Wire(true, true, rapidX(t, append(slices.Clone(two), confirm(1)[0], d6Msg(1.1, "RENEW", false, d6IA(d6NA), nil)))), FAIL, "want SOLICIT REPLY")
	// A Solicit that repeats under load collapses to one.
	rep := []DHCP6Msg{two[0], d6Msg(0.05, "SOLICIT", true, []IA6{{IAID: 1}}, nil), two[1]}
	needF(t, judgeF4Wire(true, true, rapidX(t, append(rep, confirm(1)...))), PASS, "two messages")
}

// D1 reads the lifetimes the persistent client installs; a row with no
// Confirm, Renew or Rebind inside the window is an attach failure (plugin
// #1369, lab #102). The Confirm lines are synthetic.
func TestJudgeD1PersistentSeparatesAttachFromLifetimes(t *testing.T) {
	o := goodD1()
	o.Msgs = append(o.Msgs, confirmPair(1)...)
	out, _ := judgeD1Persistent(o)
	needF(t, out, PASS, "IA_NA")

	bare := goodD1()
	out, _ = judgeD1Persistent(bare)
	needF(t, out, FAIL, "attach failure")
	if out.Reason == "" || strings.Contains(out.Reason, "carries valid") {
		t.Errorf("an attach failure reads as a lifetime fault: %q", out.Reason)
	}

	late := goodD1()
	late.Msgs = append(late.Msgs, confirmPair(30)...)
	out, _ = judgeD1Persistent(late)
	needF(t, out, FAIL, "attach failure")

	early := goodD1()
	early.Msgs = append(early.Msgs, confirmPair(0.05)...)
	out, _ = judgeD1Persistent(early)
	needF(t, out, FAIL, "attach failure")

	rebind := goodD1()
	rebind.Msgs = append(rebind.Msgs, d6Msg(1, "REBIND", false, d6IA(d6NA), nil), d6Msg(1.1, "REPLY", false, d6IA(d6NA), nil))
	out, _ = judgeD1Persistent(rebind)
	needF(t, out, PASS, "IA_NA")

	stuck := goodD1()
	stuck.Msgs = append(stuck.Msgs, confirmPair(1)...)
	stuck.Settled.Addrs[1].Valid, stuck.Settled.Addrs[1].Pref = forever, forever
	out, _ = judgeD1Persistent(stuck)
	needF(t, out, FAIL, "-1 is forever")

	above := goodD1()
	above.Msgs = append(above.Msgs, confirmPair(1)...)
	above.Settled.Addrs[1].Valid = 7300
	out, _ = judgeD1Persistent(above)
	needF(t, out, FAIL, "carries valid 7300")
}
