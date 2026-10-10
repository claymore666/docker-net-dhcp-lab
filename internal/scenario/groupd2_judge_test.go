package scenario

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

var (
	d4P1 = netip.MustParsePrefix("fd42:200:0:100::/64")
	d4P2 = netip.MustParsePrefix("fd42:200:0:101::/64")
)

func mustEUI(t *testing.T, p netip.Prefix) netip.Addr {
	t.Helper()
	a, err := eui64(p, d2MAC)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func raWith(at float64, managed bool, pios ...PIO) RAMsg {
	return RAMsg{At: d6At(at), Src: d6Router, Managed: managed, RouterLifetime: 1800, PIOs: pios}
}

func pio(p netip.Prefix, auto bool) PIO { return PIO{Prefix: p, Auto: auto, Valid: 7200, Pref: 3600} }

// Defeat 6: the M and A bits come from the capture. The row asked for
// M=1 A=0; a wire that says M=0 must not pass, and an A=0 PIO is read
// as A=0.
func TestJudgeRAFlagsReadsTheWireNotTheConfig(t *testing.T) {
	want := sourceadapter.RAParams{Managed: true}
	needOK := func(ras []RAMsg, w sourceadapter.RAParams, ok bool) {
		t.Helper()
		o, got := judgeRAFlags(ras, w)
		if got != ok || (!ok && o.Result != BLOCKED) {
			t.Errorf("ras %+v want %+v: ok %v %s %q", ras, w, got, o.Result, o.Reason)
		}
	}
	needOK([]RAMsg{raWith(0, false, pio(d4P1, false))}, want, false)
	needOK([]RAMsg{raWith(0, true, pio(d4P1, false)), raWith(1, false, pio(d4P1, false))}, want, false)
	needOK([]RAMsg{raWith(0, true, pio(d4P1, false))}, want, true)
	needOK([]RAMsg{raWith(0, true, pio(d4P1, true))}, want, false)
	needOK([]RAMsg{raWith(0, false, pio(d4P1, false))}, sourceadapter.RAParams{Autonomous: true}, false)
	needOK([]RAMsg{raWith(0, false, pio(d4P1, true))}, sourceadapter.RAParams{Autonomous: true}, true)
	needOK(nil, want, false)
}

func d4Good(t *testing.T, ras ...RAMsg) d4Obs {
	a1, a2 := mustEUI(t, d4P1), mustEUI(t, d4P2)
	set := []addr6{d6LL, {Addr: a1, Bits: 64, Scope: "global", Valid: 7180, Pref: 3580}, {Addr: a2, Bits: 64, Scope: "global", Valid: 7180, Pref: 3580}}
	return d4Obs{d2Obs: d2Obs{RAs: ras, MAC: d2MAC, Start: d6Read{At: d6At(1), Addrs: set}, Settled: d6Read{At: d6At(21), Addrs: set}, Inspect: a1.String()}}
}

// Defeat 7: docker inspect holds the first PIO in capture order, so a
// fixture with the PIOs swapped turns the expected address round.
func TestJudgeD4InspectFollowsTheFirstPIOOnTheWire(t *testing.T) {
	a1, a2 := mustEUI(t, d4P1), mustEUI(t, d4P2)
	inOrder := []RAMsg{raWith(-5, false, pio(d4P1, true), pio(d4P2, true)), raWith(5, false, pio(d4P1, true), pio(d4P2, true))}
	swapped := []RAMsg{raWith(-5, false, pio(d4P2, true), pio(d4P1, true)), raWith(5, false, pio(d4P2, true), pio(d4P1, true))}
	o := d4Good(t, inOrder...)
	needF(t, judgeD4(o), PASS, "first advertised")
	o.Inspect = a2.String()
	needF(t, judgeD4(o), FAIL, "first advertised prefix's address")
	o = d4Good(t, swapped...)
	needF(t, judgeD4(o), FAIL, "first advertised prefix's address")
	o.Inspect = a2.String()
	needF(t, judgeD4(o), PASS, "first advertised")
	o = d4Good(t, inOrder[0], swapped[1])
	o.Inspect = a2.String()
	needF(t, judgeD4(o), PASS, "unstable on the wire")
	o = d4Good(t, inOrder...)
	o.Settled.Addrs = o.Settled.Addrs[:2]
	needF(t, judgeD4(o), FAIL, "no "+a2.String())
	o = d4Good(t, raWith(-5, false, pio(d4P1, true), pio(d4P2, false)))
	needF(t, judgeD4(o), BLOCKED, "1 autonomous prefixes")
	o = d4Good(t, inOrder...)
	o.Msgs = []DHCP6Msg{d6Msg(0, "SOLICIT", false, nil, nil)}
	needF(t, judgeD4(o), FAIL, "sends no Solicit")
	_ = a1
}

func TestJudgeD4mInspectFollowsTheMainPrefix(t *testing.T) {
	inOrder := []RAMsg{raWith(-5, false, pio(d4P1, true), pio(d4P2, true))}
	o := d4Good(t, inOrder...)
	o.Main = d4P2
	needF(t, judgeD4(o), FAIL, "ipv6_main_prefix=")
	o.Inspect = mustEUI(t, d4P2).String()
	needF(t, judgeD4(o), PASS, "ipv6_main_prefix's")
	o.Main = netip.MustParsePrefix("fd42:200:0:1ff::/64")
	needF(t, judgeD4(o), BLOCKED, "not among the advertised")
}

func TestJudgeD4bDropAndExpiry(t *testing.T) {
	a1, a2 := mustEUI(t, d4P1), mustEUI(t, d4P2)
	only1 := []addr6{d6LL, {Addr: a1, Bits: 64, Scope: "global"}}
	both := append(only1, addr6{Addr: a2, Bits: 64, Scope: "global"})
	after := []RAMsg{raWith(30, true, pio(d4P1, true))}
	kept := "fd42:200:0:100::/64 dev eth0 proto kernel metric 256\nfd42:200:0:101::/64 dev eth0 proto ra metric 1024 expires 7100sec\n"
	gone := "fd42:200:0:100::/64 dev eth0 proto kernel metric 256\n"
	needF(t, judgeD4bDrop(after, only1, kept, d4P1, d4P2, d2MAC, true), PASS, "route for "+d4P2.String()+" kept")
	needF(t, judgeD4bDrop(after, only1, gone, d4P1, d4P2, d2MAC, true), FAIL, "#1088")
	needF(t, judgeD4bDrop(after, only1, gone, d4P1, d4P2, d2MAC, false), PASS, "not judged before v2.2.3")
	needF(t, judgeD4bDrop(after, both, kept, d4P1, d4P2, d2MAC, true), FAIL, "still on the link")
	needF(t, judgeD4bDrop(after, []addr6{d6LL}, kept, d4P1, d4P2, d2MAC, true), FAIL, "left the link")
	needF(t, judgeD4bDrop(nil, only1, kept, d4P1, d4P2, d2MAC, true), BLOCKED, "no RA after")
	needF(t, judgeD4bDrop([]RAMsg{raWith(30, true, pio(d4P1, true), pio(d4P2, true))}, only1, kept, d4P1, d4P2, d2MAC, true), BLOCKED, "still carries")

	exp := pio(d4P2, true)
	exp.Valid, exp.Pref = 0, 0
	afterExp := []RAMsg{raWith(60, true, pio(d4P1, true), exp)}
	needF(t, judgeD4bExpired(afterExp, only1, gone, d4P2, d2MAC), PASS, "address and route gone")
	needF(t, judgeD4bExpired(afterExp, only1, kept, d4P2, d2MAC), FAIL, "still in the container")
	needF(t, judgeD4bExpired(afterExp, both, gone, d4P2, d2MAC), FAIL, "still on the link")
	needF(t, judgeD4bExpired(after, only1, gone, d4P2, d2MAC), BLOCKED, "valid lifetime 0")
}

func TestRouteForReadsPastTheRouteType(t *testing.T) {
	out := "unreachable fd42:200:0:180::/64 dev lo proto 16 metric 1024 pref medium\nfd42:200:0:100::/64 dev eth0 proto kernel metric 256\ndefault via fe80::1 dev eth0\n"
	if l, ok := routeFor(out, netip.MustParsePrefix("fd42:200:0:180::/64")); !ok || l[:11] != "unreachable" {
		t.Errorf("unreachable route: %q %v", l, ok)
	}
	if _, ok := routeFor(out, netip.MustParsePrefix("fd42:200:0:100::/64")); !ok {
		t.Error("plain route not found")
	}
	if _, ok := routeFor(out, netip.MustParsePrefix("fd42:200:0:181::/64")); ok {
		t.Error("absent route found")
	}
}

// Defeat E: D3c's dhcp and strict legs fail on any start, a SLAAC
// address on the link included.
func TestJudgeD3cFailsLegsCountAStartAsFail(t *testing.T) {
	slaac := []addr6{d6LL, {Addr: mustEUI(t, d4P1), Bits: 64, Scope: "global"}}
	needF(t, judgeD3cFails("ipv6_mode=dhcp", nil, slaac), FAIL, mustEUI(t, d4P1).String())
	needF(t, judgeD3cFails("ipv6_mode=dhcp", nil, nil), FAIL, "fail the endpoint")
	needF(t, judgeD3cFails("ipv6_mode=auto ipv6_auto_strict=true", errors.New("exit 125"), nil), PASS, "endpoint failed")
}

func TestJudgeD3cAutoFallsBackToThePrefix(t *testing.T) {
	o, _ := goodD2(t)
	o.Msgs = []DHCP6Msg{d6Msg(0, "SOLICIT", false, []IA6{{IAID: 1}}, nil), d6Msg(1, "SOLICIT", false, []IA6{{IAID: 1}}, nil)}
	needF(t, judgeD3cAuto(o, "+1"), PASS, "2 Solicits unanswered")
	o.Msgs = append(o.Msgs, d6Msg(1.1, "REPLY", false, d6IA(d6NA), nil))
	needF(t, judgeD3cAuto(o, "+0"), BLOCKED, "not silent")
	o.Msgs = nil
	needF(t, judgeD3cAuto(o, "+0"), FAIL, "no Solicit")
	o.Msgs = []DHCP6Msg{d6Msg(0, "SOLICIT", false, []IA6{{IAID: 1}}, nil)}
	o.Inspect = ""
	needF(t, judgeD3cAuto(o, "+1"), FAIL, "docker inspect")
}

// Defeat D: the health reader matches the endpoint, not the first entry.
func TestParseHealthEndpointPicksTheRightEndpointsPrefixes(t *testing.T) {
	body := `{"dhcpv6_auto_fallbacks":3,"endpoints":[` +
		`{"endpoint":"aaaaaaaaaaaaaaaa","delegated_prefixes":[{"prefix":"fd42:200:0:181::/64"}],"nat64_prefixes":["64:ff9b::/96"]},` +
		`{"endpoint":"bbbbbbbbbbbbbbbb","delegated_prefixes":[{"prefix":"fd42:200:0:180::/64"}],"nat64_prefixes":["fd42:200:0:164::/96"]}]}`
	h, ok, err := parseHealthEndpoint(body, "bbbbbbbbbbbb")
	if err != nil || !ok || len(h.DelegatedPrefixes) != 1 || h.DelegatedPrefixes[0].Prefix != "fd42:200:0:180::/64" || h.NAT64Prefixes[0] != "fd42:200:0:164::/96" {
		t.Errorf("got %+v %v %v", h, ok, err)
	}
	if n, ok := healthCounter(body, "dhcpv6_auto_fallbacks"); !ok || n != 3 {
		t.Errorf("counter %d %v", n, ok)
	}
	if _, ok := healthCounter(body, "dhcpv6_absence_remembered"); ok {
		t.Error("an absent counter read as present")
	}
	if _, ok := healthCounter(`{"dhcpv6_auto_fallbacks":"x"}`, "dhcpv6_auto_fallbacks"); ok {
		t.Error("a string counter read as a number")
	}
}

func TestV6DeriveStaysInsideTheCellsSlash56(t *testing.T) {
	p, err := v6Derive("fd42:200:0:100::/64")
	if err != nil || p.Second.String() != "fd42:200:0:101::/64" || p.Pref64.String() != "fd42:200:0:164::/96" || p.PDPool.String() != "fd42:200:0:180::/57" {
		t.Errorf("got %+v %v", p, err)
	}
	for _, bad := range []string{"fd42:200:0:101::/64", "fd42:200:0:100::/56", "10.200.1.0/24", ""} {
		if _, err := v6Derive(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

var f6PD = netip.MustParsePrefix("fd42:200:0:180::/64")

func goodF6() (d1Obs, string, healthEndpoint) {
	o := goodD1()
	for i := range o.Msgs {
		o.Msgs[i].PD = []IA6{{IAID: 2}}
	}
	o.Msgs[3].PD = []IA6{{IAID: 2, Prefix: f6PD, Valid: 7200, Pref: 3600}}
	o.Leases = append(o.Leases, sourceadapter.Lease6{Type: sourceadapter.Lease6PD, Address: f6PD.Addr(), Prefix: f6PD, DUID: d6DUID, IAID: 2})
	return o, "unreachable fd42:200:0:180::/64 dev lo proto dhcp metric 1024 pref medium\n", healthEndpoint{DelegatedPrefixes: []healthPrefix{{Prefix: f6PD.String()}}}
}

func TestJudgeF6(t *testing.T) {
	pool := netip.MustParsePrefix("fd42:200:0:180::/57")
	o, routes, h := goodF6()
	needF(t, judgeF6(o, true, pool, routes, h, true), PASS, "IA_PD "+f6PD.String())
	needF(t, judgeF6(o, true, pool, "unreachable fd42:200:0:180::/64 dev lo proto 16 metric 1024\n", h, true), PASS, "IA_PD")
	needF(t, judgeF6(o, true, pool, "", h, true), FAIL, "unreachable")
	needF(t, judgeF6(o, true, pool, routes, healthEndpoint{}, true), FAIL, "delegated_prefixes")
	needF(t, judgeF6(o, true, pool, routes, h, false), FAIL, "no entry")
	needF(t, judgeF6(o, false, pool, routes, h, true), BLOCKED, "out of date")
	needF(t, judgeF6(o, true, netip.MustParsePrefix("fd42:200:0:200::/57"), routes, h, true), BLOCKED, "outside")
	bad := o
	bad.Leases = bad.Leases[:1]
	needF(t, judgeF6(bad, true, pool, routes, h, true), FAIL, "no IA_PD")
	o2, _, _ := goodF6()
	o2.Msgs[2].PD = nil
	needF(t, judgeF6(o2, true, pool, routes, h, true), FAIL, "REQUEST carries no IA_PD")
	o3, _, _ := goodF6()
	o3.Msgs[3].PD = []IA6{{IAID: 2}}
	needF(t, judgeF6(o3, false, pool, "", healthEndpoint{}, true), PASS, "delegates no prefix")
	needF(t, judgeF6(o3, true, pool, "", healthEndpoint{}, true), FAIL, "although the source has a PD pool")
	needF(t, judgeF6(o3, false, pool, routes, healthEndpoint{}, true), FAIL, "still has")
	needF(t, judgeF6(o3, false, pool, "", h, true), FAIL, "delegated_prefixes")
}

func TestJudgeF7(t *testing.T) {
	p64 := netip.MustParsePrefix("fd42:200:0:164::/96")
	ras := []RAMsg{raWith(-5, true, pio(d4P1, true))}
	ras[0].Pref64 = []netip.Prefix{p64}
	routes := "fd42:200:0:100::/64 dev eth0 proto kernel metric 256\ndefault via fe80::1 dev eth0 proto ra metric 1024 expires 1790sec\n"
	good := f7Reads{Addrs: []addr6{d6LL}, Routes: routes, Routes2: "fd42:200:0:100::/64 dev eth0 proto kernel metric 256\ndefault via fe80::1 dev eth0 proto ra metric 1024 expires 1775sec\n",
		Resolv: "nameserver 10.200.1.1\n", Resolv2: "nameserver 10.200.1.1\n", Health: healthEndpoint{NAT64Prefixes: []string{"fd42:200:0:164::/96"}}, Found: true}
	needF(t, judgeF7(ras, true, good), PASS, "equals the RA's PREF64")
	r := good
	r.Health.NAT64Prefixes = nil
	needF(t, judgeF7(ras, true, r), FAIL, "nat64_prefixes")
	r = good
	r.Addrs = append(r.Addrs, addr6{Addr: netip.MustParseAddr("fd42:200:0:164::1"), Bits: 128, Scope: "global"})
	needF(t, judgeF7(ras, true, r), FAIL, "inside PREF64")
	r = good
	r.Routes = "fd42:200:0:164::/96 dev eth0 metric 1024\n"
	r.Routes2 = r.Routes
	needF(t, judgeF7(ras, true, r), FAIL, "route")
	r = good
	r.Resolv2 = "nameserver fd42:200:0:164::35\n"
	needF(t, judgeF7(ras, true, r), FAIL, "resolv.conf")
	r = good
	r.Routes2 = "default via fe80::1 dev eth0\n"
	needF(t, judgeF7(ras, true, r), FAIL, "routes changed")
	needF(t, judgeF7([]RAMsg{raWith(-5, true, pio(d4P1, true))}, true, good), BLOCKED, "no RA carrying it")
	needF(t, judgeF7(ras, false, good), BLOCKED, "out of date")
	neg := good
	neg.Health = healthEndpoint{}
	needF(t, judgeF7([]RAMsg{raWith(-5, true, pio(d4P1, true))}, false, neg), PASS, "carries no PREF64")
	needF(t, judgeF7([]RAMsg{raWith(-5, true, pio(d4P1, true))}, false, good), FAIL, "nat64_prefixes")
}
