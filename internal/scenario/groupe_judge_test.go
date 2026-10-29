package scenario

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group E judge tests (lab #15 PR 2). The defeat rows are numbered as in
// the design's list; "own" rows are this build's.

const (
	eMAC = "02:aa:bb:cc:dd:01"
	eIP  = "10.200.1.150"
	eSrv = "10.200.1.2"
)

var eT0 = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func eAt(sec float64) time.Time { return eT0.Add(time.Duration(sec * float64(time.Second))) }

func srvEv(typ, ip string, sec float64) sourceadapter.ServerEvent {
	return sourceadapter.ServerEvent{At: eAt(sec).Truncate(time.Second), Type: typ, MAC: eMAC, IP: ip}
}

func wireMsg(typ, xid, ciaddr, yiaddr, dst string, sec float64) DHCPMsg {
	return DHCPMsg{At: eAt(sec), Type: typ, XID: xid, CHAddr: eMAC, CIAddr: ciaddr, YIAddr: yiaddr, Dst: dst}
}

func boundWire(xid, ip string, sec float64) []DHCPMsg {
	return []DHCPMsg{
		wireMsg("DISCOVER", xid, "", "", "255.255.255.255", sec),
		wireMsg("OFFER", xid, "", ip, "255.255.255.255", sec+0.01),
		wireMsg("REQUEST", xid, "", "", "255.255.255.255", sec+0.02),
		wireMsg("ACK", xid, "", ip, "255.255.255.255", sec+0.03),
	}
}

func renewWire(xid, ip string, sec float64) []DHCPMsg {
	return []DHCPMsg{
		wireMsg("REQUEST", xid, ip, "", eSrv, sec),
		wireMsg("ACK", xid, "", ip, ip, sec+0.01),
	}
}

func led(kind, ip string) LedgerEntry {
	return LedgerEntry{TS: eAt(0), Kind: kind, IP: ip, Endpoint: strings.Repeat("a", 64)}
}

func cat(parts ...[]DHCPMsg) []DHCPMsg {
	var out []DHCPMsg
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func happyE1() e1Obs {
	return e1Obs{
		Server:       []sourceadapter.ServerEvent{srvEv("ACK", eIP, 0), srvEv("ACK", eIP, 20), srvEv("RELEASE", eIP, 31)},
		Ledger:       []LedgerEntry{led("bound", eIP), led("renew", eIP), led("stopped", eIP)},
		Wire:         cat(boundWire("a1", eIP, 0), renewWire("b2", eIP, 20)),
		ReleasesSent: 1,
	}
}

func wantOutcome(t *testing.T, got fOutcome, res Result, sub string) {
	t.Helper()
	if got.Result != res || !strings.Contains(got.Reason, sub) {
		t.Errorf("got %s %q, want %s containing %q", got.Result, got.Reason, res, sub)
	}
}

func TestJudgeE1HappyPath(t *testing.T) {
	wantOutcome(t, judgeE1(happyE1()), PASS, "matches the wire")
}

// Row 1: 0 == 0 must never pass.
func TestJudgeE1ZeroServerLinesIsBlockedNotPass(t *testing.T) {
	wantOutcome(t, judgeE1(e1Obs{}), BLOCKED, "no ACK")
}

// Server ACKs with an empty capture name the missing wire side, not a
// misalignment (#15).
func TestJudgeE1EmptyCaptureNamesTheWireSide(t *testing.T) {
	o := happyE1()
	o.Wire = nil
	wantOutcome(t, judgeE1(o), BLOCKED, "no wire side")
}

func TestJudgeE1EmptyLedgerWithServerACKsFails(t *testing.T) {
	o := happyE1()
	o.Ledger = nil
	wantOutcome(t, judgeE1(o), FAIL, "0 bound and 0 renew")
}

// Row 2.
func TestJudgeE1LedgerAbsentIsBlocked(t *testing.T) {
	o := happyE1()
	o.LedgerAbsent = true
	wantOutcome(t, judgeE1(o), BLOCKED, "absent")
}

// Row 3: no timestamp is compared across machines; the order of
// addresses decides.
func TestJudgeE1SkewedClocksSameVerdict(t *testing.T) {
	o := happyE1()
	for i := range o.Server {
		o.Server[i].At = o.Server[i].At.Add(7 * time.Hour)
	}
	for i := range o.Ledger {
		o.Ledger[i].TS = o.Ledger[i].TS.Add(-5 * time.Hour)
	}
	wantOutcome(t, judgeE1(o), PASS, "")
}

func TestJudgeE1IPOrderDecides(t *testing.T) {
	o := e1Obs{
		Server:       []sourceadapter.ServerEvent{srvEv("ACK", "10.200.1.150", 0), srvEv("ACK", "10.200.1.151", 20), srvEv("RELEASE", "10.200.1.151", 31)},
		Wire:         cat(boundWire("a1", "10.200.1.150", 0), renewWire("b2", "10.200.1.151", 20)),
		Ledger:       []LedgerEntry{led("bound", "10.200.1.151"), led("renew", "10.200.1.150")},
		ReleasesSent: 1,
	}
	wantOutcome(t, judgeE1(o), FAIL, "order")
	o.Ledger = []LedgerEntry{led("bound", "10.200.1.150"), led("renew", "10.200.1.151")}
	wantOutcome(t, judgeE1(o), PASS, "")
}

// Row 4: a duplicate ACK inside the window is one exchange; outside it
// the witnesses disagree and nothing passes.
func TestJudgeE1DuplicateACKInsideWindowIsOneGroup(t *testing.T) {
	o := happyE1()
	o.Server = append([]sourceadapter.ServerEvent{srvEv("ACK", eIP, 0), srvEv("ACK", eIP, 1)}, o.Server[1:]...)
	wantOutcome(t, judgeE1(o), PASS, "")
}

func TestJudgeE1DuplicateACKOutsideWindowIsBlocked(t *testing.T) {
	o := happyE1()
	o.Server = append([]sourceadapter.ServerEvent{srvEv("ACK", eIP, 0), srvEv("ACK", eIP, 5)}, o.Server[1:]...)
	wantOutcome(t, judgeE1(o), BLOCKED, "disagree")
}

// Row 5: Kea's four-type view and the six-type view give one verdict.
func TestJudgeE1KeaFourTypeViewEqualsSixTypeView(t *testing.T) {
	six := happyE1()
	six.Server = []sourceadapter.ServerEvent{
		srvEv("DISCOVER", "", 0), srvEv("OFFER", eIP, 0), srvEv("REQUEST", eIP, 0), srvEv("ACK", eIP, 0),
		srvEv("REQUEST", eIP, 20), srvEv("ACK", eIP, 20), srvEv("RELEASE", eIP, 31),
	}
	four := happyE1()
	four.Server = []sourceadapter.ServerEvent{srvEv("OFFER", eIP, 0), srvEv("ACK", eIP, 0), srvEv("ACK", eIP, 20), srvEv("RELEASE", eIP, 31)}
	a, b := judgeE1(six), judgeE1(four)
	if a != b || a.Result != PASS {
		t.Errorf("six-type %v, four-type %v", a, b)
	}
}

// Own A: the plugin's immediate late-hostname renew lands inside the 3 s
// window of the bound ACK; the source merges them, the ledger has two.
func TestJudgeE1BoundPlusImmediateRenewIsTwoLedgerEntries(t *testing.T) {
	o := happyE1()
	o.Server = []sourceadapter.ServerEvent{srvEv("ACK", eIP, 0), srvEv("ACK", eIP, 1), srvEv("ACK", eIP, 20), srvEv("RELEASE", eIP, 31)}
	o.Wire = cat(boundWire("a1", eIP, 0), renewWire("c3", eIP, 1.2), renewWire("b2", eIP, 20))
	o.Ledger = []LedgerEntry{led("bound", eIP), led("renew", eIP), led("renew", eIP), led("stopped", eIP)}
	wantOutcome(t, judgeE1(o), PASS, "")
	o.Ledger = []LedgerEntry{led("bound", eIP), led("renew", eIP), led("stopped", eIP)}
	wantOutcome(t, judgeE1(o), FAIL, "2 renew")
}

// Own B: the design's plausible defect, a double bound for one ACK.
func TestJudgeE1DoubleBoundFails(t *testing.T) {
	o := happyE1()
	o.Ledger = []LedgerEntry{led("bound", eIP), led("bound", eIP), led("renew", eIP)}
	wantOutcome(t, judgeE1(o), FAIL, "2 bound")
}

// Own C.
func TestJudgeE1LedgerEventWithoutGroupFails(t *testing.T) {
	o := happyE1()
	o.Ledger = append(o.Ledger, led("renew", eIP))
	wantOutcome(t, judgeE1(o), FAIL, "2 renew")
}

func TestJudgeE1GroupWithoutLedgerEventFails(t *testing.T) {
	o := happyE1()
	o.Ledger = []LedgerEntry{led("bound", eIP)}
	wantOutcome(t, judgeE1(o), FAIL, "0 renew")
}

// Own D.
func TestJudgeE1ReleaseLikeLedgerKindFails(t *testing.T) {
	for _, k := range []string{"release", "release_failed"} {
		o := happyE1()
		o.Ledger = append(o.Ledger, led(k, eIP))
		wantOutcome(t, judgeE1(o), FAIL, "release-like")
	}
}

func TestJudgeE1ReleaseCounterWithoutServerReleaseFails(t *testing.T) {
	o := happyE1()
	o.Server = o.Server[:2]
	wantOutcome(t, judgeE1(o), FAIL, "0 RELEASE")
	o = happyE1()
	o.ReleasesSent = 0
	wantOutcome(t, judgeE1(o), FAIL, "moved by 0")
	o = happyE1()
	o.Server = append(o.Server, srvEv("RELEASE", eIP, 32))
	o.ReleasesSent = 2
	wantOutcome(t, judgeE1(o), FAIL, "2 RELEASE")
}

// Own E.
func TestJudgeE1DeclineFails(t *testing.T) {
	o := happyE1()
	o.Server = append(o.Server, srvEv("DECLINE", eIP, 32))
	wantOutcome(t, judgeE1(o), FAIL, "DECLINE")
}

// Own F.
func TestJudgeE1NoRenewalInWindowIsBlocked(t *testing.T) {
	o := happyE1()
	o.Server = []sourceadapter.ServerEvent{srvEv("ACK", eIP, 0), srvEv("RELEASE", eIP, 31)}
	o.Wire = boundWire("a1", eIP, 0)
	o.Ledger = []LedgerEntry{led("bound", eIP)}
	wantOutcome(t, judgeE1(o), BLOCKED, "renew half")
}

// Own G.
func TestJudgeE1UnknownLedgerKindIsBlocked(t *testing.T) {
	o := happyE1()
	o.Ledger = append(o.Ledger, led("migrated", eIP))
	wantOutcome(t, judgeE1(o), BLOCKED, "unknown kind")
}

// Own M: a rebind or INIT-REBOOT exchange is not covered by any ledger kind.
func TestJudgeE1UnclassifiableExchangeFails(t *testing.T) {
	o := happyE1()
	rebind := []DHCPMsg{wireMsg("REQUEST", "d4", eIP, "", "255.255.255.255", 40), wireMsg("ACK", "d4", "", eIP, eIP, 40.01)}
	o.Wire = cat(boundWire("a1", eIP, 0), renewWire("b2", eIP, 20), rebind)
	o.Server = []sourceadapter.ServerEvent{srvEv("ACK", eIP, 0), srvEv("ACK", eIP, 20), srvEv("ACK", eIP, 40), srvEv("RELEASE", eIP, 51)}
	wantOutcome(t, judgeE1(o), FAIL, "rebind")
}

// Row 13: each server's real journal shape, through its real adapter.
type journalRunner struct{ reply string }

func (j journalRunner) Run(context.Context, string) (string, error) { return j.reply, nil }

func TestJudgeE1EachServersJournalFixture(t *testing.T) {
	since := time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name, file string
		mk         func(sourceadapter.Runner) sourceadapter.Adapter
	}{
		{"kea", "journal-kea.txt", func(r sourceadapter.Runner) sourceadapter.Adapter { return &sourceadapter.KeaAdapter{Runner: r} }},
		{"isc", "journal-isc.txt", func(r sourceadapter.Runner) sourceadapter.Adapter { return &sourceadapter.ISCDHCPAdapter{Runner: r} }},
		{"dnsmasq", "journal-dnsmasq.txt", func(r sourceadapter.Runner) sourceadapter.Adapter { return &sourceadapter.DnsmasqAdapter{Runner: r} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := os.ReadFile("../sourceadapter/testdata/" + c.file)
			if err != nil {
				t.Fatal(err)
			}
			evs, err := c.mk(journalRunner{string(raw)}).ServerEvents(context.Background(), since, "02:aa:bb:cc:dd:01")
			if err != nil {
				t.Fatal(err)
			}
			var wire []DHCPMsg
			var ledger []LedgerEntry
			for i, ev := range evs {
				if ev.Type != "ACK" {
					continue
				}
				at := float64(ev.At.Unix() - eT0.Unix())
				if len(wire) == 0 {
					wire = append(wire, boundWire("x0", ev.IP, at)...)
					ledger = append(ledger, led("bound", ev.IP))
				} else {
					wire = append(wire, renewWire("x"+string(rune('a'+i)), ev.IP, at)...)
					ledger = append(ledger, led("renew", ev.IP))
				}
			}
			o := e1Obs{Server: evs, Wire: wire, Ledger: ledger, ReleasesSent: 1}
			wantOutcome(t, judgeE1(o), PASS, "")
		})
	}
}

// E2.

func eCounters(v map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for _, n := range e2Names {
		out[n+"_v4"] = v[n]
		out[n+"_v6"] = 0
		out[n] = v[n]
	}
	return out
}

func happyE2() e2Obs {
	before := map[string]int64{"leases_obtained": 7, "leases_renewed": 3, "releases_sent": 2}
	after := map[string]int64{"leases_obtained": 8, "leases_renewed": 4, "releases_sent": 3}
	h := happyE1()
	return e2Obs{
		Server: h.Server, Wire: h.Wire,
		Before: eCounters(before), After: eCounters(after), Health: eCounters(after),
		InstanceBefore: "i1", InstanceAfter: "i1",
		AddrBefore: eIP, AddrAfter: eIP, Address: eIP,
	}
}

func TestJudgeE2HappyPath(t *testing.T) {
	wantOutcome(t, judgeE2(happyE2()), PASS, "obtained +1, renewed +1, released +1")
}

func TestJudgeE2ZeroServerACKsIsBlocked(t *testing.T) {
	o := happyE2()
	o.Server = nil
	wantOutcome(t, judgeE2(o), BLOCKED, "no ACK")
}

func TestJudgeE2EachInequalityFails(t *testing.T) {
	for _, c := range []struct {
		name string
		mut  func(*e2Obs)
		sub  string
	}{
		{"obtained", func(o *e2Obs) { o.After["leases_obtained_v4"]++ }, "leases_obtained moved by 2"},
		{"renewed", func(o *e2Obs) { o.After["leases_renewed_v4"]-- }, "leases_renewed moved by 0"},
		{"released", func(o *e2Obs) { o.After["releases_sent_v4"]++ }, "releases_sent moved by 2"},
		{"nak counter", func(o *e2Obs) { o.After["naks_received_v4"]++ }, "naks_received moved by 1"},
		{"nak on wire", func(o *e2Obs) { o.Wire = append(o.Wire, wireMsg("NAK", "z9", "", "", "255.255.255.255", 25)) }, "NAK"},
		{"nak in log", func(o *e2Obs) { o.Server = append(o.Server, srvEv("NAK", "", 25)) }, "naks_received moved by 0, the source's NAK lines says 1"},
		{"timeouts", func(o *e2Obs) { o.After["dhcp_timeouts_v4"] = 1 }, "dhcp_timeouts moved by 1"},
		{"unanswered", func(o *e2Obs) { o.After["renewals_unanswered_v4"] = 2 }, "renewals_unanswered moved by 2"},
		{"lease_changed", func(o *e2Obs) { o.After["lease_changed_v4"] = 1 }, "lease_changed moved by 1"},
		{"address", func(o *e2Obs) { o.AddrAfter = "10.200.1.151" }, "address changed"},
		{"ack ip", func(o *e2Obs) { o.Address = "10.200.1.151" }, "container holds"},
		{"views", func(o *e2Obs) { o.Health["leases_renewed_v4"]++ }, "/Plugin.Health says"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := happyE2()
			c.mut(&o)
			wantOutcome(t, judgeE2(o), FAIL, c.sub)
		})
	}
}

// Row 7: plugin-wide counters.
func TestJudgeE2ExtraCounterMovementFails(t *testing.T) {
	o := happyE2()
	o.After["lease_changed_v4"] = 1
	o.Health["lease_changed_v4"] = 1
	o.Health["lease_changed"] = 1
	wantOutcome(t, judgeE2(o), FAIL, "lease_changed")
}

func TestJudgeE2PluginRestartIsBlocked(t *testing.T) {
	o := happyE2()
	o.InstanceAfter = "i2"
	wantOutcome(t, judgeE2(o), BLOCKED, "instance changed")
	o = happyE2()
	o.After["leases_obtained_v4"] = 0
	wantOutcome(t, judgeE2(o), BLOCKED, "restarted")
}

// Own I and J.
func TestJudgeE2HealthMetricsDisagreementFails(t *testing.T) {
	o := happyE2()
	o.Health["releases_sent"] = 99
	wantOutcome(t, judgeE2(o), FAIL, "sum=99")
	o = happyE2()
	delete(o.Health, "leases_obtained_v6")
	wantOutcome(t, judgeE2(o), FAIL, "lacks")
}

func TestJudgeE2MissingSeriesIsBlocked(t *testing.T) {
	o := happyE2()
	delete(o.After, "naks_received_v4")
	wantOutcome(t, judgeE2(o), BLOCKED, "missing")
}

func TestJudgeE2NoRenewalIsBlocked(t *testing.T) {
	o := happyE2()
	o.Server = []sourceadapter.ServerEvent{srvEv("ACK", eIP, 0), srvEv("RELEASE", eIP, 31)}
	o.Wire = boundWire("a1", eIP, 0)
	wantOutcome(t, judgeE2(o), BLOCKED, "renew half")
}

const metricsBody = `# HELP net_dhcp_build_info Plugin build.
# TYPE net_dhcp_build_info gauge
net_dhcp_build_info{instance_id="abc123",version="v2.6.1",commit="x",library="y"} 1

# TYPE net_dhcp_leases_obtained_total counter
net_dhcp_leases_obtained_total{family="ipv4"} 8
net_dhcp_leases_obtained_total{family="ipv6"} 0
net_dhcp_leases_renewed_total{family="ipv4"} 4
net_dhcp_leases_renewed_total{family="ipv6"} 0
net_dhcp_lease_changed_total{family="ipv4"} 0
net_dhcp_lease_changed_total{family="ipv6"} 0
net_dhcp_renewals_unanswered_total{family="ipv4"} 0
net_dhcp_renewals_unanswered_total{family="ipv6"} 0
net_dhcp_dhcp_timeouts_total{family="ipv4"} 0
net_dhcp_dhcp_timeouts_total{family="ipv6"} 0
net_dhcp_naks_received_total{family="ipv4"} 0
net_dhcp_naks_received_total{family="ipv6"} 0
net_dhcp_releases_sent_total{family="ipv4"} 3
net_dhcp_releases_sent_total{family="ipv6"} 0
net_dhcp_healthy 1
`

func TestParseMetrics(t *testing.T) {
	c, id, err := parseMetrics(metricsBody)
	if err != nil || id != "abc123" || c["leases_obtained_v4"] != 8 || c["releases_sent_v4"] != 3 || len(c) != 14 {
		t.Fatalf("got %v %q %v", c, id, err)
	}
}

func TestParseMetricsRejectsGarbage(t *testing.T) {
	for name, body := range map[string]string{
		"float":    strings.Replace(metricsBody, "ipv4\"} 8", "ipv4\"} 8.5", 1),
		"no label": strings.Replace(metricsBody, `{family="ipv4"} 8`, " 8", 1),
		"missing":  strings.Replace(metricsBody, "net_dhcp_releases_sent_total{family=\"ipv6\"} 0\n", "", 1),
		"no id":    strings.Replace(metricsBody, "instance_id=\"abc123\"", "other=\"x\"", 1),
		"empty":    "",
	} {
		if _, _, err := parseMetrics(body); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestParseEHealth(t *testing.T) {
	body := `{"instance_id":"abc123","active_endpoints":0,"leases_obtained":1,"leases_obtained_v4":1,"leases_obtained_v6":0,"leases_renewed":0,"leases_renewed_v4":0,"leases_renewed_v6":0,"lease_changed":0,"lease_changed_v4":0,"lease_changed_v6":0,"renewals_unanswered":0,"renewals_unanswered_v4":0,"renewals_unanswered_v6":0,"dhcp_timeouts":0,"dhcp_timeouts_v4":0,"dhcp_timeouts_v6":0,"naks_received":0,"naks_received_v4":0,"naks_received_v6":0,"releases_sent":0,"releases_sent_v4":0,"releases_sent_v6":0}`
	h, err := parseEHealth(body)
	if err != nil || h.Instance != "abc123" || h.Active != 0 || h.Counters["leases_obtained_v4"] != 1 {
		t.Fatalf("got %+v %v", h, err)
	}
	if _, err := parseEHealth(strings.Replace(body, `"active_endpoints":0,`, "", 1)); err == nil {
		t.Error("a body without active_endpoints parsed")
	}
	if _, err := parseEHealth(strings.Replace(body, `"releases_sent_v6":0`, `"x":0`, 1)); err == nil {
		t.Error("a body without releases_sent_v6 parsed")
	}
}
