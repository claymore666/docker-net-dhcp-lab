package scenario

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group E judges (lab #15): pure functions over what the source logged,
// what the plugin's ledger and counters said, and what the wire showed.
// A count is only ever tied across machines by (MAC, IP) and order, never
// by a timestamp; a timestamp is compared inside one witness only.

// eWindow is design D3's tolerance: ACKs for one (MAC, yiaddr) inside it
// are one exchange. It is the only tolerance; no count is ever slack.
const eWindow = 3 * time.Second

const (
	eBound = "bound"
	eRenew = "renew"
	eOther = "other"
)

// wireExchange is one XID's exchange that ended in an ACK. Class says
// what started it: a DISCOVER (bound), a unicast REQUEST carrying ciaddr
// (renew), or anything else, which no ledger kind covers (#15 row M).
type wireExchange struct {
	XID, Class, IP, Start string
	At                    time.Time
}

func classifyStart(st DHCPMsg, seen bool) (class, why string) {
	switch {
	case !seen:
		return eOther, "an ACK whose request is not in the capture"
	case st.Type == "DISCOVER":
		return eBound, "DISCOVER"
	case st.Type == "REQUEST" && st.CIAddr != "" && st.CIAddr != "0.0.0.0" && st.Dst != "255.255.255.255":
		return eRenew, "unicast REQUEST with ciaddr"
	case st.Type == "REQUEST" && st.CIAddr != "":
		return eOther, "broadcast REQUEST with ciaddr (a rebind)"
	case st.Type == "REQUEST":
		return eOther, "REQUEST without ciaddr (INIT-REBOOT)"
	}
	return eOther, st.Type
}

// wireExchanges lists the exchanges in the order their first ACK appears.
func wireExchanges(msgs []DHCPMsg) []wireExchange {
	starts := map[string]DHCPMsg{}
	acked := map[string]bool{}
	var out []wireExchange
	for _, m := range msgs {
		switch m.Type {
		case "DISCOVER", "REQUEST", "INFORM":
			if _, ok := starts[m.XID]; !ok {
				starts[m.XID] = m
			}
		case "ACK":
			if acked[m.XID] {
				continue
			}
			acked[m.XID] = true
			st, seen := starts[m.XID]
			class, why := classifyStart(st, seen)
			out = append(out, wireExchange{XID: m.XID, Class: class, IP: m.YIAddr, Start: why, At: m.At})
		}
	}
	return out
}

// eGroup is the server-side unit of D3: the ACK lines for one address
// inside eWindow of the first.
type eGroup struct {
	IP    string
	First time.Time
	Lines int
}

func windowGroups(n int, ip func(i int) string, at func(i int) time.Time) []eGroup {
	var groups []eGroup
	open := map[string]int{}
	for i := 0; i < n; i++ {
		k := ip(i)
		if gi, ok := open[k]; ok && at(i).Sub(groups[gi].First) <= eWindow {
			groups[gi].Lines++
			continue
		}
		open[k] = len(groups)
		groups = append(groups, eGroup{IP: k, First: at(i), Lines: 1})
	}
	return groups
}

func serverGroups(acks []sourceadapter.ServerEvent) []eGroup {
	return windowGroups(len(acks), func(i int) string { return acks[i].IP }, func(i int) time.Time { return acks[i].At })
}

func exchangeGroups(ex []wireExchange) []eGroup {
	return windowGroups(len(ex), func(i int) string { return ex[i].IP }, func(i int) time.Time { return ex[i].At })
}

func groupIPs(g []eGroup) string {
	ips := make([]string, len(g))
	for i := range g {
		ips[i] = g[i].IP
	}
	return "[" + strings.Join(ips, " ") + "]"
}

// alignGroups proves the two witnesses saw the same exchanges, in the
// same address order. A disagreement is the witnesses' (a retransmit
// outside the window, a missed line), never the plugin's verdict.
func alignGroups(sg, wg []eGroup) error {
	if len(sg) == len(wg) {
		same := true
		for i := range sg {
			same = same && sg[i].IP == wg[i].IP
		}
		if same {
			return nil
		}
	}
	return fmt.Errorf("the source logged %d ACK groups %s, the wire shows %d %s", len(sg), groupIPs(sg), len(wg), groupIPs(wg))
}

// eTally keeps the four types every source logs (Kea logs only these at
// INFO, #15 row 5); DISCOVER, REQUEST and OFFER lines never count.
func eTally(server []sourceadapter.ServerEvent) (acks []sourceadapter.ServerEvent, releases, declines, naks int) {
	for _, ev := range server {
		switch ev.Type {
		case "ACK":
			acks = append(acks, ev)
		case "RELEASE":
			releases++
		case "DECLINE":
			declines++
		case "NAK":
			naks++
		}
	}
	return acks, releases, declines, naks
}

func eCount(ex []wireExchange, class string) int {
	n := 0
	for _, x := range ex {
		if x.Class == class {
			n++
		}
	}
	return n
}

func eUnclassified(ex []wireExchange) []string {
	var out []string
	for _, x := range ex {
		if x.Class == eOther {
			out = append(out, fmt.Sprintf("exchange %s for %s started by %s is neither a DISCOVER nor a unicast renewal", x.XID, x.IP, x.Start))
		}
	}
	return out
}

// eAligned is the shared front of both judges: it returns the wire
// exchanges, or the BLOCKED outcome that says why they cannot be judged.
func eAligned(server []sourceadapter.ServerEvent, wire []DHCPMsg) (acks []sourceadapter.ServerEvent, ex []wireExchange, releases, declines, naks int, blk *fOutcome) {
	acks, releases, declines, naks = eTally(server)
	b := func(format string, a ...any) { o := fBlocked(format, a...); blk = &o }
	if len(acks) == 0 {
		b("the source logged no ACK for this client, so a count of 0 equals 0 proves nothing")
		return
	}
	ex = wireExchanges(wire)
	if len(ex) == 0 {
		b("the capture holds no ACK for this client, so there is no wire side to tie the logs to")
		return
	}
	if err := alignGroups(serverGroups(acks), exchangeGroups(ex)); err != nil {
		b("the witnesses disagree before any plugin number is read: %v", err)
		return
	}
	if eCount(ex, eRenew) == 0 {
		b("no unicast renewal ACK in the window, so the renew half of the rule was not exercised")
	}
	return
}

// e1Obs is everything judgeE1 reads. ReleasesSent is the releases_sent_v4
// delta over the window.
type e1Obs struct {
	Server       []sourceadapter.ServerEvent
	Ledger       []LedgerEntry
	LedgerAbsent bool
	Wire         []DHCPMsg
	ReleasesSent int64
}

// judgeE1 -- the ledger and the source's own log must tell the same
// story: one bound entry per DISCOVER-started exchange, one renew per
// unicast renewal, in the same address order, and the one release the
// source logged is the one the plugin counted (#15 E1).
func judgeE1(o e1Obs) fOutcome {
	if o.LedgerAbsent {
		return fBlocked("the audit ledger is absent (audit_log not set, or STATE_DIR repointed), so there is nothing to compare")
	}
	acks, ex, releases, declines, _, blk := eAligned(o.Server, o.Wire)
	if blk != nil {
		return *blk
	}
	var gotKinds, gotIPs []string
	var fails []string
	for _, l := range o.Ledger {
		switch {
		case strings.HasPrefix(l.Kind, "release"):
			fails = append(fails, fmt.Sprintf("ledger has a release-like entry %q; releases are counted, never ledgered", l.Kind))
		case l.Kind == eBound || l.Kind == eRenew:
			gotKinds = append(gotKinds, l.Kind)
			gotIPs = append(gotIPs, l.IP)
		case l.Kind == "stopped" || l.Kind == "stop_failed":
		default:
			return fBlocked("ledger entry of unknown kind %q: this judge does not know what it means", l.Kind)
		}
	}
	fails = append(fails, eUnclassified(ex)...)
	var wantKinds, wantIPs []string
	for _, x := range ex {
		if x.Class != eOther {
			wantKinds = append(wantKinds, x.Class)
			wantIPs = append(wantIPs, x.IP)
		}
	}
	bound, renew := eCount(ex, eBound), eCount(ex, eRenew)
	gb, gr := countKind(gotKinds, eBound), countKind(gotKinds, eRenew)
	switch {
	case gb != bound || gr != renew:
		fails = append(fails, fmt.Sprintf("ledger has %d bound and %d renew entries, the wire shows %d DISCOVER-started and %d renewal exchanges", gb, gr, bound, renew))
	case pairSeq(gotKinds, gotIPs) != pairSeq(wantKinds, wantIPs):
		fails = append(fails, fmt.Sprintf("ledger order %s differs from the wire's %s", pairSeq(gotKinds, gotIPs), pairSeq(wantKinds, wantIPs)))
	}
	if declines > 0 {
		fails = append(fails, fmt.Sprintf("the source logged %d DECLINE", declines))
	}
	if releases != 1 {
		fails = append(fails, fmt.Sprintf("the source logged %d RELEASE, want exactly 1 after release_lease=on_stop", releases))
	}
	if int64(releases) != o.ReleasesSent {
		fails = append(fails, fmt.Sprintf("the source logged %d RELEASE but releases_sent_v4 moved by %d", releases, o.ReleasesSent))
	}
	if len(fails) > 0 {
		return fFail("%s", strings.Join(fails, "; "))
	}
	return fOK("ledger %s matches the wire and the source's %d ACK groups in address order; 1 source RELEASE equals releases_sent_v4; no DECLINE", pairSeq(gotKinds, gotIPs), len(serverGroups(acks)))
}

func countKind(kinds []string, k string) int {
	n := 0
	for _, x := range kinds {
		if x == k {
			n++
		}
	}
	return n
}

func pairSeq(kinds, ips []string) string {
	parts := make([]string, len(kinds))
	for i := range kinds {
		parts[i] = kinds[i] + " " + ips[i]
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// e2Names are the counters E2 reads, as /Plugin.Health spells them
// without the family suffix.
var e2Names = []string{"leases_obtained", "leases_renewed", "lease_changed", "renewals_unanswered", "dhcp_timeouts", "naks_received", "releases_sent"}

// e2Obs is everything judgeE2 reads. Before and After are the /metrics
// series (keys such as leases_obtained_v4); Health is the /Plugin.Health
// read taken between them, keyed the same plus the unsuffixed sum.
type e2Obs struct {
	Server                         []sourceadapter.ServerEvent
	Wire                           []DHCPMsg
	Before, After, Health          map[string]int64
	InstanceBefore, InstanceAfter  string
	AddrBefore, AddrAfter, Address string
}

// judgeE2 -- every counter that moved over the window must have moved by
// what the source's own log and the wire show, and the two views of the
// plugin's counters must be one snapshot (#15 E2).
func judgeE2(o e2Obs) fOutcome {
	if o.InstanceBefore == "" || o.InstanceBefore != o.InstanceAfter {
		return fBlocked("the plugin instance changed or is unreadable (%q to %q): counters restarted inside the window", o.InstanceBefore, o.InstanceAfter)
	}
	delta := map[string]int64{}
	for _, n := range e2Names {
		k := n + "_v4"
		b, okb := o.Before[k]
		a, oka := o.After[k]
		if !okb || !oka {
			return fBlocked("the %s series is missing from a /metrics scrape", k)
		}
		if a < b {
			return fBlocked("%s went from %d to %d: the plugin restarted inside the window", k, b, a)
		}
		delta[n] = a - b
	}
	_, ex, releases, _, naks, blk := eAligned(o.Server, o.Wire)
	if blk != nil {
		return *blk
	}
	var fails []string
	eq := func(name string, want int, what string) {
		if delta[name] != int64(want) {
			fails = append(fails, fmt.Sprintf("%s moved by %d, %s says %d", name, delta[name], what, want))
		}
	}
	eq("leases_obtained", eCount(ex, eBound), "the wire's DISCOVER-started exchanges")
	eq("leases_renewed", eCount(ex, eRenew), "the wire's unicast renewal exchanges")
	eq("releases_sent", releases, "the source's RELEASE lines")
	eq("naks_received", naks, "the source's NAK lines")
	for _, m := range o.Wire {
		if m.Type == "NAK" {
			fails = append(fails, "the capture shows a NAK for this client")
			break
		}
	}
	for _, n := range []string{"dhcp_timeouts", "renewals_unanswered", "lease_changed"} {
		if delta[n] != 0 {
			fails = append(fails, fmt.Sprintf("%s moved by %d, want 0", n, delta[n]))
		}
	}
	fails = append(fails, eUnclassified(ex)...)
	if o.AddrBefore != o.AddrAfter {
		fails = append(fails, fmt.Sprintf("the lease table address changed from %s to %s", o.AddrBefore, o.AddrAfter))
	}
	for _, x := range ex {
		if x.IP != o.Address {
			fails = append(fails, fmt.Sprintf("an ACK granted %s but the container holds %s", x.IP, o.Address))
			break
		}
	}
	fails = append(fails, viewsDisagree(o.After, o.Health)...)
	if len(fails) > 0 {
		return fFail("%s", strings.Join(fails, "; "))
	}
	return fOK("obtained +%d, renewed +%d, released +%d match the source's log and the wire; timeouts, unanswered, lease_changed and NAKs flat; /metrics and /Plugin.Health agree",
		delta["leases_obtained"], delta["leases_renewed"], delta["releases_sent"])
}

// viewsDisagree compares /metrics with /Plugin.Health, which the plugin
// renders from one snapshot (docs/reference.md "/metrics"): each family
// half equal, the health sum equal to both halves.
func viewsDisagree(metrics, health map[string]int64) []string {
	var out []string
	for _, n := range e2Names {
		m4, m6 := metrics[n+"_v4"], metrics[n+"_v6"]
		h4, ok4 := health[n+"_v4"]
		h6, ok6 := health[n+"_v6"]
		h, ok := health[n]
		if !ok4 || !ok6 || !ok {
			out = append(out, fmt.Sprintf("/Plugin.Health lacks %s", n))
			continue
		}
		if h4 != m4 || h6 != m6 || h != m4+m6 {
			out = append(out, fmt.Sprintf("%s: /Plugin.Health says v4=%d v6=%d sum=%d, /metrics says v4=%d v6=%d", n, h4, h6, h, m4, m6))
		}
	}
	return out
}

var (
	metricCounterRE = regexp.MustCompile(`^net_dhcp_([a-z0-9_]+)_total\{family="(ipv4|ipv6)"\} ([0-9]+)$`)
	metricBuildRE   = regexp.MustCompile(`^net_dhcp_build_info\{instance_id="([^"]*)"`)
)

// parseMetrics reads the counters E2 needs from a /metrics body, keyed
// like /Plugin.Health (leases_obtained_v4). A line of one of those
// series that does not parse is an error, and so is a missing series:
// a scrape that lost a counter must never read as zero.
func parseMetrics(text string) (map[string]int64, string, error) {
	want := map[string]bool{}
	for _, n := range e2Names {
		want[n] = true
	}
	counters := map[string]int64{}
	instance := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := metricBuildRE.FindStringSubmatch(line); m != nil {
			instance = m[1]
			continue
		}
		m := metricCounterRE.FindStringSubmatch(line)
		if m == nil {
			if name, _, _ := strings.Cut(strings.TrimPrefix(line, "net_dhcp_"), "_total"); strings.HasPrefix(line, "net_dhcp_") && want[name] {
				return nil, "", fmt.Errorf("metrics line %q is not an integer counter with a family label", line)
			}
			continue
		}
		if !want[m[1]] {
			continue
		}
		v, err := strconv.ParseInt(m[3], 10, 64)
		if err != nil {
			return nil, "", fmt.Errorf("metrics line %q: %w", line, err)
		}
		suffix := "_v4"
		if m[2] == "ipv6" {
			suffix = "_v6"
		}
		counters[m[1]+suffix] = v
	}
	for _, n := range e2Names {
		for _, s := range []string{"_v4", "_v6"} {
			if _, ok := counters[n+s]; !ok {
				return nil, "", fmt.Errorf("metrics has no %s%s series", n, s)
			}
		}
	}
	if instance == "" {
		return nil, "", fmt.Errorf("metrics has no net_dhcp_build_info instance_id")
	}
	return counters, instance, nil
}

// eHealth is the part of a /Plugin.Health body E1 and E2 read.
type eHealth struct {
	Counters map[string]int64
	Instance string
	Active   int64
}

func parseEHealth(body string) (eHealth, error) {
	h := eHealth{Counters: map[string]int64{}}
	for _, n := range e2Names {
		for _, s := range []string{"", "_v4", "_v6"} {
			v, ok := healthCounter(body, n+s)
			if !ok {
				return eHealth{}, fmt.Errorf("/Plugin.Health has no %s%s", n, s)
			}
			h.Counters[n+s] = v
		}
	}
	active, ok := healthCounter(body, "active_endpoints")
	if !ok {
		return eHealth{}, fmt.Errorf("/Plugin.Health has no active_endpoints")
	}
	h.Active = active
	var id struct {
		Instance string `json:"instance_id"`
	}
	if err := json.Unmarshal([]byte(body), &id); err != nil || id.Instance == "" {
		return eHealth{}, fmt.Errorf("/Plugin.Health has no instance_id")
	}
	h.Instance = id.Instance
	return h, nil
}

func sameCounters(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
