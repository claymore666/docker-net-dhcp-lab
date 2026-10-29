package scenario

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group E (lab #15 PR 2): the plugin's own record of a lease against the
// source's own log. E1 reads the audit ledger, E2 the counters. One
// container runs a lease past T1 and is stopped; every number is tied to
// the source's journal by (MAC, address) and order, never by a timestamp
// across machines.

// pluginMetricsCmd is pluginHealthCmd's twin for the /metrics route on
// the same plugin socket.
var pluginMetricsCmd = strings.Replace(pluginHealthCmd, "/Plugin.Health", "/metrics", 1)

const (
	eLeaseSeconds = 40
	eWaitPastT1   = 30 * time.Second
	// eSinceSlack widens the journal and ledger reads so a clock that
	// runs behind the session's never hides the window; the baseline
	// prefix check removes what the slack lets in (#15 row 3).
	eSinceSlack = time.Hour
)

// eTune carries the waits so a unit test need not sit through them.
type eTune struct {
	lease                     int
	wait, idle, release, tail time.Duration
	poll                      time.Duration
}

var eReal = eTune{lease: eLeaseSeconds, wait: eWaitPastT1, idle: 20 * time.Second, release: 20 * time.Second, tail: 3 * time.Second, poll: time.Second}

// eRaw is what one run collected, before any judge reads it.
type eRaw struct {
	server        []sourceadapter.ServerEvent
	wire          []DHCPMsg
	ledger        []LedgerEntry
	ledgerAbsent  bool
	healthBefore  eHealth
	healthAfter   eHealth
	metricsBefore map[string]int64
	metricsAfter  map[string]int64
	instBefore    string
	instAfter     string
	addr          string
	addrBefore    string
	addrAfter     string
	ev            map[string]string
}

func sameEvents(a, b []sourceadapter.ServerEvent) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].At.Equal(b[i].At) || a[i].Type != b[i].Type || a[i].MAC != b[i].MAC || a[i].IP != b[i].IP || a[i].TID != b[i].TID {
			return false
		}
	}
	return true
}

func endpointMatches(ledgerEndpoint, endpointID string) bool {
	if len(ledgerEndpoint) < 12 || len(endpointID) < 12 {
		return false
	}
	return strings.HasPrefix(ledgerEndpoint, endpointID) || strings.HasPrefix(endpointID, ledgerEndpoint)
}

func readHealthE(ctx context.Context, e Env, scenario, label string, raw *eRaw) (eHealth, error) {
	path := evidencePath(e, scenario, label)
	body, err := pluginHealthBody(ctx, e.Host, path)
	if err != nil {
		return eHealth{}, err
	}
	raw.ev[label] = path
	return parseEHealth(body)
}

func readMetricsE(ctx context.Context, e Env, scenario, label string, raw *eRaw) (map[string]int64, string, error) {
	out, err := e.Host.Run(ctx, pluginMetricsCmd)
	if err != nil {
		return nil, "", fmt.Errorf("read /metrics: %w", err)
	}
	path := evidencePath(e, scenario, label)
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return nil, "", err
	}
	raw.ev[label] = path
	return parseMetrics(out)
}

// eCollect runs the window and returns what it saw, or the verdict that
// ended it early.
func eCollect(ctx context.Context, e Env, scenario, suffix string, withMetrics bool, t eTune) (eRaw, *Verdict) {
	raw := eRaw{ev: map[string]string{}}
	stop := func(v Verdict) (eRaw, *Verdict) { return raw, &v }
	blk := func(format string, a ...any) (eRaw, *Verdict) {
		return stop(blocked(scenario, e.Cell, e.Shape, fmt.Sprintf(format, a...), e.GitSHA))
	}
	bad := func(format string, a ...any) (eRaw, *Verdict) {
		return stop(fail(scenario, e.Cell, e.Shape, fmt.Sprintf(format, a...), raw.ev, e.GitSHA))
	}
	if e.Capture == nil {
		return blk("no capture reader for this run: the wire side cannot be read")
	}
	restore, err := e.Source.ShortenLeaseTime(ctx, t.lease)
	if err != nil {
		return bad("could not shorten the source's lease time: %v", err)
	}
	defer restore(bCleanupCtx(ctx))

	net, err := NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, suffix, []string{"audit_log=true", "release_lease=on_stop"})
	defer NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, suffix)
	if err != nil {
		return bad("could not create the audit_log network: %v", err)
	}
	name := containerName(e, scenario)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)

	// Row 7: no other container may move a plugin-wide counter.
	idleBy := time.Now().Add(t.idle)
	for {
		if raw.healthBefore, err = readHealthE(ctx, e, scenario, "health-before", &raw); err != nil {
			return blk("could not read /Plugin.Health before the window: %v", err)
		}
		if raw.healthBefore.Active == 0 {
			break
		}
		if time.Now().After(idleBy) {
			return blk("the plugin reports %d endpoints before the window: another container would move the plugin-wide counters", raw.healthBefore.Active)
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return bad("%v", err)
		}
	}
	if withMetrics {
		if raw.metricsBefore, raw.instBefore, err = readMetricsE(ctx, e, scenario, "metrics-before", &raw); err != nil {
			return blk("could not scrape /metrics before the window: %v", err)
		}
	}
	since := time.Now().Add(-eSinceSlack).UTC()
	base, err := e.Source.ServerEvents(ctx, since, "")
	if err != nil {
		return blk("could not read the source's journal before the window: %v", err)
	}

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return bad("container did not start: %v", err)
	}
	raw.addr = addr
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return blk("no wire identity for the container: %v", err)
	}
	lease, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, evidencePath(e, scenario, "leases-before"))
	if err != nil {
		return bad("could not read source lease table: %v", err)
	}
	raw.ev["leases-before"] = evidencePath(e, scenario, "leases-before")
	if !ok {
		return bad("before T1: %s", leaseFailReason(e.Shape, mac, addr, endpointID))
	}
	raw.addrBefore = lease.Address

	if err := sleepCtx(ctx, t.wait); err != nil {
		return bad("%v", err)
	}
	lease, _, ok, err = lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, evidencePath(e, scenario, "leases-after-t1"))
	if err != nil {
		return bad("could not read source lease table after %s: %v", t.wait, err)
	}
	raw.ev["leases-after-t1"] = evidencePath(e, scenario, "leases-after-t1")
	if !ok {
		return bad("with a %ds lease, past T1: %s", t.lease, leaseFailReason(e.Shape, mac, addr, endpointID))
	}
	raw.addrAfter = lease.Address

	if _, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker stop %s", name)); err != nil {
		return bad("docker stop: %v", err)
	}
	releaseBy := time.Now().Add(t.release)
	var now []sourceadapter.ServerEvent
	for {
		if now, err = e.Source.ServerEvents(ctx, since, ""); err != nil {
			return blk("could not read the source's journal after the stop: %v", err)
		}
		if (len(now) >= len(base) && hasEventType(now[len(base):], "RELEASE")) || time.Now().After(releaseBy) {
			break
		}
		if err := sleepCtx(ctx, t.poll); err != nil {
			return bad("%v", err)
		}
	}
	if err := sleepCtx(ctx, t.tail); err != nil {
		return bad("%v", err)
	}

	if raw.healthAfter, err = readHealthE(ctx, e, scenario, "health-after", &raw); err != nil {
		return blk("could not read /Plugin.Health after the window: %v", err)
	}
	if withMetrics {
		if raw.metricsAfter, raw.instAfter, err = readMetricsE(ctx, e, scenario, "metrics-after", &raw); err != nil {
			return blk("could not scrape /metrics after the window: %v", err)
		}
	}
	again, err := readHealthE(ctx, e, scenario, "health-after-2", &raw)
	if err != nil {
		return blk("could not read /Plugin.Health a second time: %v", err)
	}
	if again.Instance != raw.healthAfter.Instance || !sameCounters(again.Counters, raw.healthAfter.Counters) {
		return blk("the plugin's counters were still moving between two reads after the window")
	}
	if raw.healthAfter.Instance != raw.healthBefore.Instance {
		return blk("the plugin restarted inside the window (instance_id changed): its counters began again")
	}

	final, err := e.Source.ServerEvents(ctx, since, "")
	if err != nil {
		return blk("could not read the source's journal after the window: %v", err)
	}
	if len(final) < len(base) || !sameEvents(final[:len(base)], base) {
		return blk("the source's journal changed under the baseline (%d lines before, first %d differ): the new lines cannot be told apart", len(base), len(base))
	}
	fresh := final[len(base):]

	msgs, err := readCapture(ctx, e, scenario, "capture", ident, raw.ev)
	if err != nil {
		return blk("could not read the capture: %v", err)
	}
	wireMAC := strings.ToLower(mac)
	if e.Shape == ShapeIpvlan {
		wireMAC = ""
		for _, m := range msgs {
			if m.CHAddr == "" || (wireMAC != "" && !strings.EqualFold(m.CHAddr, wireMAC)) {
				return blk("the capture for client id %s carries more than one hardware address", ident)
			}
			wireMAC = strings.ToLower(m.CHAddr)
		}
		if wireMAC == "" {
			return blk("the capture holds no message for client id %s", ident)
		}
	}
	raw.wire = msgs
	for _, ev := range fresh {
		if strings.EqualFold(ev.MAC, wireMAC) {
			raw.server = append(raw.server, ev)
		}
	}

	entries, err := ReadLedger(ctx, e.Host, since, "")
	switch {
	case errors.Is(err, ErrLedgerAbsent):
		raw.ledgerAbsent = true
	case err != nil:
		return blk("could not read the ledger: %v", err)
	}
	for _, l := range entries {
		if endpointMatches(l.Endpoint, endpointID) {
			raw.ledger = append(raw.ledger, l)
		}
	}
	if err := writeEvidenceE(e, scenario, &raw); err != nil {
		return bad("could not keep the evidence: %v", err)
	}
	return raw, nil
}

func hasEventType(evs []sourceadapter.ServerEvent, typ string) bool {
	for _, ev := range evs {
		if ev.Type == typ {
			return true
		}
	}
	return false
}

// writeEvidenceE keeps the two logs the judge compared, one line per
// entry, so the verdict can be re-read without the host.
func writeEvidenceE(e Env, scenario string, raw *eRaw) error {
	var b strings.Builder
	for _, ev := range raw.server {
		fmt.Fprintf(&b, "%s %s %s %s\n", ev.At.UTC().Format(time.RFC3339), ev.Type, ev.MAC, ev.IP)
	}
	if b.Len() == 0 {
		b.WriteString("# no server events for this client\n")
	}
	p := evidencePath(e, scenario, "server-events")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		return err
	}
	raw.ev["server-events"] = p
	b.Reset()
	for _, l := range raw.ledger {
		fmt.Fprintf(&b, "%s %s %s %s\n", l.TS.UTC().Format(time.RFC3339), l.Kind, l.IP, l.Endpoint)
	}
	if b.Len() == 0 {
		b.WriteString("# no ledger entries for this endpoint\n")
	}
	p = evidencePath(e, scenario, "ledger")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		return err
	}
	raw.ev["ledger"] = p
	return nil
}

func runE1(ctx context.Context, e Env) Verdict { return runE1Tuned(ctx, e, eReal) }

// runE1Tuned -- audit_log=true and release_lease=on_stop: the ledger's
// bound and renew entries are the exchanges the wire and the source's
// log show, in the same address order, and the one release is counted.
func runE1Tuned(ctx context.Context, e Env, t eTune) Verdict {
	if v, ok := ipamNA(NameE1, e, "the audit-ledger network"); ok {
		return v
	}
	raw, v := eCollect(ctx, e, NameE1, "e1", false, t)
	if v != nil {
		return *v
	}
	rel := raw.healthAfter.Counters["releases_sent_v4"] - raw.healthBefore.Counters["releases_sent_v4"]
	if rel < 0 {
		return blocked(NameE1, e.Cell, e.Shape, fmt.Sprintf("releases_sent_v4 went down by %d: the plugin restarted inside the window", -rel), e.GitSHA)
	}
	o := judgeE1(e1Obs{Server: raw.server, Ledger: raw.ledger, LedgerAbsent: raw.ledgerAbsent, Wire: raw.wire, ReleasesSent: rel})
	return fFinish(NameE1, e, o, "", raw.ev)
}

func runE2(ctx context.Context, e Env) Verdict { return runE2Tuned(ctx, e, eReal) }

// runE2Tuned -- the plugin's counters moved by exactly what the source's
// log and the wire show, and /metrics and /Plugin.Health agree.
func runE2Tuned(ctx context.Context, e Env, t eTune) Verdict {
	if v, ok := ipamNA(NameE2, e, "the audit-ledger network"); ok {
		return v
	}
	raw, v := eCollect(ctx, e, NameE2, "e2", true, t)
	if v != nil {
		return *v
	}
	o := judgeE2(e2Obs{
		Server: raw.server, Wire: raw.wire,
		Before: raw.metricsBefore, After: raw.metricsAfter, Health: raw.healthAfter.Counters,
		InstanceBefore: raw.instBefore, InstanceAfter: raw.instAfter,
		AddrBefore: raw.addrBefore, AddrAfter: raw.addrAfter, Address: raw.addr,
	})
	return fFinish(NameE2, e, o, "", raw.ev)
}
