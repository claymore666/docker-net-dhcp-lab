package scenario

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The relay scenarios (lab #11, RFC 3046, RFC 2131 section 4.4.5). A
// relay cell has two observers: Env.Capture on the client segment and
// Env.ServerCapture on the source's server segment. Both are read live
// and decoded by dhcp_relay_log.

// relayKind orders a judge's answer: a BLOCKED cell problem (the lab
// cannot judge the plugin) outranks a FAIL (the plugin broke a rule),
// DESIGN-11 section 7 (#11).
type relayKind int

const (
	relayOK relayKind = iota
	relayFail
	relayBlocked
)

type relayOutcome struct {
	kind   relayKind
	reason string
	note   string // recorded, not judged
}

func (o relayOutcome) verdict(scenario string, e Env, ev map[string]string, passReason string) Verdict {
	switch o.kind {
	case relayBlocked:
		return blocked(scenario, e.Cell, e.Shape, o.reason, e.GitSHA)
	case relayFail:
		return fail(scenario, e.Cell, e.Shape, o.reason, ev, e.GitSHA)
	}
	return pass(scenario, e.Cell, e.Shape, passReason, ev, e.GitSHA)
}

func relayBlock(f string, a ...any) relayOutcome {
	return relayOutcome{kind: relayBlocked, reason: fmt.Sprintf(f, a...)}
}
func relayFailf(f string, a ...any) relayOutcome {
	return relayOutcome{kind: relayFail, reason: fmt.Sprintf(f, a...)}
}

// relayReaders returns the two relay-aware readers of a relay cell. It
// is an error, never a pass, when the cell has no second observer or the
// relay MACs were not read: every eth address rule below would be vacuous
// (lab #11 defeat: RelayClientMAC read before the relay is up).
func relayReaders(e Env) (client, server RelayReader, err error) {
	c, ok1 := e.Capture.(RelayReader)
	s, ok2 := e.ServerCapture.(RelayReader)
	switch {
	case !ok1 || !ok2:
		return nil, nil, errors.New("this run has no relay-aware capture reader on both segments")
	case e.RelayClientMAC == "" || e.RelayServerMAC == "":
		return nil, nil, errors.New("the relay's leg MACs are not known")
	case e.SegGateway == "" || e.SourceAddr == "" || e.SegGateway == e.SourceAddr:
		return nil, nil, fmt.Errorf("the env does not describe a relay cell (router %q, source %q)", e.SegGateway, e.SourceAddr)
	}
	return c, s, nil
}

// isRelayCell tells a relay cell from its Env: a second observer, a relay
// MAC or a router that is not the source (#11).
func isRelayCell(e Env) bool {
	return e.ServerCapture != nil || e.RelayClientMAC != "" || e.RelayServerMAC != "" ||
		(e.SourceAddr != "" && e.SegGateway != e.SourceAddr)
}

// readRelay is readCapture for a RelayReader: the pcap snapshot and the
// decoded log both stay in the evidence directory (#11).
func readRelay(ctx context.Context, r RelayReader, e Env, scenario, label, ident string, ev map[string]string) ([]RelayMsg, error) {
	logPath := evidencePath(e, scenario, label)
	msgs, err := r.RelayMessages(ctx, ident, strings.TrimSuffix(logPath, ".txt")+".pcap")
	if err != nil {
		return nil, err
	}
	if err := writeRelayLog(logPath, msgs); err != nil {
		return nil, err
	}
	ev[label] = logPath
	return msgs, nil
}

// ownedBy keeps the messages of one identity, and the replies that
// answer its requests by xid: on ipvlan chaddr is the parent MAC and a
// source need not echo option 61 (RFC 2131 section 4.3.1), so a reply is
// tied to its request the way dhcp_relay_log ties them (#11).
func ownedBy(msgs []RelayMsg, ident string) []RelayMsg {
	own := func(m RelayMsg) bool {
		return strings.EqualFold(m.CHAddr, ident) || strings.EqualFold(m.ClientID, ident)
	}
	asked := map[string]bool{}
	for _, m := range msgs {
		if (m.Type == "DISCOVER" || m.Type == "REQUEST") && own(m) {
			asked[m.XID] = true
		}
	}
	var out []RelayMsg
	for _, m := range msgs {
		reply := m.Type == "OFFER" || m.Type == "ACK" || m.Type == "NAK"
		if own(m) || (reply && asked[m.XID]) {
			out = append(out, m)
		}
	}
	return out
}

func relayOfType(msgs []RelayMsg, types ...string) []RelayMsg {
	var out []RelayMsg
	for _, m := range msgs {
		for _, t := range types {
			if m.Type == t {
				out = append(out, m)
			}
		}
	}
	return out
}

func sameMAC(a, b string) bool { return a != "" && strings.EqualFold(a, b) }

// judgeC12Wire applies the C12 wire rules to one container's two
// captures. upTo is the client-side bind ACK: later traffic (a renewal,
// answered from the source's address by routing) is not the acquisition.
func judgeC12Wire(e Env, ident string, client, server []RelayMsg, upTo time.Time) relayOutcome {
	client, server = ownedBy(client, ident), ownedBy(server, ident)
	// Cell checks (BLOCKED): the relay did the relaying, on the wire.
	type pair struct{ req, rep string }
	var sourceMAC string
	var echoed []string
	for _, p := range []pair{{"DISCOVER", "OFFER"}, {"REQUEST", "ACK"}} {
		var req *RelayMsg
		var reqNo82 bool
		for _, m := range relayOfType(server, p.req) {
			if !sameMAC(m.EthSrc, e.RelayServerMAC) || m.Dst != e.SourceAddr || m.GIAddr != e.SegGateway {
				continue
			}
			if m.Opt82 == "" {
				reqNo82 = true
				continue
			}
			m := m
			req = &m
			break
		}
		if req == nil {
			if reqNo82 {
				return relayBlock("the server capture shows the relay's %s with giaddr %s but without option 82: the relay runs without -a", p.req, e.SegGateway)
			}
			return relayBlock("the server capture shows no %s from the relay's server leg (%s) to %s with giaddr %s for %s: the relay did not forward it", p.req, e.RelayServerMAC, e.SourceAddr, e.SegGateway, ident)
		}
		var rep *RelayMsg
		for _, m := range relayOfType(server, p.rep) {
			if m.XID == req.XID && m.Dst == e.SegGateway {
				m := m
				rep = &m
				break
			}
		}
		if rep == nil {
			return relayBlock("the server capture shows no %s for xid %s addressed to giaddr %s: the source did not answer the relayed %s", p.rep, req.XID, e.SegGateway, p.req)
		}
		if rep.Server != e.SourceAddr {
			return relayBlock("the %s for xid %s carries option 54 %q, want the source %s", p.rep, rep.XID, rep.Server, e.SourceAddr)
		}
		ok, err := opt82Echoed(req.Opt82, rep.Opt82)
		if err != nil {
			return relayBlock("the %s for xid %s: option 82: %v", p.rep, rep.XID, err)
		}
		if !ok {
			return relayBlock("the %s for xid %s does not echo the %s's option 82 (RFC 3046 section 2.2): sent %s, got %s", p.rep, rep.XID, p.req, req.Opt82, rep.Opt82)
		}
		sourceMAC = rep.EthSrc
		echoed = append(echoed, p.rep)
	}
	for _, m := range client {
		if m.At.After(upTo) {
			continue
		}
		if m.Src == e.SourceAddr || sameMAC(m.EthSrc, sourceMAC) {
			return relayBlock("the client capture holds a %s from the source itself (ip %s, mac %s): the client heard the source directly, the relay was bypassed", m.Type, m.Src, m.EthSrc)
		}
	}
	// Plugin rules (FAIL): what the client was given.
	var bcast, ucast int
	for _, t := range []string{"OFFER", "ACK"} {
		n := 0
		for _, m := range relayOfType(client, t) {
			if m.At.After(upTo) {
				continue
			}
			n++
			if !sameMAC(m.EthSrc, e.RelayClientMAC) || m.Src != e.SegGateway {
				return relayFailf("the client's %s came from ip %s mac %s, want the relay %s %s", t, m.Src, m.EthSrc, e.SegGateway, e.RelayClientMAC)
			}
			if m.Server != e.SourceAddr {
				return relayFailf("the client's %s carries option 54 %q, want the source %s", t, m.Server, e.SourceAddr)
			}
			if m.Opt82 != "" {
				return relayFailf("the client's %s still carries option 82 %s: the relay must strip it (RFC 3046 section 2.1)", t, m.Opt82)
			}
			if m.Dst == "255.255.255.255" {
				bcast++
			} else {
				ucast++
			}
		}
		if n == 0 {
			return relayFailf("the client capture shows no %s for %s from the relay", t, ident)
		}
	}
	note := fmt.Sprintf("relay delivered %d reply(ies) by broadcast, %d unicast; the client's DISCOVER/REQUEST flags: %s",
		bcast, ucast, flagsOf(client, upTo))
	return relayOutcome{note: note + "; option 82 echoed in " + strings.Join(echoed, ", ")}
}

// flagsOf lists the broadcast flags of the client's DISCOVER and REQUEST
// up to t, recorded and not judged (RFC 2131 section 2).
func flagsOf(client []RelayMsg, t time.Time) string {
	var f []string
	for _, m := range client {
		if (m.Type == "DISCOVER" || m.Type == "REQUEST") && !m.At.After(t) {
			f = append(f, m.Type+"="+m.Flags)
		}
	}
	if len(f) == 0 {
		return "none seen"
	}
	return strings.Join(f, " ")
}

func runC12(ctx context.Context, e Env) Verdict { return runC12Tuned(ctx, e, cDefault) }

// runC12Tuned -- the plugin behind a relay: a container on the shape's
// network and one on a network that allows only the source and denies the
// relay, both leased through option 82 and giaddr, the second filter
// working on option 54 alone (internals.md, the 2.0 server filter).
func runC12Tuned(ctx context.Context, e Env, t cTiming) Verdict {
	if v, ok := bIPAMNA(NameC12, e); ok {
		return v
	}
	cli, srv, err := relayReaders(e)
	if err != nil {
		return blocked(NameC12, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	ev := map[string]string{}
	var done []string
	base := containerName(e, NameC12)
	for _, r := range []struct {
		suffix string
		opts   []string
	}{
		{"", nil},
		{"c12s", []string{"dhcp_servers=" + e.SourceAddr, "dhcp_deny_servers=" + e.SegGateway}},
	} {
		net, label, name := e.Network, "main", base
		if r.suffix != "" {
			var down func()
			net, down, err = cNetwork(ctx, e, r.suffix, r.opts)
			defer down()
			if err != nil {
				return blocked(NameC12, e.Cell, e.Shape, fmt.Sprintf("could not create the %s network: %v", r.suffix, err), e.GitSHA)
			}
			label, name = r.suffix, base+"-"+r.suffix
		}
		defer removeContainer(bCleanupCtx(ctx), e.Host, name)
		mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
		if err != nil {
			return fail(NameC12, e.Cell, e.Shape, fmt.Sprintf("%s: container did not start: %v", label, err), ev, e.GitSHA)
		}
		ident, err := cIdent(e.Shape, mac, endpointID)
		if err != nil {
			return fail(NameC12, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
		}
		bind, err := bindACKLabeled(ctx, e, NameC12, "capture-bind-"+label, ident, addr, t.anchor, t.poll, ev)
		if err != nil {
			return blocked(NameC12, e.Cell, e.Shape, fmt.Sprintf("%s: no bind time: %v", label, err), e.GitSHA)
		}
		cm, err := readRelay(ctx, cli, e, NameC12, "client-"+label, ident, ev)
		if err != nil {
			return blocked(NameC12, e.Cell, e.Shape, fmt.Sprintf("could not read the client capture: %v", err), e.GitSHA)
		}
		sm, err := readRelay(ctx, srv, e, NameC12, "server-"+label, ident, ev)
		if err != nil {
			return blocked(NameC12, e.Cell, e.Shape, fmt.Sprintf("could not read the server capture: %v", err), e.GitSHA)
		}
		o := judgeC12Wire(e, ident, cm, sm, bind.At)
		if o.kind != relayOK {
			o.reason = label + ": " + o.reason
			return o.verdict(NameC12, e, ev, "")
		}
		done = append(done, fmt.Sprintf("%s leased %s through the relay (%s)", label, addr, o.note))
		snap := evidencePath(e, NameC12, "leases-"+label)
		l, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
		if err != nil {
			return blocked(NameC12, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
		}
		ev["leases-"+label] = snap
		if !ok {
			return fail(NameC12, e.Cell, e.Shape, label+": "+leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
		}
		if !inMainPool(e, l.Address) || (!l.Expires.IsZero() && !l.Expires.After(time.Now())) {
			return fail(NameC12, e.Cell, e.Shape, fmt.Sprintf("%s: the source's lease %s is expired or outside the pool %s-%s", label, l.Address, e.PoolStart, e.PoolEnd), ev, e.GitSHA)
		}
		gw, err := containerDefaultGateway(ctx, e.Host, name)
		if err != nil {
			return fail(NameC12, e.Cell, e.Shape, fmt.Sprintf("%s: could not read the container's default route: %v", label, err), ev, e.GitSHA)
		}
		if gw != e.SegGateway {
			return fail(NameC12, e.Cell, e.Shape, fmt.Sprintf("%s: the default route is via %q, want the relay %s", label, gw, e.SegGateway), ev, e.GitSHA)
		}
		if secs, err := reachableWithRetry(ctx, e.Source, addr); err != nil {
			return fail(NameC12, e.Cell, e.Shape, fmt.Sprintf("%s: leased %s, but the source could not reach it within %ds: %v", label, addr, secs, err), ev, e.GitSHA)
		}
	}
	return pass(NameC12, e.Cell, e.Shape, strings.Join(done, "; ")+"; the client capture holds no frame from the source, the default route is the relay", ev, e.GitSHA)
}

// c12bWindow is how far after the first renewal REQUEST the server leg
// may show the same xid: the router forwards it at once, so seconds
// (DESIGN-11 section 7, #11).
const c12bWindow = 5 * time.Second

// judgeC12b applies the renewal rules to one container's captures.
// bindAt is the client-side bind ACK; nothing before it is a renewal, and
// only this identity's messages count (a renewal xid from another client
// proves nothing about this one).
func judgeC12b(e Env, ident, addr string, bindAt time.Time, client, server []RelayMsg) relayOutcome {
	client, server = ownedBy(client, ident), ownedBy(server, ident)
	var first *RelayMsg
	for _, m := range relayOfType(client, "REQUEST") {
		if m.At.After(bindAt) && (first == nil || m.At.Before(first.At)) {
			m := m
			first = &m
		}
	}
	if first == nil {
		return relayFailf("the client capture shows no REQUEST after the bind: no renewal at T1")
	}
	// The client's frame first: a wrong destination is the plugin's.
	if first.Dst != e.SourceAddr {
		return relayFailf("the first REQUEST after the bind (xid %s) went to ip %s, want a unicast renewal to the source %s (RFC 2131 section 4.4.5): a broadcast is a T2 rebind", first.XID, first.Dst, e.SourceAddr)
	}
	if first.CIAddr != addr || first.Src != addr {
		return relayFailf("the renewal REQUEST (xid %s) has ciaddr %q from ip %q, want %s in both", first.XID, first.CIAddr, first.Src, addr)
	}
	if !sameMAC(first.EthDst, e.RelayClientMAC) {
		return relayFailf("the renewal REQUEST (xid %s) is addressed at layer 2 to %s, want the relay's client leg %s: it can never be routed", first.XID, first.EthDst, e.RelayClientMAC)
	}
	if first.GIAddr != "" {
		return relayFailf("the renewal REQUEST carries giaddr %s, want 0", first.GIAddr)
	}
	if first.Opt82 != "" {
		return relayFailf("the client's renewal REQUEST (xid %s) carries option 82 %s: only a relay adds it (RFC 3046 section 2.1)", first.XID, first.Opt82)
	}
	var routed *RelayMsg
	relayed := 0
	for _, m := range relayOfType(server, "REQUEST") {
		if m.XID != first.XID || m.At.Before(first.At.Add(-time.Second)) || m.At.After(first.At.Add(c12bWindow)) {
			continue
		}
		if m.GIAddr != "" {
			relayed++
			continue
		}
		if m.Src == addr && routed == nil {
			m := m
			routed = &m
		}
	}
	if routed == nil && relayed == 0 {
		return relayBlock("the client's renewal REQUEST (xid %s, to the relay's MAC) never shows on the server capture: the relay's router did not forward it", first.XID)
	}
	// The plugin is judged on the client-side frame above; what the
	// server leg shows of a clean frame is the relay's doing (DESIGN-11
	// section 7, #11).
	if routed == nil {
		return relayBlock("the server capture shows xid %s only as the relay's forwarded copy (giaddr set), no routed unicast REQUEST from %s with giaddr 0: the relay's router did not route the clean client frame", first.XID, addr)
	}
	if routed.Opt82 != "" {
		return relayBlock("the routed renewal on the server leg carries option 82 %s though the client's frame carried none: the relay side added it", routed.Opt82)
	}
	acked := false
	for _, m := range relayOfType(client, "ACK") {
		if m.XID == first.XID && m.At.After(first.At) && m.At.Before(first.At.Add(c12bWindow)) {
			acked = true
		}
	}
	if !acked {
		return relayFailf("no ACK for the renewal xid %s reached the client (RFC 2131 section 4.1)", first.XID)
	}
	for _, m := range relayOfType(client, "REQUEST") {
		if m.At.After(bindAt) && m.Dst == "255.255.255.255" {
			return relayFailf("the client broadcast a REQUEST (xid %s) after the bind: a rebind, not the unicast renewal alone", m.XID)
		}
	}
	return relayOutcome{note: fmt.Sprintf("renewal xid %s unicast to %s via the relay MAC, routed on the server leg with giaddr 0, ACKed to the client; relayed copies (giaddr set) on the server leg: %d; flag %s", first.XID, e.SourceAddr, relayed, first.Flags)}
}

func runC12b(ctx context.Context, e Env) Verdict { return runC12bTuned(ctx, e, cDefault) }

// runC12bTuned -- renewal across a relay: with a 120 s lease, T1 at
// 60 s must be a unicast to the source, addressed to the relay at layer 2
// and routed (RFC 2131 section 4.4.5), and the source's ACK must reach the
// client. The docs say nothing on how the plugin addresses an off-link
// renewal; this is the outside check.
func runC12bTuned(ctx context.Context, e Env, t cTiming) Verdict {
	cli, srv, err := relayReaders(e)
	if err != nil {
		return blocked(NameC12b, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	b, cleanup, v := cStartBound(ctx, e, NameC12b, t)
	defer cleanup()
	if v != nil {
		return *v
	}
	if err := sleepUntil(ctx, b.bindAt.Add(t.c12bWait)); err != nil {
		return blocked(NameC12b, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	cm, err := readRelay(ctx, cli, e, NameC12b, "client", b.ident, b.ev)
	if err != nil {
		return blocked(NameC12b, e.Cell, e.Shape, fmt.Sprintf("could not read the client capture: %v", err), e.GitSHA)
	}
	sm, err := readRelay(ctx, srv, e, NameC12b, "server", b.ident, b.ev)
	if err != nil {
		return blocked(NameC12b, e.Cell, e.Shape, fmt.Sprintf("could not read the server capture: %v", err), e.GitSHA)
	}
	o := judgeC12b(e, b.ident, b.addr, b.bindAt, cm, sm)
	if o.kind != relayOK {
		return o.verdict(NameC12b, e, b.ev, "")
	}
	snap := evidencePath(e, NameC12b, "leases-after")
	l, _, ok, err := lookupLease(ctx, e.Source, e.Shape, b.mac, b.addr, b.endpointID, snap)
	if err != nil {
		return blocked(NameC12b, e.Cell, e.Shape, fmt.Sprintf("could not read the source's table: %v", err), e.GitSHA)
	}
	b.ev["leases-after"] = snap
	switch {
	case !ok:
		return fail(NameC12b, e.Cell, e.Shape, "after the renewal: "+leaseFailReason(e.Shape, b.mac, b.addr, b.endpointID), b.ev, e.GitSHA)
	case l.Address != b.addr:
		return fail(NameC12b, e.Cell, e.Shape, fmt.Sprintf("the renewal changed the address from %s to %s", b.addr, l.Address), b.ev, e.GitSHA)
	case !l.Expires.After(b.before.Expires):
		return fail(NameC12b, e.Cell, e.Shape, fmt.Sprintf("the lease expiry did not move (%s before, %s after)", b.before.Expires.Format(time.RFC3339), l.Expires.Format(time.RFC3339)), b.ev, e.GitSHA)
	}
	return pass(NameC12b, e.Cell, e.Shape, fmt.Sprintf("%s; lease expiry moved to %s, address unchanged", o.note, l.Expires.Format(time.RFC3339)), b.ev, e.GitSHA)
}
