package scenario

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group F (#20): the plugin's client-side features, judged by what the
// client puts on the wire and what the source's own table then shows.
// Each scenario that changes the source does it through EnableFeature
// and puts it back in a defer that outlives a cancelled context, on every
// path including a failed verdict; a restore that fails turns the verdict
// BLOCKED, never a PASS. The IPv6 rows need the IPv6 segment (#23 group D).

const (
	fUserClass  = "lab-uc-f1"
	f108Seconds = 1800
)

// fCaptureWait bounds how long a scenario waits for the observer's
// capture to show the messages of the exchange it just completed;
// fCapturePoll is how often it is re-read. Variables so the tests do
// not wait.
var (
	fCaptureWait = 30 * time.Second
	fCapturePoll = 2 * time.Second
)

// f108Bytes is option 108's value as the wire carries it: four bytes, big endian.
func f108Bytes() []byte {
	n := uint32(f108Seconds)
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func fClientID(shape Shape) string { return "lab-f2-" + string(shape) }

// fRestoreInto puts the source back and, when that fails, replaces the
// verdict: a leftover feature config changes every later scenario.
func fRestoreInto(ctx context.Context, e Env, scenario string, restore func(context.Context) error, v *Verdict) {
	if restore == nil {
		return
	}
	if err := restore(ctx); err != nil {
		*v = blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("the source could not be put back after the scenario (%v); it must be recovered before anything else runs (scenario result was %s: %s)", err, v.Result, v.Reason), e.GitSHA)
	}
}

// fEnable turns one feature on; the returned restore is never nil.
func fEnable(ctx context.Context, e Env, f sourceadapter.Feature, p sourceadapter.FeatureParams) (func(context.Context) error, error) {
	restore, err := e.Source.EnableFeature(ctx, f, p)
	if err != nil || restore == nil {
		if err == nil {
			err = errors.New("the adapter returned no restore")
		}
		return func(context.Context) error { return nil }, err
	}
	return restore, nil
}

func optsAfter(msgs []OptMsg, from time.Time) []OptMsg {
	var out []OptMsg
	for _, m := range msgs {
		if !m.At.Before(from) {
			out = append(out, m)
		}
	}
	return out
}

// fOptions reads the option bytes the capture holds for ident since from,
// re-reading until ready says the exchange is complete or fCaptureWait
// passes. The decoded log is kept as evidence under label.
func fOptions(ctx context.Context, e Env, scenario, label, ident string, codes []int, from time.Time, ready func([]OptMsg) bool, ev map[string]string) ([]OptMsg, error) {
	oc, ok := e.Capture.(OptionReader)
	if !ok {
		return nil, errors.New("this run's capture reader cannot read option bytes")
	}
	snap := strings.TrimSuffix(evidencePath(e, scenario, label), ".txt") + ".pcap"
	deadline := time.Now().Add(fCaptureWait)
	for {
		all, err := oc.Options(ctx, ident, snap, codes)
		if err != nil {
			return nil, err
		}
		msgs := optsAfter(all, from)
		if ready(msgs) || time.Now().After(deadline) {
			logPath := evidencePath(e, scenario, label)
			if err := writeOptLog(logPath, msgs); err != nil {
				return nil, err
			}
			ev[label] = logPath
			return msgs, nil
		}
		if err := sleepCtx(ctx, fCapturePoll); err != nil {
			return nil, err
		}
	}
}

func hasType(msgs []OptMsg, typ string) bool { return len(ofType(msgs, typ)) > 0 }

// fLeaseConfirm checks the container's address against the source's own
// table and that it answers. ok false returns the finished verdict.
func fLeaseConfirm(ctx context.Context, e Env, scenario string, lease sourceadapter.Lease, found bool, addr, missing string, ev map[string]string) (Verdict, bool) {
	if !found {
		return fail(scenario, e.Cell, e.Shape, missing, ev, e.GitSHA), false
	}
	if lease.Address != addr {
		return fail(scenario, e.Cell, e.Shape, fmt.Sprintf("the source's table shows %s, the container reports %s", lease.Address, addr), ev, e.GitSHA), false
	}
	if _, err := reachableWithRetry(ctx, e.Source, addr); err != nil {
		return fail(scenario, e.Cell, e.Shape, fmt.Sprintf("%s is leased but does not answer: %v", addr, err), ev, e.GitSHA), false
	}
	return Verdict{}, true
}

func fFinish(scenario string, e Env, o fOutcome, extra string, ev map[string]string) Verdict {
	reason := o.Reason
	if extra != "" {
		reason += "; " + extra
	}
	switch o.Result {
	case PASS:
		return pass(scenario, e.Cell, e.Shape, reason, ev, e.GitSHA)
	case BLOCKED:
		return blocked(scenario, e.Cell, e.Shape, reason, e.GitSHA)
	}
	return fail(scenario, e.Cell, e.Shape, reason, ev, e.GitSHA)
}

func clientState(e Env, scenario string) (present bool, blk *Verdict) {
	present, err := clientHasFeature(e.PluginTag, fSince4)
	if err != nil {
		v := blocked(scenario, e.Cell, e.Shape, err.Error(), e.GitSHA)
		return false, &v
	}
	return present, nil
}

// runF1 -- user class: with user_class set the client sends option 77 in
// every DISCOVER and REQUEST, and the source serves that class from its
// own pool (.203-.210), outside the main pool. Before v2.4.0 the client
// sends none and lands in the main pool.
func runF1(ctx context.Context, e Env) (v Verdict) {
	if v, ok := bIPAMNA(NameF1, e); ok {
		return v
	}
	present, blk := clientState(e, NameF1)
	if blk != nil {
		return *blk
	}
	first, last, err := userClassPool(e)
	if err != nil {
		return fail(NameF1, e.Cell, e.Shape, fmt.Sprintf("no usable user-class pool: %v", err), nil, e.GitSHA)
	}
	t0 := time.Now().Add(-2 * time.Second)
	restore, err := fEnable(ctx, e, sourceadapter.FeatureUserClassPool, sourceadapter.FeatureParams{
		Class: fUserClass, PoolStart: first.String(), PoolEnd: last.String()})
	defer fRestoreInto(bCleanupCtx(ctx), e, NameF1, restore, &v)
	if err != nil {
		return blocked(NameF1, e.Cell, e.Shape, fmt.Sprintf("could not set up the user-class pool on the source: %v", err), e.GitSHA)
	}
	var opts []string
	if present {
		opts = []string{"user_class=" + fUserClass}
	}
	net, down, err := cNetwork(ctx, e, "f1", opts)
	defer down()
	if err != nil {
		return fail(NameF1, e.Cell, e.Shape, fmt.Sprintf("could not create the network (user_class=%q): %v", fUserClass, err), nil, e.GitSHA)
	}
	name := containerName(e, NameF1)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameF1, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{}
	snap := evidencePath(e, NameF1, "leases-after")
	lease, _, found, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
	if err != nil {
		return fail(NameF1, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev["leases-after"] = snap
	if bad, ok := fLeaseConfirm(ctx, e, NameF1, lease, found, addr, leaseFailReason(e.Shape, mac, addr, endpointID), ev); !ok {
		return bad
	}
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return blocked(NameF1, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	msgs, err := fOptions(ctx, e, NameF1, "capture-options", ident, []int{77}, t0, func(m []OptMsg) bool { return hasType(m, "ACK") }, ev)
	if err != nil {
		return blocked(NameF1, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	o := judgeF1Wire(present, fUserClass, msgs)
	if o.Result != PASS {
		return fFinish(NameF1, e, o, "", ev)
	}
	in, err := inUserClassPool(e, addr)
	if err != nil {
		return fail(NameF1, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
	}
	if present && !in {
		return fail(NameF1, e.Cell, e.Shape, fmt.Sprintf("%s; but the address %s is outside the user-class pool %s-%s", o.Reason, addr, first, last), ev, e.GitSHA)
	}
	if !present && in {
		return blocked(NameF1, e.Cell, e.Shape, fmt.Sprintf("%s sent no option 77 yet got %s from the user-class pool: the source's class match is wrong (lab error)", ident, addr), e.GitSHA)
	}
	where := fmt.Sprintf("the user-class pool %s-%s", first, last)
	if !present {
		where = "the main pool, as the plugin predates user_class"
	}
	return fFinish(NameF1, e, o, fmt.Sprintf("address %s from %s, shown in the source's own table", addr, where), ev)
}

// runF2a -- IPv6-Only Preferred, not forced: the source has option 108
// set but sends it only to a client that asks. The client never asks, so
// no 108 appears in its parameter request list and its IPv4 lease stands.
func runF2a(ctx context.Context, e Env) (v Verdict) {
	t0 := time.Now().Add(-2 * time.Second)
	restore, err := fEnable(ctx, e, sourceadapter.FeatureOffer108, sourceadapter.FeatureParams{Seconds: f108Seconds})
	defer fRestoreInto(bCleanupCtx(ctx), e, NameF2a, restore, &v)
	if err != nil {
		return blocked(NameF2a, e.Cell, e.Shape, fmt.Sprintf("could not set option 108 on the source: %v", err), e.GitSHA)
	}
	name := containerName(e, NameF2a)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
	if err != nil {
		return fail(NameF2a, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{}
	snap := evidencePath(e, NameF2a, "leases-after")
	lease, _, found, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
	if err != nil {
		return fail(NameF2a, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev["leases-after"] = snap
	if bad, ok := fLeaseConfirm(ctx, e, NameF2a, lease, found, addr, leaseFailReason(e.Shape, mac, addr, endpointID), ev); !ok {
		return bad
	}
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return blocked(NameF2a, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	msgs, err := fOptions(ctx, e, NameF2a, "capture-options", ident, []int{55, 108}, t0, func(m []OptMsg) bool { return hasType(m, "ACK") }, ev)
	if err != nil {
		return blocked(NameF2a, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	o, note := judgeF2aWire(msgs)
	return fFinish(NameF2a, e, o, strings.TrimPrefix(note+"; IPv4 lease "+addr+" kept, shown in the source's own table", "; "), ev)
}

// runF2b -- IPv6-Only Preferred, forced: the source sends option 108 to
// one client id although it did not ask. RFC 8925 3.2 says such a client
// must ignore it, so the IPv4 lease still completes. A second client with
// no client id then takes a lease and must see no 108: the scoping test.
func runF2b(ctx context.Context, e Env) (v Verdict) {
	if v, ok := bIPAMNA(NameF2b, e); ok {
		return v
	}
	id := fClientID(e.Shape)
	wire := b2WireClientID(id)
	t0 := time.Now().Add(-2 * time.Second)
	restore, err := fEnable(ctx, e, sourceadapter.FeatureForce108, sourceadapter.FeatureParams{Seconds: f108Seconds, ClientID: wire})
	defer fRestoreInto(bCleanupCtx(ctx), e, NameF2b, restore, &v)
	if err != nil {
		return blocked(NameF2b, e.Cell, e.Shape, fmt.Sprintf("could not force option 108 on the source: %v", err), e.GitSHA)
	}
	net, down, err := cNetwork(ctx, e, "f2", []string{"client_id=" + id})
	defer down()
	if err != nil {
		return fail(NameF2b, e.Cell, e.Shape, fmt.Sprintf("could not create the client_id network: %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameF2b)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	_, addr, _, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameF2b, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{}
	snap := evidencePath(e, NameF2b, "leases-after")
	lease, _, found, err := lookupLeaseByClientID(ctx, e.Source, wire, snap)
	if err != nil {
		return fail(NameF2b, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev["leases-after"] = snap
	if bad, ok := fLeaseConfirm(ctx, e, NameF2b, lease, found, addr, fmt.Sprintf("no lease under client id %s (address %s) in the source's own table", wire, addr), ev); !ok {
		return bad
	}
	ready := func(m []OptMsg) bool { return hasType(m, "ACK") }
	msgs, err := fOptions(ctx, e, NameF2b, "capture-options", wire, []int{55, 108}, t0, ready, ev)
	if err != nil {
		return blocked(NameF2b, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	all, err := fOptions(ctx, e, NameF2b, "capture-all-108", "*", []int{108}, t0, func([]OptMsg) bool { return true }, ev)
	if err != nil {
		return blocked(NameF2b, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	o := judgeF2bWire(msgs, all, f108Bytes())
	if o.Result != PASS {
		return fFinish(NameF2b, e, o, "", ev)
	}
	// The control: another client takes a lease while the forcing is on.
	ctl := name + "-ctl"
	defer removeContainer(bCleanupCtx(ctx), e.Host, ctl)
	cmac, caddr, cep, err := runContainer(ctx, e.Host, e.Shape, e.Network, ctl)
	if err != nil {
		return fail(NameF2b, e.Cell, e.Shape, fmt.Sprintf("the control container did not start: %v", err), nil, e.GitSHA)
	}
	cident, err := cIdent(e.Shape, cmac, cep)
	if err != nil {
		return blocked(NameF2b, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	cmsgs, err := fOptions(ctx, e, NameF2b, "capture-control", cident, []int{108}, t0, ready, ev)
	if err != nil {
		return blocked(NameF2b, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	if c := judgeF2bControl(cmsgs); c.Result != PASS {
		return fFinish(NameF2b, e, c, "", ev)
	}
	return fFinish(NameF2b, e, o, fmt.Sprintf("IPv4 lease %s kept, shown in the source's own table; the control client (%s) got %s with no option 108", addr, cident, caddr), ev)
}

// serverHas reports whether the source declares c.
func serverHas(s sourceadapter.Adapter, c sourceadapter.Capability) bool {
	for _, have := range s.Capabilities() {
		if have == c {
			return true
		}
	}
	return false
}

// runF3 -- DHCPv4 rapid commit: with rapid_commit set the client sends
// option 80 in its DISCOVER. dnsmasq (rapid commit on) answers with an ACK
// and the lease takes two messages; Kea and ISC have none and answer an
// OFFER, and the exchange continues as four, which is what the plugin's
// docs promise ("the exchange continues unchanged").
func runF3(ctx context.Context, e Env) (v Verdict) {
	if v, ok := bIPAMNA(NameF3, e); ok {
		return v
	}
	present, blk := clientState(e, NameF3)
	if blk != nil {
		return *blk
	}
	serverRapid := serverHas(e.Source, sourceadapter.CapRapidCommit4)
	t0 := time.Now().Add(-2 * time.Second)
	restore := func(context.Context) error { return nil }
	if serverRapid {
		var err error
		restore, err = fEnable(ctx, e, sourceadapter.FeatureRapidCommit4, sourceadapter.FeatureParams{})
		defer fRestoreInto(bCleanupCtx(ctx), e, NameF3, restore, &v)
		if err != nil {
			return blocked(NameF3, e.Cell, e.Shape, fmt.Sprintf("could not turn rapid commit on at the source: %v", err), e.GitSHA)
		}
	}
	var opts []string
	if present {
		opts = []string{"rapid_commit=true"}
	}
	net, down, err := cNetwork(ctx, e, "f3", opts)
	defer down()
	if err != nil {
		return fail(NameF3, e.Cell, e.Shape, fmt.Sprintf("could not create the network (rapid_commit=true): %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameF3)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameF3, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{}
	snap := evidencePath(e, NameF3, "leases-after")
	lease, _, found, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
	if err != nil {
		return fail(NameF3, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev["leases-after"] = snap
	if bad, ok := fLeaseConfirm(ctx, e, NameF3, lease, found, addr, leaseFailReason(e.Shape, mac, addr, endpointID), ev); !ok {
		return bad
	}
	ident, err := cIdent(e.Shape, mac, endpointID)
	if err != nil {
		return blocked(NameF3, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	msgs, err := fOptions(ctx, e, NameF3, "capture-options", ident, []int{80}, t0, func(m []OptMsg) bool { return hasType(m, "ACK") }, ev)
	if err != nil {
		return blocked(NameF3, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	o := judgeF3Wire(present, serverRapid, msgs)
	return fFinish(NameF3, e, o, "lease "+addr+" shown in the source's own table", ev)
}

// f8Gap is the wait after each dropped FORCERENEW and f8SignedWait the
// one after the signed send (design F8-forcerenew row, #21); f8Rand draws the
// nonce. Variables so the tests do not wait and can pin the nonce.
var (
	f8Gap        = 15 * time.Second
	f8SignedWait = 10 * time.Second
	f8Rand       = rand.Read
)

var f8XIDRE = regexp.MustCompile(`xid=0x([0-9a-f]{8})`)

// fReadyInto (defeat 13) checks the source after F8-forcerenew's restore: a raw
// sender that disturbed the server must not leak into the next scenario.
func fReadyInto(ctx context.Context, e Env, scenario string, v *Verdict) {
	if err := e.Source.Ready(ctx); err != nil {
		*v = blocked(scenario, e.Cell, e.Shape, fmt.Sprintf("the source is not ready after F8-forcerenew (%v) (scenario result was %s: %s)", err, v.Result, v.Reason), e.GitSHA)
	}
}

// f8Expiry reads the identity's lease from the source's own table.
func f8Expiry(ctx context.Context, e Env, wire, label string, ev map[string]string) (sourceadapter.Lease, error) {
	snap := evidencePath(e, NameF8, label)
	lease, _, found, err := lookupLeaseByClientID(ctx, e.Source, wire, snap)
	if err != nil {
		return lease, err
	}
	ev[label] = snap
	if !found {
		return lease, fmt.Errorf("no lease under client id %s in the source's own table", wire)
	}
	return lease, nil
}

// runF8 -- FORCERENEW (RFC 3203, RFC 6704): the source hands F8-forcerenew's client
// a nonce in its ACK; the lab then sends an unsigned, a wrongly signed
// and a signed FORCERENEW from the source VM and reads what the client
// does with each. Before v2.4.0 the client has no 145 and renews on none.
func runF8(ctx context.Context, e Env) (v Verdict) {
	if v, ok := bIPAMNA(NameF8, e); ok {
		return v
	}
	present, blk := clientState(e, NameF8)
	if blk != nil {
		return *blk
	}
	script, err := os.ReadFile(e.RepoRoot + "/scripts/forcerenew-send.py")
	if err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the FORCERENEW sender: %v", err), e.GitSHA)
	}
	nonce := make([]byte, sourceadapter.ForceRenewNonceLen)
	if _, err := f8Rand(nonce); err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not draw a nonce: %v", err), e.GitSHA)
	}
	id := "lab-f8-" + string(e.Shape)
	wire := b2WireClientID(id)
	t0 := time.Now().Add(-2 * time.Second)
	defer fReadyInto(bCleanupCtx(ctx), e, NameF8, &v)
	restore, err := fEnable(ctx, e, sourceadapter.FeatureForceRenewNonce, sourceadapter.FeatureParams{ClientID: wire, Nonce: nonce})
	defer fRestoreInto(bCleanupCtx(ctx), e, NameF8, restore, &v)
	if err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not give the source the FORCERENEW nonce: %v", err), e.GitSHA)
	}
	net, down, err := cNetwork(ctx, e, "f8", []string{"client_id=" + id})
	defer down()
	if err != nil {
		return fail(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not create the client_id network: %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameF8)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	_, addr, _, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameF8, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{}
	snap := evidencePath(e, NameF8, "leases-after")
	lease, _, found, err := lookupLeaseByClientID(ctx, e.Source, wire, snap)
	if err != nil {
		return fail(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev["leases-after"] = snap
	if bad, ok := fLeaseConfirm(ctx, e, NameF8, lease, found, addr, fmt.Sprintf("no lease under client id %s (address %s) in the source's own table", wire, addr), ev); !ok {
		return bad
	}
	hasACK := func(m []OptMsg) bool { return hasType(m, "ACK") }
	opts, err := fOptions(ctx, e, NameF8, "capture-options", wire, []int{54, 90, 145}, t0, hasACK, ev)
	if err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	ack, o := judgeF8Ack(present, opts, sourceadapter.ForceRenewNonceOption(nonce))
	if o.Result != PASS {
		return fFinish(NameF8, e, o, "", ev)
	}
	msgs, err := e.Capture.Messages(ctx, wire, evidencePath(e, NameF8, "capture-ack"))
	if err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	ackMsg, ok := f8Find(msgs, "ACK", ack.XID)
	if !ok || ackMsg.CHAddr == "" {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("the message log has no ACK %s with a chaddr to address the FORCERENEW to", ack.XID), e.GitSHA)
	}
	obs := f8Obs{present: present, lease: lease.Address, addr: addr, server: net4(ack.Opts[54]), bind: ackMsg.At, signedWait: f8SignedWait}
	obs.expires[0] = lease.Expires
	p := sourceadapter.ForceRenewParams{
		Addr: lease.Address, CHAddr: ackMsg.CHAddr, ClientID: wire, Server: obs.server,
		Nonce: nonce, AckReplay: binary.BigEndian.Uint64(ack.Opts[90][3:11]),
	}
	for i, mode := range []string{"unsigned", "badkey", "signed"} {
		p.Mode = mode
		obs.sends[i] = f8Send{Mode: mode, At: time.Now()}
		out, err := e.Source.SendForceRenew(ctx, script, p)
		if err != nil {
			return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("the %s FORCERENEW could not be sent: %v", mode, err), e.GitSHA)
		}
		m := f8XIDRE.FindStringSubmatch(out)
		if m == nil {
			return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("the sender reported no xid for the %s FORCERENEW: %q", mode, out), e.GitSHA)
		}
		obs.sends[i].XID = m[1]
		wait := f8Gap
		if mode == "signed" {
			wait = f8SignedWait
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return blocked(NameF8, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
		l, err := f8Expiry(ctx, e, wire, "leases-after-"+mode, ev)
		if err != nil {
			return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the lease after the %s FORCERENEW: %v", mode, err), e.GitSHA)
		}
		obs.expires[i+1], obs.addrAfter = l.Expires, l.Address
	}
	if obs.own, err = containerAddrs(ctx, e.Host, name); err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the container's own address after the signed FORCERENEW: %v", err), e.GitSHA)
	}
	sentAll := func(m []OptMsg) bool {
		for _, s := range obs.sends {
			if _, ok := f8Opt(m, "FORCERENEW", s.XID); !ok {
				return false
			}
		}
		return true
	}
	if obs.opts, err = fOptions(ctx, e, NameF8, "capture-forcerenew", wire, []int{90}, obs.bind, sentAll, ev); err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	msnap := evidencePath(e, NameF8, "capture-messages")
	if obs.msgs, err = e.Capture.Messages(ctx, wire, msnap); err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	ev["capture-messages"] = msnap
	if isRelayCell(e) {
		cli, _, err := relayReaders(e)
		if err != nil {
			return blocked(NameF8, e.Cell, e.Shape, err.Error(), e.GitSHA)
		}
		if obs.relayMsgs, err = readRelay(ctx, cli, e, NameF8, "capture-relay", wire, ev); err != nil {
			return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the client capture: %v", err), e.GitSHA)
		}
		obs.relayMAC = e.RelayClientMAC
	}
	o = judgeF8(obs)
	if o.Result != PASS {
		return fFinish(NameF8, e, o, "", ev)
	}
	// The control: another client takes a lease while the nonce is on.
	ctl := name + "-ctl"
	defer removeContainer(bCleanupCtx(ctx), e.Host, ctl)
	cmac, caddr, cep, err := runContainer(ctx, e.Host, e.Shape, e.Network, ctl)
	if err != nil {
		return fail(NameF8, e.Cell, e.Shape, fmt.Sprintf("the control container did not start: %v", err), nil, e.GitSHA)
	}
	cident, err := cIdent(e.Shape, cmac, cep)
	if err != nil {
		return blocked(NameF8, e.Cell, e.Shape, err.Error(), e.GitSHA)
	}
	cmsgs, err := fOptions(ctx, e, NameF8, "capture-control", cident, []int{90, 145}, t0, hasACK, ev)
	if err != nil {
		return blocked(NameF8, e.Cell, e.Shape, fmt.Sprintf("could not read the capture: %v", err), e.GitSHA)
	}
	if c := judgeF8Control(cmsgs); c.Result != PASS {
		return fFinish(NameF8, e, c, "", ev)
	}
	return fFinish(NameF8, e, o, fmt.Sprintf("lease %s; the control client (%s) got %s with no option 145 or 90", addr, cident, caddr), ev)
}

func net4(b []byte) string { return net.IP(b).To4().String() }
