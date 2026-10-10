package scenario

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// fCapture serves canned option bytes; it is the OptionReader the group
// F scenarios type-assert to. msgs are stamped now, so the scenario's
// "since" cut keeps them.
type fCapture struct {
	msgs []OptMsg
	// others are what the whole-capture read ("*") also shows: messages
	// of other clients, never of the identity under test.
	others []OptMsg
	// byIdent answers a read for one identity (the control client).
	byIdent map[string][]OptMsg
	err     error
	calls   int
}

func (c *fCapture) Messages(context.Context, string, string) ([]DHCPMsg, error) { return nil, nil }
func (c *fCapture) Options(_ context.Context, ident, _ string, _ []int) ([]OptMsg, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	src := c.msgs
	if m, ok := c.byIdent[ident]; ok {
		src = m
	}
	if ident == "*" {
		src = append(append([]OptMsg{}, c.msgs...), c.others...)
	}
	out := make([]OptMsg, len(src))
	for i, m := range src {
		m.At = time.Now()
		out[i] = m
	}
	return out, nil
}

// plainCapture has no Options: the reader group F cannot use.
type plainCapture struct{}

func (plainCapture) Messages(context.Context, string, string) ([]DHCPMsg, error) { return nil, nil }

func fFast(t *testing.T) {
	t.Helper()
	w, p := fCaptureWait, fCapturePoll
	fCaptureWait, fCapturePoll = 30*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { fCaptureWait, fCapturePoll = w, p })
}

func fFour(x string, disc, req map[int][]byte) []OptMsg {
	return []OptMsg{om("DISCOVER", x, disc), om("OFFER", x, nil), om("REQUEST", x, req), om("ACK", x, nil)}
}

type fFix struct {
	h   *bRunner
	src *bAdapter
	cap *fCapture
	e   Env
}

func newFFix(t *testing.T, shape Shape, tag string, addr string, caps ...sourceadapter.Capability) *fFix {
	t.Helper()
	fFast(t)
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{caps: caps}}
	e := bEnv(t, h, src, shape)
	e.PluginTag = tag
	c := &fCapture{}
	e.Capture = c
	h.addrFn = func(string, string) string { return addr }
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: addr})
	return &fFix{h: h, src: src, cap: c, e: e}
}

func (f *fFix) cmdCount(sub string) (n int) {
	for _, c := range f.h.cmds {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

const (
	tagNew = "ghcr.io/claymore666/docker-net-dhcp:v2.5.0"
	tagOld = "ghcr.io/claymore666/docker-net-dhcp:v2.3.0-rc1"
)

var uc77 = map[int][]byte{77: userClassBytes(fUserClass)}

// ---- user class ----

func TestRunF1PassesFromTheClassPool(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.203")
	f.cap.msgs = fFour("1", uc77, uc77)
	v := runF1(context.Background(), f.e)
	needResult(t, v, PASS)
	if !f.h.has("user_class=" + fUserClass) {
		t.Errorf("network create lacks user_class: %v", f.h.cmds)
	}
	if got := f.src.features; len(got) != 1 || got[0] != sourceadapter.FeatureUserClassPool {
		t.Errorf("features = %v", got)
	}
	p := f.src.featureParams[0]
	if p.Class != fUserClass || p.PoolStart != "10.200.1.203" || p.PoolEnd != "10.200.1.210" {
		t.Errorf("params = %+v", p)
	}
	if f.src.featureRestores != 1 {
		t.Errorf("restores = %d", f.src.featureRestores)
	}
	if v.Evidence["capture-options"] == "" || v.Evidence["leases-after"] == "" {
		t.Errorf("evidence %v", v.Evidence)
	}
	needCleanup(t, f.h, "f1", containerName(f.e, NameF1))
}

func TestRunF1FailsFromTheMainPool(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.150")
	f.cap.msgs = fFour("1", uc77, uc77)
	v := runF1(context.Background(), f.e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "outside the user-class pool") {
		t.Errorf("reason %q", v.Reason)
	}
	if f.src.featureRestores != 1 {
		t.Errorf("a FAIL must still restore the source")
	}
}

func TestRunF1FailsWhenTheClientSendsNoOption77(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.203")
	f.cap.msgs = fFour("1", uc77, nil)
	needResult(t, runF1(context.Background(), f.e), FAIL)
}

func TestRunF1FailsWhenTheTableDisagrees(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.203")
	f.src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.204"})
	f.cap.msgs = fFour("1", uc77, uc77)
	needResult(t, runF1(context.Background(), f.e), FAIL)
}

// Before v2.4.0 the client must send no 77 and the main pool serves it.
func TestRunF1OnAnOldPluginExpectsNoOption77AndTheMainPool(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagOld, "10.200.1.150")
	f.cap.msgs = fFour("1", nil, nil)
	needResult(t, runF1(context.Background(), f.e), PASS)
	if f.h.has("user_class=") {
		t.Errorf("an old plugin must not be given user_class: %v", f.h.cmds)
	}
}

func TestRunF1OnAnOldPluginBlocksWhenOption77IsOnTheWire(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagOld, "10.200.1.150")
	f.cap.msgs = fFour("1", uc77, uc77)
	v := runF1(context.Background(), f.e)
	needResult(t, v, BLOCKED)
	if len(v.Evidence) != 0 {
		t.Errorf("a BLOCKED verdict carries no evidence: %v", v.Evidence)
	}
}

func TestRunF1OnAnOldPluginBlocksWhenItLandsInTheClassPool(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagOld, "10.200.1.204")
	f.cap.msgs = fFour("1", nil, nil)
	needResult(t, runF1(context.Background(), f.e), BLOCKED)
}

func TestGroupFBlocksOnAnUnparsableTagBeforeTouchingAnything(t *testing.T) {
	for _, tag := range []string{"", "latest", "dev"} {
		for _, run := range []func(context.Context, Env) Verdict{runF1, runF3} {
			f := newFFix(t, ShapeBridge, tag, "10.200.1.203", sourceadapter.CapRapidCommit4)
			v := run(context.Background(), f.e)
			needResult(t, v, BLOCKED)
			if len(f.h.cmds) != 0 || len(f.src.features) != 0 {
				t.Errorf("tag %q: the lab touched the host or the source: %v %v", tag, f.h.cmds, f.src.features)
			}
		}
	}
}

// ---- 108 not asked ----

func TestRunF2aPassesAndKeepsTheLease(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.150")
	prl := map[int][]byte{55: {1, 3, 6}}
	f.cap.msgs = fFour("1", prl, prl)
	v := runF2a(context.Background(), f.e)
	needResult(t, v, PASS)
	if got := f.src.features; len(got) != 1 || got[0] != sourceadapter.FeatureOffer108 {
		t.Errorf("features = %v", got)
	}
	if f.src.featureParams[0].Seconds != f108Seconds {
		t.Errorf("params = %+v", f.src.featureParams[0])
	}
	needCleanup(t, f.h, "", containerName(f.e, NameF2a))
}

func TestRunF2aFailsWhenTheClientAsksFor108(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.150")
	prl := map[int][]byte{55: {1, 108}}
	f.cap.msgs = fFour("1", prl, prl)
	needResult(t, runF2a(context.Background(), f.e), FAIL)
	if f.src.featureRestores != 1 {
		t.Errorf("restores = %d", f.src.featureRestores)
	}
}

func TestRunF2aRecordsAServerThatSendsItUnasked(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.150")
	prl := map[int][]byte{55: {1}}
	m := fFour("1", prl, prl)
	m[1] = om("OFFER", "1", map[int][]byte{108: f108Bytes()})
	f.cap.msgs = m
	v := runF2a(context.Background(), f.e)
	needResult(t, v, PASS)
	if !strings.Contains(v.Reason, "server finding") {
		t.Errorf("reason %q lacks the server note", v.Reason)
	}
}

// F2a uses the cell's main network, so IPAM shapes are not N/A.
func TestRunF2aRunsOnIPAMShapes(t *testing.T) {
	f := newFFix(t, ShapeBridgeIPAM, tagNew, "10.200.1.150")
	prl := map[int][]byte{55: {1}}
	f.cap.msgs = fFour("1", prl, prl)
	needResult(t, runF2a(context.Background(), f.e), PASS)
}

// ---- 108 forced ----

func f2bMsgs(want []byte) []OptMsg {
	prl := map[int][]byte{55: {1, 3}}
	m := fFour("1", prl, prl)
	m[1] = om("OFFER", "1", map[int][]byte{108: want})
	return m
}

func f2bFix(t *testing.T) *fFix {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.150")
	wire := b2WireClientID(fClientID(ShapeBridge))
	f.src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", ClientID: wire, Address: "10.200.1.150"})
	f.cap.msgs = f2bMsgs(f108Bytes())
	// The control container is the second one the fake host starts.
	f.cap.byIdent = map[string][]OptMsg{"aa:bb:cc:00:00:02": fFour("2", nil, nil)}
	return f
}

func TestRunF2bPassesWhenTheClientIgnoresTheForcedOption(t *testing.T) {
	f := f2bFix(t)
	v := runF2b(context.Background(), f.e)
	needResult(t, v, PASS)
	if !f.h.has("client_id=" + fClientID(ShapeBridge)) {
		t.Errorf("network lacks client_id: %v", f.h.cmds)
	}
	p := f.src.featureParams[0]
	if f.src.features[0] != sourceadapter.FeatureForce108 || p.ClientID != b2WireClientID(fClientID(ShapeBridge)) || p.Seconds != f108Seconds {
		t.Errorf("feature %v params %+v", f.src.features, p)
	}
	needCleanup(t, f.h, "f2", containerName(f.e, NameF2b))
	needCleanup(t, f.h, "f2", containerName(f.e, NameF2b)+"-ctl")
	if !strings.Contains(v.Reason, "control client") || v.Evidence["capture-control"] == "" {
		t.Errorf("the control must be in the verdict and its evidence: %q %v", v.Reason, v.Evidence)
	}
}

// The scoping proof: a second client with no client id that is sent
// option 108 means the forcing leaked; a control never seen means the
// scoping was not exercised. Neither may PASS.
func TestRunF2bBlocksWhenTheControlClientIsSentOption108(t *testing.T) {
	f := f2bFix(t)
	f.cap.byIdent["aa:bb:cc:00:00:02"] = []OptMsg{om("DISCOVER", "2", nil), om("OFFER", "2", map[int][]byte{108: f108Bytes()}), om("REQUEST", "2", nil), om("ACK", "2", nil)}
	v := runF2b(context.Background(), f.e)
	needResult(t, v, BLOCKED)
	if f.src.featureRestores != 1 {
		t.Errorf("restores = %d", f.src.featureRestores)
	}
}

func TestRunF2bBlocksWhenTheControlClientIsNeverSeen(t *testing.T) {
	f := f2bFix(t)
	f.cap.byIdent["aa:bb:cc:00:00:02"] = nil
	needResult(t, runF2b(context.Background(), f.e), BLOCKED)
}

func TestJudgeF2bControl(t *testing.T) {
	if o := judgeF2bControl(fFour("2", nil, nil)); o.Result != PASS {
		t.Errorf("clean control = %+v", o)
	}
	if o := judgeF2bControl(nil); o.Result != BLOCKED {
		t.Errorf("unseen control = %+v", o)
	}
	m := fFour("2", nil, nil)
	m[3] = om("ACK", "2", map[int][]byte{108: f108Bytes()})
	if o := judgeF2bControl(m); o.Result != BLOCKED {
		t.Errorf("108 on the control's ACK = %+v", o)
	}
}

func TestRunF2bFailsWhenTheClientStopsAfterTheForcedOffer(t *testing.T) {
	f := f2bFix(t)
	f.cap.msgs = f2bMsgs(f108Bytes())[:2]
	f.cap.msgs = append(f.cap.msgs, om("ACK", "9", nil)) // the lease exists, the exchange does not
	v := runF2b(context.Background(), f.e)
	if v.Result != FAIL && v.Result != BLOCKED {
		t.Fatalf("got %s", v.Result)
	}
	if f.src.featureRestores != 1 {
		t.Errorf("restores = %d", f.src.featureRestores)
	}
}

func TestRunF2bBlocksWhenTheForcingLeaksToAnotherClient(t *testing.T) {
	f := f2bFix(t)
	f.cap.others = []OptMsg{om("OFFER", "7", map[int][]byte{108: f108Bytes()})}
	needResult(t, runF2b(context.Background(), f.e), BLOCKED)
}

func TestRunF2bIsNAOnIPAMShapesWithoutTouchingTheHost(t *testing.T) {
	for _, sh := range []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		f := newFFix(t, sh, tagNew, "10.200.1.150", sourceadapter.CapRapidCommit4)
		for name, run := range map[string]func(context.Context, Env) Verdict{NameF1: runF1, NameF2b: runF2b, NameF3: runF3} {
			needResult(t, run(context.Background(), f.e), NA)
			if len(f.h.cmds) != 0 || len(f.src.features) != 0 {
				t.Errorf("%s on %s touched the host or the source", name, sh)
			}
		}
	}
}

// ---- rapid commit ----

func TestRunF3OnADnsmasqLikeSourceExpectsTwoMessages(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.150", sourceadapter.CapRapidCommit4)
	rc := map[int][]byte{80: {}}
	f.cap.msgs = []OptMsg{om("DISCOVER", "1", rc), om("ACK", "1", rc)}
	needResult(t, runF3(context.Background(), f.e), PASS)
	if !f.h.has("rapid_commit=true") {
		t.Errorf("network lacks rapid_commit: %v", f.h.cmds)
	}
	if got := f.src.features; len(got) != 1 || got[0] != sourceadapter.FeatureRapidCommit4 || f.src.featureRestores != 1 {
		t.Errorf("features %v restores %d", got, f.src.featureRestores)
	}
}

func TestRunF3OnASourceWithoutRapidCommitExpectsTheExchangeToContinue(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.150")
	rc := map[int][]byte{80: {}}
	f.cap.msgs = fFour("1", rc, nil)
	needResult(t, runF3(context.Background(), f.e), PASS)
	if len(f.src.features) != 0 {
		t.Errorf("a source without the capability must not be asked to enable it: %v", f.src.features)
	}
	// The same four messages are a FAIL where rapid commit is on.
	g := newFFix(t, ShapeBridge, tagNew, "10.200.1.150", sourceadapter.CapRapidCommit4)
	g.cap.msgs = fFour("1", rc, nil)
	needResult(t, runF3(context.Background(), g.e), FAIL)
}

func TestRunF3FailsWhenTheDiscoverCarriesNo80(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagNew, "10.200.1.150")
	f.cap.msgs = fFour("1", nil, nil)
	needResult(t, runF3(context.Background(), f.e), FAIL)
}

func TestRunF3OnAnOldPluginExpectsNo80(t *testing.T) {
	f := newFFix(t, ShapeBridge, tagOld, "10.200.1.150")
	f.cap.msgs = fFour("1", nil, nil)
	needResult(t, runF3(context.Background(), f.e), PASS)
	if f.h.has("rapid_commit=") {
		t.Errorf("an old plugin must not be given rapid_commit")
	}
}

// ---- restore on every path ----

type fRun struct {
	name string
	run  func(context.Context, Env) Verdict
	fix  func(*testing.T) *fFix
	good func(*fFix)
}

func fRuns() []fRun {
	prl := map[int][]byte{55: {1, 3}}
	rc := map[int][]byte{80: {}}
	return []fRun{
		{"user class", runF1, func(t *testing.T) *fFix { return newFFix(t, ShapeBridge, tagNew, "10.200.1.203") },
			func(f *fFix) { f.cap.msgs = fFour("1", uc77, uc77) }},
		{"108 not asked", runF2a, func(t *testing.T) *fFix { return newFFix(t, ShapeBridge, tagNew, "10.200.1.150") },
			func(f *fFix) { f.cap.msgs = fFour("1", prl, prl) }},
		{"108 forced", runF2b, f2bFix, func(f *fFix) {}},
		{"rapid commit", runF3, func(t *testing.T) *fFix {
			return newFFix(t, ShapeBridge, tagNew, "10.200.1.150", sourceadapter.CapRapidCommit4)
		}, func(f *fFix) { f.cap.msgs = []OptMsg{om("DISCOVER", "1", rc), om("ACK", "1", rc)} }},
	}
}

func TestGroupFRestoresTheSourceOnEveryPath(t *testing.T) {
	for _, r := range fRuns() {
		t.Run(r.name+"/pass", func(t *testing.T) {
			f := r.fix(t)
			r.good(f)
			needResult(t, r.run(context.Background(), f.e), PASS)
			if f.src.featureRestores != 1 {
				t.Errorf("restores = %d", f.src.featureRestores)
			}
		})
		t.Run(r.name+"/container does not start", func(t *testing.T) {
			f := r.fix(t)
			r.good(f)
			f.h.runErr = errors.New("boom")
			needResult(t, r.run(context.Background(), f.e), FAIL)
			if f.src.featureRestores != 1 {
				t.Errorf("restores = %d", f.src.featureRestores)
			}
		})
		t.Run(r.name+"/wire not readable", func(t *testing.T) {
			f := r.fix(t)
			r.good(f)
			f.cap.err = errors.New("no capture")
			needResult(t, r.run(context.Background(), f.e), BLOCKED)
			if f.src.featureRestores != 1 {
				t.Errorf("restores = %d", f.src.featureRestores)
			}
		})
		t.Run(r.name+"/reader without option bytes", func(t *testing.T) {
			f := r.fix(t)
			r.good(f)
			f.e.Capture = plainCapture{}
			needResult(t, r.run(context.Background(), f.e), BLOCKED)
			if f.src.featureRestores != 1 {
				t.Errorf("restores = %d", f.src.featureRestores)
			}
		})
		t.Run(r.name+"/restore fails", func(t *testing.T) {
			f := r.fix(t)
			r.good(f)
			f.src.featureRestoreEr = errors.New("tee refused")
			v := r.run(context.Background(), f.e)
			needResult(t, v, BLOCKED)
			if !strings.Contains(v.Reason, "could not be put back") || !strings.Contains(v.Reason, "PASS") {
				t.Errorf("reason %q", v.Reason)
			}
			if len(v.Evidence) != 0 {
				t.Errorf("a BLOCKED verdict carries no evidence: %v", v.Evidence)
			}
		})
		t.Run(r.name+"/cancelled context", func(t *testing.T) {
			f := r.fix(t)
			r.good(f)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			r.run(ctx, f.e)
			if f.src.featureRestores != f.src.featureEnabled() {
				t.Errorf("restores %d, enables %d", f.src.featureRestores, f.src.featureEnabled())
			}
			if f.src.featureRestoreCtx != nil {
				t.Errorf("the restore ran on the dead context: %v", f.src.featureRestoreCtx)
			}
		})
		t.Run(r.name+"/enable fails", func(t *testing.T) {
			f := r.fix(t)
			r.good(f)
			f.src.featureErr = errors.New("apply failed")
			v := r.run(context.Background(), f.e)
			needResult(t, v, BLOCKED)
			if f.cmdCount("docker run") != 0 {
				t.Errorf("a container started on a source whose feature did not apply")
			}
			if f.src.featureRestores != 0 {
				t.Errorf("restores = %d for a feature that never applied", f.src.featureRestores)
			}
		})
	}
}

func (a *fakeAdapter) featureEnabled() int { return len(a.features) }

// ---- catalog ----

// F6 and F7 run wherever the IPv6 segment is: dnsmasq declares neither
// CapPD nor CapPref64 and is the documented negative case of each (#23).
func TestGroupFPartTwoRowsRunOnEveryV6Source(t *testing.T) {
	for _, name := range []string{NameF6, NameF7} {
		for an, a := range map[string]sourceadapter.Adapter{
			"kea": &sourceadapter.KeaAdapter{}, "isc-dhcp": &sourceadapter.ISCDHCPAdapter{}, "dnsmasq": &sourceadapter.DnsmasqAdapter{},
			"no v6": &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}},
		} {
			found := false
			for _, s := range Catalog {
				if s.Name != name {
					continue
				}
				found = true
				ok, reason := Applicable(s, a)
				if ok != (an != "no v6") {
					t.Errorf("%s on %s: applicable=%v reason %q", name, an, ok, reason)
				}
			}
			if !found {
				t.Errorf("%s is not in the catalog", name)
			}
		}
	}
}

func TestCatalogRegistersGroupFWithTheNeedsOfTheDesign(t *testing.T) {
	want := map[string][]sourceadapter.Capability{
		NameF1:  {sourceadapter.CapV4, sourceadapter.CapUserClassPool},
		NameF2a: {sourceadapter.CapV4, sourceadapter.CapOption108},
		NameF2b: {sourceadapter.CapV4, sourceadapter.CapOption108},
		NameF3:  {sourceadapter.CapV4},
		NameF4:  {sourceadapter.CapV6},
		NameF5:  {sourceadapter.CapV6},
		NameF6:  {sourceadapter.CapV6},
		NameF7:  {sourceadapter.CapV6},
	}
	seen := 0
	for _, s := range Catalog {
		if w, ok := want[s.Name]; ok {
			seen++
			if fmt.Sprint(s.Needs) != fmt.Sprint(w) {
				t.Errorf("%s needs %v, want %v", s.Name, s.Needs, w)
			}
		}
	}
	if seen != len(want) {
		t.Fatalf("catalog holds %d of %d group F scenarios", seen, len(want))
	}
}

// Every adapter declares what the six runnable rows need; rapid commit
// and the temporary address need no feature cap, since a source without
// one is judged on its fallback.
func TestGroupFRunsOnEveryAdapterThatDeclaresItsNeeds(t *testing.T) {
	for an, a := range map[string]sourceadapter.Adapter{
		"kea": &sourceadapter.KeaAdapter{}, "isc-dhcp": &sourceadapter.ISCDHCPAdapter{}, "dnsmasq": &sourceadapter.DnsmasqAdapter{},
	} {
		for _, s := range Catalog {
			if s.Name != NameF1 && s.Name != NameF2a && s.Name != NameF2b && s.Name != NameF3 && s.Name != NameF4 && s.Name != NameF5 {
				continue
			}
			if ok, reason := Applicable(s, a); !ok {
				t.Errorf("%s on %s: %s", s.Name, an, reason)
			}
		}
	}
}

// ---- addresses ----

// The user-class pool (.203-.210) must keep clear of the main pool, the
// reservations (211+idx, 216+idx), the baked-in class pool (221-230), the
// DNS address (253) and the source's own address, in every shipped cell.
func TestUserClassPoolStaysClearOfEveryOtherAddressInEveryCell(t *testing.T) {
	cfg, err := labyaml.Load(filepath.Join("..", "..", "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Cells) == 0 {
		t.Fatal("no cells in lab.yaml")
	}
	for _, c := range cfg.Cells {
		if c.Source == nil {
			continue
		}
		e := Env{Cell: c.Name, Shape: ShapeBridge, SegSubnet: c.Segment.Subnet, PoolStart: c.Source.PoolStart, PoolEnd: c.Source.PoolEnd}
		first, last, err := userClassPool(e)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if first.Compare(last) >= 0 {
			t.Fatalf("%s: pool %s-%s is empty", c.Name, first, last)
		}
		start, end := netip.MustParseAddr(c.Source.PoolStart), netip.MustParseAddr(c.Source.PoolEnd)
		if first.Compare(end) <= 0 && last.Compare(start) >= 0 {
			t.Errorf("%s: user-class pool %s-%s overlaps the main pool %s-%s", c.Name, first, last, start, end)
		}
		seg := netip.MustParsePrefix(c.Source.SegAddress).Addr()
		if first.Compare(seg) <= 0 && last.Compare(seg) >= 0 {
			t.Errorf("%s: the source's own address %s is inside the user-class pool", c.Name, seg)
		}
		var others []string
		for _, shape := range Shapes {
			e.Shape = shape
			for _, n := range []string{NameB1, NameB2} {
				a, err := reservationAddr(e, n)
				if err != nil {
					t.Fatalf("%s %s %s: %v", c.Name, shape, n, err)
				}
				others = append(others, a)
			}
		}
		for h := classPoolFirstHost; h <= classPoolLastHost; h++ {
			a, _ := groupBAddr(e, h)
			others = append(others, a)
		}
		dns, _ := groupBAddr(e, dnsOptionHost)
		others = append(others, dns)
		for _, o := range others {
			a := netip.MustParseAddr(o)
			if first.Compare(a) <= 0 && last.Compare(a) >= 0 {
				t.Errorf("%s: %s is inside the user-class pool %s-%s", c.Name, o, first, last)
			}
		}
		for _, addr := range []string{first.String(), last.String()} {
			if in, err := inUserClassPool(e, addr); err != nil || !in {
				t.Errorf("%s: inUserClassPool(%s) = %v, %v", c.Name, addr, in, err)
			}
		}
		for _, addr := range []string{start.String(), "10.0.0.1", dns} {
			if in, _ := inUserClassPool(e, addr); in {
				t.Errorf("%s: %s is not a user-class address", c.Name, addr)
			}
		}
	}
}

// The hygiene gate lets a group F product name pass by listing it in
// full; a scenario or README row added without a gate entry would fail
// the gate on its own name, so this keeps the list in step (#20).
func TestGroupFNamesAreInTheHygieneGate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "hygiene-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	gate := string(raw)
	n := 0
	for _, s := range Catalog {
		if strings.HasPrefix(s.Name, "F") {
			n++
			if !strings.Contains(gate, `\b`+s.Name+`\b`) {
				t.Errorf("catalog name %s is not in SCENARIO_ID_RES", s.Name)
			}
		}
	}
	if n != 9 {
		t.Errorf("catalog holds %d group F names, want 9", n)
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	heads := regexp.MustCompile(`(?m)^\| (F\d+[a-z]?) \| ([^|]+?) \|`).FindAllStringSubmatch(string(readme), -1)
	if len(heads) != 9 {
		t.Errorf("README holds %d group F rows, want 9", len(heads))
	}
	for _, m := range heads {
		if want := `'^\| ` + m[1] + ` \| ` + m[2] + ` \|'`; !strings.Contains(gate, want) {
			t.Errorf("README row head %q is not in SCENARIO_ID_RES", m[0])
		}
	}
}
