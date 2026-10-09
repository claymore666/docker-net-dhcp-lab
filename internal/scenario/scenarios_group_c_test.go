package scenario

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

const ms = time.Millisecond

// cFast is cDefault in milliseconds; the bounds that judge the plugin
// are constants and stay in seconds, so the fakes report wall times and
// wire timestamps at those scales.
var cFast = cTiming{
	lease: 120, anchor: 300 * ms, poll: 5 * ms,
	stopAfter: 20 * ms, c2Start: 60 * ms, c2Settle: 400 * ms,
	c3Record: 40 * ms, c3Start: 80 * ms, c3Window: 200 * ms,
	c4Wait: 40 * ms, c1Settle: 5 * ms, c10Lift: 300 * ms,
	c6bWindow: 200 * ms, c8Settle: 20 * ms, c8Links: 50 * ms, c9Wait: 300 * ms,
}

// cRunner is bRunner plus what group C asks the docker host: the timed
// wrapper (exit code and wall time per container or network name),
// endpoint counts, network listing, container addresses and MACs.
type cRunner struct {
	*bRunner
	mu        sync.Mutex
	rc        map[string]int
	wall      map[string]time.Duration
	errs      map[string]error
	endpoints map[string]int
	listed    map[string]bool
	addrs     map[string][]string
	macs      string
	runAt     map[string]time.Time
}

var cWrapRE = regexp.MustCompile(`out=\$\((.*) 2>&1\); rc=\$\?`)

func newCRunner() *cRunner {
	return &cRunner{bRunner: newBRunner(), rc: map[string]int{}, wall: map[string]time.Duration{},
		errs: map[string]error{}, endpoints: map[string]int{}, listed: map[string]bool{},
		addrs: map[string][]string{}, runAt: map[string]time.Time{}}
}

func lastField(s string) string { f := strings.Fields(s); return f[len(f)-1] }

func (f *cRunner) Run(ctx context.Context, cmd string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := cWrapRE.FindStringSubmatch(cmd); m != nil {
		inner := m[1]
		key := lastField(inner)
		if n := bNameRE.FindStringSubmatch(inner); n != nil {
			key = n[1]
		}
		f.runAt[key] = time.Now()
		if err := f.errs[key]; err != nil {
			return "", err
		}
		rc := f.rc[key]
		if rc == 0 {
			if _, err := f.bRunner.Run(ctx, inner); err != nil {
				return "", err
			}
		} else {
			f.cmds = append(f.cmds, inner)
		}
		s := time.Now().UnixNano()
		return fmt.Sprintf("lab-wall %d %d %d\noutput of %s", rc, s, s+int64(f.wall[key]), key), nil
	}
	switch {
	case strings.Contains(cmd, "{{len .Containers}}"):
		f.cmds = append(f.cmds, cmd)
		return strconv.Itoa(f.endpoints[lastField(cmd)]), nil
	case strings.Contains(cmd, "docker network inspect"):
		f.cmds = append(f.cmds, cmd)
		if f.listed[strings.Fields(cmd)[4]] {
			return "", nil
		}
		return "", errors.New("no such network")
	case strings.Contains(cmd, "docker ps -aq"):
		f.cmds = append(f.cmds, cmd)
		return f.macs, nil
	case strings.Contains(cmd, "ip -4 -o addr show"):
		f.cmds = append(f.cmds, cmd)
		name := strings.Fields(cmd)[3]
		addrs, ok := f.addrs[name]
		if !ok && f.containers[name] != nil {
			addrs = []string{f.containers[name].addr}
		}
		var b strings.Builder
		b.WriteString("1: lo    inet 127.0.0.1/8 scope host lo\n")
		for i, a := range addrs {
			fmt.Fprintf(&b, "%d: eth0    inet %s/24 brd 10.200.1.255 scope global eth0\n", i+2, a)
		}
		return b.String(), nil
	}
	return f.bRunner.Run(ctx, cmd)
}

func (f *cRunner) container(name string) (bIdent, time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.containers[name]
	if c == nil {
		return bIdent{}, f.runAt[name], false
	}
	return *c, f.runAt[name], true
}

func (f *cRunner) setAddrs(name string, a ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs[name] = a
}

// cCapture serves the observer capture from a function of the identity
// and writes the snapshot file the reader would have written.
type cCapture struct {
	mu    sync.Mutex
	fn    func(ident string) []DHCPMsg
	err   error
	reads []string
}

func (c *cCapture) Messages(_ context.Context, ident, snapshotPath string) ([]DHCPMsg, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads = append(c.reads, ident)
	if c.err != nil {
		return nil, c.err
	}
	if err := os.WriteFile(snapshotPath, []byte("pcap"), 0o644); err != nil {
		return nil, err
	}
	if c.fn == nil {
		return nil, nil
	}
	return c.fn(ident), nil
}

type cRig struct {
	h   *cRunner
	src *bAdapter
	cap *cCapture
	e   Env
}

func cSetup(t *testing.T, shape Shape) *cRig {
	t.Helper()
	h := newCRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}}, fn: staticLeases()}
	c := &cCapture{}
	e := bEnv(t, h, src, shape)
	e.Capture = c
	return &cRig{h: h, src: src, cap: c, e: e}
}

func dmsg(at time.Time, typ, xid, ident, yi, dst string) DHCPMsg {
	return DHCPMsg{At: at, Type: typ, XID: xid, CHAddr: ident, YIAddr: yi, Src: "10.200.1.2", Dst: dst}
}

// needWritten: the verdict passes the same checks Write applies (PASS
// carries readable evidence, BLOCKED and N/A carry none).
func needWritten(t *testing.T, e Env, v Verdict) {
	t.Helper()
	if err := Write(e.EvidenceDir, v); err != nil {
		t.Fatalf("verdict does not write: %v", err)
	}
}

func needReason(t *testing.T, v Verdict, sub string) {
	t.Helper()
	if !strings.Contains(v.Reason, sub) {
		t.Fatalf("reason %q does not contain %q", v.Reason, sub)
	}
}

func needSourceBack(t *testing.T, f *fakeAdapter) {
	t.Helper()
	if f.stops > 0 && f.starts < f.stops {
		t.Fatalf("the source was stopped %d time(s) and started %d", f.stops, f.starts)
	}
}

// ---- catalog --------------------------------------------------------

func TestCatalogRegistersGroupCWithTheNeedsOfTheDesign(t *testing.T) {
	want := map[string][]sourceadapter.Capability{
		NameC1:  {sourceadapter.CapV4, sourceadapter.CapRestart},
		NameC2:  {sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapRestart},
		NameC3:  {sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapRestart},
		NameC4:  {sourceadapter.CapV4, sourceadapter.CapShortLease},
		NameC5:  {sourceadapter.CapFailoverPair},
		NameC6:  {sourceadapter.CapV4, sourceadapter.CapReserveClientID, sourceadapter.CapSquatter},
		NameC6b: {sourceadapter.CapV4, sourceadapter.CapSquatter},
		NameC7:  {sourceadapter.CapV4, sourceadapter.CapRogueServer},
		NameC8:  {sourceadapter.CapV4, sourceadapter.CapNarrowPool},
		NameC9:  {sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapRenumber},
		NameC10: {sourceadapter.CapV4, sourceadapter.CapImpair},
		NameC11: {sourceadapter.CapV4, sourceadapter.CapRestart},
		NameC12: {sourceadapter.CapRelay},
	}
	seen := 0
	for _, s := range Catalog {
		w, ok := want[s.Name]
		if !ok {
			continue
		}
		seen++
		if fmt.Sprint(s.Needs) != fmt.Sprint(w) {
			t.Errorf("%s needs %v, want %v", s.Name, s.Needs, w)
		}
	}
	if seen != len(want) {
		t.Fatalf("catalog holds %d of the %d group C scenarios", seen, len(want))
	}
}

func TestC5AndC12AreNotApplicableNamingTheirLabIssues(t *testing.T) {
	all := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapRestart,
		sourceadapter.CapShortLease, sourceadapter.CapImpair}}
	for name, issue := range map[string]string{NameC5: "docker-net-dhcp-lab#12", NameC12: "docker-net-dhcp-lab#11"} {
		for _, s := range Catalog {
			if s.Name != name {
				continue
			}
			ok, reason := Applicable(s, all)
			if ok || !strings.Contains(reason, issue) {
				t.Errorf("%s: applicable=%v reason %q, want N/A naming %s", name, ok, reason, issue)
			}
		}
	}
	ok, reason := Applicable(Scenario{Needs: []sourceadapter.Capability{sourceadapter.CapImpair}}, &fakeAdapter{})
	if ok || strings.Contains(reason, "#1") {
		t.Errorf("a capability without a map entry got %v / %q", ok, reason)
	}
}

// ---- the readiness gate (defeat 1) ------------------------------------

func cGateEnv(src *fakeAdapter) Env {
	return Env{Host: &fakeRunOneHostRunner{installed: true, pgrepOK: true}, Source: src, Cell: "kea", Shape: ShapeMacvlan}
}

func shortReadyWait(t *testing.T) {
	t.Helper()
	tries, gap := sourceReadyTries, sourceReadyGap
	sourceReadyTries, sourceReadyGap = 2, ms
	t.Cleanup(func() { sourceReadyTries, sourceReadyGap = tries, gap })
}

func TestRunOneBlocksWhenTheSourceIsNotReadyAndRecoverFails(t *testing.T) {
	shortReadyWait(t)
	ran := false
	s := Scenario{Name: "probe", Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: func(context.Context, Env) Verdict {
		ran = true
		return Verdict{}
	}}
	src := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}, readyErrs: []error{errors.New("kea down")}, recoverErr: errors.New("no restart")}
	v := RunOne(context.Background(), s, cGateEnv(src))
	needResult(t, v, BLOCKED)
	needReason(t, v, "source not in a known state")
	if ran || src.recovered != 1 {
		t.Fatalf("ran=%v recovered=%d", ran, src.recovered)
	}
}

func TestRunOneBlocksWhenTheSourceStaysNotReadyAfterRecover(t *testing.T) {
	shortReadyWait(t)
	e := errors.New("control socket silent")
	src := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}, readyErrs: []error{e, e, e}}
	v := RunOne(context.Background(), Scenario{Name: "probe", Needs: []sourceadapter.Capability{sourceadapter.CapV4}}, cGateEnv(src))
	needResult(t, v, BLOCKED)
	needReason(t, v, "still not ready after recover")
	if src.readyCalls != 1+sourceReadyTries {
		t.Fatalf("Ready called %d times, want %d", src.readyCalls, 1+sourceReadyTries)
	}
}

func TestRunOneRecordsARecoveryOnTheNextVerdict(t *testing.T) {
	shortReadyWait(t)
	s := Scenario{Name: "probe", Needs: []sourceadapter.Capability{sourceadapter.CapV4}, Run: func(_ context.Context, e Env) Verdict {
		return pass("probe", e.Cell, e.Shape, "ran", map[string]string{"x": "y"}, "sha")
	}}
	src := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}, readyErrs: []error{errors.New("impairment left on eth1")}}
	v := RunOne(context.Background(), s, cGateEnv(src))
	needResult(t, v, PASS)
	needReason(t, v, "recovered before this scenario from: impairment left on eth1")
}

// ---- small helpers ----------------------------------------------------

func TestTimedRunReadsTheWallLineAndKeepsAFailureAsAResult(t *testing.T) {
	h := newCRunner()
	h.rc["n1"], h.wall["n1"] = 125, 12345*ms
	res, err := timedRun(context.Background(), h, "sudo docker run -d --name n1 --network x alpine:3.20 sleep 600")
	if err != nil || res.RC != 125 || res.Wall != 12345*ms || res.Out != "output of n1" {
		t.Fatalf("got %+v, %v", res, err)
	}
	r := &stubRunner{out: "no wall line\n"}
	if _, err := timedRun(context.Background(), r, "true"); err == nil {
		t.Fatal("output without a lab-wall line was accepted")
	}
	r.out = "lab-wall 0 200 100\n"
	if _, err := timedRun(context.Background(), r, "true"); err == nil {
		t.Fatal("an end before the start was accepted")
	}
	r.err = errors.New("ssh down")
	if _, err := timedRun(context.Background(), r, "true"); err == nil {
		t.Fatal("a runner error was swallowed")
	}
}

type stubRunner struct {
	out  string
	err  error
	last string
}

func (s *stubRunner) Run(_ context.Context, cmd string) (string, error) {
	s.last = cmd
	return s.out, s.err
}

func TestTimedRunWrapsTheCommandOnTheDockerHost(t *testing.T) {
	r := &stubRunner{out: "lab-wall 0 1 2\n"}
	_, _ = timedRun(context.Background(), r, "sudo docker network create x")
	if !strings.HasPrefix(r.last, "s=$(date +%s%N); out=$(sudo docker network create x 2>&1); rc=$?") {
		t.Fatalf("wrapper is %q", r.last)
	}
}

func TestContainerAddrsSkipsLoopbackAndKeepsEveryInet(t *testing.T) {
	r := &stubRunner{out: "1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 10.200.1.150/24 brd x scope global eth0\n2: eth0    inet 10.200.1.151/24 scope global secondary eth0\n3: eth1 garbage\n"}
	got, err := containerAddrs(context.Background(), r, "c")
	if err != nil || fmt.Sprint(got) != "[10.200.1.150 10.200.1.151]" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestParseMessageLogReadsElevenFieldsAndDashes(t *testing.T) {
	msgs, err := parseMessageLog("100.250000 DISCOVER 0x1 aa:bb:cc:00:00:01 - - - - - 0.0.0.0 255.255.255.255\n\n101.5 ACK 0x1 aa:bb:cc:00:00:01 00:6c 10.200.1.2 - - 10.200.1.150 10.200.1.2 10.200.1.150\n")
	if err != nil || len(msgs) != 2 {
		t.Fatalf("got %v, %v", msgs, err)
	}
	if msgs[0].ClientID != "" || msgs[0].Dst != "255.255.255.255" || msgs[0].At.UnixMilli() != 100250 {
		t.Errorf("first message %+v", msgs[0])
	}
	if msgs[1].ClientID != "00:6c" || msgs[1].YIAddr != "10.200.1.150" || msgs[1].Server != "10.200.1.2" {
		t.Errorf("second message %+v", msgs[1])
	}
	if _, err := parseMessageLog("100.0 DISCOVER 0x1\n"); err == nil {
		t.Error("a short line was accepted")
	}
	if _, err := parseMessageLog("x DISCOVER 0x1 a - - - - - b c\n"); err == nil {
		t.Error("a bad timestamp was accepted")
	}
}

func TestMessageFiltersAndGaps(t *testing.T) {
	t0 := time.Unix(1000, 0)
	m := []DHCPMsg{
		dmsg(t0, "DISCOVER", "1", "a", "", "255.255.255.255"),
		dmsg(t0.Add(4*time.Second), "DISCOVER", "2", "a", "", "255.255.255.255"),
		dmsg(t0.Add(6*time.Second), "OFFER", "2", "a", "x", "255.255.255.255"),
		dmsg(t0.Add(12*time.Second), "DISCOVER", "3", "a", "", "255.255.255.255"),
	}
	if g := discoverGaps(m, 3); fmt.Sprint(g) != "[4s 8s]" {
		t.Errorf("gaps %v", g)
	}
	if n := len(messagesBetween(m, t0.Add(time.Second), t0.Add(6*time.Second))); n != 2 {
		t.Errorf("between kept %d", n)
	}
	if n := len(messagesAfter(m, t0.Add(5*time.Second))); n != 2 {
		t.Errorf("after kept %d", n)
	}
	if d, ok := offerDelay(m); !ok || d != 2*time.Second {
		t.Errorf("offer delay %v %v, want 2s matched by xid", d, ok)
	}
	if sawClientUnicast(m) {
		t.Error("broadcast only, yet unicast seen")
	}
	for _, typ := range []string{"ACK", "OFFER", "NAK"} {
		if sawClientUnicast(append(m, dmsg(t0, typ, "2", "a", "x", "10.200.1.150"))) {
			t.Errorf("a server %s to a unicast IP counted as proof the observer sees unicast", typ)
		}
	}
	for _, typ := range []string{"REQUEST", "RELEASE", "INFORM"} {
		if !sawClientUnicast(append(m, dmsg(t0, typ, "2", "a", "", "10.200.1.2"))) {
			t.Errorf("a client %s to the server's IP was not seen as unicast", typ)
		}
		if sawClientUnicast(append(m, dmsg(t0, typ, "2", "a", "", ""))) {
			t.Errorf("a client %s without a destination counted as unicast", typ)
		}
	}
}

func TestNewLeasesAndLocallyAdministered(t *testing.T) {
	before := []sourceadapter.Lease{{MAC: "AA:BB:CC:00:00:01", Address: "10.200.1.101"}}
	after := append(before, sourceadapter.Lease{MAC: "06:00:00:00:00:01", Address: "10.200.1.150"}, sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.101"})
	if n := newLeases(before, after); len(n) != 1 || n[0].Address != "10.200.1.150" {
		t.Errorf("new leases %v", n)
	}
	for mac, want := range map[string]bool{"06:00:00:00:00:01": true, "02:42:ac:11:00:02": true, "00:11:22:33:44:55": false, "junk": false} {
		if locallyAdministered(mac) != want {
			t.Errorf("locallyAdministered(%s) != %v", mac, want)
		}
	}
	now := time.Now()
	ls := []sourceadapter.Lease{{Address: "a"}, {Address: "b", Expires: now.Add(-time.Second)}, {Address: "c", Expires: now.Add(time.Second)}}
	if got := addrsOf(active(ls, now)); fmt.Sprint(got) != "[a c]" {
		t.Errorf("active %v", got)
	}
}

// ---- C1 ---------------------------------------------------------------

// c1Rig: both creates fail (exit 125) inside their bounds, with
// DISCOVERs at the given offsets from each docker run.
func c1Rig(t *testing.T) (*cRig, map[string][]time.Duration, string) {
	r := cSetup(t, ShapeMacvlan)
	base := containerName(r.e, NameC1)
	r.h.rc[base+"-c1b"], r.h.wall[base+"-c1b"] = 125, 12*time.Second
	r.h.rc[base+"-c1"], r.h.wall[base+"-c1"] = 125, 34*time.Second
	offs := map[string][]time.Duration{"c1b": {0, 4100 * ms}, "c1": {0, 3800 * ms, 12300 * ms}}
	r.cap.fn = func(ident string) []DHCPMsg {
		var out []DHCPMsg
		for s, o := range offs {
			if ident != b2WireClientID("lab-"+s+"-macvlan") {
				continue
			}
			_, at, _ := r.h.container(base + "-" + s)
			for i, d := range o {
				out = append(out, DHCPMsg{At: at.Add(d), Type: "DISCOVER", XID: strconv.Itoa(i), ClientID: ident, Dst: "255.255.255.255"})
			}
		}
		return out
	}
	return r, offs, base
}

func TestRunC1PassesWhenBothCreatesFailOnSchedule(t *testing.T) {
	r, _, base := c1Rig(t)
	v := runC1Tuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, r.e, v)
	if r.src.stops != 1 || r.src.starts != 1 {
		t.Fatalf("stops %d starts %d", r.src.stops, r.src.starts)
	}
	for _, want := range []string{"client_id=lab-c1b-macvlan", "lease_timeout=12s", "client_id=lab-c1-macvlan"} {
		if !r.h.has(want) {
			t.Errorf("no network create carried %s", want)
		}
	}
	needCleanup(t, r.h.bRunner, "c1b", base+"-c1b")
	needCleanup(t, r.h.bRunner, "c1", base+"-c1")
}

// The kea run of plugin v2.5.0 measured c1b at 15.26-15.46 s and c1 at
// 31.13-31.29 s (#23); both ends of each bound are inclusive.
func TestRunC1WallBoundsAreInclusiveAndHoldTheMeasuredWalls(t *testing.T) {
	cases := []struct {
		name         string
		c1b, c1      time.Duration
		wantPass     bool
		wantInReason string
	}{
		{"the measured walls", 15460 * time.Millisecond, 31290 * time.Millisecond, true, ""},
		{"both at the lower bound", c1bWallMin, c1WallMin, true, ""},
		{"both at the upper bound", c1bWallMax, c1WallMax, true, ""},
		{"c1b just under its lower bound", c1bWallMin - time.Millisecond, 31 * time.Second, false, "c1b failed after"},
		{"c1b just over its upper bound", c1bWallMax + time.Millisecond, 31 * time.Second, false, "c1b failed after"},
		{"c1 just under its lower bound", 15 * time.Second, c1WallMin - time.Millisecond, false, "c1 failed after"},
		{"c1 just over its upper bound", 15 * time.Second, c1WallMax + time.Millisecond, false, "c1 failed after"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _, base := c1Rig(t)
			r.h.wall[base+"-c1b"], r.h.wall[base+"-c1"] = c.c1b, c.c1
			v := runC1Tuned(context.Background(), r.e, cFast)
			if c.wantPass {
				needResult(t, v, PASS)
				return
			}
			needResult(t, v, FAIL)
			needReason(t, v, c.wantInReason)
		})
	}
}

func TestRunC1Fails(t *testing.T) {
	cases := []struct {
		name, want string
		edit       func(r *cRig, offs map[string][]time.Duration, base string)
	}{
		{"a container started with the source down", "c1 started with the source down", func(r *cRig, _ map[string][]time.Duration, base string) { r.h.rc[base+"-c1"] = 0 }},
		{"the short timeout failed late", "c1b failed after 20s, outside 12s-18.5s", func(r *cRig, _ map[string][]time.Duration, base string) { r.h.wall[base+"-c1b"] = 20 * time.Second }},
		{"the default timeout failed early", "c1 failed after 20s, outside 28s-37s", func(r *cRig, _ map[string][]time.Duration, base string) { r.h.wall[base+"-c1"] = 20 * time.Second }},
		{"the second gap is off schedule", "c1: DISCOVER gap 2 was 10.2s", func(_ *cRig, offs map[string][]time.Duration, _ string) { offs["c1"][2] = 14 * time.Second }},
		{"the first gap is off schedule", "c1b: DISCOVER gap 1 was 5.5s", func(_ *cRig, offs map[string][]time.Duration, _ string) { offs["c1b"][1] = 5500 * ms }},
		{"too few DISCOVERs", "c1b: the capture shows 1 DISCOVER(s)", func(_ *cRig, offs map[string][]time.Duration, _ string) { offs["c1b"] = offs["c1b"][:1] }},
		{"an endpoint is left", "c1 still lists 1 endpoint(s)", func(r *cRig, _ map[string][]time.Duration, _ string) { r.h.endpoints["net1-c1"] = 1 }},
		// Defeat 14: an acquisition that outlives the failed endpoint
		// leaves a lease once the source is back.
		{"a lease is stranded", "an acquisition outlived the failed endpoint", func(r *cRig, _ map[string][]time.Duration, _ string) {
			r.src.fn = staticLeases(sourceadapter.Lease{ClientID: b2WireClientID("lab-c1-macvlan"), Address: "10.200.1.120", Expires: time.Now().Add(time.Hour)})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, offs, base := c1Rig(t)
			c.edit(r, offs, base)
			v := runC1Tuned(context.Background(), r.e, cFast)
			needResult(t, v, FAIL)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			needSourceBack(t, r.src.fakeAdapter)
			needCleanup(t, r.h.bRunner, "c1", base+"-c1")
		})
	}
}

func TestRunC1IgnoresAnExpiredLeaseForTheRun(t *testing.T) {
	r, _, _ := c1Rig(t)
	r.src.fn = staticLeases(sourceadapter.Lease{ClientID: b2WireClientID("lab-c1-macvlan"), Address: "10.200.1.120", Expires: time.Now().Add(-time.Minute)})
	needResult(t, runC1Tuned(context.Background(), r.e, cFast), PASS)
}

func TestRunC1BlocksAndPutsTheSourceBack(t *testing.T) {
	cases := []struct {
		name, want string
		edit       func(r *cRig, base string)
	}{
		{"docker run errors", "docker run on net1-c1b", func(r *cRig, base string) { r.h.errs[base+"-c1b"] = errors.New("ssh down") }},
		{"no capture", "could not read the capture", func(r *cRig, _ string) { r.e.Capture = nil }},
		{"the capture errors", "could not read the capture", func(r *cRig, _ string) { r.cap.err = errors.New("no observer") }},
		{"the table errors", "could not read the source's table", func(r *cRig, _ string) { r.src.err = errors.New("x") }},
		{"start errors", "could not start the source again", func(r *cRig, _ string) { r.src.startErr = errors.New("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _, base := c1Rig(t)
			c.edit(r, base)
			src := &countingLeases{bAdapter: r.src}
			r.e.Source = src
			v := runC1Tuned(context.Background(), r.e, cFast)
			needResult(t, v, BLOCKED)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			if r.src.starts < 1 {
				t.Fatal("the source was left stopped")
			}
			needCleanup(t, r.h.bRunner, "c1b", base+"-c1b")
		})
	}
}

// countingLeases makes fakeAdapter.err reach bAdapter's table.
type countingLeases struct{ *bAdapter }

func (c *countingLeases) Leases(ctx context.Context) ([]sourceadapter.Lease, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.bAdapter.Leases(ctx)
}

func TestRunC1FailsWhenItsNetworkCannotBeCreated(t *testing.T) {
	r, _, _ := c1Rig(t)
	r.h.netErr = errors.New("refused")
	v := runC1Tuned(context.Background(), r.e, cFast)
	needResult(t, v, FAIL)
	if r.src.stops != 0 {
		t.Fatal("the source was stopped although the setup failed")
	}
	needCleanup(t, r.h.bRunner, "c1b", "")
}

func TestRunC1BlocksWhenTheSourceWillNotStopAndStartsItAnyway(t *testing.T) {
	r, _, _ := c1Rig(t)
	r.src.stopErr = errors.New("x")
	needResult(t, runC1Tuned(context.Background(), r.e, cFast), BLOCKED)
	needSourceBack(t, r.src.fakeAdapter)
}

func TestC1AndC11AreNotApplicableOnTheIPAMShapes(t *testing.T) {
	for _, shape := range []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		for name, run := range map[string]func(context.Context, Env, cTiming) Verdict{NameC1: runC1Tuned, NameC11: runC11Tuned} {
			r := cSetup(t, shape)
			v := run(context.Background(), r.e, cFast)
			needResult(t, v, NA)
			if len(r.h.cmds) != 0 || r.src.stops != 0 {
				t.Errorf("%s on %s acted: %v", name, shape, r.h.cmds)
			}
		}
	}
}

// ---- C2, C3, C4: a bound container ------------------------------------

type cBoundRig struct {
	*cRig
	name                string
	bind, stopT, startT time.Time
	extra               func(ident string) []DHCPMsg
}

func cBoundSetup(t *testing.T, shape Shape, scenario string) *cBoundRig {
	r := cSetup(t, shape)
	b := &cBoundRig{cRig: r, name: containerName(r.e, scenario)}
	r.src.onStop = func() { b.stopT = time.Now() }
	r.src.onStart = func() { b.startT = time.Now() }
	r.cap.fn = func(ident string) []DHCPMsg {
		if b.bind.IsZero() {
			b.bind = time.Now()
		}
		out := []DHCPMsg{dmsg(b.bind, "ACK", "b", ident, "10.200.1.101", "10.200.1.101")}
		if b.extra != nil {
			out = append(out, b.extra(ident)...)
		}
		return out
	}
	return b
}

func (b *cBoundRig) lease(addr string, exp time.Time) sourceadapter.Lease {
	c, _, _ := b.h.container(b.name)
	l := sourceadapter.Lease{MAC: c.mac, Address: addr, Expires: exp}
	if b.e.Shape == ShapeIpvlan {
		l.ClientID, _ = ipvlanClientID(c.endpointID)
	}
	return l
}

func (b *cBoundRig) needPutBack(t *testing.T) {
	t.Helper()
	needSourceBack(t, b.src.fakeAdapter)
	if !b.src.restored {
		t.Error("the lease time was not restored")
	}
	needCleanup(t, b.h.bRunner, "", b.name)
}

// c2Rig: the client sends its renewal REQUEST midway through the
// outage and the source extends the lease once it is back.
func c2Rig(t *testing.T, shape Shape) *cBoundRig {
	b := cBoundSetup(t, shape, NameC2)
	now := time.Now()
	b.src.fn = func(int) []sourceadapter.Lease {
		if b.startT.IsZero() {
			return []sourceadapter.Lease{b.lease("10.200.1.101", now.Add(2*time.Minute))}
		}
		return []sourceadapter.Lease{b.lease("10.200.1.101", now.Add(time.Hour))}
	}
	b.extra = func(ident string) []DHCPMsg {
		if b.startT.IsZero() {
			return nil
		}
		mid := b.stopT.Add(b.startT.Sub(b.stopT) / 2)
		return []DHCPMsg{dmsg(mid, "REQUEST", "r", ident, "", "10.200.1.2"), dmsg(b.startT.Add(ms), "ACK", "r", ident, "10.200.1.101", "10.200.1.101")}
	}
	return b
}

func TestRunC2PassesWhenTheClientTriesToRenewAcrossTheOutage(t *testing.T) {
	for _, shape := range []Shape{ShapeMacvlan, ShapeIpvlan, ShapeBridge} {
		t.Run(string(shape), func(t *testing.T) {
			b := c2Rig(t, shape)
			v := runC2Tuned(context.Background(), b.e, cFast)
			needResult(t, v, PASS)
			needWritten(t, b.e, v)
			if b.src.stops != 1 || b.src.starts != 1 {
				t.Fatalf("stops %d starts %d", b.src.stops, b.src.starts)
			}
			if got := b.stopT.Sub(b.bind); got < cFast.stopAfter {
				t.Errorf("stopped %s after the bind, want %s or later", got, cFast.stopAfter)
			}
			if shape == ShapeIpvlan && !strings.Contains(v.Reason, "00:00:00:00:00:00:00:00:01") {
				t.Errorf("ipvlan identity is not the endpoint client id: %q", v.Reason)
			}
			b.needPutBack(t)
		})
	}
}

func TestRunC2Judges(t *testing.T) {
	cases := []struct {
		name   string
		result Result
		want   string
		edit   func(b *cBoundRig)
	}{
		{"no renewal while another client's unicast renewal is visible", FAIL, "no renewal was attempted", func(b *cBoundRig) {
			b.extra = func(ident string) []DHCPMsg {
				if ident != "*" {
					return nil
				}
				return []DHCPMsg{dmsg(b.bind, "REQUEST", "p", "06:5e:00:00:00:63", "", "10.200.1.2")}
			}
		}},
		// A server reply to a unicast IP leaves with the
		// broadcast flag's ff:ff:ff:ff:ff:ff, so it reaches a blind
		// observer; only a client-sent unicast proves the port floods.
		{"no renewal and only a server unicast ACK", BLOCKED, "the observer cannot see a unicast renewal", func(b *cBoundRig) { b.extra = nil }},
		{"no renewal and only broadcast REQUESTs", BLOCKED, "the observer cannot see a unicast renewal", func(b *cBoundRig) {
			b.extra = func(ident string) []DHCPMsg {
				return []DHCPMsg{dmsg(b.bind, "REQUEST", "p", "06:5e:00:00:00:63", "", "255.255.255.255")}
			}
		}},
		{"an ACK inside the outage", BLOCKED, "the source was not down", func(b *cBoundRig) {
			b.extra = func(ident string) []DHCPMsg {
				if b.startT.IsZero() {
					return nil
				}
				return []DHCPMsg{dmsg(b.stopT.Add(b.startT.Sub(b.stopT)/2), "ACK", "r", ident, "10.200.1.101", "10.200.1.101")}
			}
		}},
		{"the lease is never renewed", FAIL, "shows no renewed lease", func(b *cBoundRig) {
			l := b.lease
			now := time.Now()
			b.src.fn = func(int) []sourceadapter.Lease {
				return []sourceadapter.Lease{l("10.200.1.101", now.Add(2*time.Minute))}
			}
		}},
		{"the container lost its address", FAIL, "no longer carries 10.200.1.101", func(b *cBoundRig) {
			b.src.onStart = func() { b.startT = time.Now(); b.h.setAddrs(b.name, "10.200.1.160") }
		}},
		{"no bind in the capture", BLOCKED, "no bind time", func(b *cBoundRig) { b.cap.fn = func(string) []DHCPMsg { return nil } }},
		{"no capture reader", BLOCKED, "no bind time", func(b *cBoundRig) { b.e.Capture = nil }},
		{"the source will not stop", BLOCKED, "could not stop the source", func(b *cBoundRig) { b.src.stopErr = errors.New("x") }},
		{"the source will not start", BLOCKED, "could not start the source again", func(b *cBoundRig) { b.src.startErr = errors.New("x") }},
		{"no lease before", FAIL, "after the first lease", func(b *cBoundRig) { b.src.fn = staticLeases() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c2Rig(t, ShapeMacvlan)
			c.edit(b)
			v := runC2Tuned(context.Background(), b.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, b.e, v)
			b.needPutBack(t)
		})
	}
}

func TestRunC2BlocksWhenTheLeaseCannotBeShortened(t *testing.T) {
	b := c2Rig(t, ShapeMacvlan)
	b.src.shortenErr = errors.New("x")
	needResult(t, runC2Tuned(context.Background(), b.e, cFast), BLOCKED)
	if len(b.h.cmds) != 0 {
		t.Fatalf("acted on the host: %v", b.h.cmds)
	}
}

// c3Rig: the source comes back past expiry and the container ends up on
// .150, in the table and in its namespace.
func c3Rig(t *testing.T) *cBoundRig {
	b := cBoundSetup(t, ShapeMacvlan, NameC3)
	now := time.Now()
	b.src.fn = func(int) []sourceadapter.Lease {
		if b.startT.IsZero() {
			return []sourceadapter.Lease{b.lease("10.200.1.101", now.Add(2*time.Minute))}
		}
		return []sourceadapter.Lease{b.lease("10.200.1.150", now.Add(time.Hour))}
	}
	b.src.onStart = func() { b.startT = time.Now(); b.h.setAddrs(b.name, "10.200.1.150") }
	return b
}

func TestRunC3PassesWhenTheContainerIsLeasedAgainAfterExpiry(t *testing.T) {
	b := c3Rig(t)
	v := runC3Tuned(context.Background(), b.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, b.e, v)
	needReason(t, v, "moved from 10.200.1.101 to 10.200.1.150")
	rec, err := os.ReadFile(v.Evidence["addr-past-expiry"])
	if err != nil || !strings.Contains(string(rec), "source down: container carries [10.200.1.101]") {
		t.Fatalf("the address was not recorded during the outage: %q %v", rec, err)
	}
	b.needPutBack(t)
}

func TestRunC3Fails(t *testing.T) {
	cases := []struct {
		name string
		edit func(b *cBoundRig)
	}{
		{"the container does not carry the leased address", func(b *cBoundRig) { b.src.onStart = func() { b.startT = time.Now() } }},
		{"the lease is expired", func(b *cBoundRig) {
			before := b.src.fn
			b.src.fn = func(call int) []sourceadapter.Lease {
				if b.startT.IsZero() {
					return before(call)
				}
				return []sourceadapter.Lease{b.lease("10.200.1.150", time.Now().Add(-time.Second))}
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c3Rig(t)
			c.edit(b)
			v := runC3Tuned(context.Background(), b.e, cFast)
			needResult(t, v, FAIL)
			needReason(t, v, "no active lease for aa:bb:cc:00:00:01 matches the container's own address")
			needWritten(t, b.e, v)
			b.needPutBack(t)
		})
	}
}

// c4Rig: the reset empties the table, then the client is leased again;
// final is the table at the judgement.
func c4Rig(t *testing.T) (*cBoundRig, *[]sourceadapter.Lease) {
	b := cBoundSetup(t, ShapeMacvlan, NameC4)
	now := time.Now()
	final := []sourceadapter.Lease{}
	afterReset := []sourceadapter.Lease{}
	b.src.fn = func(call int) []sourceadapter.Lease {
		switch {
		case b.src.resets == 0:
			return []sourceadapter.Lease{b.lease("10.200.1.101", now.Add(2*time.Minute))}
		case call == 2:
			return afterReset
		}
		return final
	}
	b.src.onReset = func() {
		final = []sourceadapter.Lease{b.lease("10.200.1.101", now.Add(time.Hour))}
	}
	return b, &afterReset
}

func TestRunC4PassesWithOneLeaseAfterTheReset(t *testing.T) {
	b, _ := c4Rig(t)
	v := runC4Tuned(context.Background(), b.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, b.e, v)
	if b.src.resets != 1 {
		t.Fatalf("resets %d", b.src.resets)
	}
	for _, label := range []string{"leases-before", "leases-after-reset", "leases-after", "capture", "capture-bind"} {
		if v.Evidence[label] == "" {
			t.Errorf("no %s evidence", label)
		}
	}
	b.needPutBack(t)
}

func TestRunC4Judges(t *testing.T) {
	other := sourceadapter.Lease{MAC: "aa:bb:cc:99:99:99", Address: "10.200.1.101", Expires: time.Now().Add(time.Hour)}
	cases := []struct {
		name   string
		result Result
		want   string
		edit   func(b *cBoundRig, afterReset *[]sourceadapter.Lease)
	}{
		{"the reset left rows", BLOCKED, "the lease file was not cleared", func(_ *cBoundRig, a *[]sourceadapter.Lease) { *a = []sourceadapter.Lease{other} }},
		{"the reset errors", BLOCKED, "could not reset", func(b *cBoundRig, _ *[]sourceadapter.Lease) { b.src.resetErr = errors.New("x") }},
		{"two leases for the identity", FAIL, "holds 2 active lease(s)", func(b *cBoundRig, _ *[]sourceadapter.Lease) {
			b.src.onReset = func() {
				f := []sourceadapter.Lease{b.lease("10.200.1.101", time.Now().Add(time.Hour)), b.lease("10.200.1.150", time.Now().Add(time.Hour))}
				b.src.fn = finalAfter(b, f)
			}
		}},
		{"no lease for the identity", FAIL, "holds 0 active lease(s)", func(b *cBoundRig, _ *[]sourceadapter.Lease) {
			b.src.onReset = func() { b.src.fn = finalAfter(b, nil) }
		}},
		{"another identity on the address", FAIL, "is also leased to another identity", func(b *cBoundRig, _ *[]sourceadapter.Lease) {
			b.src.onReset = func() {
				b.src.fn = finalAfter(b, []sourceadapter.Lease{b.lease("10.200.1.101", time.Now().Add(time.Hour)), other})
			}
		}},
		{"the container carries another address", FAIL, "the container carries [10.200.1.101]", func(b *cBoundRig, _ *[]sourceadapter.Lease) {
			b.src.onReset = func() {
				b.src.fn = finalAfter(b, []sourceadapter.Lease{b.lease("10.200.1.150", time.Now().Add(time.Hour))})
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, a := c4Rig(t)
			c.edit(b, a)
			v := runC4Tuned(context.Background(), b.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, b.e, v)
			b.needPutBack(t)
		})
	}
}

// finalAfter: an empty table for the read right after the reset, then f.
func finalAfter(b *cBoundRig, f []sourceadapter.Lease) func(int) []sourceadapter.Lease {
	first := b.src.calls + 1
	return func(call int) []sourceadapter.Lease {
		if call == first {
			return nil
		}
		return f
	}
}

// ---- C10 --------------------------------------------------------------

// c10Rig: (a) is offered 2.5 s after its DISCOVER and starts in 5 s;
// (b) sends DISCOVERs at the offsets in offs["b"] and is offered at
// offs["b-offer"]. The table leases every container docker started.
func c10Rig(t *testing.T) (*cRig, map[string][]time.Duration, string) {
	r := cSetup(t, ShapeMacvlan)
	base := containerName(r.e, NameC10)
	r.h.wall[base+"-a"], r.h.wall[base+"-b"] = 5*time.Second, 13*time.Second
	offs := map[string][]time.Duration{"a-offer": {2500 * ms}, "b": {0, 4 * time.Second, 12 * time.Second}, "b-offer": {12200 * ms}}
	r.src.fn = func(int) []sourceadapter.Lease {
		var ls []sourceadapter.Lease
		for _, s := range []string{"-a", "-b"} {
			if c, _, ok := r.h.container(base + s); ok {
				ls = append(ls, sourceadapter.Lease{MAC: c.mac, Address: c.addr})
			}
		}
		return ls
	}
	r.cap.fn = func(ident string) []DHCPMsg {
		var out []DHCPMsg
		if c, at, ok := r.h.container(base + "-a"); ok && (ident == "*" || ident == c.mac) {
			out = append(out, dmsg(at, "DISCOVER", "a", c.mac, "", "255.255.255.255"),
				dmsg(at.Add(offs["a-offer"][0]), "OFFER", "a", c.mac, c.addr, "255.255.255.255"))
		}
		if c, at, ok := r.h.container(base + "-b"); ok && (ident == "*" || ident == c.mac) {
			xid := ""
			for i, d := range offs["b"] {
				xid = "b" + strconv.Itoa(i)
				out = append(out, dmsg(at.Add(d), "DISCOVER", xid, c.mac, "", "255.255.255.255"))
			}
			out = append(out, dmsg(at.Add(offs["b-offer"][0]), "OFFER", xid, c.mac, c.addr, "255.255.255.255"))
		}
		return out
	}
	return r, offs, base
}

func TestRunC10PassesUnderDelayAndAfterLoss(t *testing.T) {
	r, _, base := c10Rig(t)
	v := runC10Tuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, r.e, v)
	needReason(t, v, "gaps 4s, 8s")
	if fmt.Sprint(r.src.impaired) != "[2s/0 0s/100]" || r.src.impairRestored != 2 {
		t.Fatalf("impaired %v, restored %d", r.src.impaired, r.src.impairRestored)
	}
	for _, label := range []string{"note-delay", "capture-delay", "capture-under-loss", "capture-loss", "leases-delay", "leases-loss"} {
		if v.Evidence[label] == "" {
			t.Errorf("no %s evidence", label)
		}
	}
	needCleanup(t, r.h.bRunner, "", base+"-a")
	needCleanup(t, r.h.bRunner, "", base+"-b")
}

func TestRunC10Judges(t *testing.T) {
	cases := []struct {
		name     string
		result   Result
		want     string
		restored int
		edit     func(r *cRig, offs map[string][]time.Duration, base string)
	}{
		{"the offer was not late", BLOCKED, "the delay did not act", 1, func(_ *cRig, offs map[string][]time.Duration, _ string) { offs["a-offer"][0] = 500 * ms }},
		{"the run was too fast for the delay", BLOCKED, "the delay did not act", 1, func(r *cRig, _ map[string][]time.Duration, base string) { r.h.wall[base+"-a"] = 3 * time.Second }},
		{"(a) did not start", FAIL, "(a) with a 2s reply delay the container did not start", 1, func(r *cRig, _ map[string][]time.Duration, base string) { r.h.rc[base+"-a"] = 125 }},
		{"(b) retransmitted too little", FAIL, "2 DISCOVER(s)", 2, func(_ *cRig, offs map[string][]time.Duration, _ string) {
			offs["b"], offs["b-offer"][0] = offs["b"][:2], 4200*ms
		}},
		{"(b) second gap off schedule", FAIL, "(b) DISCOVER gap 2 was 11s", 2, func(_ *cRig, offs map[string][]time.Duration, _ string) {
			offs["b"][2], offs["b-offer"][0] = 15*time.Second, 15200*ms
		}},
		// A retransmit at the jitter's edge plus capture
		// latency (4 s +1.2 s) is the plugin on schedule.
		{"(b) gaps at the jitter's edge", PASS, "", 2, func(_ *cRig, offs map[string][]time.Duration, _ string) {
			offs["b"], offs["b-offer"][0] = []time.Duration{0, 5200 * ms, 13400 * ms}, 13600*ms
		}},
		{"(b) first gap past the slack", FAIL, "(b) DISCOVER gap 1 was 5.3s", 2, func(_ *cRig, offs map[string][]time.Duration, _ string) {
			offs["b"], offs["b-offer"][0] = []time.Duration{0, 5300 * ms, 13300 * ms}, 13500*ms
		}},
		{"(b) first gap off schedule", FAIL, "(b) DISCOVER gap 1 was 2s", 2, func(_ *cRig, offs map[string][]time.Duration, _ string) { offs["b"][1] = 2 * time.Second }},
		{"(b) did not start", FAIL, "(b) the container did not start once the loss lifted", 2, func(r *cRig, _ map[string][]time.Duration, base string) { r.h.rc[base+"-b"] = 125 }},
		{"no capture", BLOCKED, "could not read the capture", 1, func(r *cRig, _ map[string][]time.Duration, _ string) { r.cap.err = errors.New("no observer") }},
		{"the impairment cannot be set", BLOCKED, "could not delay the source's replies", 0, func(r *cRig, _ map[string][]time.Duration, _ string) { r.src.impairErr = errors.New("no sch_netem") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, offs, base := c10Rig(t)
			c.edit(r, offs, base)
			v := runC10Tuned(context.Background(), r.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			if r.src.impairRestored != c.restored || len(r.src.impaired) != c.restored {
				t.Fatalf("impaired %v, restored %d, want every one of %d restored", r.src.impaired, r.src.impairRestored, c.restored)
			}
		})
	}
}

// Defeat A6: the loss lifts on the second DISCOVER the capture shows,
// not on a fixed timer, and by c10Lift at the latest; one DISCOVER from
// each of two identities is not two.
func TestC10LiftsTheLossByTheDeadlineWithoutTwoDiscovers(t *testing.T) {
	r, _, _ := c10Rig(t)
	from := time.Now()
	r.cap.fn = func(string) []DHCPMsg {
		return []DHCPMsg{dmsg(from.Add(ms), "DISCOVER", "1", "a", "", ""), dmsg(from.Add(2*ms), "DISCOVER", "2", "b", "", "")}
	}
	after, err := c10WaitTwoDiscovers(context.Background(), r.e, cFast, from, map[string]string{})
	if err != nil || after < cFast.c10Lift {
		t.Fatalf("lifted after %s (%v), want the %s deadline", after, err, cFast.c10Lift)
	}
	from = time.Now()
	t0 := from.Add(ms)
	r.cap.fn = func(string) []DHCPMsg {
		return []DHCPMsg{dmsg(t0, "DISCOVER", "1", "a", "", ""), dmsg(t0, "DISCOVER", "2", "b", "", ""), dmsg(t0.Add(time.Second), "DISCOVER", "3", "a", "", "")}
	}
	if after, err = c10WaitTwoDiscovers(context.Background(), r.e, cFast, from, map[string]string{}); err != nil || after >= cFast.c10Lift {
		t.Fatalf("did not lift on the second DISCOVER of one identity: %s %v", after, err)
	}
	if r.cap.reads[len(r.cap.reads)-1] != "*" {
		t.Fatalf("the watch read %q, want every identity", r.cap.reads[len(r.cap.reads)-1])
	}
}

// ---- C11 --------------------------------------------------------------

// c11Rig: the create with the source up succeeds and its probe leaves
// one lease on a locally administered MAC; the create with the source
// down is refused after 9 s.
func c11Rig(t *testing.T) (*cRig, *[]sourceadapter.Lease) {
	r := cSetup(t, ShapeMacvlan)
	after := []sourceadapter.Lease{{MAC: "06:5e:00:00:00:01", Address: "10.200.1.170"}}
	r.src.fn = func(call int) []sourceadapter.Lease {
		if call == 1 {
			return nil
		}
		return after
	}
	r.h.rc["net1-c11b"], r.h.wall["net1-c11b"] = 1, 9*time.Second
	r.h.macs = "aa:bb:cc:00:00:01 02:42:ac:11:00:02 "
	return r, &after
}

func TestRunC11PassesWhenTheProbeLeasesOnceAndRefusesWithTheSourceDown(t *testing.T) {
	r, _ := c11Rig(t)
	v := runC11Tuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, r.e, v)
	if r.src.stops != 1 || r.src.starts != 1 {
		t.Fatalf("stops %d starts %d", r.src.stops, r.src.starts)
	}
	if !r.h.has("-o validate_dhcp=true") {
		t.Error("no create carried validate_dhcp=true")
	}
	needCleanup(t, r.h.bRunner, "c11", "")
	needCleanup(t, r.h.bRunner, "c11b", "")
}

func TestRunC11Judges(t *testing.T) {
	cases := []struct {
		name   string
		result Result
		want   string
		edit   func(r *cRig, after *[]sourceadapter.Lease)
	}{
		{"refused with the source up", FAIL, "was refused with the source up", func(r *cRig, _ *[]sourceadapter.Lease) { r.h.rc["net1-c11"] = 1 }},
		{"the probe left no lease", FAIL, "left 0 new lease(s)", func(_ *cRig, a *[]sourceadapter.Lease) { *a = nil }},
		{"the probe left two leases", FAIL, "left 2 new lease(s)", func(_ *cRig, a *[]sourceadapter.Lease) {
			*a = append(*a, sourceadapter.Lease{MAC: "06:5e:00:00:00:02", Address: "10.200.1.171"})
		}},
		{"the probe MAC is globally administered", FAIL, "not a locally administered one", func(_ *cRig, a *[]sourceadapter.Lease) { (*a)[0].MAC = "00:11:22:33:44:55" }},
		{"the probe MAC is a container's", FAIL, "belongs to a container", func(r *cRig, a *[]sourceadapter.Lease) {
			(*a)[0].MAC, r.h.macs = "06:5E:00:00:00:01", "06:5e:00:00:00:01"
		}},
		{"created with the source down", FAIL, "was created with the source down", func(r *cRig, _ *[]sourceadapter.Lease) { r.h.rc["net1-c11b"] = 0 }},
		{"refused too slowly", FAIL, "refused after 13s, over the 12s", func(r *cRig, _ *[]sourceadapter.Lease) { r.h.wall["net1-c11b"] = 13 * time.Second }},
		{"refused but still listed", FAIL, "docker still lists it", func(r *cRig, _ *[]sourceadapter.Lease) { r.h.listed["net1-c11b"] = true }},
		{"the source will not stop", BLOCKED, "could not stop the source", func(r *cRig, _ *[]sourceadapter.Lease) { r.src.stopErr = errors.New("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, a := c11Rig(t)
			c.edit(r, a)
			v := runC11Tuned(context.Background(), r.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			if r.src.stops > 0 && r.src.starts < 1 {
				t.Fatal("the source was left stopped")
			}
			needCleanup(t, r.h.bRunner, "c11", "")
		})
	}
}

func TestRunC11IsNotApplicableOnBridgeQuotingThePluginDocs(t *testing.T) {
	r, _ := c11Rig(t)
	r.e.Shape = ShapeBridge
	v := runC11Tuned(context.Background(), r.e, cFast)
	needResult(t, v, NA)
	needReason(t, v, `"Bridge mode rejects the option."`)
	if len(r.h.cmds) != 0 {
		t.Fatalf("acted on the host: %v", r.h.cmds)
	}
}
