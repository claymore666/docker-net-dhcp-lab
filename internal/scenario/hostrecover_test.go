package scenario

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// errSSHRefused is what the run-6 openwrt host gave every call after A5b (#158).
var errSSHRefused = errors.New("ssh: connect to host 10.200.255.150 port 22: Connection refused: exit status 255")

// fakeVirsh records each virsh call; resetErr fails the reset, and back
// tells the host runner the domain was power-cycled.
type fakeVirsh struct {
	calls    []string
	resetErr error
	back     func()
}

func (f *fakeVirsh) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch args[0] {
	case "domstate":
		return "running", nil
	case "reset":
		if f.resetErr != nil {
			return "error: domain is not running", f.resetErr
		}
	}
	if f.back != nil {
		f.back()
	}
	return "Domain '" + args[1] + "' was " + args[0], nil
}

// downHost refuses ssh until up is set, then answers like readyHost.
type downHost struct {
	up       bool
	neverUp  bool
	noPlugin bool
	calls    int
}

func (h *downHost) Run(ctx context.Context, cmd string) (string, error) {
	h.calls++
	if !h.up || h.neverUp {
		return "", errSSHRefused
	}
	if cmd == bootIDCmd {
		return "new-boot", nil
	}
	if strings.Contains(cmd, "{{.Enabled}}") && !h.noPlugin {
		return "true", nil
	}
	return readyHost{&fakeRunOneHostRunner{installed: !h.noPlugin, pgrepOK: true}}.Run(ctx, cmd)
}

func newRecovery(t *testing.T, v *fakeVirsh, max int) *HostRecovery {
	t.Helper()
	return &HostRecovery{Cell: "openwrt", Shape: ShapeMacvlan, EvidenceDir: t.TempDir(), Virsh: v.run,
		Max: max, Wait: 200 * time.Millisecond, Poll: 5 * time.Millisecond}
}

func evidenceFiles(t *testing.T, dir string) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(dir, "openwrt-macvlan-host-reset-*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestHostRecoveryLeavesAnyOtherErrorAlone(t *testing.T) {
	v := &fakeVirsh{}
	h := newRecovery(t, v, 2)
	for _, gateErr := range []error{nil, errors.New("plugin not installed under alias net-dhcp: exit status 1"),
		errors.New("Connection to 10.200.255.150 closed by remote host.: exit status 255")} {
		if _, tried, err := h.Try(context.Background(), &downHost{up: true}, gateErr); tried || err != nil {
			t.Errorf("%v: tried=%v err=%v, want no reset", gateErr, tried, err)
		}
	}
	if len(v.calls) != 0 || len(evidenceFiles(t, h.EvidenceDir)) != 0 {
		t.Errorf("virsh %q, evidence %v: want none", v.calls, evidenceFiles(t, h.EvidenceDir))
	}
	var none *HostRecovery
	if _, tried, _ := none.Try(context.Background(), &downHost{}, errSSHRefused); tried || none.TakeNote() != "" {
		t.Error("a nil HostRecovery reset something")
	}
}

func TestHostRecoveryResetsOnlyTheCellsOwnHostAndRecordsIt(t *testing.T) {
	host := &downHost{}
	v := &fakeVirsh{back: func() { host.up = true }}
	h := newRecovery(t, v, 2)
	note, tried, err := h.Try(context.Background(), host, errSSHRefused)
	if !tried || err != nil {
		t.Fatalf("tried=%v err=%v, want a successful reset", tried, err)
	}
	want := []string{"domstate lab-openwrt-dockerhost", "reset lab-openwrt-dockerhost"}
	if strings.Join(v.calls, "|") != strings.Join(want, "|") {
		t.Errorf("virsh calls %q, want %q", v.calls, want)
	}
	files := evidenceFiles(t, h.EvidenceDir)
	if len(files) != 1 {
		t.Fatalf("evidence files %v, want one", files)
	}
	body, _ := os.ReadFile(files[0])
	for _, s := range []string{"cell=openwrt shape=macvlan domain=lab-openwrt-dockerhost reset=1/2",
		"gate error: " + errSSHRefused.Error(), "domstate before: running", "outcome: ssh and docker answered"} {
		if !strings.Contains(string(body), s) {
			t.Errorf("evidence lacks %q:\n%s", s, body)
		}
	}
	if !strings.Contains(note, "virsh reset") || !strings.Contains(note, files[0]) {
		t.Errorf("note %q names neither the reset nor its evidence", note)
	}
	if got := h.TakeNote(); got != note {
		t.Errorf("TakeNote %q, want the reset's note", got)
	}
	if got := h.TakeNote(); got != "" {
		t.Errorf("a second TakeNote gave %q, want it taken once", got)
	}
}

func TestHostRecoveryStopsAtItsBudget(t *testing.T) {
	host := &downHost{}
	v := &fakeVirsh{back: func() { host.up = true }}
	h := newRecovery(t, v, 1)
	if _, tried, err := h.Try(context.Background(), host, errSSHRefused); !tried || err != nil {
		t.Fatalf("first: tried=%v err=%v", tried, err)
	}
	host.up = false
	if _, tried, _ := h.Try(context.Background(), host, errSSHRefused); tried {
		t.Error("a second reset ran past Max 1")
	}
	if len(v.calls) != 2 {
		t.Errorf("virsh calls %q, want one domstate and one reset", v.calls)
	}
}

func TestHostRecoveryStartsADomainThatWillNotReset(t *testing.T) {
	host := &downHost{}
	v := &fakeVirsh{resetErr: errors.New("exit status 1"), back: func() { host.up = true }}
	h := newRecovery(t, v, 2)
	note, tried, err := h.Try(context.Background(), host, errSSHRefused)
	if !tried || err != nil {
		t.Fatalf("tried=%v err=%v", tried, err)
	}
	if v.calls[len(v.calls)-1] != "start lab-openwrt-dockerhost" || !strings.Contains(note, "virsh start") {
		t.Errorf("virsh calls %q, note %q: want a start after the failed reset", v.calls, note)
	}
}

func TestHostRecoveryReportsAHostThatStaysDownWithinItsBound(t *testing.T) {
	host := &downHost{neverUp: true}
	h := newRecovery(t, &fakeVirsh{}, 2)
	start := time.Now()
	note, tried, err := h.Try(context.Background(), host, errSSHRefused)
	if !tried || err == nil || note != "" {
		t.Fatalf("tried=%v err=%v note=%q, want a failed reset", tried, err, note)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("took %s, past the 200ms bound", took)
	}
	body, _ := os.ReadFile(evidenceFiles(t, h.EvidenceDir)[0])
	if !strings.Contains(string(body), "outcome: still not back") || h.TakeNote() != "" {
		t.Errorf("evidence or note wrong for a host that stayed down:\n%s", body)
	}
}

// The reset reaches the verdict of the scenario it ran before, on both the
// BLOCKED path and the path that runs the scenario body.
func TestRunOneNamesTheHostResetInTheVerdict(t *testing.T) {
	host := &downHost{}
	v := &fakeVirsh{back: func() { host.up = true }}
	h := newRecovery(t, v, 2)
	e := Env{Host: host, Source: &fakeAdapter{caps: allNeeds()}, Cell: "openwrt", Shape: ShapeMacvlan,
		GitSHA: "abc1234", EvidenceDir: t.TempDir(), HostRecovery: h}
	ran := false
	s := Scenario{Name: "A5b", Run: func(context.Context, Env) Verdict {
		ran = true
		return pass("A5b", "openwrt", ShapeMacvlan, "body ran", nil, "abc1234")
	}}
	got := RunOne(context.Background(), s, e)
	if !ran || got.Result != BLOCKED || !strings.Contains(got.Reason, "body passed on a power-cycled host") ||
		!strings.Contains(got.Reason, "before this scenario the docker host stopped answering ssh") {
		t.Errorf("ran=%v %s %q: want the body run, BLOCKED, and the reset named", ran, got.Result, got.Reason)
	}

	host.up, host.noPlugin = false, true
	got = RunOne(context.Background(), s, e)
	if got.Result != BLOCKED || !strings.Contains(got.Reason, "plugin not installed") || !strings.Contains(got.Reason, "power-cycled (virsh reset") {
		t.Errorf("%s %q: want BLOCKED on the plugin, naming the reset that brought the host back", got.Result, got.Reason)
	}

	h.Max, host.up, host.neverUp = 3, false, true
	got = RunOne(context.Background(), s, e)
	if got.Result != BLOCKED || !strings.Contains(got.Reason, "did not bring it back") {
		t.Errorf("%s %q: want BLOCKED naming the failed reset", got.Result, got.Reason)
	}
	got = RunOne(context.Background(), s, e)
	if got.Result != BLOCKED || strings.Contains(got.Reason, "power-cycled") || len(evidenceFiles(t, h.EvidenceDir)) != 3 {
		t.Errorf("%s %q: a scenario past Max must block without a reset", got.Result, got.Reason)
	}
}

func TestRunOneNeverHidesAHostLostAfterAPassingScenario(t *testing.T) {
	host := &downHost{up: true}
	v := &fakeVirsh{back: func() { host.up = true }}
	h := newRecovery(t, v, 2)
	e := Env{Host: host, Source: &fakeAdapter{caps: allNeeds()}, Cell: "openwrt", Shape: ShapeMacvlan,
		GitSHA: "abc1234", EvidenceDir: t.TempDir(), HostRecovery: h}
	x := Scenario{Name: "X", Run: func(context.Context, Env) Verdict {
		defer func() { host.up = false }()
		return pass("X", "openwrt", ShapeMacvlan, "body ran", nil, "abc1234")
	}}
	y := Scenario{Name: "Y", Run: func(context.Context, Env) Verdict {
		return pass("Y", "openwrt", ShapeMacvlan, "body ran", nil, "abc1234")
	}}
	vx, vy := RunOne(context.Background(), x, e), RunOne(context.Background(), y, e)
	if vx.Result == PASS && vy.Result == PASS {
		t.Errorf("X %s, Y %s %q: a host lost after X must show in a verdict worse than PASS", vx.Result, vy.Result, vy.Reason)
	}
	if vy.Result != BLOCKED || !strings.Contains(vy.Reason, "power-cycled") {
		t.Errorf("Y %s %q: want BLOCKED naming the reset", vy.Result, vy.Reason)
	}

	host.up = false
	f := Scenario{Name: "F", Run: func(context.Context, Env) Verdict {
		return fail("F", "openwrt", ShapeMacvlan, "lease missing", nil, "abc1234")
	}}
	if vf := RunOne(context.Background(), f, e); vf.Result != FAIL || !strings.Contains(vf.Reason, "power-cycled") {
		t.Errorf("F %s %q: a FAIL after a reset stays FAIL and names the reset", vf.Result, vf.Reason)
	}
}

func TestShapeStartGateResetsADeadHostThroughWaitPluginReady(t *testing.T) {
	host := &downHost{}
	v := &fakeVirsh{back: func() { host.up = true }}
	h := newRecovery(t, v, 2)
	ctx := context.Background()
	wait := func() error { return waitPluginReadyTuned(ctx, host, 20*time.Millisecond, 5*time.Millisecond) }
	if err := h.Gate(ctx, host, wait); err != nil {
		t.Fatalf("gate after reset: %v", err)
	}
	if len(v.calls) == 0 || len(evidenceFiles(t, h.EvidenceDir)) != 1 || h.TakeNote() == "" {
		t.Errorf("virsh %v: a host refusing ssh at the shape-start gate must be reset and recorded", v.calls)
	}

	host.noPlugin = true
	if err := h.Gate(ctx, host, wait); err == nil || len(evidenceFiles(t, h.EvidenceDir)) != 1 {
		t.Errorf("err %v, virsh %v: a host that answers ssh with no plugin must not be reset", err, v.calls)
	}
}

// scriptedHost answers each command through fn, counting calls.
type scriptedHost struct {
	calls int
	fn    func(n int, cmd string) (string, error)
}

func (h *scriptedHost) Run(_ context.Context, cmd string) (string, error) {
	h.calls++
	return h.fn(h.calls, cmd)
}

func TestWaitPluginReadyNamesOnlyTheLastAttemptsSSHError(t *testing.T) {
	ctx := context.Background()
	backNoPlugin := &scriptedHost{fn: func(n int, cmd string) (string, error) {
		if n <= 2 {
			return "", errSSHRefused
		}
		return "false", nil
	}}
	if err := waitPluginReadyTuned(ctx, backNoPlugin, 30*time.Millisecond, 2*time.Millisecond); err == nil || sourceadapter.IsConnectError(err) {
		t.Errorf("%v: a host that answers again must not read as unreachable", err)
	}
	socketRefused := &scriptedHost{fn: func(_ int, cmd string) (string, error) {
		if strings.Contains(cmd, "{{.Enabled}}") {
			return "true", nil
		}
		return "", errSSHRefused
	}}
	if err := waitPluginReadyTuned(ctx, socketRefused, 10*time.Millisecond, 2*time.Millisecond); !sourceadapter.IsConnectError(err) {
		t.Errorf("%v: a refused socket check must carry the ssh error", err)
	}
}

func TestHostRecoveryPrintsOneLinePerResetNamingDomainAndEvidence(t *testing.T) {
	host := &downHost{}
	v := &fakeVirsh{back: func() { host.up = true }}
	h := newRecovery(t, v, 2)
	var log strings.Builder
	h.Log = &log
	if _, tried, err := h.Try(context.Background(), host, errSSHRefused); !tried || err != nil {
		t.Fatalf("tried=%v err=%v", tried, err)
	}
	files := evidenceFiles(t, h.EvidenceDir)
	want := "labctl run: docker host lab-openwrt-dockerhost reset after an ssh connect error; evidence " + files[0] + "\n"
	if len(files) != 1 || log.String() != want {
		t.Errorf("log %q, files %v: want exactly %q", log.String(), files, want)
	}
}
