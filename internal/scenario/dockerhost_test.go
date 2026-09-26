package scenario

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const bootIDCmd = "cat /proc/sys/kernel/random/boot_id"

// fakeContainerRunner answers docker inspect with canned mac/addr and
// records every command, so runContainerPolicy's command construction
// (issue #3, lead directive 2026-09-26: A4/A5 need --restart
// unless-stopped) is checked without a real docker host.
type fakeContainerRunner struct {
	mac, addr, endpointID string
	calls                 []string
}

func (f *fakeContainerRunner) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	switch {
	case strings.Contains(cmd, "MacAddress"):
		return f.mac, nil
	case strings.Contains(cmd, "IPAddress"):
		return f.addr, nil
	case strings.Contains(cmd, "EndpointID"):
		return f.endpointID, nil
	default:
		return "", nil
	}
}

// fakeKnownStateRunner scripts docker plugin inspect (PluginReference)
// and pgrep, independently failable, so ensurePluginKnownState's three
// readings (issue #3, lead directive 2026-09-26) are checked without a
// real docker host: not installed, installed but process missing (with
// or without a successful manual re-enable), and the healthy case.
type fakeKnownStateRunner struct {
	notInstalled bool
	pgrepOK      bool
	enableFixes  bool
	enabled      bool
	calls        []string
}

func (f *fakeKnownStateRunner) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	switch {
	case strings.Contains(cmd, "PluginReference"):
		if f.notInstalled {
			return "", fmt.Errorf("no such plugin")
		}
		return "ghcr.io/claymore666/docker-net-dhcp:v2.3.0-rc1", nil
	case strings.Contains(cmd, "pgrep"):
		if f.pgrepOK || f.enabled {
			return "1234", nil
		}
		return "", fmt.Errorf("no process")
	case strings.Contains(cmd, "plugin enable"):
		f.enabled = f.enableFixes
		if !f.enableFixes {
			return "", fmt.Errorf("enable failed")
		}
		return "", nil
	default:
		return "", nil
	}
}

// knownStateTestBounds shrinks both wait windows and the poll interval
// so these tests exercise the same code as the real 30s/30s bounds
// without sitting through them (the same shrink-the-window-only
// discipline waitHostRebootedTuned's own tests already follow: never a
// way to weaken the check itself).
const (
	knownStateTestBound = 50 * time.Millisecond
	knownStateTestPoll  = 5 * time.Millisecond
)

func TestEnsurePluginKnownStateFailsWhenNotInstalled(t *testing.T) {
	r := &fakeKnownStateRunner{notInstalled: true}
	if err := ensurePluginKnownStateTuned(context.Background(), r, knownStateTestBound, knownStateTestBound, knownStateTestPoll); err == nil {
		t.Fatal("want an error when the plugin is not installed under the alias at all")
	}
}

func TestEnsurePluginKnownStateOKWhenProcessAlreadyAlive(t *testing.T) {
	r := &fakeKnownStateRunner{pgrepOK: true}
	if err := ensurePluginKnownStateTuned(context.Background(), r, knownStateTestBound, knownStateTestBound, knownStateTestPoll); err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "plugin enable") {
			t.Fatalf("a healthy plugin was re-enabled unnecessarily: %v", r.calls)
		}
	}
}

// The precondition check restores a missing process the same way A7's
// own recovery does: it needs a manual enable to come back, and does.
func TestEnsurePluginKnownStateRestoresViaEnable(t *testing.T) {
	r := &fakeKnownStateRunner{pgrepOK: false, enableFixes: true}
	if err := ensurePluginKnownStateTuned(context.Background(), r, knownStateTestBound, knownStateTestBound, knownStateTestPoll); err != nil {
		t.Fatalf("want the precondition check to restore the process via enable, got %v", err)
	}
}

// A process that a manual enable also cannot bring back is unrestorable:
// the caller (RunOne) must read this as BLOCKED, never attempt the
// scenario body.
func TestEnsurePluginKnownStateFailsWhenUnrestorable(t *testing.T) {
	r := &fakeKnownStateRunner{pgrepOK: false, enableFixes: false}
	if err := ensurePluginKnownStateTuned(context.Background(), r, knownStateTestBound, knownStateTestBound, knownStateTestPoll); err == nil {
		t.Fatal("want an error when neither self-heal nor a manual enable brings the process back")
	}
}

// fakeReadyRunner scripts docker plugin inspect (Enabled) and the socket
// glob independently, and counts how many polls each needed before
// answering true/ok, so waitPluginReadyTuned's two-stage gate (issue #3,
// lead directive 2026-09-26: enabled, then the socket, bounded and
// logged) is checked without a real docker host.
type fakeReadyRunner struct {
	enabledAfter int // polls before "docker plugin inspect -f Enabled" answers true
	socketAfter  int // polls before the socket glob answers ok, counted from enabledAfter
	neverReady   bool
	polls        int
}

func (f *fakeReadyRunner) Run(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "Enabled"):
		f.polls++
		if f.neverReady || f.polls <= f.enabledAfter {
			return "false", nil
		}
		return "true", nil
	case strings.Contains(cmd, pluginSocketGlob):
		if f.neverReady || f.polls <= f.enabledAfter+f.socketAfter {
			return "", fmt.Errorf("no such file or directory")
		}
		return "/run/docker/plugins/abc/net-dhcp.sock", nil
	default:
		return "", nil
	}
}

const (
	readyTestTimeout = 50 * time.Millisecond
	readyTestPoll    = 5 * time.Millisecond
)

func TestWaitPluginReadyOKOnceEnabledAndSocketAnswer(t *testing.T) {
	r := &fakeReadyRunner{enabledAfter: 1, socketAfter: 1}
	if err := waitPluginReadyTuned(context.Background(), r, readyTestTimeout, readyTestPoll); err != nil {
		t.Fatalf("want no error once both enabled and the socket answer, got %v", err)
	}
}

func TestWaitPluginReadyOKImmediatelyWhenAlreadyReady(t *testing.T) {
	r := &fakeReadyRunner{}
	if err := waitPluginReadyTuned(context.Background(), r, readyTestTimeout, readyTestPoll); err != nil {
		t.Fatalf("want no error when already enabled with an answering socket, got %v", err)
	}
}

func TestWaitPluginReadyFailsAfterTimeoutWhenSocketNeverAnswers(t *testing.T) {
	r := &fakeReadyRunner{neverReady: true}
	if err := waitPluginReadyTuned(context.Background(), r, readyTestTimeout, readyTestPoll); err == nil {
		t.Fatal("want an error when the socket never answers inside the bound")
	}
}

// fakeLogRunner scripts journalctl for CapturePluginLog: mixed lines, so
// the net-dhcp-only filter (issue #3, lead directive 2026-09-26) is
// checked without a real docker host.
type fakeLogRunner struct {
	journal string
	failErr error
}

func (f *fakeLogRunner) Run(_ context.Context, cmd string) (string, error) {
	if !strings.Contains(cmd, "journalctl") {
		return "", fmt.Errorf("unexpected command: %s", cmd)
	}
	if f.failErr != nil {
		return "", f.failErr
	}
	return f.journal, nil
}

func TestCapturePluginLogKeepsOnlyNetDHCPLines(t *testing.T) {
	r := &fakeLogRunner{journal: "Sep 26 net-dhcp: started\nSep 26 containerd: unrelated\nSep 26 net-dhcp: ready\n"}
	path := t.TempDir() + "/plugin.log"
	if err := CapturePluginLog(context.Background(), r, path); err != nil {
		t.Fatalf("CapturePluginLog failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if strings.Contains(string(got), "containerd") {
		t.Fatalf("CapturePluginLog kept a line outside net-dhcp: %q", got)
	}
	if !strings.Contains(string(got), "started") || !strings.Contains(string(got), "ready") {
		t.Fatalf("CapturePluginLog dropped a net-dhcp line: %q", got)
	}
}

func TestCapturePluginLogWritesAPlaceholderWhenNothingMatches(t *testing.T) {
	r := &fakeLogRunner{journal: "Sep 26 containerd: unrelated only\n"}
	path := t.TempDir() + "/plugin.log"
	if err := CapturePluginLog(context.Background(), r, path); err != nil {
		t.Fatalf("CapturePluginLog failed: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(got) == 0 {
		t.Fatal("CapturePluginLog left the file empty instead of a placeholder; Write() would refuse this as evidence")
	}
}

// fakeInstallRunner answers the Config.Env settings-name query with a
// scripted list and records every command, so installPluginChecked's
// "only set what the ref actually declares" rule (issue #3, lead
// directive 2026-09-26) is checked without a real docker host.
type fakeInstallRunner struct {
	envNames []string
	calls    []string
}

func (f *fakeInstallRunner) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	if strings.Contains(cmd, "Config.Env") {
		return strings.Join(f.envNames, "\n"), nil
	}
	return "", nil
}

func TestInstallPluginCheckedSkipsSettingTheRefDoesNotDeclare(t *testing.T) {
	r := &fakeInstallRunner{envNames: []string{"DEBUG"}}
	skipped, err := installPluginChecked(context.Background(), r, "alias1", "ref:v1", map[string]string{"DHCP_LOG_LEVEL": "debug"})
	if err != nil {
		t.Fatalf("installPluginChecked failed: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != "DHCP_LOG_LEVEL" {
		t.Fatalf("want DHCP_LOG_LEVEL reported skipped, got %v", skipped)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "plugin set") {
			t.Fatalf("a setting the ref does not declare reached the runner: %q", c)
		}
	}
	var sawEnable bool
	for _, c := range r.calls {
		if strings.Contains(c, "plugin enable alias1") {
			sawEnable = true
		}
	}
	if !sawEnable {
		t.Fatalf("installPluginChecked never enabled the plugin: %v", r.calls)
	}
}

func TestInstallPluginCheckedSetsSettingTheRefDeclares(t *testing.T) {
	r := &fakeInstallRunner{envNames: []string{"DHCP_LOG_LEVEL", "DEBUG"}}
	skipped, err := installPluginChecked(context.Background(), r, "alias1", "ref:v1", map[string]string{"DHCP_LOG_LEVEL": "debug"})
	if err != nil {
		t.Fatalf("installPluginChecked failed: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("want nothing skipped, got %v", skipped)
	}
	var sawSet bool
	for _, c := range r.calls {
		if strings.Contains(c, "plugin set alias1 DHCP_LOG_LEVEL=debug") {
			sawSet = true
		}
	}
	if !sawSet {
		t.Fatalf("installPluginChecked never set a setting the ref declares: %v", r.calls)
	}
}

func TestRunContainerPolicyAddsRestartFlagWhenGiven(t *testing.T) {
	r := &fakeContainerRunner{mac: "aa:bb:cc:dd:ee:ff", addr: "10.200.1.100", endpointID: "abc123"}
	mac, addr, _, err := runContainerPolicy(context.Background(), r, ShapeBridge, "net1", "box1", "unless-stopped")
	if err != nil {
		t.Fatalf("runContainerPolicy failed: %v", err)
	}
	if mac != "aa:bb:cc:dd:ee:ff" || addr != "10.200.1.100" {
		t.Fatalf("got mac=%q addr=%q", mac, addr)
	}
	var runCmd string
	for _, c := range r.calls {
		if strings.Contains(c, "docker run") {
			runCmd = c
		}
	}
	if !strings.Contains(runCmd, "--restart unless-stopped") {
		t.Fatalf("docker run did not carry --restart unless-stopped: %q", runCmd)
	}
}

// Preservation: runContainer (no policy argument) still starts a
// container with no restart flag at all, matching Docker's own default
// -- A1/A2/A3/A6/A7/A8 must not silently start setting one too.
func TestRunContainerHasNoRestartFlag(t *testing.T) {
	r := &fakeContainerRunner{mac: "aa:bb:cc:dd:ee:ff", addr: "10.200.1.100", endpointID: "abc123"}
	if _, _, _, err := runContainer(context.Background(), r, ShapeBridge, "net1", "box1"); err != nil {
		t.Fatalf("runContainer failed: %v", err)
	}
	var runCmd string
	for _, c := range r.calls {
		if strings.Contains(c, "docker run") {
			runCmd = c
		}
	}
	if strings.Contains(runCmd, "--restart") {
		t.Fatalf("runContainer's docker run unexpectedly carried a restart flag: %q", runCmd)
	}
}

// ipvlan slaves share the parent NIC's MAC (docs/parent-attached-modes.md),
// so docker legitimately reports an empty MacAddress for them; that must
// not fail inspectContainer under this one shape (issue #3, lead
// directive 2026-09-26, item 3).
func TestInspectContainerAllowsEmptyMACUnderIpvlan(t *testing.T) {
	r := &fakeContainerRunner{mac: "", addr: "10.200.1.100", endpointID: "abc123"}
	mac, addr, endpointID, err := inspectContainer(context.Background(), r, ShapeIpvlan, "box1")
	if err != nil {
		t.Fatalf("inspectContainer failed on an empty MAC under ipvlan: %v", err)
	}
	if mac != "" || addr != "10.200.1.100" || endpointID != "abc123" {
		t.Fatalf("got mac=%q addr=%q endpointID=%q", mac, addr, endpointID)
	}
}

// Under bridge (and macvlan) an empty MAC is not documented behaviour and
// must still fail loudly, exactly as it did before ipvlan's carve-out was
// added.
func TestInspectContainerRejectsEmptyMACUnderBridge(t *testing.T) {
	r := &fakeContainerRunner{mac: "", addr: "10.200.1.100", endpointID: "abc123"}
	if _, _, _, err := inspectContainer(context.Background(), r, ShapeBridge, "box1"); err == nil {
		t.Fatal("want an error when a bridge-shape container reports no MAC")
	}
}

// The ipvlan client-id lookup (issue #3, lead directive 2026-09-26, item
// 3) is built from the endpoint id, so a container with none reported
// cannot be looked up at all -- inspectContainer must fail here rather
// than hand an unusable empty string on to the lease lookup.
func TestInspectContainerRejectsEmptyEndpointIDUnderIpvlan(t *testing.T) {
	r := &fakeContainerRunner{mac: "", addr: "10.200.1.100", endpointID: ""}
	if _, _, _, err := inspectContainer(context.Background(), r, ShapeIpvlan, "box1"); err == nil {
		t.Fatal("want an error when an ipvlan container reports no endpoint id")
	}
}

// A5b's fixed-MAC container carries --mac-address through to docker run,
// alongside the restart policy A5b also needs.
func TestRunContainerFixedMACCarriesMacAddressFlag(t *testing.T) {
	r := &fakeContainerRunner{mac: "02:42:aa:bb:cc:dd", addr: "10.200.1.100", endpointID: "abc123"}
	mac, addr, _, err := runContainerFixedMAC(context.Background(), r, ShapeBridge, "net1", "box1", "unless-stopped", "02:42:aa:bb:cc:dd")
	if err != nil {
		t.Fatalf("runContainerFixedMAC failed: %v", err)
	}
	if mac != "02:42:aa:bb:cc:dd" || addr != "10.200.1.100" {
		t.Fatalf("got mac=%q addr=%q", mac, addr)
	}
	var runCmd string
	for _, c := range r.calls {
		if strings.Contains(c, "docker run") {
			runCmd = c
		}
	}
	if !strings.Contains(runCmd, "--mac-address 02:42:aa:bb:cc:dd") || !strings.Contains(runCmd, "--restart unless-stopped") {
		t.Fatalf("docker run did not carry both flags: %q", runCmd)
	}
}

// fakeBootRunner answers bootIDCmd with a scripted sequence of ids (one
// entry consumed per call, the last entry repeats once exhausted) and
// docker info with a canned error. It exists because
// TestNetworkUp*'s fakeShapeRunner can only fail or succeed a whole
// command, not hand back a different value on each successive call --
// exactly what a poll loop that must see the id change, then confirm it
// twice, needs.
type fakeBootRunner struct {
	bootIDs     []string
	bootIDCalls int
	dockerErr   error
	calls       []string
}

func (f *fakeBootRunner) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	switch {
	case cmd == bootIDCmd:
		i := f.bootIDCalls
		if i >= len(f.bootIDs) {
			i = len(f.bootIDs) - 1
		}
		f.bootIDCalls++
		return f.bootIDs[i], nil
	case strings.HasPrefix(cmd, "sudo docker info"):
		if f.dockerErr != nil {
			return "", f.dockerErr
		}
		return "", nil
	default:
		return "", nil
	}
}

// Happy path: the id changes once and the settle poll sees the same new
// id again after the window -- fakeBootRunner repeats the last entry,
// so "new" answers both the first sighting and every settle poll after
// it, the same as a host that genuinely stayed up on its new boot.
func TestWaitHostRebootedSucceedsWhenBootIDChangesAndSettles(t *testing.T) {
	r := &fakeBootRunner{bootIDs: []string{"old", "new"}}
	err := waitHostRebootedTuned(context.Background(), r, "old", time.Second, 30*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("expected the repeated 'new' id to satisfy the settle check, got: %v", err)
	}
}

// The failure mode the live diagnostic measured (issue #3, A5,
// 2026-09-26): the OLD boot answers SSH successfully twice, close
// together, while genuinely mid-shutdown, before the connection drops
// for real. A settle check keyed only on "the id changed at some point"
// would still need a second, later confirmation of the SAME new id --
// this pins that a same-second repeat of the OLD id before the real
// change is not itself mistaken for settling.
func TestWaitHostRebootedIgnoresARepeatOfTheOldIDBeforeItChanges(t *testing.T) {
	r := &fakeBootRunner{bootIDs: []string{"old", "old", "new"}}
	err := waitHostRebootedTuned(context.Background(), r, "old", time.Second, 15*time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("expected the eventual 'new' id to still settle correctly, got: %v", err)
	}
	if r.calls[0] != bootIDCmd || r.calls[1] != bootIDCmd {
		t.Fatalf("expected the first polls to re-check the boot id, got: %v", r.calls[:2])
	}
}

// A boot id that never changes from the pre-reboot value -- e.g. the
// reboot command silently no-op'd, or the host never came back at all
// -- must fail by naming the id, not time out with no explanation.
func TestWaitHostRebootedFailsWhenBootIDNeverChanges(t *testing.T) {
	r := &fakeBootRunner{bootIDs: []string{"old", "old", "old", "old", "old"}}
	err := waitHostRebootedTuned(context.Background(), r, "old", 40*time.Millisecond, 30*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error when the boot id never changes")
	}
	if !strings.Contains(err.Error(), "boot id never changed") {
		t.Fatalf("error does not explain the boot id never changed: %v", err)
	}
}

// A second, unplanned reboot mid-settle (the id changes again before
// the settle window elapses) is itself a finding, not something the
// check should paper over by just waiting for yet another new id.
func TestWaitHostRebootedFailsOnASecondRebootMidSettle(t *testing.T) {
	r := &fakeBootRunner{bootIDs: []string{"old", "new1", "new2", "new2", "new2"}}
	err := waitHostRebootedTuned(context.Background(), r, "old", time.Second, 15*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error when the boot id changes again mid-settle")
	}
	if !strings.Contains(err.Error(), "second reboot") {
		t.Fatalf("error does not name a second reboot: %v", err)
	}
}

// The boot id settling is not enough on its own -- dockerd itself must
// answer on the confirmed new boot before the scenario proceeds to
// start a container against it.
func TestWaitHostRebootedFailsWhenDockerInfoNeverAnswers(t *testing.T) {
	r := &fakeBootRunner{bootIDs: []string{"old", "new", "new", "new"}, dockerErr: context.DeadlineExceeded}
	err := waitHostRebootedTuned(context.Background(), r, "old", time.Second, 15*time.Millisecond, 5*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error when docker info never answers")
	}
	if !strings.Contains(err.Error(), "docker info") {
		t.Fatalf("error does not name docker info as the missing confirmation: %v", err)
	}
}

// bootID itself must fail loudly on an empty read (e.g. a truncated
// remote command) rather than let an empty string quietly compare equal
// to "no change yet" and loop forever inside the caller.
func TestBootIDRejectsAnEmptyRead(t *testing.T) {
	r := &fakeShapeRunner{}
	if _, err := bootID(context.Background(), r); err == nil {
		t.Fatal("expected an error for an empty boot id read")
	}
}
