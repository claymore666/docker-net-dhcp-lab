package scenario

import (
	"context"
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
	mac, addr string
	calls     []string
}

func (f *fakeContainerRunner) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	switch {
	case strings.Contains(cmd, "MacAddress"):
		return f.mac, nil
	case strings.Contains(cmd, "IPAddress"):
		return f.addr, nil
	default:
		return "", nil
	}
}

func TestRunContainerPolicyAddsRestartFlagWhenGiven(t *testing.T) {
	r := &fakeContainerRunner{mac: "aa:bb:cc:dd:ee:ff", addr: "10.200.1.100"}
	mac, addr, err := runContainerPolicy(context.Background(), r, "net1", "box1", "unless-stopped")
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
	r := &fakeContainerRunner{mac: "aa:bb:cc:dd:ee:ff", addr: "10.200.1.100"}
	if _, _, err := runContainer(context.Background(), r, "net1", "box1"); err != nil {
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
