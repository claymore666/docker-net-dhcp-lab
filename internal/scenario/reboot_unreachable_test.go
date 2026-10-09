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

var errGuestNoRoute = errors.New("ssh lab@10.200.255.40: exit status 255: ssh: connect to host 10.200.255.40 port 22: No route to host\r\n")

var errGuestKilled = errors.New("ssh lab@10.200.255.40: signal: killed: ")

// bootStep is one boot id poll's answer: an id, an error, or (hang) an
// attempt that ends when the caller's deadline kills it (2 s at most, so
// a broken bound fails instead of hanging).
type bootStep struct {
	id   string
	err  error
	hang bool
}

type steppedBootRunner struct {
	steps     []bootStep
	i         int
	dockerErr error
}

func (f *steppedBootRunner) Run(ctx context.Context, cmd string) (string, error) {
	switch {
	case cmd == bootIDCmd:
		i := f.i
		if i >= len(f.steps) {
			i = len(f.steps) - 1
		}
		f.i++
		if f.steps[i].hang {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
			return "", errGuestKilled
		}
		return f.steps[i].id, f.steps[i].err
	case strings.HasPrefix(cmd, "sudo docker info"):
		return "", f.dockerErr
	default:
		return "", nil
	}
}

func TestWaitHostRebootedReportsUnreachableWhenTheGuestNeverAnswersAgain(t *testing.T) {
	r := &steppedBootRunner{steps: []bootStep{{id: "old"}, {err: errGuestNoRoute}}}
	err := waitHostRebootedTuned(context.Background(), r, "old", 40*time.Millisecond, 10*time.Millisecond, 2*time.Millisecond)
	var u *HostUnreachableError
	if !errors.As(err, &u) {
		t.Fatalf("expected HostUnreachableError, got %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "boot id never changed") || !strings.Contains(err.Error(), "No route to host") {
		t.Fatalf("reason lost the boot id or the ssh error: %v", err)
	}
}

func TestWaitHostRebootedStaysAFailureWhenTheOldBootStillAnswers(t *testing.T) {
	r := &steppedBootRunner{steps: []bootStep{{err: errGuestNoRoute}, {id: "old"}}}
	err := waitHostRebootedTuned(context.Background(), r, "old", 40*time.Millisecond, 10*time.Millisecond, 2*time.Millisecond)
	var u *HostUnreachableError
	if err == nil || errors.As(err, &u) {
		t.Fatalf("a host stuck on its old boot answers ssh: expected a plain failure, got %T %v", err, err)
	}
}

func TestWaitHostRebootedReportsUnreachableWhenTheNewBootStopsAnswering(t *testing.T) {
	r := &steppedBootRunner{steps: []bootStep{{id: "new"}, {err: errGuestNoRoute}}}
	err := waitHostRebootedTuned(context.Background(), r, "old", 40*time.Millisecond, 10*time.Millisecond, 2*time.Millisecond)
	var u *HostUnreachableError
	if !errors.As(err, &u) || !strings.Contains(err.Error(), "second confirmation") {
		t.Fatalf("expected an unreachable settle failure, got %T %v", err, err)
	}
}

func TestWaitHostRebootedSplitsDockerInfoByReachability(t *testing.T) {
	var u *HostUnreachableError
	r := &steppedBootRunner{steps: []bootStep{{id: "new"}}, dockerErr: errGuestNoRoute}
	if err := waitHostRebootedTuned(context.Background(), r, "old", time.Second, 10*time.Millisecond, 2*time.Millisecond); !errors.As(err, &u) {
		t.Fatalf("docker info over a dead connection: expected HostUnreachableError, got %T %v", err, err)
	}
	r = &steppedBootRunner{steps: []bootStep{{id: "new"}}, dockerErr: errors.New("ssh lab@h: exit status 1: Cannot connect to the Docker daemon")}
	err := waitHostRebootedTuned(context.Background(), r, "old", time.Second, 10*time.Millisecond, 2*time.Millisecond)
	if err == nil || errors.As(err, &u) {
		t.Fatalf("dockerd down on a reachable host must stay a failure, got %T %v", err, err)
	}
}

func TestWaitHostRebootedKeepsItsBoundUnderARetryingRunner(t *testing.T) {
	inner := &steppedBootRunner{steps: []bootStep{{err: errGuestNoRoute}}}
	r := &sourceadapter.RetryRunner{Inner: inner, Bound: 2 * time.Second, Poll: time.Millisecond}
	start := time.Now()
	err := waitHostRebootedTuned(context.Background(), r, "old", 50*time.Millisecond, 10*time.Millisecond, 2*time.Millisecond)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("a 50ms reboot bound took %s under a retrying runner", el)
	}
	var u *HostUnreachableError
	if !errors.As(err, &u) {
		t.Fatalf("expected HostUnreachableError at the bound, got %T %v", err, err)
	}
}

func TestRebootWaitVerdictIsBlockedOnlyForAnUnreachableHost(t *testing.T) {
	dir := t.TempDir()
	ev := filepath.Join(dir, "leases-before.txt")
	if err := os.WriteFile(ev, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := Env{Cell: "dnsmasq", Shape: "bridge", GitSHA: "abc"}
	evBefore := map[string]string{"leases-before": ev}
	v := rebootWaitVerdict(NameA5, e, &HostUnreachableError{Msg: "boot id never changed", Err: errGuestNoRoute}, evBefore)
	if v.Result != BLOCKED || len(v.Evidence) != 0 {
		t.Fatalf("unreachable host: expected BLOCKED with no evidence, got %s %v", v.Result, v.Evidence)
	}
	v = rebootWaitVerdict(NameA5, e, errors.New("boot id never changed from old within 3m0s"), evBefore)
	if v.Result != FAIL || v.Evidence["leases-before"] != ev {
		t.Fatalf("reachable host: expected FAIL with its evidence, got %s %v", v.Result, v.Evidence)
	}
}

func TestWaitHostRebootedKeepsItsBoundWhenTheNewBootStopsAnsweringUnderARetryingRunner(t *testing.T) {
	inner := &steppedBootRunner{steps: []bootStep{{id: "new"}, {err: errGuestNoRoute}}}
	r := &sourceadapter.RetryRunner{Inner: inner, Bound: 2 * time.Second, Poll: time.Millisecond}
	start := time.Now()
	err := waitHostRebootedTuned(context.Background(), r, "old", 50*time.Millisecond, 10*time.Millisecond, 2*time.Millisecond)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("a 50ms reboot bound took %s in the settle phase under a retrying runner", el)
	}
	var u *HostUnreachableError
	if !errors.As(err, &u) {
		t.Fatalf("expected HostUnreachableError at the bound, got %T %v", err, err)
	}
}

func TestWaitHostRebootedJudgesByThePollBeforeOneItsBoundCut(t *testing.T) {
	var u *HostUnreachableError
	for _, steps := range [][]bootStep{
		{{id: "old"}, {err: errGuestNoRoute}, {hang: true}},
		{{id: "new"}, {err: errGuestNoRoute}, {hang: true}},
	} {
		err := waitHostRebootedTuned(context.Background(), &steppedBootRunner{steps: steps}, "old", 60*time.Millisecond, 10*time.Millisecond, 2*time.Millisecond)
		if !errors.As(err, &u) || !strings.Contains(err.Error(), "No route to host") || strings.Contains(err.Error(), "killed") {
			t.Fatalf("%v: expected unreachable judged by the poll before the cut one, got %T %v", steps, err, err)
		}
	}
	for _, steps := range [][]bootStep{
		{{id: "old"}, {hang: true}},
		{{err: errGuestNoRoute}, {err: errors.New("ssh lab@10.200.255.40: exit status 1: cat: boot_id: Permission denied")}},
	} {
		err := waitHostRebootedTuned(context.Background(), &steppedBootRunner{steps: steps}, "old", 60*time.Millisecond, 10*time.Millisecond, 2*time.Millisecond)
		if err == nil || errors.As(err, &u) {
			t.Fatalf("%v: the host answered last: expected a plain failure, got %T %v", steps, err, err)
		}
	}
}
