package sourceadapter

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	errBanner  = errors.New("ssh lab@10.200.255.20: exit status 255: Connection timed out during banner exchange\r\nConnection to 10.200.255.20 port 22 timed out\r\n")
	errRefused = errors.New("ssh lab@10.200.255.40: exit status 255: ssh: connect to host 10.200.255.40 port 22: Connection refused\r\n")
	errNoRoute = errors.New("ssh lab@10.200.255.40: exit status 255: ssh: connect to host 10.200.255.40 port 22: No route to host\r\n")
	errDropped = errors.New("ssh lab@10.200.255.20: exit status 255: Connection to 10.200.255.20 closed by remote host.\r\n")
	errRemote  = errors.New("ssh lab@10.200.255.20: exit status 1: Error response from daemon: no such container")
)

// scriptedRunner answers call i with errs[i] (nil means success); past the
// end it repeats the last entry.
type scriptedRunner struct {
	errs  []error
	calls int
}

func (s *scriptedRunner) Run(_ context.Context, _ string) (string, error) {
	i := s.calls
	if i >= len(s.errs) {
		i = len(s.errs) - 1
	}
	s.calls++
	if s.errs[i] != nil {
		return "", s.errs[i]
	}
	return "ok", nil
}

func TestIsConnectErrorOnlyForPreCommandFailures(t *testing.T) {
	for _, err := range []error{errBanner, errRefused, errNoRoute,
		errors.New("ssh lab@h: exit status 255: kex_exchange_identification: read: Connection reset by peer")} {
		if !IsConnectError(err) {
			t.Errorf("not classed as a connect error: %v", err)
		}
	}
	for _, err := range []error{nil, errDropped, errRemote,
		errors.New("ssh lab@h: exit status 1: ssh: connect to host x port 22: Connection refused")} {
		if IsConnectError(err) {
			t.Errorf("classed as a connect error, but the command may have run: %v", err)
		}
	}
}

func TestRetryRunnerRetriesConnectFailuresUntilTheGuestAnswers(t *testing.T) {
	inner := &scriptedRunner{errs: []error{errBanner, errNoRoute, errRefused, nil}}
	var log bytes.Buffer
	r := &RetryRunner{Inner: inner, Bound: time.Second, Poll: time.Millisecond, Log: &log}
	out, err := r.Run(context.Background(), "true")
	if err != nil || out != "ok" {
		t.Fatalf("expected success after three connect failures, got %q, %v", out, err)
	}
	if inner.calls != 4 {
		t.Fatalf("expected 4 attempts, got %d", inner.calls)
	}
	line := log.String()
	if !strings.Contains(line, "4 attempts") || !strings.Contains(line, "banner exchange Connection to") ||
		strings.Count(line, "\n") != 1 || strings.Contains(line, "\r") {
		t.Fatalf("expected one log line naming the attempts and the first error, got %q", line)
	}
}

func TestRetryRunnerLogsNothingWhenTheFirstAttemptAnswers(t *testing.T) {
	var log bytes.Buffer
	r := &RetryRunner{Inner: &scriptedRunner{errs: []error{nil}}, Bound: time.Second, Poll: time.Millisecond, Log: &log}
	if _, err := r.Run(context.Background(), "true"); err != nil || log.Len() != 0 {
		t.Fatalf("expected a silent success, got %v and log %q", err, log.String())
	}
}

func TestRetryRunnerNeverRetriesACommandThatMayHaveRun(t *testing.T) {
	for _, e := range []error{errDropped, errRemote} {
		inner := &scriptedRunner{errs: []error{e, nil}}
		r := &RetryRunner{Inner: inner, Bound: time.Second, Poll: time.Millisecond}
		if _, err := r.Run(context.Background(), "sudo systemctl reboot"); !errors.Is(err, e) {
			t.Fatalf("expected the first error back unchanged, got %v", err)
		}
		if inner.calls != 1 {
			t.Fatalf("%v: expected exactly one attempt, got %d", e, inner.calls)
		}
	}
}

func TestRetryRunnerGivesUpAtItsBoundThenFailsFastUntilASuccess(t *testing.T) {
	inner := &scriptedRunner{errs: []error{errBanner}}
	r := &RetryRunner{Inner: inner, Bound: 30 * time.Millisecond, Poll: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := r.Run(ctx, "true"); !IsConnectError(err) {
		t.Fatalf("expected the connect error after the bound, got %v", err)
	}
	if el := time.Since(start); el < 30*time.Millisecond || el > time.Second {
		t.Fatalf("first call should retry for about its bound, took %s", el)
	}
	before := inner.calls
	if _, err := r.Run(context.Background(), "true"); err == nil {
		t.Fatal("expected the dead guest to still fail")
	}
	if inner.calls-before != 1 {
		t.Fatalf("after an exhausted bound a call must make one attempt, made %d", inner.calls-before)
	}
	inner.errs = []error{nil}
	if _, err := r.Run(context.Background(), "true"); err != nil {
		t.Fatalf("expected success once the guest answers, got %v", err)
	}
	inner.errs = []error{errRefused, nil}
	inner.calls = 0
	if _, err := r.Run(context.Background(), "true"); err != nil || inner.calls != 2 {
		t.Fatalf("a success must restore retrying: err %v, attempts %d", err, inner.calls)
	}
}

func TestRetryRunnerStopsAtTheCallersDeadlineWithoutMarkingDown(t *testing.T) {
	inner := &scriptedRunner{errs: []error{errNoRoute}}
	r := &RetryRunner{Inner: inner, Bound: 5 * time.Second, Poll: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := r.Run(ctx, "cat /proc/sys/kernel/random/boot_id"); !IsConnectError(err) {
		t.Fatalf("expected the connect error at the caller's deadline, got %v", err)
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("retry ran past the caller's deadline: %s", el)
	}
	inner.errs = []error{errNoRoute, nil}
	inner.calls = 0
	r.Poll = time.Millisecond
	if _, err := r.Run(context.Background(), "true"); err != nil || inner.calls != 2 {
		t.Fatalf("a caller's deadline must not mark the runner down: err %v, attempts %d", err, inner.calls)
	}
}

// cutRunner fails its first call with a connect error and holds every later
// one until the caller's deadline kills it, as exec.CommandContext does.
type cutRunner struct{ calls int }

func (c *cutRunner) Run(ctx context.Context, _ string) (string, error) {
	c.calls++
	if c.calls == 1 {
		return "", errBanner
	}
	<-ctx.Done()
	return "", errors.New("ssh lab@10.200.255.20: signal: killed: ")
}

func TestRetryRunnerReturnsTheConnectErrorWhenTheDeadlineCutsARetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r := &RetryRunner{Inner: &cutRunner{}, Bound: 2 * time.Second, Poll: time.Millisecond}
	if _, err := r.Run(ctx, "true"); !IsConnectError(err) || r.down.Load() {
		t.Fatalf("expected the connect error and no down mark, got %v (down %v)", err, r.down.Load())
	}
}
