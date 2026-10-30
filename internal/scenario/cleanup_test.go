package scenario

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dockerHostFake models the containers of one docker host and the ssh
// failures in front of it: reset answers the first n calls of a command
// with ssh's exit 255 before it ran (-1: always), keep makes `docker rm -f`
// exit 0 without removing anything.
type dockerHostFake struct {
	containers map[string]bool
	reset      map[string]int
	keep       map[string]bool
	calls      []string
	tried      map[string]int
}

func newDockerHostFake(names ...string) *dockerHostFake {
	f := &dockerHostFake{containers: map[string]bool{}, reset: map[string]int{}, keep: map[string]bool{}, tried: map[string]int{}}
	for _, n := range names {
		f.containers[n] = true
	}
	return f
}

func (f *dockerHostFake) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	f.tried[cmd]++
	if f.reset[cmd] != 0 {
		if f.reset[cmd] > 0 {
			f.reset[cmd]--
		}
		return "", errSSH255
	}
	switch {
	case strings.HasPrefix(cmd, "sudo docker rm -f "):
		name := strings.TrimPrefix(cmd, "sudo docker rm -f ")
		if !f.keep[name] {
			delete(f.containers, name)
		}
		return "", nil
	case strings.HasPrefix(cmd, "sudo docker ps -a -q --filter 'name=^/"):
		name := strings.TrimSuffix(strings.TrimPrefix(cmd, "sudo docker ps -a -q --filter 'name=^/"), "$'")
		if f.containers[name] {
			return "4f2a9c1d7e03\n", nil
		}
		return "", nil
	case strings.HasPrefix(cmd, "sudo docker ps -a --format '{{.Names}}' --filter 'name=^/lab-"):
		prefix := strings.TrimSuffix(strings.TrimPrefix(cmd, "sudo docker ps -a --format '{{.Names}}' --filter 'name=^/"), "'")
		var out string
		for n := range f.containers {
			if strings.HasPrefix(n, prefix) {
				out += n + "\n"
			}
		}
		return out, nil
	}
	return "", fmt.Errorf("unexpected command %q", cmd)
}

func fastCleanup(t *testing.T) *bytes.Buffer {
	t.Helper()
	oldB, oldP, oldL := cleanupRetryBound, cleanupRetryPoll, cleanupLog
	cleanupRetryBound, cleanupRetryPoll = 40*time.Millisecond, time.Millisecond
	var log bytes.Buffer
	cleanupLog = &log
	fastTeardown(t)
	t.Cleanup(func() { cleanupRetryBound, cleanupRetryPoll, cleanupLog = oldB, oldP, oldL })
	return &log
}

const c9 = "lab-kea-macvlan-C9-subnet-renumbered"

func TestRemoveContainerRetriesAfterAnSSHFailure(t *testing.T) {
	log := fastCleanup(t)
	f := newDockerHostFake(c9)
	f.reset["sudo docker rm -f "+c9] = 3
	removeContainer(context.Background(), f, c9)
	if f.containers[c9] || f.tried["sudo docker rm -f "+c9] != 4 || log.Len() != 0 {
		t.Errorf("container left %v, rm tried %d times, log %q", f.containers[c9], f.tried["sudo docker rm -f "+c9], log)
	}
}

func TestRemoveContainerTakesAnSSHFailureOfTheReadForNotGone(t *testing.T) {
	log := fastCleanup(t)
	f := newDockerHostFake(c9)
	f.reset["sudo docker ps -a -q --filter 'name=^/"+c9+"$'"] = -1
	removeContainer(context.Background(), f, c9)
	if !strings.Contains(log.String(), "lab: container "+c9+" could not be removed") || !strings.Contains(log.String(), "exit status 255") {
		t.Errorf("log %q", log)
	}
}

func TestRemoveContainerReadsDockerNotTheExitCode(t *testing.T) {
	log := fastCleanup(t)
	f := newDockerHostFake(c9)
	f.keep[c9] = true
	removeContainer(context.Background(), f, c9)
	if !strings.Contains(log.String(), "docker ps -a still lists") {
		t.Errorf("log %q", log)
	}
}

func TestRemoveContainerOfAnAbsentContainerIsOneRemovalAndOneRead(t *testing.T) {
	log := fastCleanup(t)
	f := newDockerHostFake()
	removeContainer(context.Background(), f, c9)
	if len(f.calls) != 2 || log.Len() != 0 {
		t.Errorf("calls %v, log %q", f.calls, log)
	}
}

func TestRemoveContainerGivesUpAtItsBound(t *testing.T) {
	fastCleanup(t)
	f := newDockerHostFake(c9)
	f.reset["sudo docker rm -f "+c9] = -1
	start := time.Now()
	err := removeContainerVerified(context.Background(), f, c9)
	if err == nil || time.Since(start) > 2*time.Second {
		t.Errorf("err %v after %s", err, time.Since(start))
	}
}

func TestRemoveContainerStopsWhenItsContextEnds(t *testing.T) {
	fastCleanup(t)
	cleanupRetryBound = time.Hour
	f := newDockerHostFake(c9)
	f.reset["sudo docker rm -f "+c9] = -1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := removeContainerVerified(ctx, f, c9); err == nil || f.tried["sudo docker rm -f "+c9] != 1 {
		t.Errorf("err %v, tried %d", err, f.tried["sudo docker rm -f "+c9])
	}
}

func TestRemoveLeftoverContainersRemovesAndRecords(t *testing.T) {
	fastCleanup(t)
	dir := t.TempDir()
	f := newDockerHostFake(c9, "lab-kea-bridge-A1-lease", "lab-dnsmasq-bridge-A1-lease", "plugin-sidecar")
	f.reset["sudo docker rm -f "+c9] = 1
	if err := RemoveLeftoverContainers(context.Background(), f, "kea", ShapeIpvlan, dir); err != nil {
		t.Fatal(err)
	}
	if f.containers[c9] || f.containers["lab-kea-bridge-A1-lease"] || !f.containers["lab-dnsmasq-bridge-A1-lease"] || !f.containers["plugin-sidecar"] {
		t.Errorf("containers left: %v", f.containers)
	}
	rec, err := os.ReadFile(filepath.Join(dir, "kea-ipvlan-leftover-containers.txt"))
	if err != nil || !strings.Contains(string(rec), "removed "+c9) || !strings.Contains(string(rec), "removed lab-kea-bridge-A1-lease") {
		t.Errorf("record %q, %v", rec, err)
	}
	if !strings.Contains(f.calls[0], "name=^/lab-kea-'") {
		t.Errorf("listing command %q", f.calls[0])
	}
}

func TestRemoveLeftoverContainersWritesNothingWhenThereAreNone(t *testing.T) {
	fastCleanup(t)
	dir := t.TempDir()
	if err := RemoveLeftoverContainers(context.Background(), newDockerHostFake(), "kea", ShapeMacvlan, dir); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("wrote %v", ents)
	}
}

func TestRemoveLeftoverContainersFailsWhenOneCannotGo(t *testing.T) {
	fastCleanup(t)
	dir := t.TempDir()
	f := newDockerHostFake(c9)
	f.keep[c9] = true
	err := RemoveLeftoverContainers(context.Background(), f, "kea", ShapeMacvlan, dir)
	if err == nil || !strings.HasPrefix(err.Error(), "lab: ") || !strings.Contains(err.Error(), c9) {
		t.Fatalf("err = %v", err)
	}
	if rec, _ := os.ReadFile(filepath.Join(dir, "kea-macvlan-leftover-containers.txt")); !strings.Contains(string(rec), "could not remove "+c9) {
		t.Errorf("record %q", rec)
	}
}

func TestRemoveLeftoverContainersDoesNotTakeAnUnreadListingForNone(t *testing.T) {
	fastCleanup(t)
	f := newDockerHostFake(c9)
	f.reset["sudo docker ps -a --format '{{.Names}}' --filter 'name=^/lab-kea-'"] = -1
	if err := RemoveLeftoverContainers(context.Background(), f, "kea", ShapeMacvlan, t.TempDir()); err == nil {
		t.Fatal("an unreadable listing passed as no leftovers")
	}
}

func TestRemoveLeftoverContainersRefusesAnUnsafeCellName(t *testing.T) {
	f := newDockerHostFake()
	if err := RemoveLeftoverContainers(context.Background(), f, "kea'; rm -rf /", ShapeMacvlan, t.TempDir()); err == nil || len(f.calls) != 0 {
		t.Fatalf("err %v, calls %v", err, f.calls)
	}
}

// The sweep runs inside ParentReady, before the wait for a clean parent
// reads the child links the leftover container holds.
func TestParentReadyRemovesLeftoversBeforeItReadsTheLinks(t *testing.T) {
	fastCleanup(t)
	f := newDockerHostFake(c9)
	r := &orderRunner{inner: f}
	if _, err := ParentReady(context.Background(), r, "kea", ShapeMacvlan, t.TempDir(), 20*time.Millisecond, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	rm, link := -1, -1
	for i, c := range r.seen {
		if strings.HasPrefix(c, "sudo docker rm -f ") && rm < 0 {
			rm = i
		}
		if strings.HasPrefix(c, "ip -d -o link show") && link < 0 {
			link = i
		}
	}
	if rm < 0 || link < 0 || rm > link {
		t.Errorf("rm at %d, first link read at %d: %v", rm, link, r.seen)
	}
}

func TestParentReadyFailsWhenALeftoverCannotBeRemoved(t *testing.T) {
	fastCleanup(t)
	f := newDockerHostFake(c9)
	f.keep[c9] = true
	_, err := ParentReady(context.Background(), &orderRunner{inner: f}, "kea", ShapeMacvlan, t.TempDir(), 20*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), c9) {
		t.Fatalf("err = %v", err)
	}
}

// orderRunner answers the parent wait's reads with a clean host and sends
// the docker calls to the container fake, recording the order.
type orderRunner struct {
	inner *dockerHostFake
	seen  []string
}

func (o *orderRunner) Run(ctx context.Context, cmd string) (string, error) {
	o.seen = append(o.seen, cmd)
	if strings.HasPrefix(cmd, "sudo docker rm -f ") || strings.HasPrefix(cmd, "sudo docker ps -a ") {
		return o.inner.Run(ctx, cmd)
	}
	return (&ipRunner{outs: []string{ipLinkClean}}).Run(ctx, cmd)
}
