package scenario

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const ipLinkClean = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:aa:bb:cc brd ff:ff:ff:ff:ff:ff promiscuity 0
5: veth1@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default\    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 1 \    veth
`

const ipLinkMacvlan = ipLinkClean + `9: mvl-abc@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\    link/ether 02:42:11:22:33:44 brd ff:ff:ff:ff:ff:ff promiscuity 0 \    macvlan mode bridge bcnqueuelen 1000
`

const ipLinkIpvlan = ipLinkClean + `11: ivl-abc@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:aa:bb:cc brd ff:ff:ff:ff:ff:ff link-netns c1 promiscuity 0 \    ipvlan mode l2 bridge
15: mvl-ten@eth10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP\    link/ether 02:42:11:22:33:66 brd ff:ff:ff:ff:ff:ff promiscuity 0 \    macvlan mode bridge
13: mvl-other@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP\    link/ether 02:42:11:22:33:55 brd ff:ff:ff:ff:ff:ff promiscuity 0 \    macvlan mode bridge
`

// ipRunner answers `ip -d -o link show` from a script, one entry per
// call; the last entry repeats.
type ipRunner struct {
	outs  []string
	err   error
	calls int
}

func (f *ipRunner) Run(_ context.Context, cmd string) (string, error) {
	if !strings.HasPrefix(cmd, "ip -d -o link show") {
		return "", fmt.Errorf("unexpected command %q", cmd)
	}
	i := f.calls
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	if i >= len(f.outs) {
		i = len(f.outs) - 1
	}
	return f.outs[i], nil
}

func TestParentChildrenReadsOnlyThisParentsMacvlanAndIpvlan(t *testing.T) {
	if got := parentChildren(ipLinkClean, "eth1"); len(got) != 0 {
		t.Fatalf("clean output reported children: %v", got)
	}
	got := parentChildren(ipLinkMacvlan, "eth1")
	if len(got) != 1 || got[0].Name != "mvl-abc" || got[0].Kind != "macvlan" || got[0].Owner != "not shown by ip -d" {
		t.Fatalf("macvlan child not read: %v", got)
	}
	got = parentChildren(ipLinkIpvlan, "eth1")
	if len(got) != 1 || got[0].Name != "ivl-abc" || got[0].Kind != "ipvlan" || got[0].Owner != "netns c1" {
		t.Fatalf("ipvlan child with owner not read (eth0 and eth10 children must be ignored): %v", got)
	}
}

func TestParentAttachedCoversExactlyTheChildShapes(t *testing.T) {
	want := map[Shape]bool{ShapeBridge: false, ShapeMacvlan: true, ShapeIpvlan: true, ShapeBridgeIPAM: false, ShapeMacvlanIPAM: true}
	for _, s := range Shapes {
		if ParentAttached(s) != want[s] {
			t.Errorf("ParentAttached(%s) = %v, want %v", s, ParentAttached(s), want[s])
		}
	}
}

// A child that disappears after two polls: the wait ends clean, and the
// report says what was attached at each poll and how long it took.
func TestWaitParentCleanEndsWhenTheChildIsGone(t *testing.T) {
	r := &ipRunner{outs: []string{ipLinkMacvlan, ipLinkMacvlan, ipLinkClean}}
	report, left, err := WaitParentClean(context.Background(), r, "eth1", 30*time.Second, time.Millisecond)
	if err != nil || len(left) != 0 {
		t.Fatalf("want clean, got left=%v err=%v", left, err)
	}
	if r.calls != 3 {
		t.Fatalf("polled %d times, want 3", r.calls)
	}
	for _, want := range []string{"poll 1 at", "still attached: mvl-abc (macvlan, owner not shown by ip -d)", "poll 2 at", "poll 3 at", ": clean", "waited "} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q:\n%s", want, report)
		}
	}
}

func TestWaitParentCleanGivesUpAndNamesTheLeftover(t *testing.T) {
	r := &ipRunner{outs: []string{ipLinkIpvlan}}
	report, left, err := WaitParentClean(context.Background(), r, "eth1", 30*time.Millisecond, time.Millisecond)
	if err != nil || len(left) != 1 {
		t.Fatalf("want one leftover, got left=%v err=%v", left, err)
	}
	if !strings.Contains(report, "gave up after") {
		t.Errorf("report does not say it gave up:\n%s", report)
	}
	reason := ParentBusyReason("eth1", 30*time.Second, left)
	for _, want := range []string{"eth1", "ivl-abc", "ipvlan", "netns c1", "no scenario of this shape was run"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason lacks %q: %s", want, reason)
		}
	}
}

func TestWaitParentCleanFailsOnAnIpError(t *testing.T) {
	r := &ipRunner{err: fmt.Errorf("ssh: no route")}
	if _, _, err := WaitParentClean(context.Background(), r, "eth1", time.Second, time.Millisecond); err == nil || !strings.Contains(err.Error(), "no route") {
		t.Fatalf("want the ip error, got %v", err)
	}
}

func TestWaitParentCleanStopsWithTheContext(t *testing.T) {
	r := &ipRunner{outs: []string{ipLinkMacvlan}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := WaitParentClean(ctx, r, "eth1", time.Hour, time.Hour); err == nil {
		t.Fatal("want an error once the context ends")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("waited %s past a 30ms context", time.Since(start))
	}
}

// ParentReady writes the wait into the evidence dir for the child shapes
// and does not even look at the host for the others.
func TestParentReadyWritesEvidenceForChildShapesOnly(t *testing.T) {
	dir := t.TempDir()
	r := &ipRunner{outs: []string{ipLinkMacvlan, ipLinkClean}}
	blocked, err := ParentReady(context.Background(), r, "kea", ShapeMacvlan, dir, 30*time.Second, time.Millisecond)
	if err != nil || blocked != "" {
		t.Fatalf("want ready, got blocked=%q err=%v", blocked, err)
	}
	b, rerr := os.ReadFile(filepath.Join(dir, "kea-macvlan-parent-ready.txt"))
	if rerr != nil || !strings.Contains(string(b), "still attached: mvl-abc") || !strings.Contains(string(b), "waited ") {
		t.Fatalf("evidence file missing or without the wait: %v %q", rerr, b)
	}

	other := &ipRunner{outs: []string{ipLinkMacvlan}}
	dir2 := t.TempDir()
	blocked, err = ParentReady(context.Background(), other, "kea", ShapeBridge, dir2, time.Second, time.Millisecond)
	if err != nil || blocked != "" || other.calls != 0 {
		t.Fatalf("bridge shape must not wait: blocked=%q err=%v calls=%d", blocked, err, other.calls)
	}
	if entries, _ := os.ReadDir(dir2); len(entries) != 0 {
		t.Fatalf("bridge shape wrote evidence: %v", entries)
	}
}

func TestParentReadyBlocksWithTheLeftoverNamed(t *testing.T) {
	dir := t.TempDir()
	r := &ipRunner{outs: []string{ipLinkIpvlan}}
	blocked, err := ParentReady(context.Background(), r, "kea", ShapeMacvlan, dir, 20*time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(blocked, "ivl-abc") || !strings.Contains(blocked, "ipvlan") || !strings.Contains(blocked, "kea-macvlan-parent-ready.txt") {
		t.Fatalf("blocked reason does not name the leftover and the record: %q", blocked)
	}
	if _, rerr := os.Stat(filepath.Join(dir, "kea-macvlan-parent-ready.txt")); rerr != nil {
		t.Fatalf("a blocked wait must still leave its record: %v", rerr)
	}
}
