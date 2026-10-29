package scenario

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A macvlan child as ip prints it inside a container namespace: the lower
// device is only an ifindex there (@if3 is eth1 in ipLinkClean).
const (
	ipLinkChildInContainer = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0
17: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default\    link/ether 02:42:c0:a8:63:05 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0 minmtu 68 maxmtu 9194 \    macvlan mode bridge bcnqueuelen 1000
`
	ipLinkOtherParent = `17: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default\    link/ether 02:42:c0:a8:63:05 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0 \    macvlan mode bridge bcnqueuelen 1000
19: eth1@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default\    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0 \    veth
21: br0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default\    link/ether 02:42:ac:11:00:04 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0 \    bridge
`
	busyErr = `ssh lab@host: exit status 125: docker: Error response from daemon: failed to create endpoint web on network lan: failed to create macvlan link on "eth1": device or resource busy`
)

// nsFake answers exact commands, records every call and fails any other.
type nsFake struct {
	ans   map[string]string
	errs  map[string]error
	calls []string
}

func (f *nsFake) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	if err, ok := f.errs[cmd]; ok {
		return "", err
	}
	if out, ok := f.ans[cmd]; ok {
		return out, nil
	}
	return "", fmt.Errorf("unexpected command %q", cmd)
}

func (f *nsFake) count(cmd string) int {
	n := 0
	for _, c := range f.calls {
		if c == cmd {
			n++
		}
	}
	return n
}

const (
	cmdHostLinks   = "ip -d -o link show"
	cmdNetnsLinks  = "sudo ip netns exec ns-a ip -d -o link show"
	cmdCtrInspect  = "sudo docker inspect -f '{{.Name}} {{.State.Pid}}' abc123"
	cmdCtrLinks    = "sudo nsenter -t 777 -n ip -d -o link show"
	cmdPluginLinks = "sudo nsenter -t 42 -n ip -d -o link show"
	cmdDockerRun   = "sudo docker run -d --name web --network lan alpine:3.20 sleep 600"
)

// newNSFake is a host with one named netns, one running container and the
// plugin; the host view and the plugin's are clean, the others as given.
func newNSFake(netnsLinks, containerLinks string) *nsFake {
	return &nsFake{
		ans: map[string]string{
			cmdHostLinks:             ipLinkClean,
			"ip netns list":          "ns-a (id: 0)\n",
			cmdNetnsLinks:            netnsLinks,
			"sudo docker ps -q":      "abc123\n",
			cmdCtrInspect:            "/web 777\n",
			cmdCtrLinks:              containerLinks,
			"sudo pgrep -x net-dhcp": "42\n",
			cmdPluginLinks:           ipLinkClean,
		},
		errs: map[string]error{cmdDockerRun: errors.New(busyErr)},
	}
}

func readBusyFile(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "kea-parent-busy-links.txt"))
	if err != nil {
		t.Fatalf("no parent-busy file: %v", err)
	}
	return string(b)
}

func TestBusyCaptureWritesEveryNamespace(t *testing.T) {
	dir := t.TempDir()
	f := newNSFake(ipLinkClean, ipLinkChildInContainer)
	c := &BusyCapture{Inner: f, Cell: "kea", EvidenceDir: dir}
	if _, err := c.Run(context.Background(), cmdDockerRun); err == nil {
		t.Fatal("the EBUSY must reach the caller")
	}
	got := readBusyFile(t, dir)
	for _, want := range []string{
		"first parent EBUSY of cell kea at ", "from: " + cmdDockerRun,
		"== host ==", "== netns ns-a ==", "== container web (pid 777) ==", "== plugin (pid 42) ==",
		"17: eth0@if3:", "macvlan mode bridge",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("file lacks %q:\n%s", want, got)
		}
	}
	// The child line sits under the container's header, not another one.
	i := strings.Index(got, "== container web (pid 777) ==")
	j := strings.Index(got, "== plugin (pid 42) ==")
	if k := strings.Index(got, "17: eth0@if3:"); k < i || k > j {
		t.Errorf("the child line is outside the container section:\n%s", got)
	}
}

func TestBusyCaptureOncePerCell(t *testing.T) {
	dir := t.TempDir()
	f := newNSFake(ipLinkClean, ipLinkChildInContainer)
	c := &BusyCapture{Inner: f, Cell: "kea", EvidenceDir: dir}
	_, _ = c.Run(context.Background(), cmdDockerRun)
	first := readBusyFile(t, dir)
	listing := f.count(cmdCtrLinks)
	_, _ = c.Run(context.Background(), cmdDockerRun)
	_, _ = c.Run(context.Background(), cmdDockerRun)
	if n := f.count(cmdCtrLinks); n != listing {
		t.Fatalf("later EBUSYs listed the namespaces again: %d reads, want %d", n, listing)
	}
	got := readBusyFile(t, dir)
	if !strings.HasPrefix(got, first) {
		t.Fatalf("the first dump was changed:\n%s", got)
	}
	if rest := strings.TrimPrefix(got, first); strings.Count(rest, "\n") != 2 || strings.Count(rest, "later parent EBUSY at ") != 2 {
		t.Fatalf("want exactly one marker line per later EBUSY, got %q", rest)
	}
	// A second process of the same cell (the next shape) appends too.
	c2 := &BusyCapture{Inner: newNSFake(ipLinkClean, ipLinkChildInContainer), Cell: "kea", EvidenceDir: dir}
	_, _ = c2.Run(context.Background(), cmdDockerRun)
	if after := readBusyFile(t, dir); strings.Count(after, "== host ==") != 1 {
		t.Fatalf("a second process wrote a second dump:\n%s", after)
	}
}

func TestBusyCaptureReturnsTheInnerResultUnchanged(t *testing.T) {
	dir := t.TempDir()
	f := newNSFake(ipLinkClean, ipLinkChildInContainer)
	c := &BusyCapture{Inner: f, Cell: "kea", EvidenceDir: dir}
	out, err := c.Run(context.Background(), cmdHostLinks)
	if err != nil || out != ipLinkClean {
		t.Fatalf("a passing command was altered: %q %v", out, err)
	}
	_, err = c.Run(context.Background(), cmdDockerRun)
	if err == nil || err.Error() != busyErr {
		t.Fatalf("the EBUSY error was altered: %v", err)
	}
	// A capture that cannot run (every listing fails, the dir is gone)
	// still leaves the caller the original error.
	bad := &BusyCapture{Inner: &nsFake{errs: map[string]error{cmdDockerRun: errors.New(busyErr)}}, Cell: "kea", EvidenceDir: filepath.Join(dir, "gone")}
	if _, err := bad.Run(context.Background(), cmdDockerRun); err == nil || err.Error() != busyErr {
		t.Fatalf("a failed capture replaced the error: %v", err)
	}
}

func TestBusyCaptureTriggers(t *testing.T) {
	cases := []struct {
		name string
		err  string
		want bool
	}{
		{"macvlan", `failed to create macvlan link on "eth1": device or resource busy`, true},
		{"ipvlan", `failed to create ipvlan link on "eth1": device or resource busy`, true},
		{"capitalised", `failed to create macvlan link on "eth1": Device or resource busy`, true},
		{"mount busy", `unable to remove filesystem: device or resource busy`, false},
		{"bridge port, out of scope", `RTNETLINK answers: Device or resource busy`, false},
		{"macvlan without busy", `failed to create macvlan link on "eth1": operation not supported`, false},
		{"ssh", `ssh lab@host: exit status 255: connect to host: no route`, false},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		f := &nsFake{errs: map[string]error{"x": errors.New(tc.err)}}
		c := &BusyCapture{Inner: f, Cell: "kea", EvidenceDir: dir}
		_, _ = c.Run(context.Background(), "x")
		_, statErr := os.Stat(filepath.Join(dir, "kea-parent-busy-links.txt"))
		if (statErr == nil) != tc.want {
			t.Errorf("%s: capture=%v, want %v", tc.name, statErr == nil, tc.want)
		}
		if !tc.want && len(f.calls) != 1 {
			t.Errorf("%s: listing commands ran for a non-trigger: %v", tc.name, f.calls)
		}
	}
}

func TestParentCleanSeesAChildInAContainerNamespace(t *testing.T) {
	f := newNSFake(ipLinkClean, ipLinkChildInContainer)
	_, left, err := WaitParentClean(context.Background(), f, "eth1", 20*time.Millisecond, time.Millisecond)
	if err != nil || len(left) != 1 {
		t.Fatalf("want the container's child as leftover, got %v %v", left, err)
	}
	if s := left[0].String(); !strings.Contains(s, "eth0") || !strings.Contains(s, "macvlan") || !strings.Contains(s, "container web (pid 777)") {
		t.Fatalf("leftover does not name the child and its namespace: %s", s)
	}
	reason := ParentBusyReason("eth1", time.Second, left)
	if !strings.Contains(reason, "container web (pid 777)") {
		t.Fatalf("blocked reason does not name the namespace: %s", reason)
	}
}

func TestParentCleanSeesAChildInANamedNetns(t *testing.T) {
	f := newNSFake(ipLinkChildInContainer, ipLinkClean)
	_, left, err := WaitParentClean(context.Background(), f, "eth1", 20*time.Millisecond, time.Millisecond)
	if err != nil || len(left) != 1 || !strings.Contains(left[0].String(), "netns ns-a") {
		t.Fatalf("want the named netns' child, got %v %v", left, err)
	}
}

// Preservation: another parent's macvlan, a veth and a bridge on @if3 are
// not this parent's children; with none, the wait ends on the first poll.
func TestParentCleanIgnoresOtherParentsAndVeths(t *testing.T) {
	f := newNSFake(ipLinkOtherParent, ipLinkClean)
	report, left, err := WaitParentClean(context.Background(), f, "eth1", time.Second, time.Millisecond)
	if err != nil || len(left) != 0 || !strings.Contains(report, "poll 1 at") || !strings.Contains(report, ": clean") {
		t.Fatalf("want clean on the first poll, got %v %v\n%s", left, err, report)
	}
}

func TestParentCleanFailsWhenNamespacesCannotBeEnumerated(t *testing.T) {
	for _, cmd := range []string{"ip netns list", "sudo docker ps -q"} {
		f := newNSFake(ipLinkClean, ipLinkClean)
		f.errs[cmd] = errors.New("denied")
		if _, left, err := WaitParentClean(context.Background(), f, "eth1", time.Second, time.Millisecond); err == nil || len(left) != 0 || !strings.Contains(err.Error(), "denied") {
			t.Errorf("%s failing must be an error, not clean: left=%v err=%v", cmd, left, err)
		}
	}
}

func TestParentCleanReportsAnUnreadableNamespace(t *testing.T) {
	f := newNSFake(ipLinkClean, ipLinkClean)
	f.errs[cmdCtrLinks] = errors.New("no such process")
	report, left, err := WaitParentClean(context.Background(), f, "eth1", time.Second, time.Millisecond)
	if err != nil || len(left) != 0 {
		t.Fatalf("a vanished container is not an abort: %v %v", left, err)
	}
	if !strings.Contains(report, "1 namespaces unreadable: container web (pid 777)") {
		t.Fatalf("clean must say what could not be read:\n%s", report)
	}
}

func TestNamespaceNamesAreValidated(t *testing.T) {
	f := newNSFake(ipLinkClean, ipLinkClean)
	f.ans["ip netns list"] = "a;touch x (id: 1)\nns-a (id: 0)\n"
	f.ans["sudo docker ps -q"] = "abc123\nzz;id\n"
	f.ans[cmdCtrInspect] = "/web 777;id\n"
	nss, err := listOtherNamespaces(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.ContainsAny(c, ";") {
			t.Errorf("an unvalidated value reached a command: %q", c)
		}
	}
	bad := 0
	for _, ns := range nss {
		if ns.Err != nil {
			bad++
		}
	}
	if bad != 3 {
		t.Fatalf("want 3 refused sections (netns name, container id, pid), got %d: %+v", bad, nss)
	}
}
