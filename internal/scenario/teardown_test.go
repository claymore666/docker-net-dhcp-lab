package scenario

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
)

// flakyHost is the stateful Debian 11 docker host with ssh failures
// injected per command: reset answers the first n calls of a command with
// ssh's exit 255 before it ran, swallow answers exit 0 without running it.
type flakyHost struct {
	*fakeIfupdownHost
	reset   map[string]int
	swallow map[string]bool
	other   map[string]error
	tried   map[string]int
}

func newFlakyHost(t *testing.T) *flakyHost {
	return &flakyHost{
		fakeIfupdownHost: newFakeIfupdownHost(t, debian11Image(t)),
		reset:            map[string]int{}, swallow: map[string]bool{}, other: map[string]error{}, tried: map[string]int{},
	}
}

func (h *flakyHost) Run(ctx context.Context, cmd string) (string, error) {
	h.tried[cmd]++
	if h.reset[cmd] != 0 {
		if h.reset[cmd] > 0 {
			h.reset[cmd]--
		}
		return "", errSSH255
	}
	if err := h.other[cmd]; err != nil {
		return "", err
	}
	if h.swallow[cmd] {
		return "", nil
	}
	return h.fakeIfupdownHost.Run(ctx, cmd)
}

func fastTeardown(t *testing.T) {
	t.Helper()
	oldB, oldP := teardownRetryBound, teardownRetryPoll
	teardownRetryBound, teardownRetryPoll = 40*time.Millisecond, time.Millisecond
	t.Cleanup(func() { teardownRetryBound, teardownRetryPoll = oldB, oldP })
}

const nomasterCmd = "sudo ip link set eth1 nomaster"

// upBridge brings the bridge shape up on h and returns the bridge name.
func upBridge(t *testing.T, h *flakyHost, shape Shape) string {
	t.Helper()
	net, err := NetworkUp(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, shape)
	if err != nil {
		t.Fatal(err)
	}
	br := hostBridgeName(net)
	if h.links["eth1"].master != br {
		t.Fatalf("setup: eth1 master = %q, want %q", h.links["eth1"].master, br)
	}
	clear(h.tried)
	return br
}

func TestNetworkDownRetriesAStepAfterAnSSHReset(t *testing.T) {
	fastTeardown(t)
	h := newFlakyHost(t)
	upBridge(t, h, ShapeBridge)
	h.reset[nomasterCmd] = 1
	if err := NetworkDown(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeBridge); err != nil {
		t.Fatalf("NetworkDown after one reset: %v", err)
	}
	if h.tried[nomasterCmd] != 2 || h.links["eth1"].master != "" {
		t.Errorf("nomaster tried %d times, eth1 master %q", h.tried[nomasterCmd], h.links["eth1"].master)
	}
}

func TestNetworkDownNamesAStepSSHNeverAnswers(t *testing.T) {
	fastTeardown(t)
	h := newFlakyHost(t)
	upBridge(t, h, ShapeBridge)
	h.reset[nomasterCmd] = -1
	err := NetworkDown(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeBridge)
	if err == nil || !strings.Contains(err.Error(), nomasterCmd) || !strings.Contains(err.Error(), "ssh still failing") {
		t.Fatalf("persistent reset on nomaster: err = %v", err)
	}
}

func TestNetworkDownReadsTheStateNotTheExitCode(t *testing.T) {
	fastTeardown(t)
	for name, tc := range map[string]struct {
		swallow func(br string) []string
		want    string
	}{
		// ifdown and the bridge's removal also release the port, so each case
		// swallows every command that could clean the thing it reads
		"nomaster, ifdown and link del exit 0 and do nothing": {func(br string) []string {
			return []string{nomasterCmd, "sudo ifdown " + br, "sudo ip link del " + br}
		}, "still enslaved"},
		"ifdown and link del exit 0 and do nothing": {func(br string) []string {
			return []string{"sudo ifdown " + br, "sudo ip link del " + br}
		}, "still exists"},
	} {
		h := newFlakyHost(t)
		br := upBridge(t, h, ShapeBridge)
		for _, c := range tc.swallow(br) {
			h.swallow[c] = true
		}
		err := NetworkDown(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeBridge)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestNetworkDownDoesNotCallAnUnreadableLinkClean(t *testing.T) {
	fastTeardown(t)
	h := newFlakyHost(t)
	upBridge(t, h, ShapeBridge)
	h.reset["ip -o link show eth1"] = -1
	err := NetworkDown(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeBridge)
	if err == nil || !strings.Contains(err.Error(), "ip -o link show eth1") {
		t.Fatalf("unreadable eth1: err = %v", err)
	}
}

func TestNetworkDownDoesNotCallAnUnreadableBridgeGone(t *testing.T) {
	fastTeardown(t)
	h := newFlakyHost(t)
	br := upBridge(t, h, ShapeBridge)
	h.reset["ip -o link show "+br] = -1
	err := NetworkDown(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeBridge)
	if err == nil || !strings.Contains(err.Error(), "ip -o link show "+br) {
		t.Fatalf("unreadable bridge: err = %v", err)
	}
}

func TestNetworkDownOnAFreshHostAndAfterACommandsOwnFailure(t *testing.T) {
	fastTeardown(t)
	for _, shape := range allShapes {
		h := newFlakyHost(t)
		net := NetworkName(ifupdownTestCell, shape)
		h.other["sudo docker network rm "+net] = fmt.Errorf("ssh lab@x: exit status 1: Error: No such network")
		if err := NetworkDown(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, shape); err != nil {
			t.Errorf("%s: teardown of a host with nothing up: %v", shape, err)
		}
		if n := h.tried["sudo docker network rm "+net]; n != 1 {
			t.Errorf("%s: a command's own failure was retried %d times", shape, n)
		}
	}
}

func TestNetworkUpRefusesAHeldParent(t *testing.T) {
	fastTeardown(t)
	for _, shape := range []Shape{ShapeMacvlan, ShapeIpvlan, ShapeMacvlanIPAM} {
		h := newFlakyHost(t)
		h.links["brlstale"] = &fakeLink{bridge: true, up: true}
		h.links["eth1"].master = "brlstale"
		_, err := NetworkUp(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, shape)
		if err == nil || !strings.Contains(err.Error(), "lab:") || !strings.Contains(err.Error(), "brlstale") || !strings.Contains(err.Error(), "eth1") {
			t.Errorf("%s: err = %v", shape, err)
		}
		for _, c := range h.calls {
			if strings.HasPrefix(c, "sudo docker network create ") {
				t.Errorf("%s: asked docker to create a network on a held parent: %s", shape, c)
			}
		}
	}
}

func TestNetworkUpCreatesOnAFreeParentAndBridgeShapesTakeOverAHeldOne(t *testing.T) {
	fastTeardown(t)
	for _, shape := range []Shape{ShapeMacvlan, ShapeIpvlan, ShapeMacvlanIPAM} {
		h := newFlakyHost(t)
		if _, err := NetworkUp(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, shape); err != nil {
			t.Errorf("%s: free parent refused: %v", shape, err)
		}
	}
	for _, shape := range []Shape{ShapeBridge, ShapeBridgeIPAM} {
		h := newFlakyHost(t)
		h.links["brlstale"] = &fakeLink{bridge: true, up: true}
		h.links["eth1"].master = "brlstale"
		net, err := NetworkUp(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, shape)
		if err != nil {
			t.Errorf("%s: a held parent is the bridge shape's to take over: %v", shape, err)
			continue
		}
		if m := h.links["eth1"].master; m != hostBridgeName(net) {
			t.Errorf("%s: eth1 master = %q", shape, m)
		}
	}
}

func TestNetworkUpReturnsTheTeardownErrorAsALabError(t *testing.T) {
	fastTeardown(t)
	h := newFlakyHost(t)
	h.reset[nomasterCmd] = -1
	_, err := NetworkUp(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeBridge)
	if err == nil || !strings.HasPrefix(err.Error(), "networkup(bridge): lab: ") || !strings.Contains(err.Error(), nomasterCmd) {
		t.Fatalf("err = %v", err)
	}
}

func TestNetworkUpRefusesAParentItCannotRead(t *testing.T) {
	fastTeardown(t)
	h := newFlakyHost(t)
	h.reset["ip -o link show eth1"] = -1
	_, err := NetworkUp(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeMacvlan)
	if err == nil || !strings.Contains(err.Error(), "lab: could not read whether eth1 has a master") {
		t.Fatalf("err = %v", err)
	}
}

func TestAnUnreadableMasterIsAnErrorEvenWhenSSHItselfWorked(t *testing.T) {
	fastTeardown(t)
	read := "ip -o link show eth1"
	bad := fmt.Errorf("ssh lab@x: exit status 2: RTNETLINK answers: Operation not supported")
	h := newFlakyHost(t)
	h.other[read] = bad
	if m, err := linkMaster(context.Background(), h, "eth1"); err == nil || m != "" {
		t.Fatalf("linkMaster = %q, %v; a failed read is an error, not no master", m, err)
	}
	if _, err := NetworkUp(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeMacvlan); err == nil ||
		!strings.Contains(err.Error(), "lab: could not read whether eth1 has a master") {
		t.Fatalf("NetworkUp took an unreadable parent for free: %v", err)
	}
	h = newFlakyHost(t)
	upBridge(t, h, ShapeBridge)
	h.other[read] = bad
	if err := NetworkDown(context.Background(), h, labyaml.NetStackIfupdown, ifupdownTestCell, ShapeBridge); err == nil ||
		!strings.Contains(err.Error(), read) {
		t.Fatalf("NetworkDown called an unreadable eth1 clean: %v", err)
	}
}

func TestRunRetryingStopsAtACancelledContext(t *testing.T) {
	h := newFlakyHost(t)
	h.reset["x"] = -1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runRetrying(ctx, h, "x")
	if !errors.Is(err, errSSH255) && !isTransport(err) {
		t.Fatalf("err = %v", err)
	}
	if h.tried["x"] != 1 {
		t.Errorf("tried %d times under a cancelled context", h.tried["x"])
	}
}

// netplanHost is a Debian 13 docker host whose networkd rebuilds the
// bridge from its config whenever the bridge is deleted while the config
// exists: networkd aborts on the deletion and its restart reads the
// netdev netplan left in /run (measured on the dnsmasq cell).
type netplanHost struct {
	br             string
	config, bridge bool
	master         string
	calls          []string
}

func (h *netplanHost) Run(_ context.Context, cmd string) (string, error) {
	h.calls = append(h.calls, cmd)
	switch cmd {
	case "sudo rm -f " + bridgeNetplanPath:
		h.config = false
	case "sudo ip link del " + h.br:
		h.bridge, h.master = h.config, ""
	case nomasterCmd:
		h.master = ""
	case "ip -o link show eth1":
		if h.master != "" {
			return "3: eth1: <UP> mtu 1500 master " + h.master + " state UP", nil
		}
		return "3: eth1: <UP> mtu 1500 state UP", nil
	case "ip -o link show " + h.br:
		if !h.bridge {
			return "", errors.New("exit status 1")
		}
		return "6: " + h.br + ": <UP> mtu 1500 state UP", nil
	}
	return "", nil
}

func TestNetplanNetworkDownRemovesTheConfigBeforeTheBridge(t *testing.T) {
	fastTeardown(t)
	br := hostBridgeName(NetworkName("dnsmasq", ShapeBridge))
	h := &netplanHost{br: br, config: true, bridge: true, master: br}
	if err := NetworkDown(context.Background(), h, labyaml.NetStackNetplan, "dnsmasq", ShapeBridge); err != nil {
		t.Fatalf("NetworkDown left the bridge: %v\n%s", err, strings.Join(h.calls, "\n"))
	}
	// the check still reads a real leftover
	h = &netplanHost{br: br, config: true, bridge: true, master: br}
	h.calls = nil
	r := &swallowRunner{Runner: h, cmd: "sudo rm -f " + bridgeNetplanPath}
	err := NetworkDown(context.Background(), r, labyaml.NetStackNetplan, "dnsmasq", ShapeBridge)
	if err == nil || !strings.Contains(err.Error(), "bridge "+br+" still exists") {
		t.Fatalf("a bridge networkd rebuilt passed the check: %v", err)
	}
}

// swallowRunner answers cmd with exit 0 without running it.
type swallowRunner struct {
	Runner interface {
		Run(context.Context, string) (string, error)
	}
	cmd string
}

func (s *swallowRunner) Run(ctx context.Context, cmd string) (string, error) {
	if cmd == s.cmd {
		return "", nil
	}
	return s.Runner.Run(ctx, cmd)
}
