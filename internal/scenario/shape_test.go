package scenario

import (
	"context"
	"strings"
	"testing"
)

// fakeShapeRunner is the same no-network fakeRunner pattern
// internal/sourceadapter/adapter_test.go uses, extended to answer
// per-command: NetworkUp's regression path needs one specific command
// (the -C check) to fail while every other command in the same run
// succeeds, which a single canned reply cannot express.
type fakeShapeRunner struct {
	fail  func(cmd string) bool
	calls []string
}

func (f *fakeShapeRunner) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	if f.fail != nil && f.fail(cmd) {
		return "", context.DeadlineExceeded
	}
	return "", nil
}

// NetworkUp must apply docs/bridge-mode.md's own recipe (line 53)
// verbatim: appended, -i only, no -o mirror and no ip6tables (the docs
// carry no v6 firewall recipe at all -- only the unrelated ipv6_mode
// network option). CI's harness uses -I plus an -o mirror; the lab must
// not silently upgrade to that, or it would stop testing what the docs
// actually tell a user to run.
func TestNetworkUpAppliesTheDocumentedForwardRuleVerbatim(t *testing.T) {
	r := &fakeShapeRunner{}
	net := NetworkName("dnsmasq", ShapeBridge)
	br := hostBridgeName(net)

	if _, err := NetworkUp(context.Background(), r, "dnsmasq", ShapeBridge); err != nil {
		t.Fatalf("NetworkUp failed against a runner that accepts every command: %v", err)
	}

	wantAdd := forwardRuleAdd(br)
	wantCheck := forwardRuleCheck(br)
	var sawAdd, sawCheck bool
	for _, c := range r.calls {
		if c == wantAdd {
			sawAdd = true
		}
		if c == wantCheck {
			sawCheck = true
		}
		if strings.Contains(c, "-I FORWARD") {
			t.Fatalf("NetworkUp used an -I insert, not the docs' -A append: %q", c)
		}
		if strings.Contains(c, "-o") && strings.Contains(c, "FORWARD") {
			t.Fatalf("NetworkUp added an -o mirror the docs do not document: %q", c)
		}
		if strings.Contains(c, "ip6tables") {
			t.Fatalf("NetworkUp ran an ip6tables command; the docs carry no v6 firewall recipe: %q", c)
		}
	}
	if !sawAdd {
		t.Fatalf("NetworkUp never ran the documented rule %q; calls: %v", wantAdd, r.calls)
	}
	if !sawCheck {
		t.Fatalf("NetworkUp never verified the rule with %q; calls: %v", wantCheck, r.calls)
	}
}

// Regression: with the FORWARD rule missing, the bridge shape must
// fail right there with a clear message naming the rule -- a bare
// context-deadline timeout must not be the only symptom. This is
// exactly the failure mode issue #3's original
// root cause produced: a host with no ACCEPT rule for the bridge passed
// every step up to docker network create and only then went quiet.
func TestNetworkUpNamesTheRuleWhenForwardRuleIsMissing(t *testing.T) {
	net := NetworkName("kea", ShapeBridge)
	br := hostBridgeName(net)
	checkCmd := forwardRuleCheck(br)

	r := &fakeShapeRunner{fail: func(cmd string) bool { return cmd == checkCmd }}

	_, err := NetworkUp(context.Background(), r, "kea", ShapeBridge)
	if err == nil {
		t.Fatal("NetworkUp succeeded although the FORWARD rule check reported it missing")
	}
	if !strings.Contains(err.Error(), forwardRuleAdd(br)) {
		t.Fatalf("error does not name the missing rule: %v", err)
	}
	if !strings.Contains(err.Error(), "docs/bridge-mode.md") {
		t.Fatalf("error does not point at the doc the rule comes from: %v", err)
	}

	for _, c := range r.calls {
		if strings.Contains(c, "docker network create") {
			t.Fatalf("NetworkUp created the docker network after the rule check failed: %q", c)
		}
	}
}

// A failure elsewhere in the bridge setup must still fail by naming the
// exact command that failed, not just "networkup(bridge) failed". Since
// the netplan-recipe rewrite (issue #3), the bridge is brought up by
// writing docs/bridge-mode.md's netplan stanza
// and applying it; "netplan apply" is the equivalent early, singular
// command to inject a failure at.
func TestNetworkUpNamesTheCommandOnAnyBridgeSetupFailure(t *testing.T) {
	applyCmd := "sudo netplan apply"

	r := &fakeShapeRunner{fail: func(cmd string) bool { return cmd == applyCmd }}
	_, err := NetworkUp(context.Background(), r, "isc-dhcp", ShapeBridge)
	if err == nil {
		t.Fatal("NetworkUp succeeded although its netplan apply failed")
	}
	if !strings.Contains(err.Error(), applyCmd) {
		t.Fatalf("error does not name the failing command: %v", err)
	}
}

// NetworkDown must remove the same rule NetworkUp adds, or every run's
// ACCEPT rule for its (by-then-deleted) bridge name piles up in FORWARD
// forever.
func TestNetworkDownRemovesTheForwardRule(t *testing.T) {
	r := &fakeShapeRunner{}
	NetworkDown(context.Background(), r, "dnsmasq", ShapeBridge)

	br := hostBridgeName(NetworkName("dnsmasq", ShapeBridge))
	want := forwardRuleDel(br)
	for _, c := range r.calls {
		if c == want {
			return
		}
	}
	t.Fatalf("NetworkDown never ran %q; calls: %v", want, r.calls)
}

// NetworkUp calls NetworkDown first on every run, including a fresh
// one; that first pass must not choke on the rule already being absent
// (best-effort/idempotent, matching down-cell.sh's own style).
func TestNetworkDownToleratesForwardRuleAlreadyAbsent(t *testing.T) {
	net := NetworkName("kea", ShapeBridge)
	br := hostBridgeName(net)
	delCmd := forwardRuleDel(br)

	r := &fakeShapeRunner{fail: func(cmd string) bool { return cmd == delCmd }}
	NetworkDown(context.Background(), r, "kea", ShapeBridge) // must not panic or block
}

// The two IPAM shapes (issue #3 part 2) must pass --ipam-driver with
// this plugin's own alias, never null, while every original shape keeps
// null-IPAM exactly as before -- a mixed-up flag would silently hand a
// container docker's own default IPAM instead of a real regression.
func TestNetworkUpPicksIPAMDriverByShape(t *testing.T) {
	cases := []struct {
		shape Shape
		want  string
	}{
		{ShapeBridge, "--ipam-driver null"},
		{ShapeMacvlan, "--ipam-driver null"},
		{ShapeIpvlan, "--ipam-driver null"},
		{ShapeBridgeIPAM, "--ipam-driver " + driverAlias},
		{ShapeMacvlanIPAM, "--ipam-driver " + driverAlias},
	}
	for _, c := range cases {
		r := &fakeShapeRunner{}
		if _, err := NetworkUp(context.Background(), r, "dnsmasq", c.shape); err != nil {
			t.Fatalf("%s: NetworkUp: %v", c.shape, err)
		}
		var sawCreate bool
		for _, cmd := range r.calls {
			if strings.Contains(cmd, "docker network create") {
				sawCreate = true
				if !strings.Contains(cmd, c.want) {
					t.Errorf("%s: create command %q does not contain %q", c.shape, cmd, c.want)
				}
			}
		}
		if !sawCreate {
			t.Errorf("%s: NetworkUp never ran docker network create; calls: %v", c.shape, r.calls)
		}
	}
}

// bridge-ipam is IPAM-mode's L2 attachment axis unchanged from bridge:
// it still needs the same host-bridge machinery (netplan, FORWARD rule)
// bridge itself needs, since that machinery is about the L2 attachment,
// never about which IPAM driver is layered over it.
func TestNetworkUpBridgeIPAMUsesHostBridgeMachinery(t *testing.T) {
	r := &fakeShapeRunner{}
	net := NetworkName("kea", ShapeBridgeIPAM)
	br := hostBridgeName(net)

	if _, err := NetworkUp(context.Background(), r, "kea", ShapeBridgeIPAM); err != nil {
		t.Fatalf("NetworkUp: %v", err)
	}
	wantCheck := forwardRuleCheck(br)
	var sawCheck bool
	for _, c := range r.calls {
		if c == wantCheck {
			sawCheck = true
		}
	}
	if !sawCheck {
		t.Fatalf("NetworkUp(bridge-ipam) never verified the FORWARD rule %q; calls: %v", wantCheck, r.calls)
	}
	if !usesHostBridge(ShapeBridgeIPAM) {
		t.Fatal("usesHostBridge(bridge-ipam) = false, want true")
	}
	if usesHostBridge(ShapeMacvlanIPAM) {
		t.Fatal("usesHostBridge(macvlan-ipam) = true, want false")
	}
}

// NetworkUpSecondary is A13's mechanism (one container, two plugin
// networks, #3 part 2): it must work for the parent-attached shapes,
// where Linux allows many independent macvlan/ipvlan devices off one
// NIC, and refuse outright for the two bridge shapes, where SegmentNIC
// is already wholly enslaved to the one bridge NetworkUp built -- a
// second bridge network on the same NIC is not a real configuration,
// so a caller must get an error here, never a silently broken network.
func TestNetworkUpSecondaryByShape(t *testing.T) {
	ok := []Shape{ShapeMacvlan, ShapeIpvlan, ShapeMacvlanIPAM}
	for _, shape := range ok {
		r := &fakeShapeRunner{}
		if err := NetworkUpSecondary(context.Background(), r, "labrun-dnsmasq-"+string(shape)+"-a13b", shape); err != nil {
			t.Errorf("%s: NetworkUpSecondary: %v", shape, err)
		}
		var sawCreate bool
		for _, c := range r.calls {
			if strings.Contains(c, "docker network create") {
				sawCreate = true
			}
		}
		if !sawCreate {
			t.Errorf("%s: NetworkUpSecondary never created a network; calls: %v", shape, r.calls)
		}
	}
	refused := []Shape{ShapeBridge, ShapeBridgeIPAM}
	for _, shape := range refused {
		r := &fakeShapeRunner{}
		if err := NetworkUpSecondary(context.Background(), r, "labrun-dnsmasq-"+string(shape)+"-a13b", shape); err == nil {
			t.Errorf("%s: NetworkUpSecondary succeeded, want refused (one NIC cannot join a second bridge)", shape)
		}
		for _, c := range r.calls {
			if strings.Contains(c, "docker network create") {
				t.Errorf("%s: NetworkUpSecondary ran docker network create despite being refused; calls: %v", shape, r.calls)
			}
		}
	}
}
