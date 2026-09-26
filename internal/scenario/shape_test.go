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

// Regression (lead directive, 2026-09-26): with the FORWARD rule
// missing, the bridge shape must fail right there with a clear message
// naming the rule -- a bare context-deadline timeout must not be the
// only symptom. This is exactly the failure mode issue #3's original
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
// the netplan-recipe rewrite (issue #3, lead directive 2026-09-26), the
// bridge is brought up by writing docs/bridge-mode.md's netplan stanza
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
// forever (lead directive, 2026-09-26).
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
