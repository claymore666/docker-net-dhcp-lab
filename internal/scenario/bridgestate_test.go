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

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
)

// stateRunner fails the commands fail names and answers the capture
// commands with a recognisable output; every call is recorded.
type stateRunner struct {
	fail  func(cmd string) error
	calls []string
}

func (s *stateRunner) Run(ctx context.Context, cmd string) (string, error) {
	s.calls = append(s.calls, cmd)
	if s.fail != nil {
		if err := s.fail(cmd); err != nil {
			return "partial:" + cmd, err
		}
	}
	return "out:" + cmd, nil
}

func (s *stateRunner) ran(sub string) bool {
	for _, c := range s.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func bridgeUpErr(t *testing.T, r *stateRunner, ctx context.Context) error {
	t.Helper()
	fastReadyRetry(t, 0)
	_, err := NetworkUp(ctx, r, labyaml.NetStackNetplan, "dnsmasq", ShapeBridgeIPAM)
	if err == nil {
		t.Fatal("NetworkUp succeeded although the bridge never came up")
	}
	return err
}

func brOf() string { return hostBridgeName(NetworkName("dnsmasq", ShapeBridgeIPAM)) }

func TestNetworkUpNamesTheConditionThatFailed(t *testing.T) {
	br := brOf()
	linkCmd := "ip link show " + br
	masterCmd := fmt.Sprintf("readlink -f /sys/class/net/%s/master | grep -q '/%s$'", SegmentNIC, br)
	for name, tc := range map[string]struct {
		failing []string
		want    []string
		wantNot []string
	}{
		"link only":   {[]string{linkCmd}, []string{br + " is missing"}, []string{"not enslaved"}},
		"master only": {[]string{masterCmd}, []string{SegmentNIC + " is not enslaved to " + br}, []string{"is missing"}},
		"both":        {[]string{linkCmd, masterCmd}, []string{br + " is missing", "not enslaved to " + br}, nil},
	} {
		r := &stateRunner{fail: func(cmd string) error {
			for _, f := range tc.failing {
				if cmd == f {
					return errRuleAbsent
				}
			}
			return nil
		}}
		err := bridgeUpErr(t, r, context.Background())
		for _, w := range append([]string{"did not come up after netplan apply"}, tc.want...) {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q missing from %v", name, w, err)
			}
		}
		for _, w := range tc.wantNot {
			if strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q must not appear in %v", name, w, err)
			}
		}
	}
}

func TestBridgeFailedConditionsTakesAnSSHFailureForUnreadNotMissing(t *testing.T) {
	br := brOf()
	r := &stateRunner{fail: func(cmd string) error {
		switch cmd {
		case forwardRuleCheck(br):
			return errSSH255
		case forwardRule6Check(br):
			return errRuleAbsent
		}
		return nil
	}}
	got := strings.Join(bridgeFailedConditions(context.Background(), r, br), "|")
	if !strings.Contains(got, "IPv4 FORWARD rule for "+br+" is missing (could not be read: ssh failed)") {
		t.Errorf("v4 ssh failure: %q", got)
	}
	if !strings.Contains(got, "IPv6 FORWARD rule for "+br+" is missing") || strings.Contains(strings.SplitN(got, "|", 2)[1], "could not be read") {
		t.Errorf("v6 own failure must read as missing: %q", got)
	}
	if n := len(bridgeFailedConditions(context.Background(), &stateRunner{}, br)); n != 0 {
		t.Errorf("ready bridge reports %d failed conditions", n)
	}
}

func TestNetworkUpLeavesTheHostStateInTheEvidenceDir(t *testing.T) {
	dir := t.TempDir()
	br := brOf()
	r := &stateRunner{fail: func(cmd string) error {
		if cmd == "ip link show "+br {
			return errRuleAbsent
		}
		return nil
	}}
	err := bridgeUpErr(t, r, WithEvidenceDir(context.Background(), dir))
	file := "dnsmasq-bridge-ipam-bridge-not-ready.txt"
	if !strings.Contains(err.Error(), "(host state: "+file+")") {
		t.Fatalf("reason does not name the file: %v", err)
	}
	b, rerr := os.ReadFile(filepath.Join(dir, file))
	if rerr != nil {
		t.Fatal(rerr)
	}
	for _, w := range []string{br + " is missing", "$ ip -d link show", "out:ip -d link show",
		"$ networkctl status --no-pager " + br + " " + SegmentNIC, "$ sudo journalctl -u systemd-networkd -n 80 --no-pager"} {
		if !strings.Contains(string(b), w) {
			t.Errorf("%q missing from the capture:\n%s", w, b)
		}
	}
}

func TestNetworkUpStillAbortsWhenTheCaptureFails(t *testing.T) {
	br := brOf()
	captureCmds := func(cmd string) bool {
		return strings.HasPrefix(cmd, "ip -d link") || strings.HasPrefix(cmd, "networkctl") || strings.Contains(cmd, "journalctl")
	}
	failing := func(cmd string) error {
		switch {
		case cmd == "ip link show "+br:
			return errRuleAbsent
		case captureCmds(cmd):
			return errors.New("ssh lab@x: exit status 127: networkctl: command not found")
		}
		return nil
	}
	dir := t.TempDir()
	r := &stateRunner{fail: failing}
	err := bridgeUpErr(t, r, WithEvidenceDir(context.Background(), dir))
	if !strings.Contains(err.Error(), br+" is missing") || !strings.Contains(err.Error(), "did not come up") {
		t.Fatalf("abort reason lost: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "dnsmasq-bridge-ipam-bridge-not-ready.txt"))
	if n := strings.Count(string(b), "(command failed:"); n != 3 {
		t.Errorf("%d failed captures recorded, want all 3:\n%s", n, b)
	}

	// A directory that cannot be written leaves the abort whole, minus the pointer.
	r = &stateRunner{fail: failing}
	err = bridgeUpErr(t, r, WithEvidenceDir(context.Background(), filepath.Join(dir, "absent", "dir")))
	if !strings.Contains(err.Error(), br+" is missing") || strings.Contains(err.Error(), "host state:") {
		t.Fatalf("unwritable evidence dir: %v", err)
	}
}

func TestNetworkUpCapturesNothingWithoutAnEvidenceDir(t *testing.T) {
	br := brOf()
	r := &stateRunner{fail: func(cmd string) error {
		if cmd == "ip link show "+br {
			return errRuleAbsent
		}
		return nil
	}}
	err := bridgeUpErr(t, r, context.Background())
	if r.ran("networkctl") || r.ran("journalctl") || strings.Contains(err.Error(), "host state") {
		t.Fatalf("captured without a directory: calls=%v err=%v", r.calls, err)
	}
}

type hangRunner struct{ stateRunner }

func (h *hangRunner) Run(ctx context.Context, cmd string) (string, error) {
	if strings.HasPrefix(cmd, "ip -d link") {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return h.stateRunner.Run(ctx, cmd)
}

func TestCaptureBridgeStateIsBoundedWhenTheHostStopsAnswering(t *testing.T) {
	old := bridgeCaptureBound
	bridgeCaptureBound = 50 * time.Millisecond
	t.Cleanup(func() { bridgeCaptureBound = old })
	start := time.Now()
	file := captureBridgeState(context.Background(), &hangRunner{}, t.TempDir(), "c", ShapeBridge, "br", []string{"x"})
	if time.Since(start) > 5*time.Second || file == "" {
		t.Fatalf("capture took %s, file %q", time.Since(start), file)
	}
}

func TestCaptureBridgeStateSkipsACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &stateRunner{}
	if f := captureBridgeState(ctx, r, t.TempDir(), "c", ShapeBridge, "br", nil); f != "" || len(r.calls) != 0 {
		t.Fatalf("cancelled ctx: file %q, calls %v", f, r.calls)
	}
}
