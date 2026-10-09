package sourceadapter

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// hostRunner answers by command shape, so Ready and Recover can be
// driven through a source whose state changes between calls (#23).
type hostRunner struct {
	active  bool
	netns   string
	netem   bool
	addrs   string
	cfg     string
	written string
	calls   []string
}

func (h *hostRunner) Run(_ context.Context, cmd string) (string, error) {
	h.calls = append(h.calls, cmd)
	switch {
	case strings.Contains(cmd, "is-active"):
		if !h.active {
			return "", errors.New("inactive")
		}
		return "", nil
	case strings.HasPrefix(cmd, "sudo cat "+dnsmasqLeaseFile):
		return "", nil
	case strings.HasPrefix(cmd, "printf 'netns:'"):
		n := "0"
		if h.netem {
			n = "1"
		}
		return "netns:" + h.netns + "\nnetem:" + n + "\naddr:" + h.addrs + "\ncfg:\n" + h.cfg, nil
	case strings.HasPrefix(cmd, "sudo tee "):
		body := cmd[strings.Index(cmd, "<<'LABEOF'\n")+len("<<'LABEOF'\n"):]
		h.written = strings.TrimSuffix(body, "LABEOF\n")
		h.cfg = h.written
		return "", nil
	case strings.Contains(cmd, "ip netns del"):
		h.netns, h.netem = "", false
		return "", nil
	case strings.Contains(cmd, "systemctl restart"):
		h.active = true
		return "", nil
	}
	return "", nil
}

func healthyHost() *hostRunner {
	return &hostRunner{active: true, addrs: "10.200.1.2/24 ", cfg: "dhcp-range=10.200.1.100,10.200.1.200\n"}
}

func TestReadyTakesTheBaselineThenHoldsTheSourceToIt(t *testing.T) {
	h := healthyHost()
	a := &DnsmasqAdapter{Runner: h}
	ctx := context.Background()
	if err := a.Ready(ctx); err != nil {
		t.Fatalf("first Ready on a healthy source: %v", err)
	}
	cases := []struct {
		name  string
		spoil func(*hostRunner)
		want  string
	}{
		{"service stopped", func(h *hostRunner) { h.active = false }, "not active"},
		{"leftover netns", func(h *hostRunner) { h.netns = "labc-rogue " }, "labc-rogue"},
		{"netem left on", func(h *hostRunner) { h.netem = true }, "netem"},
		{"segment address changed", func(h *hostRunner) { h.addrs = "10.200.101.2/24 " }, "eth1 carries"},
		{"config drifted", func(h *hostRunner) { h.cfg = "dhcp-range=10.200.1.201,10.200.1.202\n" }, "differs"},
	}
	for _, c := range cases {
		h2 := healthyHost()
		a.Runner = h2
		c.spoil(h2)
		err := a.Ready(ctx)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Ready = %v, want an error naming %q", c.name, err, c.want)
		}
	}
}

func TestRecoverPutsTheBaselineBackAndRestarts(t *testing.T) {
	h := healthyHost()
	a := &DnsmasqAdapter{Runner: h}
	ctx := context.Background()
	if err := a.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	orig := h.cfg
	h.active, h.netns, h.netem, h.cfg = false, "labc-squat ", true, "changed\n"
	if err := a.Ready(ctx); err == nil {
		t.Fatal("Ready on a broken source passed")
	}
	if err := a.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if h.written != orig {
		t.Fatalf("Recover wrote %q, want the baseline %q byte for byte", h.written, orig)
	}
	if err := a.Ready(ctx); err != nil {
		t.Fatalf("Ready after Recover: %v", err)
	}
	var sawQdiscDel bool
	for _, c := range h.calls {
		if strings.Contains(c, "/usr/sbin/tc qdisc del dev eth1 root") {
			sawQdiscDel = true
		}
	}
	if !sawQdiscDel {
		t.Fatalf("Recover never removed the qdisc: %v", h.calls)
	}
}

func TestRecoverWithoutABaselineOnlyCleansAndRestarts(t *testing.T) {
	h := healthyHost()
	a := &KeaAdapter{Runner: h}
	if err := a.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.written != "" {
		t.Fatalf("Recover wrote a config with no baseline taken: %q", h.written)
	}
	if last := h.calls[len(h.calls)-1]; last != "sudo systemctl restart kea-dhcp4-server" {
		t.Fatalf("last call = %q, want the restart", last)
	}
}

func TestParseStateRefusesAnIncompleteRead(t *testing.T) {
	for _, out := range []string{"", "netns:\nnetem:0\ncfg:\nx", "netns:\naddr:a\ncfg:\n"} {
		if _, err := parseState(out); err == nil {
			t.Errorf("parseState(%q) accepted", out)
		}
	}
}

func TestImpairAppliesReadsBackAndRestores(t *testing.T) {
	for name, a := range map[string]Adapter{"kea": &KeaAdapter{}, "isc-dhcp": &ISCDHCPAdapter{}, "dnsmasq": &DnsmasqAdapter{}} {
		r := &fakeRunner{}
		switch v := a.(type) {
		case *KeaAdapter:
			v.Runner = r
		case *ISCDHCPAdapter:
			v.Runner = r
		case *DnsmasqAdapter:
			v.Runner = r
		}
		restore, err := a.Impair(context.Background(), 2*time.Second, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := "sudo /usr/sbin/tc qdisc replace dev eth1 root netem delay 2000ms loss 0% && /usr/sbin/tc qdisc show dev eth1 root | grep -q netem"
		if len(r.calls) != 1 || !strings.Contains(r.calls[0], want) {
			t.Fatalf("%s: calls = %v, want one containing %q", name, r.calls, want)
		}
		if err := restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		if r.calls[1] != "sudo /usr/sbin/tc qdisc del dev eth1 root" {
			t.Fatalf("%s: restore ran %q", name, r.calls[1])
		}
	}
}

func TestImpairRefusesBadInputBeforeAnySSH(t *testing.T) {
	cases := []struct {
		d    time.Duration
		loss int
	}{{0, 0}, {-time.Second, 0}, {11 * time.Second, 0}, {0, 101}, {0, -1}, {1500 * time.Microsecond, 0}}
	for _, c := range cases {
		r := &fakeRunner{}
		if _, err := (&KeaAdapter{Runner: r}).Impair(context.Background(), c.d, c.loss); err == nil {
			t.Errorf("Impair(%s, %d) accepted", c.d, c.loss)
		}
		if len(r.calls) != 0 {
			t.Errorf("Impair(%s, %d) reached the runner", c.d, c.loss)
		}
	}
}

// A netem that is not in place after the replace (no sch_netem in the
// source kernel) is an error, and the half-made qdisc is removed (defeat 9).
func TestImpairNotInPlaceIsAnErrorAndCleansUp(t *testing.T) {
	r := &fakeRunner{err: errors.New("exit 1")}
	restore, err := (&DnsmasqAdapter{Runner: r}).Impair(context.Background(), 0, 100)
	if err == nil || restore != nil {
		t.Fatalf("Impair = (%v, %v), want an error and no restore", restore != nil, err)
	}
	if len(r.calls) != 2 || r.calls[1] != "sudo /usr/sbin/tc qdisc del dev eth1 root" {
		t.Fatalf("calls = %v, want the replace then a cleanup delete", r.calls)
	}
}

// ResetLeases on Kea removes every LFC copy Kea reloads at start, after
// the stop and before the start; ISC and dnsmasq reload one file only
// (C4 defeat 2, #23).
func TestResetLeasesClearsEveryReloadedFile(t *testing.T) {
	r := &fakeRunner{}
	if err := (&KeaAdapter{Runner: r}).ResetLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	call := r.calls[0]
	rmAt := strings.Index(call, "sudo rm -f -- ")
	if rmAt < 0 || rmAt < strings.Index(call, "stop kea-dhcp4-server") || rmAt > strings.Index(call, "start kea-dhcp4-server") {
		t.Fatalf("kea reset = %q, want an rm between the stop and the start", call)
	}
	for _, f := range []string{".1", ".2", ".output", ".completed"} {
		if !strings.Contains(call, " /var/lib/kea/kea-leases4.csv"+f) {
			t.Errorf("kea reset does not remove kea-leases4.csv%s: %q", f, call)
		}
	}
	for name, a := range map[string]Adapter{"isc-dhcp": &ISCDHCPAdapter{Runner: r}, "dnsmasq": &DnsmasqAdapter{Runner: r}} {
		r.calls = nil
		if err := a.ResetLeases(context.Background()); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(r.calls[0], "rm ") {
			t.Errorf("%s reset removes files it does not reload: %q", name, r.calls[0])
		}
	}
}

// bareTC matches a tc that is not spelled with a path: the ssh user's
// non-login shell has no /usr/sbin in PATH (first kea run, #23).
var bareTC = regexp.MustCompile(`(^|[^/\w-])tc\s`)

func TestEveryTCCommandNamesTheAbsolutePath(t *testing.T) {
	ctx := context.Background()
	h := healthyHost()
	adapters := map[string]Adapter{"kea": &KeaAdapter{Runner: h}, "isc-dhcp": &ISCDHCPAdapter{Runner: h}, "dnsmasq": &DnsmasqAdapter{Runner: h}}
	phase := func(name string, run func() error) {
		before := len(h.calls)
		if err := run(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var named int
		for _, c := range h.calls[before:] {
			if bareTC.MatchString(c) {
				t.Errorf("%s calls tc by name: %q", name, c)
			}
			if strings.Contains(c, "/usr/sbin/tc ") {
				named++
			}
		}
		if named == 0 {
			t.Errorf("%s ran no command naming /usr/sbin/tc: %v", name, h.calls[before:])
		}
	}
	// Ready reads the qdisc on the dnsmasq source (Kea's Ready also needs its control agent).
	phase("Ready", func() error { return adapters["dnsmasq"].Ready(ctx) })
	for name, a := range adapters {
		var restore func(context.Context) error
		phase(name+" Impair", func() (err error) { restore, err = a.Impair(ctx, time.Second, 5); return })
		phase(name+" restore", func() error { return restore(ctx) })
		phase(name+" Recover", func() error { return a.Recover(ctx) })
	}
}
