package sourceadapter

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hostRunner answers by command shape, so Ready and Recover can be
// driven through a source whose state changes between calls (#23).
type hostRunner struct {
	active  bool
	stopped map[string]bool
	netns   string
	links   string
	procs   int
	netem   bool
	addrs   string
	addrs6  string
	cfg     string
	extra   map[string]string
	written string
	calls   []string
	// lease6Err makes the kea v6 lease read fail.
	lease6Err bool
}

var cfg6Probe = regexp.MustCompile(`printf 'cfg6:([^:']+):'`)

func (h *hostRunner) Run(_ context.Context, cmd string) (string, error) {
	h.calls = append(h.calls, cmd)
	switch {
	case strings.Contains(cmd, "is-active"):
		if !h.active || h.stopped[cmd[strings.LastIndex(cmd, " ")+1:]] {
			return "", errors.New("inactive")
		}
		return "", nil
	case strings.HasPrefix(cmd, "sudo cat "+dnsmasqLeaseFile), strings.HasPrefix(cmd, "sudo cat /var/lib/dhcp/"):
		return "", nil
	case cmd == keaLease6Cmd && h.lease6Err:
		return "", errors.New("kea-dhcp6 control socket refused")
	case cmd == keaLeaseCmd || cmd == keaLease6Cmd:
		return `[{"result":3,"text":"0 leases found"}]`, nil
	case strings.HasPrefix(cmd, "sudo cat ") && h.extra[strings.TrimPrefix(cmd, "sudo cat ")] != "":
		return h.extra[strings.TrimPrefix(cmd, "sudo cat ")], nil
	case strings.HasPrefix(cmd, "printf 'netns:'"):
		n := "0"
		if h.netem {
			n = "1"
		}
		out := "netns:" + h.netns + "\nlinks:" + h.links + "\nprocs:" + fmt.Sprint(h.procs) + "\nnetem:" + n + "\naddr:" + h.addrs + "\naddr6:" + h.addrs6 + "\n"
		for _, m := range cfg6Probe.FindAllStringSubmatch(cmd, -1) {
			body, ok := h.extra[m[1]]
			enc := "!"
			if ok {
				enc = base64.StdEncoding.EncodeToString([]byte(body))
			}
			out += "cfg6:" + m[1] + ":" + enc + "\n"
		}
		return out + "cfg:\n" + h.cfg, nil
	case cmd == debianHost("").segAddrCmd():
		return strings.ReplaceAll(strings.TrimSpace(h.addrs), " ", "\n") + "\n", nil
	case strings.Contains(cmd, "qdisc replace dev eth1 root netem"):
		return fakeNetemShow(cmd), nil
	case strings.HasPrefix(cmd, "sudo ip -4 addr flush dev eth1"):
		var a []string
		for _, m := range regexp.MustCompile(`ip addr add (\S+) brd \+ dev eth1`).FindAllStringSubmatch(cmd, -1) {
			a = append(a, m[1]+" ")
		}
		h.addrs = strings.Join(a, "")
		return "", nil
	case strings.HasPrefix(cmd, "sudo tee "):
		path := strings.Fields(cmd)[2]
		body := cmd[strings.Index(cmd, "<<'LABEOF'\n")+len("<<'LABEOF'\n"):]
		body = strings.TrimSuffix(body, "LABEOF\n")
		if _, ok := h.extra[path]; ok {
			h.extra[path] = body
			return "", nil
		}
		h.written = body
		h.cfg = body
		return "", nil
	case strings.Contains(cmd, "ip netns del"):
		h.netns, h.netem = "", false
		if strings.Contains(cmd, "pkill -f '"+actorRE+"'") {
			h.procs = 0
		}
		if strings.Contains(cmd, `sudo ip link del "$l"`) {
			h.links = ""
		}
		return "", nil
	case strings.HasPrefix(cmd, "sudo ip -6 addr add "):
		h.addrs6 += strings.Fields(cmd)[5] + " "
		return "", nil
	case strings.HasPrefix(cmd, "sudo ip -6 addr del "):
		h.addrs6 = strings.Replace(h.addrs6, strings.Fields(cmd)[5]+" ", "", 1)
		return "", nil
	case strings.Contains(cmd, "systemctl restart"):
		h.active = true
		delete(h.stopped, cmd[strings.LastIndex(cmd, " ")+1:])
		return "", nil
	case strings.Contains(cmd, "systemctl stop"):
		h.stopped[cmd[strings.LastIndex(cmd, " ")+1:]] = true
		return "", nil
	}
	return "", nil
}

func healthyHost() *hostRunner {
	return &hostRunner{active: true, stopped: map[string]bool{}, addrs: "10.200.1.2/24 ", addrs6: "fd42:200:0:100::2/64 ",
		cfg: "dhcp-range=10.200.1.100,10.200.1.200\n",
		extra: map[string]string{
			dnsmasqLabV6Conf: "enable-ra\ndhcp-range=fd42:200:0:100::100,fd42:200:0:100::1ff,slaac,64,2h\nra-param=eth1,10,1800\n",
			keaDHCP6Conf:     "{ \"rapid-commit\": false }\n",
			iscDHCP6Conf:     "#lab-rapid-commit option dhcp6.rapid-commit;\n",
			radvdConf:        "interface eth1 { AdvSendAdvert on; };\n",
		}}
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
		{"leftover link", func(h *hostRunner) { h.links = "labc-sq0 " }, "labc-sq0"},
		{"leftover actor process", func(h *hostRunner) { h.procs = 1 }, "actor processes"},
		{"segment address changed", func(h *hostRunner) { h.addrs = "10.200.101.2/24 " }, "eth1 carries"},
		{"segment v6 address changed", func(h *hostRunner) { h.addrs6 = "fd42:200:0:101::2/64 " }, "eth1 carries v6"},
		{"v6 config drifted", func(h *hostRunner) { h.extra[dnsmasqLabV6Conf] = "#lab-ra-off\n" }, dnsmasqLabV6Conf + " differs"},
		{"v6 config unreadable", func(h *hostRunner) { delete(h.extra, dnsmasqLabV6Conf) }, "not readable"},
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

// The kernel may list the same permanent v6 addresses in another order;
// Ready compares them as a set (#23 group D part 2).
func TestReadyComparesTheV6AddressesAsASet(t *testing.T) {
	h := healthyHost()
	h.addrs6 = "fd42:200:0:100::2/64 fd42:200:0:100::3/64 "
	a := &DnsmasqAdapter{Runner: h}
	ctx := context.Background()
	if err := a.Ready(ctx); err != nil {
		t.Fatalf("first Ready on a healthy source: %v", err)
	}
	h.addrs6 = "fd42:200:0:100::3/64 fd42:200:0:100::2/64 "
	if err := a.Ready(ctx); err != nil {
		t.Errorf("Ready after a reorder of the baseline v6 addresses: %v", err)
	}
	h.addrs6 = "fd42:200:0:100::3/64 "
	if err := a.Ready(ctx); err == nil || !strings.Contains(err.Error(), "eth1 carries v6") {
		t.Errorf("Ready with a baseline v6 address gone = %v", err)
	}
}

// A source whose DHCPv6 table cannot be read fails Ready, so a v6 row
// never judges an empty table as "no lease" (#23 group D).
func TestReadyFailsWhenTheV6LeaseTableIsUnreadable(t *testing.T) {
	h := healthyHost()
	a := &KeaAdapter{Runner: h}
	if err := a.Ready(context.Background()); err != nil {
		t.Fatalf("first Ready on a healthy source: %v", err)
	}
	h.lease6Err = true
	if err := a.Ready(context.Background()); err == nil || !strings.Contains(err.Error(), "v6 lease table not readable") {
		t.Fatalf("Ready = %v, want the v6 lease table error", err)
	}
}

// The baseline holds permanent v6 addresses only: an RA-formed address
// on the source would move it between two readiness checks (#23 group D).
func TestStateCmdReadsOnlyPermanentV6Addresses(t *testing.T) {
	cmd := debianHost("x").stateCmd(sourceUnits{cfgPath: "/etc/x"})
	if !strings.Contains(cmd, "ip -6 -o addr show dev "+segmentNIC+" scope global permanent |") {
		t.Fatalf("stateCmd reads v6 addresses without the permanent filter: %s", cmd)
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
	h.links, h.procs, h.addrs = "labc-rg0 ", 2, "10.200.101.2/24 "
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

// The searches for leftover actors must not find the shell running
// them: pgrep -f reads full argv, so a command carrying the text
// "labc-" counts itself, and pkill kills its own shell (pgrep(1), #23).
func TestActorSearchesNeverCarryTheirOwnPattern(t *testing.T) {
	h := healthyHost()
	a := &DnsmasqAdapter{Runner: h}
	ctx := context.Background()
	if err := a.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	var sawPkill, sawPgrep bool
	for _, c := range h.calls {
		if strings.Contains(c, "labc-") {
			t.Errorf("command carries the literal actor prefix: %q", c)
		}
		sawPkill = sawPkill || strings.Contains(c, "pkill -f '[l]abc-'")
		sawPgrep = sawPgrep || strings.Contains(c, "pgrep -f '[l]abc-'")
	}
	if !sawPkill || !sawPgrep {
		t.Fatalf("pkill seen %t, pgrep seen %t: %v", sawPkill, sawPgrep, h.calls)
	}
	if !regexp.MustCompile(actorRE).MatchString("labc-rogue") || regexp.MustCompile(actorRE).MatchString("[l]abc-") {
		t.Fatalf("%q must match an actor name and not itself", actorRE)
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
	tail := strings.Join(h.calls[len(h.calls)-3:], "; ")
	if want := "sudo systemctl restart kea-dhcp4-server; sudo systemctl restart kea-dhcp6-server; sudo systemctl restart radvd"; tail != want {
		t.Fatalf("last calls = %q, want %q", tail, want)
	}
}

func TestParseStateRefusesAnIncompleteRead(t *testing.T) {
	u := (&DnsmasqAdapter{}).units()
	full := "netns:\nlinks:\nprocs:0\nnetem:0\naddr:a\naddr6:b\n"
	for _, out := range []string{"", "netns:\nnetem:0\ncfg:\nx", "netns:\naddr:a\ncfg:\n",
		full + "cfg:\n",
		full + "cfg6:" + dnsmasqLabV6Conf + ":!\ncfg:\n",
		full + "cfg6:/etc/other.conf:eA==\ncfg:\n",
		full + "cfg6:" + dnsmasqLabV6Conf + ":eA==\ncfg6:" + dnsmasqLabV6Conf + ":eA==\ncfg:\n"} {
		if _, err := parseState(out, u, true); err == nil {
			t.Errorf("parseState(%q) accepted", out)
		}
	}
	st, err := parseState(full+"cfg6:"+dnsmasqLabV6Conf+":eA==\ncfg:\ny", u, true)
	if err != nil || st.extra[dnsmasqLabV6Conf] != "x" || st.addrs6 != "b" || st.cfg != "y" {
		t.Fatalf("parseState of a full read = %+v, %v", st, err)
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
		r.reply = "qdisc netem 8001: root refcnt 2 limit 1000 delay 2s\n"
		restore, err := a.Impair(context.Background(), 2*time.Second, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := "sudo /usr/sbin/tc qdisc replace dev eth1 root netem delay 2000ms loss 0% && /usr/sbin/tc qdisc show dev eth1 root"
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

// A SetRA restore that never ran must fail the next Ready on every
// adapter: radvd stopped on kea and isc, lab-v6.conf edited on dnsmasq
// (group D defeat 4, #23). Recover then brings the source back.
func TestASkippedRARestoreFailsTheNextReady(t *testing.T) {
	ctx := context.Background()
	for name, mk := range map[string]func(Runner) Adapter{
		"kea":      func(r Runner) Adapter { return &KeaAdapter{Runner: r} },
		"isc-dhcp": func(r Runner) Adapter { return &ISCDHCPAdapter{Runner: r} },
		"dnsmasq":  func(r Runner) Adapter { return &DnsmasqAdapter{Runner: r} },
	} {
		h := healthyHost()
		a := mk(h)
		if err := a.Ready(ctx); err != nil {
			t.Fatalf("%s: first Ready: %v", name, err)
		}
		before := h.extra[dnsmasqLabV6Conf]
		if _, err := a.SetRA(ctx, RAParams{Off: true}); err != nil {
			t.Fatalf("%s: SetRA: %v", name, err)
		}
		if name == "dnsmasq" && h.extra[dnsmasqLabV6Conf] == before {
			t.Fatalf("dnsmasq: SetRA left lab-v6.conf unchanged, the test proves nothing")
		}
		if err := a.Ready(ctx); err == nil {
			t.Fatalf("%s: Ready passed with the RA restore skipped", name)
		}
		if err := a.Recover(ctx); err != nil {
			t.Fatalf("%s: Recover: %v", name, err)
		}
		if err := a.Ready(ctx); err != nil {
			t.Fatalf("%s: Ready after Recover: %v", name, err)
		}
	}
}

var netemAskRE = regexp.MustCompile(`netem delay (\d+)ms loss (\d+)%`)

// fakeNetemShow is what iproute2 prints for the qdisc a replace command
// made: 2000ms as "2s", 1500ms as "1.5s", and no loss field for 0%.
func fakeNetemShow(cmd string) string {
	m := netemAskRE.FindStringSubmatch(cmd)
	if m == nil {
		return ""
	}
	ms, _ := strconv.Atoi(m[1])
	d := fmt.Sprintf("%dms", ms)
	if ms >= 1000 {
		d = strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64) + "s"
	}
	out := "qdisc netem 8001: root refcnt 2 limit 1000 delay " + d
	if m[2] != "0" {
		out += " loss " + m[2] + "%"
	}
	return out + "\n"
}

// The read-back compares the delay and loss, not just the word netem
// (lab #125, defeats 5 and 6): iproute2 prints in s, ms or us.
func TestNetemInPlaceComparesDelayAndLoss(t *testing.T) {
	ms := time.Millisecond
	cases := []struct {
		name  string
		out   string
		delay time.Duration
		loss  int
		ok    bool
	}{
		{"seconds", "qdisc netem 8001: root refcnt 2 limit 1000 delay 2s\n", 2000 * ms, 0, true},
		{"fraction of a second", "qdisc netem 8001: root refcnt 2 limit 1000 delay 1.5s\n", 1500 * ms, 0, true},
		{"milliseconds", "qdisc netem 8001: root refcnt 2 limit 1000 delay 150ms loss 5%\n", 150 * ms, 5, true},
		{"rounded print", "qdisc netem 8001: root refcnt 2 limit 1000 delay 149.9ms\n", 150 * ms, 0, true},
		{"microseconds", "qdisc netem 8001: root refcnt 2 limit 1000 delay 500us\n", 500 * time.Microsecond, 0, true},
		{"loss only", "qdisc netem 8001: root refcnt 2 limit 1000 loss 100%\n", 0, 100, true},
		{"another qdisc", "qdisc noqueue 0: root refcnt 2\n", 2000 * ms, 0, false},
		{"no output", "", 2000 * ms, 0, false},
		{"netem without a delay", "qdisc netem 8001: root refcnt 2 limit 1000\n", 2000 * ms, 0, false},
		{"within the 1 % tolerance", "qdisc netem 8001: root refcnt 2 limit 1000 delay 2015ms\n", 2000 * ms, 0, true},
		{"just outside the 1 % tolerance", "qdisc netem 8001: root refcnt 2 limit 1000 delay 2030ms\n", 2000 * ms, 0, false},
		{"just outside, below", "qdisc netem 8001: root refcnt 2 limit 1000 delay 1970ms\n", 2000 * ms, 0, false},
		{"a shorter delay", "qdisc netem 8001: root refcnt 2 limit 1000 delay 200ms\n", 2000 * ms, 0, false},
		{"a ten-times delay", "qdisc netem 8001: root refcnt 2 limit 1000 delay 20s\n", 2000 * ms, 0, false},
		{"unit mistaken", "qdisc netem 8001: root refcnt 2 limit 1000 delay 2us\n", 2000 * ms, 0, false},
		{"loss missing", "qdisc netem 8001: root refcnt 2 limit 1000 delay 2s\n", 2000 * ms, 5, false},
		{"another loss", "qdisc netem 8001: root refcnt 2 limit 1000 loss 50%\n", 0, 100, false},
		{"a higher loss", "qdisc netem 8001: root refcnt 2 limit 1000 loss 100%\n", 0, 50, false},
		{"no impairment asked, another qdisc found", "qdisc noqueue 0: root refcnt 2\n", 0, 0, false},
	}
	for _, c := range cases {
		err := netemInPlace(c.out, c.delay, c.loss)
		if (err == nil) != c.ok {
			t.Errorf("%s: netemInPlace(%q, %s, %d) = %v, want ok=%v", c.name, c.out, c.delay, c.loss, err, c.ok)
		}
	}
}

// A source whose qdisc comes back with another delay than the one asked
// for is an Impair error and the qdisc is removed again.
func TestImpairReadBackOfAnotherDelayIsAnErrorAndCleansUp(t *testing.T) {
	r := &fakeRunner{reply: "qdisc netem 8001: root refcnt 2 limit 1000 delay 200ms\n"}
	restore, err := (&DnsmasqAdapter{Runner: r}).Impair(context.Background(), 2*time.Second, 0)
	if err == nil || restore != nil {
		t.Fatalf("Impair = (%v, %v), want an error and no restore", restore != nil, err)
	}
	if len(r.calls) != 2 || r.calls[1] != "sudo /usr/sbin/tc qdisc del dev eth1 root" {
		t.Fatalf("calls = %v, want the replace then a cleanup delete", r.calls)
	}
}
