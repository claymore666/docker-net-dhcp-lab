package sourceadapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// segRunner is a cfgRunner whose eth1 addresses the adapter reads and
// replaces; ops records the order of address, config and restart steps.
type segRunner struct {
	cfgRunner
	addrs     []string
	ops       []string
	calls     []string
	failAddrN int
	addrCalls int
	failCmd   string
	out       map[string]string
}

var addrAddRE = regexp.MustCompile(`ip addr add (\S+) brd \+ dev eth1`)

func (s *segRunner) Run(ctx context.Context, cmd string) (string, error) {
	s.calls = append(s.calls, cmd)
	if s.failCmd != "" && strings.Contains(cmd, s.failCmd) {
		return "", errors.New("injected failure")
	}
	for k, v := range s.out {
		if strings.Contains(cmd, k) {
			return v, nil
		}
	}
	switch {
	case cmd == segAddrCmd:
		return strings.Join(s.addrs, "\n") + "\n", nil
	case strings.HasPrefix(cmd, "sudo ip -4 addr flush dev eth1"):
		s.addrCalls++
		if s.failAddrN == s.addrCalls {
			return "", errors.New("address change failed")
		}
		s.addrs = nil
		for _, m := range addrAddRE.FindAllStringSubmatch(cmd, -1) {
			s.addrs = append(s.addrs, m[1])
		}
		s.ops = append(s.ops, "addr "+strings.Join(s.addrs, ","))
		return "", nil
	case strings.HasPrefix(cmd, "sudo tee "):
		s.ops = append(s.ops, "write")
	case strings.Contains(cmd, "systemctl restart"):
		s.ops = append(s.ops, "restart")
	}
	return s.cfgRunner.Run(ctx, cmd)
}

func segBaseline(t *testing.T, name string) *segRunner {
	return &segRunner{cfgRunner: *baselineRunner(t, name), addrs: []string{"10.200.1.2/24"}}
}

var adapterNames = []string{"kea", "isc-dhcp", "dnsmasq"}

// C8: the main pool shrinks to two addresses and nothing else in the
// config moves; restore writes the captured bytes back (#23).
func TestNarrowPoolChangesOnlyTheMainPoolAndRestoresByteForByte(t *testing.T) {
	want := map[string]string{
		"kea":      `{ "pool": "10.200.1.201 - 10.200.1.202", "client-class": "not-b5" }`,
		"isc-dhcp": "deny members of \"b5\";\n    range 10.200.1.201 10.200.1.202;",
		"dnsmasq":  "dhcp-range=tag:!b5,10.200.1.201,10.200.1.202,12h",
	}
	for _, name := range adapterNames {
		r := baselineRunner(t, name)
		orig := r.cfg
		restore, err := groupBAdapters(r)[name].NarrowPool(context.Background(), "10.200.1.201", "10.200.1.202")
		if err != nil {
			t.Fatalf("%s: NarrowPool: %v", name, err)
		}
		got := r.cfg
		if !strings.Contains(got, want[name]) {
			t.Fatalf("%s: narrowed config lacks %q:\n%s", name, want[name], got)
		}
		if strings.Contains(got, "10.200.1.100") || strings.Contains(got, "10.200.1.200") {
			t.Fatalf("%s: the old pool bounds survive:\n%s", name, got)
		}
		if !strings.Contains(got, "10.200.1.221") || !strings.Contains(got, "10.200.1.230") {
			t.Fatalf("%s: the class pool moved:\n%s", name, got)
		}
		if strings.Count(got, "\n") != strings.Count(orig, "\n") {
			t.Fatalf("%s: line count changed", name)
		}
		if _, err := groupBAdapters(r)[name].NarrowPool(context.Background(), "10.200.1.201", "10.200.1.202"); err == nil {
			t.Fatalf("%s: a second NarrowPool on the narrowed config passed", name)
		}
		if err := restore(context.Background()); err != nil {
			t.Fatalf("%s: restore: %v", name, err)
		}
		if r.cfg != orig || r.restarts != 2 {
			t.Fatalf("%s: restore left %q after %d restarts, want the baseline after 2", name, r.cfg, r.restarts)
		}
	}
}

// A group F user-class pool adds a class test before the main pool;
// NarrowPool steps over it instead of refusing or eating it.
func TestNarrowPoolStepsOverAGroupFClassTest(t *testing.T) {
	for _, c := range featureCases {
		if c.feature != FeatureUserClassPool {
			continue
		}
		for _, name := range adapterNames {
			r := baselineRunner(t, name)
			a := groupBAdapters(r)[name]
			if _, err := a.EnableFeature(context.Background(), c.feature, c.params); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			withF := r.cfg
			if _, err := a.NarrowPool(context.Background(), "10.200.1.201", "10.200.1.202"); err != nil {
				t.Fatalf("%s: NarrowPool over a user-class pool: %v", name, err)
			}
			if !strings.Contains(r.cfg, "10.200.1.201") || strings.Count(r.cfg, "f1") != strings.Count(withF, "f1") {
				t.Fatalf("%s: narrowed config lost the class test or the pool:\n%s", name, r.cfg)
			}
		}
	}
}

func TestNarrowPoolRefusesABadPool(t *testing.T) {
	for _, name := range adapterNames {
		r := baselineRunner(t, name)
		for _, p := range [][2]string{{"10.200.1.202", "10.200.1.201"}, {"10.200.1.201", "x"}, {"fe80::1", "fe80::2"}} {
			if _, err := groupBAdapters(r)[name].NarrowPool(context.Background(), p[0], p[1]); err == nil {
				t.Fatalf("%s: NarrowPool(%s, %s) passed", name, p[0], p[1])
			}
		}
		if len(r.writes) != 0 {
			t.Fatalf("%s: a refused NarrowPool wrote the config", name)
		}
	}
}

// C9: eth1 moves before the config is written and the server restarts
// on it (an ISC subnet must match its interface); restore moves the
// address back first, then the config, then restarts (#23).
func TestRenumberMovesTheSegmentFirstAndRestoresInOrder(t *testing.T) {
	keep := map[string][]string{
		"kea":      {`"valid-lifetime": 3600,`, `"interfaces": [ "eth1" ]`, "libdhcp_lease_cmds.so", `"name": "/var/lib/kea/kea-leases4.csv"`, `"id": 2,`, `"subnet": "10.200.101.0/24"`, `"pool": "10.200.101.100 - 10.200.101.200"`, `"data": "10.200.101.2"`},
		"isc-dhcp": {"default-lease-time 600;", "max-lease-time 7200;", "authoritative;", "subnet 10.200.101.0 netmask 255.255.255.0 {", "range 10.200.101.100 10.200.101.200;", "option routers 10.200.101.2;"},
		"dnsmasq":  {"interface=eth1\nbind-interfaces\nexcept-interface=eth0\ndhcp-authoritative\n", "dhcp-range=10.200.101.100,10.200.101.200,12h\n", "dhcp-option=3,10.200.101.2\n"},
	}
	gone := []string{"10.200.1.", "b5", "reservations", "include", "conf-dir"}
	for _, name := range adapterNames {
		r := segBaseline(t, name)
		orig := r.cfg
		restore, err := groupBAdapters(r)[name].Renumber(context.Background(), "10.200.101.0/24", "10.200.101.2", "10.200.101.100", "10.200.101.200")
		if err != nil {
			t.Fatalf("%s: Renumber: %v", name, err)
		}
		if got := strings.Join(r.ops, "; "); got != "addr 10.200.101.2/24; write; restart" {
			t.Fatalf("%s: Renumber ran %q", name, got)
		}
		for _, k := range keep[name] {
			if !strings.Contains(r.cfg, k) {
				t.Errorf("%s: renumbered config lacks %q:\n%s", name, k, r.cfg)
			}
		}
		for _, g := range gone {
			if strings.Contains(r.cfg, g) {
				t.Errorf("%s: renumbered config still carries %q:\n%s", name, g, r.cfg)
			}
		}
		r.ops = nil
		if err := restore(context.Background()); err != nil {
			t.Fatalf("%s: restore: %v", name, err)
		}
		if got := strings.Join(r.ops, "; "); got != "addr 10.200.1.2/24; write; restart" {
			t.Fatalf("%s: restore ran %q", name, got)
		}
		if r.cfg != orig {
			t.Fatalf("%s: restore left a config that is not the baseline byte for byte", name)
		}
	}
}

// A shortened lease time is what C9's renewal clock runs on; the
// renumbered config keeps it.
func TestRenumberKeepsAShortenedLeaseTime(t *testing.T) {
	want := map[string]string{"kea": `"valid-lifetime": 120,`, "isc-dhcp": "default-lease-time 120;", "dnsmasq": ",120\n"}
	for _, name := range adapterNames {
		r := segBaseline(t, name)
		a := groupBAdapters(r)[name]
		if _, err := a.ShortenLeaseTime(context.Background(), 120); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Renumber(context.Background(), "10.200.101.0/24", "10.200.101.2", "10.200.101.100", "10.200.101.200"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(r.cfg, want[name]) {
			t.Fatalf("%s: renumbered config lost the lease time %q:\n%s", name, want[name], r.cfg)
		}
	}
}

// Every failure after the address moved puts the address and the
// config back before the error returns.
func TestRenumberFailuresRestoreTheSegment(t *testing.T) {
	for _, name := range adapterNames {
		for _, fail := range []string{"write", "restart", "addr"} {
			r := segBaseline(t, name)
			orig := r.cfg
			switch fail {
			case "write":
				r.failWriteN = 1
			case "restart":
				r.failRestartN = 1
			case "addr":
				r.failAddrN = 1
			}
			if _, err := groupBAdapters(r)[name].Renumber(context.Background(), "10.200.101.0/24", "10.200.101.2", "10.200.101.100", "10.200.101.200"); err == nil {
				t.Fatalf("%s: Renumber with a failed %s passed", name, fail)
			}
			if strings.Join(r.addrs, ",") != "10.200.1.2/24" || r.cfg != orig {
				t.Fatalf("%s: failed %s left eth1 %v and a changed config: %v", name, fail, r.addrs, r.ops)
			}
		}
	}
}

func TestRenumberRefusesABadPlan(t *testing.T) {
	bad := [][4]string{
		{"10.200.101.1/24", "10.200.101.2", "10.200.101.100", "10.200.101.200"},   // not a network prefix
		{"10.200.101.0/24", "10.200.1.2", "10.200.101.100", "10.200.101.200"},     // address outside
		{"10.200.101.0/24", "10.200.101.150", "10.200.101.100", "10.200.101.200"}, // address in pool
		{"10.200.101.0/24", "10.200.101.2", "10.200.101.200", "10.200.101.100"},   // backwards
		{"10.200.101.0/24", "10.200.101.0", "10.200.101.100", "10.200.101.200"},   // network address
		{"fd00::/64", "fd00::2", "fd00::100", "fd00::200"},
	}
	for _, name := range adapterNames {
		for _, b := range bad {
			r := segBaseline(t, name)
			if _, err := groupBAdapters(r)[name].Renumber(context.Background(), b[0], b[1], b[2], b[3]); err == nil {
				t.Fatalf("%s: Renumber%v passed", name, b)
			}
			if len(r.ops) != 0 {
				t.Fatalf("%s: a refused Renumber%v touched the source: %v", name, b, r.ops)
			}
		}
	}
}

const sqMAC = "02:11:22:33:44:55"

func squatOut(arp, mac, icmp string) map[string]string {
	return map[string]string{"printf 'arp:'": "arp:" + arp + "\nmac:" + mac + "\nicmp:" + icmp + "\n"}
}

const goodARP = "ARPING 10.200.1.231 from 0.0.0.0 labc-pr0 Unicast reply from 10.200.1.231 [02:11:22:33:44:55]  0.6ms Sent 1 probes (1 broadcast(s)) Received 1 response(s) "

// C6 and C6b: the squatter holds X in its own netns, answers an
// RFC 5227 probe with its own MAC and ignores ping (#23).
func TestSquatSetsUpTheNetnsAndChecksItAnswersAProbe(t *testing.T) {
	for _, announce := range []bool{false, true} {
		r := &segRunner{addrs: []string{"10.200.1.2/24"}, out: squatOut(goodARP, sqMAC, "1")}
		a := &KeaAdapter{Runner: r}
		stop, err := a.Squat(context.Background(), "10.200.1.231", announce)
		if err != nil {
			t.Fatalf("Squat: %v", err)
		}
		all := strings.Join(r.calls, "\n")
		for _, w := range []string{"sudo ip netns add labc-squat", "type macvlan mode bridge", "icmp_echo_ignore_all=1", "ip addr add 10.200.1.231/24 dev labc-sq0", "arping -D -c 2 -w 3 -I labc-pr0 10.200.1.231"} {
			if !strings.Contains(all, w) {
				t.Fatalf("Squat never ran %q:\n%s", w, all)
			}
		}
		if got := strings.Contains(all, "arping -q -U"); got != announce {
			t.Fatalf("announce=%t but gratuitous ARP sent=%t", announce, got)
		}
		if !strings.Contains(all, "ip netns del labc-probe") {
			t.Fatalf("the probe netns was never removed:\n%s", all)
		}
		n := len(r.calls)
		if err := stop(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(r.calls[n:], "\n"), "ip netns del labc-squat") {
			t.Fatalf("stop never removed the squatter")
		}
	}
}

func TestSquatFailsAndCleansUpWhenTheProbeSeesNoSquatter(t *testing.T) {
	cases := map[string]map[string]string{
		"no reply":        squatOut("Sent 2 probes Received 0 response(s)", sqMAC, "1"),
		"someone else":    squatOut(strings.ReplaceAll(goodARP, sqMAC, "02:aa:bb:cc:dd:ee"), sqMAC, "1"),
		"ping answered":   squatOut(goodARP, sqMAC, "0"),
		"unreadable MAC":  squatOut(goodARP, "", "1"),
		"probe cmd fails": nil,
	}
	for name, out := range cases {
		r := &segRunner{addrs: []string{"10.200.1.2/24"}, out: out}
		if out == nil {
			r.failCmd = "printf 'arp:'"
		}
		if _, err := (&DnsmasqAdapter{Runner: r}).Squat(context.Background(), "10.200.1.231", false); err == nil {
			t.Fatalf("%s: Squat passed", name)
		}
		if !strings.Contains(strings.Join(r.calls, "\n"), "ip netns del labc-squat") {
			t.Fatalf("%s: a failed Squat left the squatter's netns", name)
		}
	}
}

func TestActorsRefuseAddressesOffTheSegment(t *testing.T) {
	for _, addr := range []string{"10.200.2.231", "10.200.1.2", "x"} {
		r := &segRunner{addrs: []string{"10.200.1.2/24"}}
		if _, err := (&ISCDHCPAdapter{Runner: r}).Squat(context.Background(), addr, false); err == nil {
			t.Fatalf("Squat(%s) passed", addr)
		}
		if _, err := (&ISCDHCPAdapter{Runner: r}).StartRogue(context.Background(), addr, "10.200.1.241", "10.200.1.250"); err == nil {
			t.Fatalf("StartRogue(%s) passed", addr)
		}
		for _, c := range r.calls {
			if strings.Contains(c, "netns add") {
				t.Fatalf("a refused actor set up a netns: %q", c)
			}
		}
	}
	r := &segRunner{addrs: []string{"10.200.1.2/24", "10.200.1.3/24"}}
	if _, err := (&ISCDHCPAdapter{Runner: r}).Squat(context.Background(), "10.200.1.231", false); err == nil {
		t.Fatal("Squat on a segment with two addresses passed")
	}
	if _, err := (&ISCDHCPAdapter{Runner: r}).StartRogue(context.Background(), "10.200.1.245", "10.200.1.241", "10.200.1.250"); err == nil {
		t.Fatal("StartRogue with its address inside its pool passed")
	}
}

// C7: the rogue reads no config file (on the dnsmasq source
// /etc/dnsmasq.conf is the real server's), serves no DNS, does not ping
// before an offer and is not authoritative, so it never NAKs.
func TestStartRogueRunsAnIsolatedNonAuthoritativeDnsmasq(t *testing.T) {
	r := &segRunner{addrs: []string{"10.200.1.2/24"}}
	stop, err := (&DnsmasqAdapter{Runner: r}).StartRogue(context.Background(), "10.200.1.240", "10.200.1.241", "10.200.1.250")
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.calls, "\n")
	for _, w := range []string{"ip addr add 10.200.1.240/24 dev labc-rg0", "ip netns exec labc-rogue dnsmasq --conf-file=/dev/null --port=0", "--no-ping", "--dhcp-range=10.200.1.241,10.200.1.250,2m", "--dhcp-leasefile=/run/labc-rogue.leases", "ip netns pids labc-rogue | grep -q ."} {
		if !strings.Contains(all, w) {
			t.Fatalf("StartRogue never ran %q:\n%s", w, all)
		}
	}
	if strings.Contains(all, "authoritative") {
		t.Fatalf("the rogue is authoritative:\n%s", all)
	}
	if err := stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	r2 := &segRunner{addrs: []string{"10.200.1.2/24"}, failCmd: "--conf-file=/dev/null"}
	if _, err := (&DnsmasqAdapter{Runner: r2}).StartRogue(context.Background(), "10.200.1.240", "10.200.1.241", "10.200.1.250"); err == nil {
		t.Fatal("StartRogue with a dead dnsmasq passed")
	}
	if !strings.Contains(strings.Join(r2.calls, "\n"), "ip netns del labc-rogue") {
		t.Fatal("a failed StartRogue left its netns")
	}
}

// A deleted netns lives on while a process runs in it (ip-netns(8)):
// teardown kills first and fails if the netns is still listed.
func TestNetnsTeardownKillsBeforeDeletingAndChecks(t *testing.T) {
	c := netnsDownCmd(rogueNetns, rogueLink)
	kill, del, check := strings.Index(c, "sudo kill $p"), strings.Index(c, "sudo ip netns del labc-rogue"), strings.LastIndex(c, "END {exit f}")
	if kill < 0 || del < 0 || check < 0 || !(kill < del && del < check) {
		t.Fatalf("teardown order wrong: %s", c)
	}
}

func TestRogueLeasesReadsTheRoguesOwnFile(t *testing.T) {
	r := &segRunner{out: map[string]string{"sudo cat /run/labc-rogue.leases": "1700000000 02:42:0a:c8:01:05 10.200.1.241 lab-c7 01:02:42:0a:c8:01:05\n"}}
	ls, err := (&KeaAdapter{Runner: r}).RogueLeases(context.Background())
	if err != nil || len(ls) != 1 || ls[0].Address != "10.200.1.241" {
		t.Fatalf("RogueLeases = %+v, %v", ls, err)
	}
}

// The rogue runs dnsmasq from dnsmasq-base and the squatter probes with
// arping from iputils-arping; a source VM without either reports C6-C9
// BLOCKED (#23).
func TestSourceTemplatesInstallTheHostileTools(t *testing.T) {
	for _, tmpl := range []string{"kea-user-data.tmpl.yaml", "isc-dhcp-user-data.tmpl.yaml", "dnsmasq-user-data.tmpl.yaml", "udhcpd-user-data.tmpl.yaml", "pihole-user-data.tmpl.yaml"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "cloud-init", tmpl))
		if err != nil {
			t.Fatal(err)
		}
		var install []string
		for _, l := range strings.Split(string(raw), "\n") {
			if i := strings.Index(l, "apt-get install -y "); i >= 0 {
				install = append(install, strings.Fields(l[i+len("apt-get install -y "):])...)
			}
		}
		for _, pkg := range []string{"dnsmasq-base", "iputils-arping"} {
			found := false
			for _, f := range install {
				found = found || f == pkg
			}
			if !found {
				t.Errorf("%s: apt-get install lists %v, missing %s", tmpl, install, pkg)
			}
		}
		// udhcpd and pihole must not pull the dnsmasq package: its postinst
		// starts a resolver on the segment (lab #10).
		if strings.HasPrefix(tmpl, "udhcpd") || strings.HasPrefix(tmpl, "pihole") {
			for _, f := range install {
				if f == "dnsmasq" {
					t.Errorf("%s installs the dnsmasq package, not dnsmasq-base", tmpl)
				}
			}
		}
	}
}
