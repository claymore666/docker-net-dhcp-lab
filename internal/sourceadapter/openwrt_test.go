package sourceadapter

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The two files a scenario edit may change, as build-openwrt-image.sh
// renders them for the openwrt cell (lab #9).
const (
	owDHCP = "config dnsmasq\n\toption domainneeded '1'\n\nconfig dhcp 'lan'\n\toption interface 'lan'\n\toption start '100'\n\toption limit '101'\n"
	owConf = "# lab header\ndhcp-option=3,10.200.15.2\ndhcp-vendorclass=set:b5,lab-class-b5\ndhcp-range=tag:b5,10.200.15.221,10.200.15.230,12h\n"
)

// owLeaseLine: dnsmasq 2.93 on the OpenWrt image wrote these two lines
// for udhcpc clients, with and without option 61 (lab #9, defeat N4).
const owLeaseLine = "1791666707 02:00:00:00:09:01 10.200.15.129 m4client 01:02:00:00:00:09:01\n" +
	"1791666720 02:00:00:00:09:03 10.200.15.131 m4noid *\n"

type owRunner struct {
	files map[string]string
	addr  string // what eth1 carries
	calls []string

	// netifd's side (lab #127): cfgAddr is network.lan.ipaddr, applied to
	// eth1 by a network reload; start and limit are the uci pool, -1 for
	// "as the dhcp file says".
	cfgAddr, cfgAddr0 string
	start, limit      int
	// faults a test may set
	staleView bool // dnsmasq.init keeps deriving the pool from the old subnet
	revert    bool // netifd puts the old address back a moment after the reload
	noReload  bool // the reload changes nothing
	// forceRange replaces the lan pool "first,last" in dnsmasq.init's output;
	// keepConf drops the write of the lab conf, so its router option stays old.
	forceRange string
	keepConf   bool
	reloaded   bool
}

var (
	owAddListRE = regexp.MustCompile(`'add_list' 'network\.lan\.ipaddr=([^']+)'`)
	owStartRE   = regexp.MustCompile(`'set' 'dhcp\.lan\.start=(\d+)'`)
	owLimitRE   = regexp.MustCompile(`'set' 'dhcp\.lan\.limit=(\d+)'`)
	owOptNumRE  = regexp.MustCompile(`option (start|limit) '(\d+)'`)
)

// generated is dnsmasq.init's output: the lan pool from uci's offsets and
// netifd's view of lan, then the lab conf's vendor-class range.
func (r *owRunner) generated() string {
	view := netip.MustParsePrefix(r.addr)
	if r.staleView {
		view = netip.MustParsePrefix(r.cfgAddr0)
	}
	start, limit := r.start, r.limit
	for _, m := range owOptNumRE.FindAllStringSubmatch(r.files[openwrtDHCPConf], -1) {
		n, _ := strconv.Atoi(m[2])
		if m[1] == "start" && start < 0 {
			start = n
		}
		if m[1] == "limit" && limit < 0 {
			limit = n
		}
	}
	base := view.Masked().Addr().As4()
	first := netip.AddrFrom4([4]byte{base[0], base[1], base[2], base[3] + byte(start)})
	last := netip.AddrFrom4([4]byte{base[0], base[1], base[2], base[3] + byte(start+limit-1)})
	pool := first.String() + "," + last.String()
	if r.forceRange != "" {
		pool = r.forceRange
	}
	return fmt.Sprintf("conf-file=/etc/dnsmasq.conf\ndhcp-authoritative\ndhcp-range=set:lan,%s,255.255.255.0,12h\n%s", pool,
		owRangeRE.FindString(r.files[openwrtLabConf]))
}

var owRangeRE = regexp.MustCompile(`(?m)^dhcp-range=tag:b5.*\n`)

var owAddrAddRE = regexp.MustCompile(`ip addr add (\S+) brd \+ dev eth1`)
var owWriteRE = regexp.MustCompile(`(?s)^sudo tee (\S+) >/dev/null <<'LABEOF'\n(.*)LABEOF\n$`)

func newOwRunner() *owRunner {
	return &owRunner{files: map[string]string{openwrtDHCPConf: owDHCP, openwrtLabConf: owConf, openwrtLeaseFile: owLeaseLine, openwrtNetConf: "config interface 'lan'\n"},
		addr: "10.200.15.2/24", cfgAddr: "10.200.15.2/24", cfgAddr0: "10.200.15.2/24", start: -1, limit: -1}
}

func (r *owRunner) Run(_ context.Context, cmd string) (string, error) {
	r.calls = append(r.calls, cmd)
	if p, ok := strings.CutPrefix(cmd, "sudo cat "); ok {
		if p == openwrtGenConf {
			return r.generated(), nil
		}
		return r.files[p], nil
	}
	if m := owWriteRE.FindStringSubmatch(cmd); m != nil {
		if m[1] == openwrtLabConf && r.keepConf && strings.Contains(m[2], "dhcp-option=3,10.200.115.2") {
			return "", nil
		}
		r.files[m[1]] = m[2]
		switch m[1] {
		case openwrtNetConf:
			r.cfgAddr = r.cfgAddr0
		case openwrtDHCPConf:
			r.start, r.limit = -1, -1
		}
		return "", nil
	}
	if strings.HasPrefix(cmd, openwrtUCI) {
		if m := owAddListRE.FindStringSubmatch(cmd); m != nil {
			r.cfgAddr = m[1]
		}
		if m := owStartRE.FindStringSubmatch(cmd); m != nil {
			r.start, _ = strconv.Atoi(m[1])
		}
		if m := owLimitRE.FindStringSubmatch(cmd); m != nil {
			r.limit, _ = strconv.Atoi(m[1])
		}
	}
	switch {
	case cmd == "sudo /etc/init.d/network reload":
		if !r.noReload {
			r.addr = r.cfgAddr
		}
		r.reloaded = true
		return "", nil
	case cmd == "sleep 2" && r.revert && r.reloaded:
		r.addr = r.cfgAddr0
		return "", nil
	}
	if strings.HasPrefix(cmd, "printf 'addr:'") {
		st := "addr:" + r.addr + " \naddr6:\n"
		for _, p := range []string{openwrtNetConf, openwrtLabConf} {
			st += "cfg6:" + p + ":" + base64.StdEncoding.EncodeToString([]byte(r.files[p])) + "\n"
		}
		return st + "cfg:\n" + r.files[openwrtDHCPConf], nil
	}
	if m := owAddrAddRE.FindStringSubmatch(cmd); m != nil {
		r.addr = m[1]
	}
	switch {
	case strings.HasPrefix(cmd, "ip -4 -o addr show dev eth1 "):
		return r.addr + "\n", nil
	case strings.HasPrefix(cmd, openwrtUCI+" 'get' 'dhcp.lan.leasetime'"):
		return "12h\n", nil
	}
	return "", nil
}

func TestOpenwrtCapabilitiesAreTheDnsmasqCellSet(t *testing.T) {
	want := []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease, CapReserveClientID, CapDNSRegistration, CapVendorClassPool, CapOptionChange, CapUserClassPool, CapOption108, CapRapidCommit4, CapNarrowPool, CapRenumber}
	got := (&OpenwrtAdapter{}).Capabilities()
	key := func(cs []Capability) string {
		s := make([]string, len(cs))
		for i, c := range cs {
			s[i] = string(c)
		}
		sort.Strings(s)
		return strings.Join(s, ",")
	}
	if key(got) != key(want) {
		t.Errorf("caps = %s, want %s", key(got), key(want))
	}
}

// D17: the four group C capabilities name the missing image tools, and
// the v6 calls name the v4-only service (lab #9).
func TestOpenwrtNAReasonsAndV6Refusals(t *testing.T) {
	a := &OpenwrtAdapter{Runner: newOwRunner()}
	for _, c := range []Capability{CapImpair, CapSquatter, CapRogueServer, CapForceRenewNonce} {
		why, ok := a.NAReason(c)
		if !ok || !strings.Contains(why, "tc-full, kmod-netem, kmod-macvlan and python3") || !strings.Contains(why, "OpenWrt runs dnsmasq 2.93") {
			t.Errorf("NAReason(%s) = %q, %v", c, why, ok)
		}
	}
	if _, ok := a.NAReason(CapV4); ok {
		t.Error("NAReason(V4) set for a capability the cell has")
	}
	ctx := context.Background()
	if _, err := a.Leases6(ctx); err == nil || !strings.Contains(err.Error(), "DHCPv4 only") {
		t.Errorf("Leases6 = %v", err)
	}
	if _, err := a.SetRA(ctx, RAParams{}); err == nil || !strings.Contains(err.Error(), "DHCPv4 only") {
		t.Errorf("SetRA = %v", err)
	}
}

// owExercise drives every method that sends commands and returns them,
// restores included: Ready takes the baseline first, so Recover puts the
// moved files and eth1 address back (lab #9, defeat D14).
func owExercise(t *testing.T) []string {
	t.Helper()
	r := newOwRunner()
	a := &OpenwrtAdapter{Runner: r}
	ctx := context.Background()
	if err := a.Ready(ctx); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	base := map[string]string{}
	for p, c := range r.files {
		base[p] = c
	}
	undo := func(f func(context.Context) error, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("edit: %v", err)
		}
		if err := f(ctx); err != nil {
			t.Fatalf("restore: %v", err)
		}
	}
	undo(a.ShortenLeaseTime(ctx, 60))
	undo(a.SetDNSOption(ctx, "10.200.15.53"))
	undo(a.EnableFeature(ctx, FeatureUserClassPool, FeatureParams{Class: "labclass", PoolStart: "10.200.15.211", PoolEnd: "10.200.15.220"}))
	undo(a.EnableFeature(ctx, FeatureOffer108, FeatureParams{Seconds: 1800}))
	undo(a.EnableFeature(ctx, FeatureForce108, FeatureParams{ClientID: "01:02:03", Seconds: 1800}))
	undo(a.EnableFeature(ctx, FeatureRapidCommit4, FeatureParams{}))
	undo(a.NarrowPool(ctx, "10.200.15.120", "10.200.15.129"))
	undo(a.Renumber(ctx, "10.200.115.0/24", "10.200.115.2", "10.200.115.100", "10.200.115.200"))
	for _, err := range []error{
		a.ReserveMAC(ctx, "02:00:00:00:09:02", "10.200.15.180"),
		a.ReserveClientID(ctx, "01:02:00:00:00:09:03", "10.200.15.181"),
		a.Restart(ctx), a.Stop(ctx), a.Start(ctx), a.ResetLeases(ctx),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Leases(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Reachable(ctx, "10.200.15.129"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{openwrtDHCPConf, openwrtNetConf, openwrtLabConf} {
		r.files[p] += "# moved\n"
	}
	r.addr = "10.200.115.2/24"
	if err := a.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	for _, p := range []string{openwrtDHCPConf, openwrtNetConf, openwrtLabConf} {
		if r.files[p] != base[p] {
			t.Errorf("recover left %s as %q, baseline %q", p, r.files[p], base[p])
		}
	}
	if r.addr != "10.200.15.2/24" {
		t.Errorf("recover left eth1 at %s", r.addr)
	}
	if err := a.Ready(ctx); err != nil {
		t.Errorf("ready after recover: %v", err)
	}
	return r.calls
}

var owPathRE = regexp.MustCompile(`/(?:etc|tmp|var|run|usr)/[^\s'"|;&>:]*`)

// D14: every file named is one of the cell's; a write (tee, sed -i,
// truncate) lands only in openwrtLabConf or the lease file, or puts
// captured bytes back: the uci dhcp file after an edit, and the network
// file, which Recover restores from Ready's baseline (lab #9).
func TestOpenwrtEditsWriteOnlyUCIAndDnsmasqConf(t *testing.T) {
	allowed := map[string]bool{openwrtDHCPConf: true, openwrtNetConf: true, openwrtLabConf: true, openwrtLeaseFile: true,
		"/etc/init.d/dnsmasq": true, "/etc/init.d/network": true, "/sbin/uci": true, openwrtGenConf: true}
	writeRE := regexp.MustCompile(`(?:tee(?: -a)?|sed -i '[^']*'|truncate -s 0) (/\S+)`)
	for _, c := range owExercise(t) {
		for _, p := range owPathRE.FindAllString(c, -1) {
			if !allowed[p] {
				t.Errorf("%q names %s, outside the cell's files", c, p)
			}
		}
		for _, m := range writeRE.FindAllStringSubmatch(c, -1) {
			switch m[1] {
			case openwrtLabConf, openwrtLeaseFile:
			case openwrtDHCPConf, openwrtNetConf:
				if !strings.Contains(c, "<<'LABEOF'\n") {
					t.Errorf("%q writes %s other than as a captured restore", c, m[1])
				}
			default:
				t.Errorf("%q writes %s", c, m[1])
			}
		}
	}
}

// The exercise reaches Recover's restore of every file and Reachable
// (lab #9 D14): a rule over commands never sent proves nothing.
func TestOpenwrtExerciseReachesTheRestoreAndReachable(t *testing.T) {
	want := map[string]bool{"sudo tee " + openwrtNetConf: false, "sudo tee " + openwrtDHCPConf: false,
		"sudo tee " + openwrtLabConf: false, "sudo ping -c1 -W2 10.200.15.129": false}
	for _, c := range owExercise(t) {
		for w := range want {
			if strings.HasPrefix(c, w) {
				want[w] = true
			}
		}
	}
	for w, seen := range want {
		if !seen {
			t.Errorf("the exercise never sends %q", w)
		}
	}
}

// ReserveClientID replaces an earlier reservation of the same client-id;
// the command runs against a copy of the lab conf (lab #9).
func TestOpenwrtReserveClientIDReplacesTheOldLine(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "dnsmasq.conf")
	if err := os.WriteFile(conf, []byte(owConf), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &owShRunner{t: t, conf: conf, restart: openwrtService("dnsmasq").restart}
	a := &OpenwrtAdapter{Runner: r}
	ctx := context.Background()
	for _, ip := range []string{"10.200.15.181", "10.200.15.182"} {
		if err := a.ReserveClientID(ctx, "01:02:00:00:00:09:03", ip); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if want := owConf + "dhcp-host=id:01:02:00:00:00:09:03,10.200.15.182\n"; string(got) != want {
		t.Errorf("conf = %q, want %q", got, want)
	}
}

// owShRunner runs a command in sh with the lab conf moved to a temp
// file, sudo dropped and the restart a no-op.
type owShRunner struct {
	t       *testing.T
	conf    string
	restart string
}

func (r *owShRunner) Run(_ context.Context, cmd string) (string, error) {
	cmd = strings.ReplaceAll(cmd, r.restart, "true")
	cmd = strings.ReplaceAll(strings.ReplaceAll(cmd, "sudo ", ""), openwrtLabConf, r.conf)
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		r.t.Errorf("%q: %v", cmd, err)
	}
	return string(out), err
}

// D15: no systemd, no netns, no pgrep; the group C actors refuse before
// a command is sent (lab #9).
func TestOpenwrtSendsNoSystemctlOrNetns(t *testing.T) {
	for _, c := range owExercise(t) {
		for _, bad := range []string{"systemctl", "netns", "pgrep", "nsenter", "python3", " tc "} {
			if strings.Contains(c, bad) {
				t.Errorf("%q carries %q", c, bad)
			}
		}
	}
	r := newOwRunner()
	a := &OpenwrtAdapter{Runner: r}
	ctx := context.Background()
	if _, err := a.Impair(ctx, time.Second, 10); err == nil {
		t.Error("Impair ran")
	}
	if _, err := a.Squat(ctx, "10.200.15.170", true); err == nil || !strings.Contains(err.Error(), "the openwrt source has no") {
		t.Errorf("Squat = %v", err)
	}
	if _, err := a.StartRogue(ctx, "10.200.15.9", "10.200.15.210", "10.200.15.212"); err == nil {
		t.Error("StartRogue ran")
	}
	if _, err := a.RogueLeases(ctx); err == nil {
		t.Error("RogueLeases ran")
	}
	if _, err := a.SendForceRenew(ctx, nil, ForceRenewParams{}); err == nil {
		t.Error("SendForceRenew ran")
	}
	if len(r.calls) != 0 {
		t.Errorf("refused actors sent %q", r.calls)
	}
}

func TestOpenwrtServiceIsTheInitScript(t *testing.T) {
	s := openwrtService("dnsmasq")
	if s.isActive != "sudo /etc/init.d/dnsmasq running" || s.restart != "sudo /etc/init.d/dnsmasq restart" || s.stop != "sudo /etc/init.d/dnsmasq stop" || s.start != "sudo /etc/init.d/dnsmasq start" {
		t.Errorf("dnsmasq service = %+v", s)
	}
	if n := openwrtService("network"); n.restart != "sudo /etc/init.d/network reload" {
		t.Errorf("network restart = %q, want a reload that keeps the management link", n.restart)
	}
	st := (&OpenwrtAdapter{}).host().stateCmd((&OpenwrtAdapter{}).units())
	for _, p := range []string{openwrtDHCPConf, openwrtNetConf, openwrtLabConf} {
		if !strings.Contains(st, p) {
			t.Errorf("Ready does not read %s", p)
		}
	}
}

func TestOpenwrtEditsGoThroughUCIWhereAKeyExists(t *testing.T) {
	r := newOwRunner()
	a := &OpenwrtAdapter{Runner: r}
	ctx := context.Background()
	if _, err := a.ShortenLeaseTime(ctx, 60); err != nil {
		t.Fatal(err)
	}
	if _, err := a.EnableFeature(ctx, FeatureRapidCommit4, FeatureParams{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.NarrowPool(ctx, "10.200.15.120", "10.200.15.129"); err != nil {
		t.Fatal(err)
	}
	if err := a.ReserveMAC(ctx, "02:00:00:00:09:02", "10.200.15.180"); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(r.calls, "\n")
	for _, want := range []string{"'set' 'dhcp.lan.leasetime=60'", "'set' 'dhcp.@dnsmasq[0].rapidcommit=1'",
		"'set' 'dhcp.lan.start=120' && " + openwrtUCI + " 'set' 'dhcp.lan.limit=10'",
		"'set' 'dhcp.labres_020000000902=host'", "'set' 'dhcp.labres_020000000902.ip=10.200.15.180'", "'commit' 'dhcp'"} {
		if !strings.Contains(all, want) {
			t.Errorf("no uci %s in %q", want, all)
		}
	}
	if strings.Contains(all, "tee "+openwrtLabConf) {
		t.Error("a uci-keyed edit wrote dnsmasq.conf")
	}
}

func TestOpenwrtEditRefusesASecondApplication(t *testing.T) {
	r := newOwRunner()
	r.files[openwrtLabConf] = owConf + "dhcp-option=6,10.200.15.53\n"
	if _, err := (&OpenwrtAdapter{Runner: r}).SetDNSOption(context.Background(), "10.200.15.54"); err == nil || !strings.Contains(err.Error(), "already carries") {
		t.Errorf("second DNS option = %v", err)
	}
}

// N6: a reservation moves Ready's copy of its file only when the file
// held exactly that copy before (lab #9).
func TestOpenwrtReservationMovesTheBaselineOnlyFromTheBaseline(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, base, want string
	}{{"clean", owConf, "after"}, {"dirty", "other", "other"}} {
		r := &owSeqRunner{outs: []string{owConf, "", "after"}}
		a := &OpenwrtAdapter{Runner: r}
		a.base.taken, a.base.extra = true, map[string]string{openwrtLabConf: tc.base}
		if err := a.ReserveClientID(ctx, "01:02:03", "10.200.15.181"); err != nil {
			t.Fatal(err)
		}
		if got := a.base.extra[openwrtLabConf]; got != tc.want {
			t.Errorf("%s: baseline = %q, want %q", tc.name, got, tc.want)
		}
	}
}

type owSeqRunner struct{ outs []string }

func (r *owSeqRunner) Run(context.Context, string) (string, error) {
	out := r.outs[0]
	r.outs = r.outs[1:]
	return out, nil
}

func TestOpenwrtLeaseLineParses(t *testing.T) {
	ls, err := (&OpenwrtAdapter{Runner: newOwRunner()}).Leases(context.Background())
	if err != nil || len(ls) != 2 || ls[0].Address != "10.200.15.129" || ls[0].ClientID != "01:02:00:00:00:09:01" ||
		ls[1].MAC != "02:00:00:00:09:03" || ls[1].Address != "10.200.15.131" || ls[1].ClientID != "" {
		t.Errorf("leases = %+v, %v", ls, err)
	}
}

// OpenWrt's busybox ping needs root (run 2, lab #98); every other source
// keeps the unprivileged command byte for byte.
func TestReachableSudoOnlyOnOpenwrt(t *testing.T) {
	cases := []struct {
		name string
		a    func(Runner) Adapter
		addr string
		want string
	}{
		{"openwrt", func(r Runner) Adapter { return &OpenwrtAdapter{Runner: r} }, "10.200.15.129", "sudo ping -c1 -W2 10.200.15.129"},
		{"kea", func(r Runner) Adapter { return &KeaAdapter{Runner: r} }, "10.200.1.150", "ping -c1 -W2 10.200.1.150"},
		{"isc-dhcp", func(r Runner) Adapter { return &ISCDHCPAdapter{Runner: r} }, "10.200.1.150", "ping -c1 -W2 10.200.1.150"},
		{"dnsmasq", func(r Runner) Adapter { return &DnsmasqAdapter{Runner: r} }, "10.200.1.150", "ping -c1 -W2 10.200.1.150"},
		{"pihole", func(r Runner) Adapter { return &PiholeAdapter{Runner: r} }, "10.200.1.150", "ping -c1 -W2 10.200.1.150"},
		{"udhcpd", func(r Runner) Adapter { return &UdhcpdAdapter{Runner: r} }, "10.200.1.150", "ping -c1 -W2 10.200.1.150"},
	}
	for _, tc := range cases {
		r := &fakeRunner{}
		if err := tc.a(r).Reachable(context.Background(), tc.addr); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(r.calls) != 1 || r.calls[0] != tc.want {
			t.Errorf("%s: sent %q, want exactly %q", tc.name, r.calls, tc.want)
		}
	}
}

// The prefix reaches both address families and never the validation:
// a bad address stops before any command, on OpenWrt too (lab #98).
func TestReachableAsPrefixesBothFamiliesAndKeepsTheGuard(t *testing.T) {
	r := &fakeRunner{}
	if err := reachableAs(context.Background(), r, "fd42:200:0:300::1f1", "sudo "); err != nil {
		t.Fatal(err)
	}
	if r.calls[0] != "sudo ping -6 -c1 -W2 fd42:200:0:300::1f1" {
		t.Errorf("v6 command %q", r.calls[0])
	}
	r = &fakeRunner{}
	for _, bad := range []string{"10.200.15.129; reboot", "not-an-ip", ""} {
		if err := (&OpenwrtAdapter{Runner: r}).Reachable(context.Background(), bad); err == nil {
			t.Errorf("Reachable(%q) accepted", bad)
		}
	}
	if len(r.calls) != 0 {
		t.Errorf("a bad address reached the runner: %q", r.calls)
	}
}

// ---- Renumber (lab #127) ---------------------------------------------

func owRenumber(t *testing.T, r *owRunner) (func(context.Context) error, error) {
	t.Helper()
	return (&OpenwrtAdapter{Runner: r}).Renumber(context.Background(), "10.200.115.0/24", "10.200.115.2", "10.200.115.100", "10.200.115.200")
}

func owIndex(calls []string, sub string) int {
	for i, c := range calls {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

// owUntouched: the failed or restored source is the one the test started from.
func owUntouched(t *testing.T, r *owRunner, files map[string]string) {
	t.Helper()
	for p, want := range files {
		if r.files[p] != want {
			t.Errorf("%s = %q, want the original %q", p, r.files[p], want)
		}
	}
	if r.addr != "10.200.15.2/24" {
		t.Errorf("eth1 carries %s, want the original 10.200.15.2/24", r.addr)
	}
}

func owCopy(r *owRunner) map[string]string {
	c := map[string]string{}
	for p, s := range r.files {
		c[p] = s
	}
	return c
}

func TestOpenwrtRenumberGoesThroughUCIAndNetifd(t *testing.T) {
	r := newOwRunner()
	orig := owCopy(r)
	restore, err := owRenumber(t, r)
	if err != nil {
		t.Fatal(err)
	}
	if r.addr != "10.200.115.2/24" {
		t.Fatalf("eth1 carries %s after the renumber", r.addr)
	}
	uci := owIndex(r.calls, "'add_list' 'network.lan.ipaddr=10.200.115.2/24'")
	reload := owIndex(r.calls, "/etc/init.d/network reload")
	restart := owIndex(r.calls, "/etc/init.d/dnsmasq restart")
	if uci < 0 || reload < uci || restart < reload {
		t.Fatalf("uci %d, network reload %d, dnsmasq restart %d: want that order\n%q", uci, reload, restart, r.calls)
	}
	for _, want := range []string{"'delete' 'network.lan.ipaddr'", "'set' 'dhcp.lan.start=100'", "'set' 'dhcp.lan.limit=101'", "'commit' 'network'", "'commit' 'dhcp'"} {
		if !strings.Contains(r.calls[uci], want) {
			t.Errorf("the uci command lacks %s: %s", want, r.calls[uci])
		}
	}
	for _, c := range r.calls {
		if strings.Contains(c, "network.mgmt") || strings.Contains(c, "ip -4 addr flush") || strings.Contains(c, "ip addr add") {
			t.Errorf("Renumber ran %q: only network.lan goes through uci, never a hand-made move", c)
		}
	}
	lab := r.files[openwrtLabConf]
	for _, keep := range []string{"# lab header\n", "dhcp-vendorclass=set:b5,lab-class-b5\n", "dhcp-range=tag:b5,10.200.15.221,10.200.15.230,12h\n", "dhcp-option=3,10.200.115.2\n"} {
		if !strings.Contains(lab, keep) {
			t.Errorf("the lab conf lost %q: %q", keep, lab)
		}
	}
	if strings.Contains(lab, "dhcp-option=3,10.200.15.2") {
		t.Errorf("the lab conf still names the old router: %q", lab)
	}
	if err := restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	owUntouched(t, r, orig)
	if i := owIndex(r.calls[uci+1:], "/etc/init.d/network reload"); i < 0 {
		t.Error("restore did not reload the network")
	}
}

// Each of these ends with the source put back and an error that names
// what the source showed, never a renumber the scenario then judges.
func TestOpenwrtRenumberChecksTheSourceAndPutsItBack(t *testing.T) {
	cases := []struct {
		name  string
		fault func(r *owRunner)
		want  string
	}{
		{"dnsmasq.init keeps deriving the old pool", func(r *owRunner) { r.staleView = true }, "dnsmasq still serves 10.200.15.100"},
		{"netifd puts the old address back", func(r *owRunner) { r.revert = true }, "eth1 carries [10.200.15.2/24], want only 10.200.115.2/24"},
		{"the reload changes nothing", func(r *owRunner) { r.noReload = true }, "20 s after the network reload"},
		{"the pool ends outside the new subnet", func(r *owRunner) { r.forceRange = "10.200.115.100,10.200.116.50" }, "outside 10.200.115.0/24"},
		{"the pool starts elsewhere in the new subnet", func(r *owRunner) { r.forceRange = "10.200.115.150,10.200.115.200" }, "no pool starting at 10.200.115.100"},
		{"the router option keeps the old address", func(r *owRunner) { r.keepConf = true }, "router option is"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newOwRunner()
			orig := owCopy(r)
			c.fault(r)
			restore, err := owRenumber(t, r)
			if err == nil || restore != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Renumber = (%v, %v), want an error containing %q", restore != nil, err, c.want)
			}
			if r.addr != "10.200.15.2/24" {
				t.Errorf("eth1 carries %s, want the original 10.200.15.2/24", r.addr)
			}
			if r.files[openwrtLabConf] != orig[openwrtLabConf] || r.files[openwrtNetConf] != orig[openwrtNetConf] || r.files[openwrtDHCPConf] != orig[openwrtDHCPConf] {
				t.Errorf("the files were not put back: %v", r.files)
			}
		})
	}
}

func TestOpenwrtRenumberRefusesBeforeChangingAnything(t *testing.T) {
	for name, edit := range map[string]func(r *owRunner){
		"no router option":               func(r *owRunner) { r.files[openwrtLabConf] = "# lab header\n" },
		"two router options":             func(r *owRunner) { r.files[openwrtLabConf] += "dhcp-option=3,10.200.15.9\n" },
		"a file without a final newline": func(r *owRunner) { r.files[openwrtNetConf] = "config interface 'lan'" },
	} {
		r := newOwRunner()
		edit(r)
		if restore, err := owRenumber(t, r); err == nil || restore != nil {
			t.Errorf("%s: Renumber = (%v, %v), want a refusal", name, restore != nil, err)
		}
		for _, c := range r.calls {
			if strings.Contains(c, "/sbin/uci") || strings.HasPrefix(c, "sudo tee ") || strings.Contains(c, "init.d") {
				t.Errorf("%s: changed the source before refusing: %q", name, c)
			}
		}
	}
}
