package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Lease lines the CHR printed, verbatim from the M3 transcripts (#9). The
// first four come from rosLeaseCmd on a table with two bound
// reservations (by MAC, by client-id with no mac-address) and two dynamic
// leases, one a week long. The next two are those reservations before a
// client bound them (status=waiting, no active-* fields), the last two
// the dynamic leases bound at the same time.
const (
	rosLeaseStaticMAC = `.id=*1;active-address=10.200.14.150;active-agent-circuit-id=;active-agent-remote-id=;active-mac-address=02:00:00:00:00:51;active-server=lab;address=10.200.14.150;address-lists=;agent-circuit-id=;agent-remote-id=;blocked=false;class-id=udhcp 1.37.0;dhcp-option=;disabled=false;dynamic=false;expires-after=00:29:46;last-seen=14s;mac-address=02:00:00:00:00:51;radius=false;server=lab;status=bound`
	rosLeaseStaticCID = `.id=*2;active-address=10.200.14.152;active-agent-circuit-id=;active-agent-remote-id=;active-client-id=ff:0:0:0:1:0:1:aa;active-mac-address=66:96:D7:BB:7B:66;active-server=lab;address=10.200.14.152;address-lists=;agent-circuit-id=;agent-remote-id=;blocked=false;class-id=udhcp 1.37.0;client-id=ff:00:00:00:01:00:01:aa;dhcp-option=;disabled=false;dynamic=false;expires-after=00:29:46;last-seen=14s;radius=false;server=lab;status=bound`
	rosLeaseWeek      = `.id=*3;active-address=10.200.14.200;active-agent-circuit-id=;active-agent-remote-id=;active-client-id=1:66:96:d7:bb:7b:66;active-mac-address=66:96:D7:BB:7B:66;active-server=lab;address=10.200.14.200;address-lists=;age=00:00:31;agent-circuit-id=;agent-remote-id=;blocked=false;class-id=udhcp 1.37.0;client-id=1:66:96:d7:bb:7b:66;dhcp-option=;disabled=false;dynamic=true;expires-after=1w2d03:04:04;host-name=m3;last-seen=1s;mac-address=66:96:D7:BB:7B:66;radius=false;server=lab;status=bound`
	rosLeaseLongCID   = `.id=*4;active-address=10.200.14.199;active-agent-circuit-id=;active-agent-remote-id=;active-client-id=ff:0:0:0:1:0:1:0:aa;active-mac-address=66:96:D7:BB:7B:66;active-server=lab;address=10.200.14.199;address-lists=;age=00:00:30;agent-circuit-id=;agent-remote-id=;blocked=false;class-id=udhcp 1.37.0;client-id=ff:0:0:0:1:0:1:0:aa;dhcp-option=;disabled=false;dynamic=true;expires-after=00:29:30;last-seen=30s;mac-address=66:96:D7:BB:7B:66;radius=false;server=lab;status=bound`
	rosWaitingMAC     = `.id=*1;active-agent-circuit-id=;active-agent-remote-id=;address=10.200.14.150;address-lists=;agent-circuit-id=;agent-remote-id=;blocked=false;dhcp-option=;disabled=false;dynamic=false;last-seen=never;mac-address=02:00:00:00:00:51;radius=false;server=lab;status=waiting`
	rosWaitingCID     = `.id=*2;active-agent-circuit-id=;active-agent-remote-id=;address=10.200.14.152;address-lists=;agent-circuit-id=;agent-remote-id=;blocked=false;client-id=ff:00:00:00:01:00:01:aa;dhcp-option=;disabled=false;dynamic=false;last-seen=never;radius=false;server=lab;status=waiting`
	rosBoundDynamic   = `.id=*3;active-address=10.200.14.200;active-agent-circuit-id=;active-agent-remote-id=;active-client-id=1:66:96:d7:bb:7b:66;active-mac-address=66:96:D7:BB:7B:66;active-server=lab;address=10.200.14.200;address-lists=;age=00:00:16;agent-circuit-id=;agent-remote-id=;blocked=false;class-id=udhcp 1.37.0;client-id=1:66:96:d7:bb:7b:66;dhcp-option=;disabled=false;dynamic=true;expires-after=00:29:45;host-name=m3-client;last-seen=15s;mac-address=66:96:D7:BB:7B:66;radius=false;server=lab;status=bound`
	rosBoundLongCID   = `.id=*4;active-address=10.200.14.199;active-agent-circuit-id=;active-agent-remote-id=;active-client-id=ff:0:0:0:1:0:1:0:aa;active-mac-address=66:96:D7:BB:7B:66;active-server=lab;address=10.200.14.199;address-lists=;age=00:00:15;agent-circuit-id=;agent-remote-id=;blocked=false;class-id=udhcp 1.37.0;client-id=ff:0:0:0:1:0:1:0:aa;dhcp-option=;disabled=false;dynamic=true;expires-after=00:29:45;last-seen=15s;mac-address=66:96:D7:BB:7B:66;radius=false;server=lab;status=bound`
)

// rosLeaseHostile is made up: a host-name carrying a ';' and a key of its
// own, which parseAsValue must keep inside host-name (#9).
const rosLeaseHostile = ".id=*5;active-address=10.200.14.198;active-mac-address=02:00:00:00:00:52;address=10.200.14.198;dynamic=true;expires-after=10m;host-name=x;active-address=10.200.14.9;mac-address=02:00:00:00:00:52;server=lab;status=bound"

func TestParseRouterOSLeasesOffsetsExpiryFromTheReadTime(t *testing.T) {
	now := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	got, err := parseRouterOSLeases(strings.Join([]string{rosLeaseStaticMAC, rosLeaseStaticCID, rosLeaseWeek, rosLeaseLongCID, rosLeaseHostile}, "\r\n")+"\r\n", now)
	if err != nil {
		t.Fatal(err)
	}
	want := []Lease{
		{MAC: "02:00:00:00:00:51", Address: "10.200.14.150", Expires: now.Add(29*time.Minute + 46*time.Second)},
		{MAC: "66:96:d7:bb:7b:66", Address: "10.200.14.152", ClientID: "ff:00:00:00:01:00:01:aa", Expires: now.Add(29*time.Minute + 46*time.Second)},
		{MAC: "66:96:d7:bb:7b:66", Address: "10.200.14.200", Hostname: "m3", ClientID: "01:66:96:d7:bb:7b:66", Expires: now.Add(9*24*time.Hour + 3*time.Hour + 4*time.Minute + 4*time.Second)},
		{MAC: "66:96:d7:bb:7b:66", Address: "10.200.14.199", ClientID: "ff:00:00:00:01:00:01:00:aa", Expires: now.Add(29*time.Minute + 30*time.Second)},
		{MAC: "02:00:00:00:00:52", Address: "10.200.14.198", Hostname: "x;active-address=10.200.14.9", Expires: now.Add(10 * time.Minute)},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d leases, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("lease %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

func TestParseRouterOSLeasesEmptyAndBroken(t *testing.T) {
	if l, err := parseRouterOSLeases("\r\n", time.Now()); err != nil || len(l) != 0 {
		t.Errorf("empty table: %v %v", l, err)
	}
	for _, bad := range []string{".id=*1;status=bound", ".id=*1;address=10.200.14.5;mac-address=nope"} {
		if _, err := parseRouterOSLeases(bad, time.Now()); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestRosDurationReadsGetAndPrintForms(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"00:29:45":     29*time.Minute + 45*time.Second,
		"1w2d03:04:04": 9*24*time.Hour + 3*time.Hour + 4*time.Minute + 4*time.Second,
		"1w2d3h4m5s":   9*24*time.Hour + 3*time.Hour + 4*time.Minute + 5*time.Second,
		"1w2d3h":       9*24*time.Hour + 3*time.Hour,
		"45s":          45 * time.Second,
		"2d":           48 * time.Hour,
	} {
		if got, ok := rosDuration(in); !ok || got != want {
			t.Errorf("%s: %v %v, want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "never", "1x", "10:00"} {
		if _, ok := rosDuration(bad); ok {
			t.Errorf("%q read as a duration", bad)
		}
	}
}

// rosRunner answers by command prefix; an unmatched command gets "".
type rosRunner struct {
	replies map[string]string
	calls   []string
}

func (r *rosRunner) Run(_ context.Context, cmd string) (string, error) {
	r.calls = append(r.calls, cmd)
	for p, out := range r.replies {
		if strings.HasPrefix(cmd, p) {
			return out, nil
		}
	}
	return "", nil
}

// rosSeededRunner answers like a seeded CHR so that every method runs to
// its last command: the state read, one value per get expression, a ping
// reply, the import's success line and an export (#9).
type rosSeededRunner struct{ calls []string }

var rosGetRE = regexp.MustCompile(`:put \("=" \. \[([^\]]*\]?[^\]]*)\]\)`)

func (r *rosSeededRunner) Run(_ context.Context, cmd string) (string, error) {
	r.calls = append(r.calls, cmd)
	switch {
	case cmd == rosStateCmd:
		return "lab-ready\r\nfalse\r\ntrue\r\n", nil
	case strings.HasPrefix(cmd, `:put ("=" .`):
		out := ""
		for _, m := range rosGetRE.FindAllStringSubmatch(cmd, -1) {
			v := map[string]string{"lease-time": "00:30:00", "ranges": "10.200.14.100-10.200.14.200", "dns-server": "",
				"interface=ether2] address": "10.200.14.2/24", "network get [find] address": "10.200.14.0/24", "gateway": "10.200.14.2"}
			val, ok := "", false
			for k, x := range v {
				if strings.HasSuffix(m[1], k) {
					val, ok = x, true
				}
			}
			if !ok {
				return "", fmt.Errorf("no value for %q", m[1])
			}
			out += "=" + val + "\r\n"
		}
		return out, nil
	case strings.HasPrefix(cmd, ":put [/ping "):
		return "  SEQ HOST\r\n1\r\n", nil
	case strings.HasPrefix(cmd, "/import "):
		return "Script file loaded and executed successfully\r\n", nil
	case cmd == "/export":
		return rosExport, nil
	}
	return "", nil
}

// D15: every Adapter method sends RouterOS script only, never a Linux
// line or a LAN example address; each runs to its end, Ready through
// /export, and every restore func runs too (#9).
func TestRouterOSSendsNoShellCommand(t *testing.T) {
	r := &rosSeededRunner{}
	a := &RouterOSAdapter{Runner: r}
	ctx := context.Background()
	var restores []func(context.Context) error
	keep := func(f func(context.Context) error, err error) error {
		if f != nil {
			restores = append(restores, f)
		}
		return err
	}
	fp := FeatureParams{Class: "c", PoolStart: "10.200.14.231", PoolEnd: "10.200.14.240", ClientID: "01:02:00:00:00:00:01", Seconds: 1800}
	calls := map[string]func() error{
		"Capabilities":     func() error { a.Capabilities(); return nil },
		"Leases":           func() error { _, err := a.Leases(ctx); return err },
		"ReserveMAC":       func() error { return a.ReserveMAC(ctx, "02:00:00:00:00:51", "10.200.14.50") },
		"ReserveClientID":  func() error { return a.ReserveClientID(ctx, "ff:00:00:00:01:00:01:aa", "10.200.14.52") },
		"SetDNSOption":     func() error { return keep(a.SetDNSOption(ctx, "10.200.14.53")) },
		"Restart":          func() error { return a.Restart(ctx) },
		"Stop":             func() error { return a.Stop(ctx) },
		"Start":            func() error { return a.Start(ctx) },
		"Reachable":        func() error { return a.Reachable(ctx, "10.200.14.1") },
		"ShortenLeaseTime": func() error { return keep(a.ShortenLeaseTime(ctx, 120)) },
		"ResetLeases":      func() error { return a.ResetLeases(ctx) },
		"Ready":            func() error { return a.Ready(ctx) },
		"Recover":          func() error { return a.Recover(ctx) },
		"NarrowPool":       func() error { return keep(a.NarrowPool(ctx, "10.200.14.150", "10.200.14.151")) },
		"Renumber": func() error {
			return keep(a.Renumber(ctx, "10.200.114.0/24", "10.200.114.2", "10.200.114.100", "10.200.114.200"))
		},
		"EnableFeature": func() error {
			for _, f := range []Feature{FeatureUserClassPool, FeatureOffer108, FeatureForce108} {
				if err := keep(a.EnableFeature(ctx, f, fp)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	refused := []string{"Leases6", "SetRA", "StopV6Server", "Impair", "Squat", "StartRogue", "RogueLeases", "SendForceRenew"}
	it := reflect.TypeOf((*Adapter)(nil)).Elem()
	for i := 0; i < it.NumMethod(); i++ {
		if n := it.Method(i).Name; calls[n] == nil && !slices.Contains(refused, n) {
			t.Errorf("Adapter.%s is not exercised", n)
		}
	}
	for n, f := range calls {
		if err := f(); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	for i, f := range restores {
		if err := f(ctx); err != nil {
			t.Errorf("restore %d: %v", i, err)
		}
	}
	if len(restores) != 7 {
		t.Errorf("%d restore funcs, want 7", len(restores))
	}
	if !slices.Contains(r.calls, "/export") {
		t.Error("Ready never reached /export")
	}
	for _, c := range append(r.calls, routerosService.isActive, routerosService.stop, routerosService.start, routerosService.restart) {
		for _, linux := range []string{"systemctl", "ip netns", "sudo", "pgrep", "tc ", "kill", "python3", "192.168."} {
			if strings.Contains(c, linux) {
				t.Errorf("%q carries %q", c, linux)
			}
		}
	}
}

// rosLeaseTable is server lab's lease table: a "find where k=v and ..."
// in rosLeaseCmd or a lease remove selects lines by their fields, as the
// CHR does (#9).
type rosLeaseTable struct{ lines []string }

var rosFindWhereRE = regexp.MustCompile(`find where ([^\]]*)\]`)

func (t *rosLeaseTable) selects(cmd, line string) bool {
	f := parseAsValue(line)
	for _, c := range strings.Split(rosFindWhereRE.FindStringSubmatch(cmd)[1], " and ") {
		k, v, _ := strings.Cut(c, "=")
		if v == "yes" {
			v = "true"
		}
		if f[k] != v {
			return false
		}
	}
	return true
}

func (t *rosLeaseTable) Run(_ context.Context, cmd string) (string, error) {
	if !rosFindWhereRE.MatchString(cmd) {
		return "", fmt.Errorf("unexpected %q", cmd)
	}
	var hit, rest []string
	for _, l := range t.lines {
		if t.selects(cmd, l) {
			hit = append(hit, l)
		} else {
			rest = append(rest, l)
		}
	}
	switch {
	case cmd == rosLeaseCmd:
		return strings.Join(hit, "\r\n") + "\r\n", nil
	case strings.HasPrefix(cmd, "/ip dhcp-server lease remove "):
		t.lines = rest
		return "", nil
	}
	return "", fmt.Errorf("unexpected %q", cmd)
}

// A reservation no client holds yet (status=waiting) is not a lease, and
// ResetLeases leaves every reservation in place, bound or not (#9).
func TestRouterOSLeasesReadBoundAndResetKeepsReservations(t *testing.T) {
	ctx := context.Background()
	addrs := func(a *RouterOSAdapter) []string {
		l, err := a.Leases(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, x := range l {
			out = append(out, x.Address)
		}
		return out
	}
	tb := &rosLeaseTable{lines: []string{rosWaitingMAC, rosWaitingCID, rosBoundDynamic, rosBoundLongCID}}
	a := &RouterOSAdapter{Runner: tb}
	if got := addrs(a); !slices.Equal(got, []string{"10.200.14.200", "10.200.14.199"}) {
		t.Errorf("leases at %q, want the two bound ones", got)
	}
	if err := a.ResetLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tb.lines, []string{rosWaitingMAC, rosWaitingCID}) || len(addrs(a)) != 0 {
		t.Errorf("after a reset the table holds %q", tb.lines)
	}
	tb = &rosLeaseTable{lines: []string{rosLeaseStaticMAC, rosLeaseStaticCID, rosLeaseWeek, rosLeaseLongCID}}
	a = &RouterOSAdapter{Runner: tb}
	if err := a.ResetLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if got := addrs(a); !slices.Equal(got, []string{"10.200.14.150", "10.200.14.152"}) {
		t.Errorf("after a reset leases at %q, want the two bound reservations", got)
	}
}

func TestRouterOSServiceNamesServerLab(t *testing.T) {
	r := &rosRunner{}
	a := &RouterOSAdapter{Runner: r}
	ctx := context.Background()
	if err := a.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"/ip dhcp-server disable lab; /ip dhcp-server enable lab", "/ip dhcp-server disable lab"}
	if strings.Join(r.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls %q", r.calls)
	}
}

func TestRouterOSRunTreatsACLIErrorLineAsAFailure(t *testing.T) {
	for _, out := range []string{"bad command name foo (line 1 column 2)\r\n", "expected end of command (line 1 column 9)\n", "failure: already have static lease for this client\n", "no such item\n"} {
		a := &RouterOSAdapter{Runner: &fakeRunner{reply: out}}
		if err := a.ResetLeases(context.Background()); err == nil {
			t.Errorf("%q passed", out)
		}
	}
	a := &RouterOSAdapter{Runner: &fakeRunner{err: errors.New("exit status 1")}}
	if err := a.ResetLeases(context.Background()); err == nil {
		t.Error("a runner error passed")
	}
}

func TestRouterOSReservationsUseTheStoredSpelling(t *testing.T) {
	r := &rosRunner{}
	a := &RouterOSAdapter{Runner: r}
	if err := a.ReserveMAC(context.Background(), "02:00:00:aa:bb:cc", "10.200.14.50"); err != nil {
		t.Fatal(err)
	}
	if err := a.ReserveClientID(context.Background(), "ff:00:00:00:01:00:01:aa", "10.200.14.52"); err != nil {
		t.Fatal(err)
	}
	for i, frag := range []string{`mac-address="02:00:00:AA:BB:CC"`, `client-id="ff:0:0:0:1:0:1:aa"`} {
		if !strings.Contains(r.calls[i], frag) {
			t.Errorf("%q lacks %s", r.calls[i], frag)
		}
	}
	for _, bad := range [][2]string{{"02:00:00:aa:bb:cc]", "10.200.14.5"}, {"02:00:00:aa:bb:cc", "10.200.14.5;/user"}} {
		if err := a.ReserveMAC(context.Background(), bad[0], bad[1]); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if len(r.calls) != 2 {
		t.Errorf("a refused reservation reached the runner: %q", r.calls[2:])
	}
}

func TestRouterOSRestoresWriteBackWhatWasRead(t *testing.T) {
	ctx := context.Background()
	r := &rosRunner{replies: map[string]string{":put (": "=00:30:00\n"}}
	a := &RouterOSAdapter{Runner: r}
	undo, err := a.ShortenLeaseTime(ctx, 45)
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	if got := r.calls[1:]; got[0] != "/ip dhcp-server set lab lease-time=45s" || got[1] != "/ip dhcp-server set lab lease-time=00:30:00" {
		t.Errorf("calls %q", got)
	}
	r = &rosRunner{replies: map[string]string{":put (": "=x\"; /user add\n"}}
	a = &RouterOSAdapter{Runner: r}
	if _, err := a.SetDNSOption(ctx, "10.200.14.53"); err == nil || len(r.calls) != 1 {
		t.Errorf("a value it cannot write back went on: %v %q", err, r.calls)
	}
}

func TestRouterOSRenumberPointsTheGatewayAtItself(t *testing.T) {
	ctx := context.Background()
	r := &rosRunner{replies: map[string]string{":put (": "=10.200.14.2/24\n=10.200.14.100-10.200.14.200\n=10.200.14.0/24\n=10.200.14.2\n"}}
	a := &RouterOSAdapter{Runner: r}
	undo, err := a.Renumber(ctx, "10.200.114.0/24", "10.200.114.2", "10.200.114.100", "10.200.114.200")
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/ip address remove [find interface=ether2]; /ip address add interface=ether2 address=10.200.114.2/24; /ip pool set lab ranges=10.200.114.100-10.200.114.200; /ip dhcp-server network set [find] address=10.200.114.0/24 gateway=10.200.114.2",
		"/ip address remove [find interface=ether2]; /ip address add interface=ether2 address=10.200.14.2/24; /ip pool set lab ranges=10.200.14.100-10.200.14.200; /ip dhcp-server network set [find] address=10.200.14.0/24 gateway=10.200.14.2",
	}
	if got := r.calls[1:]; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("calls\n%s", strings.Join(got, "\n"))
	}
}

// The commands M3 ran on the CHR for each feature, and their undo.
func TestRouterOSFeaturesAsMeasured(t *testing.T) {
	p := FeatureParams{Class: "lab-uc", PoolStart: "10.200.14.231", PoolEnd: "10.200.14.240", ClientID: "ff:00:00:00:01:00:01:aa", Seconds: 1800}
	for f, want := range map[Feature][2]string{
		FeatureUserClassPool: {"/ip pool add name=labf77 ranges=10.200.14.231-10.200.14.240; /ip dhcp-server matcher add server=lab name=labf77 code=77 value=0x066c61622d7563 matching-type=exact address-pool=labf77",
			"/ip dhcp-server matcher remove [find name=labf77]; /ip pool remove [find name=labf77]"},
		FeatureOffer108: {"/ip dhcp-server option add name=labf108 code=108 value=0x00000708; /ip dhcp-server network set [find] dhcp-option=labf108",
			`/ip dhcp-server network set [find] dhcp-option=""; /ip dhcp-server option remove [find name=labf108]`},
		FeatureForce108: {"/ip dhcp-server option add name=labf108f code=108 value=0x00000708 force=yes; /ip dhcp-server option sets add name=labf108f options=labf108f; /ip dhcp-server matcher add server=lab name=labf108f code=61 value=0xff000000010001aa matching-type=exact address-pool=lab option-set=labf108f",
			"/ip dhcp-server matcher remove [find name=labf108f]; /ip dhcp-server option sets remove [find name=labf108f]; /ip dhcp-server option remove [find name=labf108f]"},
	} {
		r := &rosRunner{}
		undo, err := (&RouterOSAdapter{Runner: r}).EnableFeature(context.Background(), f, p)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		_ = undo(context.Background())
		if len(r.calls) != 2 || r.calls[0] != want[0] || r.calls[1] != want[1] {
			t.Errorf("%s: calls %q", f, r.calls)
		}
	}
	for _, f := range []Feature{FeatureRapidCommit4, FeatureForceRenewNonce, FeatureRapidCommit6} {
		r := &rosRunner{}
		if _, err := (&RouterOSAdapter{Runner: r}).EnableFeature(context.Background(), f, FeatureParams{Nonce: []byte{0, 1, 2, 3, 4, 5, 6, 7}}); err == nil || len(r.calls) != 0 {
			t.Errorf("%s: %v %q", f, err, r.calls)
		}
	}
}

// D12: the first lines of /export carry the date and the system id; the
// lease section is where reservations go.
const rosExport = "# 2026-10-10 09:14:29 by RouterOS 7.24.5\r\n# system id = hx/HCG56PsC\r\n#\r\n/ip pool\r\nadd name=lab ranges=10.200.14.100-10.200.14.200\r\n/ip dhcp-server lease\r\nadd address=10.200.14.51 mac-address=52:54:00:AA:BB:CC server=lab\r\n/ip dhcp-server network\r\nadd address=10.200.14.0/24 gateway=10.200.14.2\r\n/system identity\r\nset name=lab-ready\r\n"

func TestNormalizeExportDropsTheHeaderAndTheLeases(t *testing.T) {
	later := strings.Replace(strings.Replace(rosExport, "09:14:29", "11:02:07", 1), "add address=10.200.14.51 mac-address=52:54:00:AA:BB:CC server=lab", "add address=10.200.14.52 client-id=01:02 server=lab", 1)
	if normalizeExport(rosExport) != normalizeExport(later) {
		t.Errorf("date or lease moved the export:\n%s\n%s", normalizeExport(rosExport), normalizeExport(later))
	}
	want := "/ip pool\nadd name=lab ranges=10.200.14.100-10.200.14.200\n/ip dhcp-server network\nadd address=10.200.14.0/24 gateway=10.200.14.2\n/system identity\nset name=lab-ready\n\n"
	if got := normalizeExport(rosExport); got != want {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}
	if normalizeExport(rosExport) == normalizeExport(strings.Replace(rosExport, ".200\r\n/ip dhcp-server lease", ".150\r\n/ip dhcp-server lease", 1)) {
		t.Error("a pool change did not move the export")
	}
}

func readyRunner(state, export string) *rosRunner {
	return &rosRunner{replies: map[string]string{":put [/system identity": state, "/export": export}}
}

func TestRouterOSReadyHoldsIdentityServerAdminAndExport(t *testing.T) {
	ctx := context.Background()
	good := "lab-ready\r\nfalse\r\ntrue\r\n"
	for state, frag := range map[string]string{
		"CHR\r\nfalse\r\ntrue\r\n":        "identity",
		"MikroTik\r\nfalse\r\ntrue\r\n":   "identity",
		"lab-ready\r\ntrue\r\ntrue\r\n":   "not active",
		"lab-ready\r\nfalse\r\nfalse\r\n": "admin",
		"lab-ready\r\nfalse\r\n":          "state read",
	} {
		if err := (&RouterOSAdapter{Runner: readyRunner(state, rosExport)}).Ready(ctx); err == nil || !strings.Contains(err.Error(), frag) {
			t.Errorf("%q: %v, want %q", state, err, frag)
		}
	}
	r := readyRunner(good, rosExport)
	a := &RouterOSAdapter{Runner: r}
	if err := a.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	r.replies["/export"] = strings.Replace(rosExport, "09:14:29", "10:00:00", 1)
	if err := a.Ready(ctx); err != nil {
		t.Errorf("a new date failed Ready: %v", err)
	}
	r.replies["/export"] = rosExport + "/ip pool\r\nadd name=labf77 ranges=10.200.14.231-10.200.14.240\r\n"
	if err := a.Ready(ctx); err == nil {
		t.Error("a leftover scenario pool passed Ready")
	}
}

func TestRouterOSRecoverImportsTheBaselineThenRestarts(t *testing.T) {
	r := &rosRunner{replies: map[string]string{"/import": "Script file loaded and executed successfully\r\n"}}
	if err := (&RouterOSAdapter{Runner: r}).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 || r.calls[0] != "/import file-name=lab-baseline.rsc" || r.calls[1] != routerosService.restart {
		t.Errorf("calls %q", r.calls)
	}
	for _, out := range []string{"Script Error: no such item\r\n", "", "\r\n"} {
		r = &rosRunner{replies: map[string]string{"/import": out}}
		if err := (&RouterOSAdapter{Runner: r}).Recover(context.Background()); err == nil || len(r.calls) != 1 {
			t.Errorf("import answering %q went on: %v %q", out, err, r.calls)
		}
	}
}

func TestRouterOSRefusesActorsAndV6BeforeAnyCommand(t *testing.T) {
	r := &rosRunner{}
	a := &RouterOSAdapter{Runner: r}
	ctx := context.Background()
	var errs []error
	_, err := a.Impair(ctx, time.Second, 1)
	errs = append(errs, err)
	_, err = a.Squat(ctx, "10.200.14.150", true)
	errs = append(errs, err)
	_, err = a.StartRogue(ctx, "10.200.14.3", "10.200.14.10", "10.200.14.20")
	errs = append(errs, err)
	_, err = a.RogueLeases(ctx)
	errs = append(errs, err)
	_, err = a.SendForceRenew(ctx, nil, ForceRenewParams{})
	errs = append(errs, err)
	_, err = a.Leases6(ctx)
	errs = append(errs, err)
	_, err = a.SetRA(ctx, RAParams{})
	errs = append(errs, err)
	_, err = a.StopV6Server(ctx)
	errs = append(errs, err)
	for i, err := range errs {
		if err == nil {
			t.Errorf("call %d was not refused", i)
		}
	}
	if !strings.Contains(errs[5].Error(), "DHCPv4 only") || !strings.Contains(errs[6].Error(), "DHCPv4 only") {
		t.Errorf("v6 refusals do not say why: %v / %v", errs[5], errs[6])
	}
	if len(r.calls) != 0 {
		t.Errorf("a refused call sent %q", r.calls)
	}
}

func TestRouterOSNAReasonCoversEveryUndeclaredCapabilityItKnows(t *testing.T) {
	a := &RouterOSAdapter{}
	declared := map[Capability]bool{}
	for _, c := range a.Capabilities() {
		declared[c] = true
		if _, ok := a.NAReason(c); ok {
			t.Errorf("declared capability %q carries a N/A reason", c)
		}
	}
	for _, c := range []Capability{CapV4, CapReserveMAC, CapReserveClientID, CapRestart, CapShortLease, CapOptionChange, CapVendorClassPool, CapUserClassPool, CapOption108, CapNarrowPool, CapRenumber} {
		if !declared[c] {
			t.Errorf("%q is not declared", c)
		}
	}
	for _, c := range []Capability{CapImpair, CapSquatter, CapRogueServer, CapForceRenewNonce, CapRapidCommit4, CapDNSRegistration, CapV6} {
		if declared[c] {
			t.Errorf("%q is declared", c)
		}
		if why, ok := a.NAReason(c); !ok || why == "" {
			t.Errorf("no N/A reason for %q", c)
		}
	}
}
