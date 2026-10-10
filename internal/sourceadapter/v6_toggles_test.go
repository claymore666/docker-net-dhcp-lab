package sourceadapter

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

var (
	second6 = netip.MustParsePrefix("fd42:200:0:101::/64")
	pref64  = netip.MustParsePrefix("fd42:200:0:164::/96")
	pdPool  = netip.MustParsePrefix("fd42:200:0:180::/57")
)

func TestValidateRARefusesWhatNoScenarioMeans(t *testing.T) {
	bad := map[string]RAParams{
		"off plus a flag":          {Off: true, Managed: true},
		"M=0 A=0":                  {},
		"the baseline":             BaselineRA,
		"second not ULA":           {Managed: true, Autonomous: true, Second: netip.MustParsePrefix("2001:db8::/64")},
		"second /63":               {Managed: true, Autonomous: true, Second: netip.MustParsePrefix("fd42:200:0:100::/63")},
		"pref64 /64":               {Managed: true, Autonomous: true, Pref64: netip.MustParsePrefix("fd42:200:0:164::/64")},
		"pref64 v4":                {Managed: true, Autonomous: true, Pref64: netip.MustParsePrefix("10.0.0.0/8")},
		"expired without a second": {Managed: true, Autonomous: true, SecondExpired: true},
	}
	for name, p := range bad {
		if _, err := validateRA(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	got, err := validateRA(RAParams{Managed: true, Autonomous: true, Second: netip.MustParsePrefix("FD42:200:0:101::5/64")})
	if err != nil || got.Second.String() != "fd42:200:0:101::/64" {
		t.Fatalf("second not masked to lowercase: %v %v", got.Second, err)
	}
}

func TestRenderRadvdEditsEachFlagAndAppendsBlocks(t *testing.T) {
	for _, tmpl := range []string{baselines["kea"].tmpl, baselines["isc-dhcp"].tmpl} {
		orig := baselineConfig(t, tmpl, radvdConf)
		cases := []struct {
			p        RAParams
			want     []string
			wantNot  []string
			pioCount int
		}{
			{RAParams{Managed: true}, []string{"AdvManagedFlag on;", "AdvAutonomous off;"}, []string{"AdvAutonomous on;"}, 1},
			{RAParams{Autonomous: true}, []string{"AdvManagedFlag off;", "AdvAutonomous on;"}, []string{"AdvManagedFlag on;"}, 1},
			{RAParams{Managed: true, Autonomous: true, Second: second6}, []string{"prefix fd42:200:0:100::/64 {", "  prefix fd42:200:0:101::/64 {\n    AdvOnLink on;\n    AdvAutonomous on;\n    AdvValidLifetime 7200;"}, nil, 2},
			{RAParams{Managed: true, Autonomous: true, Second: second6, SecondExpired: true}, []string{"AdvValidLifetime 0;\n    AdvPreferredLifetime 0;"}, nil, 2},
			{RAParams{Managed: true, Autonomous: true, Pref64: pref64}, []string{"  nat64prefix fd42:200:0:164::/96 {\n    AdvValidLifetime 1800;\n  };\n};\n"}, nil, 1},
		}
		for _, c := range cases {
			p, err := validateRA(c.p)
			if err != nil {
				t.Fatal(err)
			}
			out, err := renderRadvd(orig, p)
			if err != nil {
				t.Fatalf("%+v: %v", c.p, err)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("%+v: %q missing in\n%s", c.p, w, out)
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(out, w) {
					t.Errorf("%+v: %q left in\n%s", c.p, w, out)
				}
			}
			if n := strings.Count(out, "  prefix "); n != c.pioCount {
				t.Errorf("%+v: %d PIOs, want %d", c.p, n, c.pioCount)
			}
			if i, j := strings.Index(out, "prefix fd42:200:0:100::"), strings.Index(out, "prefix fd42:200:0:101::"); j >= 0 && j < i {
				t.Errorf("second PIO written before the main one")
			}
		}
	}
	if _, err := renderRadvd("interface eth1 { AdvSendAdvert on; };\n", RAParams{Managed: true}); err == nil {
		t.Fatal("a drifted radvd.conf was edited")
	}
}

// SetRA on kea and isc writes radvd.conf, adds the second address,
// reloads (never restarts) radvd, and the restore undoes all three.
func TestRadvdSetRAReloadsAndRestoresAddressAndFile(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"kea", "isc-dhcp"} {
		h := healthyHost()
		h.extra[radvdConf] = baselineConfig(t, baselines[name].tmpl, radvdConf)
		orig := h.extra[radvdConf]
		restore, err := featureAdapter(name, h).SetRA(ctx, RAParams{Managed: true, Autonomous: true, Second: second6, Pref64: pref64})
		if err != nil {
			t.Fatal(err)
		}
		if h.addrs6 != "fd42:200:0:100::2/64 fd42:200:0:101::2/64 " || !strings.Contains(h.extra[radvdConf], "nat64prefix") {
			t.Fatalf("%s: addrs6 %q, radvd.conf\n%s", name, h.addrs6, h.extra[radvdConf])
		}
		if err := restore(ctx); err != nil {
			t.Fatal(err)
		}
		if h.addrs6 != "fd42:200:0:100::2/64 " || h.extra[radvdConf] != orig {
			t.Fatalf("%s: restore left addrs6 %q, file back %v", name, h.addrs6, h.extra[radvdConf] == orig)
		}
		reloads := 0
		for _, c := range h.calls {
			if strings.Contains(c, "systemctl restart radvd") || strings.Contains(c, "systemctl stop radvd") {
				t.Errorf("%s: %q: a restart's final RA withdraws the router", name, c)
			}
			if c == "sudo systemctl reload radvd" {
				reloads++
			}
		}
		if reloads != 2 {
			t.Errorf("%s: %d reloads, want 2", name, reloads)
		}
	}
}

func TestDnsmasqSetRARangeModes(t *testing.T) {
	ctx := context.Background()
	orig := baselineConfig(t, baselines["dnsmasq"].tmpl, dnsmasqLabV6Conf)
	cases := []struct {
		p    RAParams
		want string
	}{
		{RAParams{Managed: true}, "enable-ra\ndhcp-range=fd42:200:0:100::100,fd42:200:0:100::1ff,64,2h\nra-param=eth1,10,1800\n"},
		{RAParams{Autonomous: true}, "enable-ra\ndhcp-range=fd42:200:0:100::100,ra-only,64,2h\nra-param=eth1,10,1800\n"},
		{RAParams{Managed: true, Autonomous: true, Second: second6}, "enable-ra\ndhcp-range=fd42:200:0:100::100,fd42:200:0:100::1ff,slaac,64,2h\nra-param=eth1,10,1800\ndhcp-range=fd42:200:0:101::,ra-only,64,2h\n"},
	}
	for _, c := range cases {
		h := healthyHost()
		h.extra[dnsmasqLabV6Conf] = orig
		restore, err := (&DnsmasqAdapter{Runner: h}).SetRA(ctx, c.p)
		if err != nil {
			t.Fatalf("%+v: %v", c.p, err)
		}
		if h.extra[dnsmasqLabV6Conf] != c.want {
			t.Errorf("%+v:\n%s\nwant\n%s", c.p, h.extra[dnsmasqLabV6Conf], c.want)
		}
		if err := restore(ctx); err != nil || h.extra[dnsmasqLabV6Conf] != orig || h.addrs6 != "fd42:200:0:100::2/64 " {
			t.Errorf("%+v: restore %v, file back %v, addrs6 %q", c.p, err, h.extra[dnsmasqLabV6Conf] == orig, h.addrs6)
		}
	}
	for _, p := range []RAParams{
		{Managed: true, Autonomous: true, Pref64: pref64},
		{Managed: true, Autonomous: true, Second: second6, SecondExpired: true},
		{Managed: true, Second: second6},
	} {
		h := healthyHost()
		h.extra[dnsmasqLabV6Conf] = orig
		if _, err := (&DnsmasqAdapter{Runner: h}).SetRA(ctx, p); err == nil || h.extra[dnsmasqLabV6Conf] != orig || h.addrs6 != "fd42:200:0:100::2/64 " {
			t.Errorf("%+v: err %v, file touched %v, addrs6 %q", p, err, h.extra[dnsmasqLabV6Conf] != orig, h.addrs6)
		}
	}
}

// Defeat B (#23): the -6 daemon is stopped by its own pid file, and the
// -4 daemon must still be alive afterwards or the stop fails.
func TestStopV6ServerStopsOnlyTheV6Daemon(t *testing.T) {
	ctx := context.Background()
	r := &fakeRunner{}
	restore, err := (&ISCDHCPAdapter{Runner: r}).StopV6Server(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("calls %q", r.calls)
	}
	stop := r.calls[0]
	for _, w := range []string{"start-stop-daemon --stop --quiet --retry 5 --pidfile /var/run/dhcpd6.pid --exec /usr/sbin/dhcpd", "start-stop-daemon --status --pidfile /var/run/dhcpd.pid"} {
		if !strings.Contains(stop, w) {
			t.Errorf("stop %q lacks %q", stop, w)
		}
	}
	if strings.Contains(stop, "systemctl") || strings.Contains(stop, "pkill") || strings.Contains(stop, "--stop --quiet --retry 5 --pidfile /var/run/dhcpd.pid") {
		t.Errorf("stop %q can reach the v4 daemon", stop)
	}
	if err := restore(ctx); err != nil || r.calls[1] != "sudo systemctl restart isc-dhcp-server" {
		t.Fatalf("restore %v ran %q", err, r.calls)
	}
	failing := &fakeRunner{err: errors.New("v4 gone")}
	if _, err := (&ISCDHCPAdapter{Runner: failing}).StopV6Server(ctx); err == nil || len(failing.calls) != 2 {
		t.Fatalf("a failed stop must restart the unit: err %v calls %q", err, failing.calls)
	}

	r = &fakeRunner{}
	restore, err = (&KeaAdapter{Runner: r}).StopV6Server(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(ctx); err != nil || strings.Join(r.calls, "|") != "sudo systemctl stop kea-dhcp6-server|sudo systemctl start kea-dhcp6-server" {
		t.Fatalf("kea ran %q, %v", r.calls, err)
	}
	r = &fakeRunner{}
	if _, err := (&DnsmasqAdapter{Runner: r}).StopV6Server(ctx); err == nil || len(r.calls) != 0 {
		t.Fatalf("dnsmasq StopV6Server ran %q, err %v", r.calls, err)
	}
}

func TestPDBoundsAreTheFirstAndLastSlash64(t *testing.T) {
	first, last := pdBounds(pdPool)
	if first.String() != "fd42:200:0:180::" || last.String() != "fd42:200:0:1ff::" {
		t.Fatalf("%v %v", first, last)
	}
	for p, ok := range map[string]bool{"fd42:200:0:180::/57": true, "fd42:200:0:180::/63": true, "fd42:200:0:180::/64": false, "2001:db8::/57": false, "fd42::/47": false} {
		_, err := validateFeature(FeaturePD, FeatureParams{PDPool: netip.MustParsePrefix(p)})
		if (err == nil) != ok {
			t.Errorf("%s: err %v, want accepted=%v", p, err, ok)
		}
	}
	if _, err := validateFeature(FeaturePD, FeatureParams{}); err == nil {
		t.Error("FeaturePD without a pool accepted")
	}
}

// A SetRA whose restore is skipped leaves the second address and the
// rewritten config behind: Ready must fail, Recover must put both back
// (defeat A, #23).
func TestSkippedSetRARestoreFailsReadyAndRecoverRepairsIt(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"kea", "isc-dhcp", "dnsmasq"} {
		h := healthyHost()
		h.extra[radvdConf] = baselineConfig(t, baselines["kea"].tmpl, radvdConf)
		h.extra[dnsmasqLabV6Conf] = baselineConfig(t, baselines["dnsmasq"].tmpl, dnsmasqLabV6Conf)
		a := featureAdapter(name, h)
		if err := a.Ready(ctx); err != nil {
			t.Fatalf("%s: first Ready: %v", name, err)
		}
		if _, err := a.SetRA(ctx, RAParams{Managed: true, Autonomous: true, Second: second6}); err != nil {
			t.Fatal(err)
		}
		if err := a.Ready(ctx); err == nil {
			t.Fatalf("%s: Ready passed with the second PIO still advertised", name)
		}
		if err := a.Recover(ctx); err != nil {
			t.Fatalf("%s: Recover: %v", name, err)
		}
		if err := a.Ready(ctx); err != nil {
			t.Fatalf("%s: Ready after Recover: %v (addrs6 %q)", name, err, h.addrs6)
		}
	}
}
