package sourceadapter

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A lease line FTL v6.7.1 wrote to /etc/pihole/dhcp.leases on the Debian 13
// cell (#10); the expiry is an epoch, the fifth field the option 61 value.
const piholeLeaseLine = "1791620503 de:ef:59:a7:47:e6 10.200.13.115 m2host 01:de:ef:59:a7:47:e6\n"

// recordRunner keeps every command, and answers a read of the config with
// cfg so an edit sees the lab file as the template seeds it.
type recordRunner struct {
	cfg   string
	lease string
	calls []string
}

func (r *recordRunner) Run(_ context.Context, cmd string) (string, error) {
	r.calls = append(r.calls, cmd)
	switch {
	case strings.HasPrefix(cmd, "sudo cat "+piholeLeaseFile):
		return r.lease, nil
	case strings.HasPrefix(cmd, "sudo cat "):
		return r.cfg, nil
	}
	return "", nil
}

// FTL regenerates /etc/pihole/dnsmasq.conf from pihole.toml on every start,
// so a command touching either file would be undone or would move the
// stock diff (D6c, D6d).
func assertNeverTouchesFTLOwnedFiles(t *testing.T, label string, calls []string) {
	t.Helper()
	for _, c := range calls {
		for _, owned := range []string{"pihole.toml", "/etc/pihole/dnsmasq.conf", "pihole-FTL --config"} {
			if strings.Contains(c, owned) {
				t.Errorf("%s: %q touches %s, which FTL owns", label, c, owned)
			}
		}
	}
}

func TestPiholeCapabilitiesAreTheDnsmasqSetMinusWhatFTLOwns(t *testing.T) {
	have := map[Capability]bool{}
	for _, c := range (&PiholeAdapter{}).Capabilities() {
		have[c] = true
	}
	for _, c := range []Capability{CapV4, CapReserveMAC, CapRestart, CapReserveClientID, CapDNSRegistration, CapOptionChange, CapImpair, CapOption108, CapRapidCommit4, CapForceRenewNonce, CapSquatter, CapRogueServer} {
		if !have[c] {
			t.Errorf("pihole lacks %s", c)
		}
	}
	// The five the toml owns, and the three that need a cell that does not exist yet.
	for _, c := range []Capability{CapShortLease, CapNarrowPool, CapRenumber, CapVendorClassPool, CapUserClassPool, CapV6, CapFailoverPair, CapRelay} {
		if have[c] {
			t.Errorf("pihole declares %s", c)
		}
	}
}

func TestPiholeReadsItsOwnLeaseFile(t *testing.T) {
	r := &recordRunner{lease: piholeLeaseLine}
	leases, err := (&PiholeAdapter{Runner: r}).Leases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0] != "sudo cat /etc/pihole/dhcp.leases" {
		t.Fatalf("calls %q, want one read of /etc/pihole/dhcp.leases", r.calls)
	}
	if len(leases) != 1 || leases[0].Address != "10.200.13.115" || leases[0].MAC != "de:ef:59:a7:47:e6" || leases[0].ClientID != "01:de:ef:59:a7:47:e6" {
		t.Fatalf("leases %+v", leases)
	}
}

func TestPiholeServiceActionsNameTheFTLUnit(t *testing.T) {
	r := &fakeRunner{}
	a := &PiholeAdapter{Runner: r}
	for verb, fn := range map[string]func(context.Context) error{"restart": a.Restart, "stop": a.Stop, "start": a.Start} {
		r.calls = nil
		if err := fn(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(r.calls) != 1 || r.calls[0] != "sudo systemctl "+verb+" pihole-FTL" {
			t.Errorf("%s: calls %q", verb, r.calls)
		}
	}
}

func TestPiholeResetLeasesStopsTruncatesStartsFTL(t *testing.T) {
	r := &fakeRunner{}
	if err := (&PiholeAdapter{Runner: r}).ResetLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("calls %q", r.calls)
	}
	c := r.calls[0]
	stop, trunc, start := strings.Index(c, "stop pihole-FTL"), strings.Index(c, "truncate -s 0 /etc/pihole/dhcp.leases"), strings.Index(c, "start pihole-FTL")
	if stop < 0 || trunc < stop || start < trunc {
		t.Fatalf("want stop, truncate, start in that order: %q", c)
	}
}

func TestPiholeReservationsGoToTheLabReservationsFile(t *testing.T) {
	r := &recordRunner{}
	a := &PiholeAdapter{Runner: r}
	if err := a.ReserveMAC(context.Background(), "AA:BB:CC:DD:EE:01", "10.200.13.150"); err != nil {
		t.Fatal(err)
	}
	if err := a.ReserveClientID(context.Background(), "00:6C:61:62", "10.200.13.151"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 {
		t.Fatalf("calls %q", r.calls)
	}
	for i, want := range [][]string{
		{"sed -i '/^dhcp-host=aa:bb:cc:dd:ee:01,/d' /etc/dnsmasq.d/lab-reservations.conf", "echo 'dhcp-host=aa:bb:cc:dd:ee:01,10.200.13.150' | sudo tee -a /etc/dnsmasq.d/lab-reservations.conf", "restart pihole-FTL"},
		{"sed -i '/^dhcp-host=id:00:6c:61:62,/d' /etc/dnsmasq.d/lab-reservations.conf", "dhcp-host=id:00:6c:61:62,10.200.13.151", "restart pihole-FTL"},
	} {
		for _, w := range want {
			if !strings.Contains(r.calls[i], w) {
				t.Errorf("call %d %q lacks %q", i, r.calls[i], w)
			}
		}
		if strings.Contains(r.calls[i], piholeLabConf) || strings.Contains(r.calls[i], " dnsmasq") {
			t.Errorf("call %d %q touches the lab config or the Debian unit", i, r.calls[i])
		}
	}
	assertNeverTouchesFTLOwnedFiles(t, "reserve", r.calls)
}

func TestPiholeRejectsInjectionBeforeAnySSH(t *testing.T) {
	r := &fakeRunner{}
	a := &PiholeAdapter{Runner: r}
	for _, bad := range []string{`aa:bb:cc:dd:ee:ff'; rm -rf / #`, "not-a-mac", ""} {
		if err := a.ReserveMAC(context.Background(), bad, "10.200.13.150"); err == nil {
			t.Errorf("ReserveMAC %q accepted", bad)
		}
	}
	for _, bad := range []string{`00:aa'; id #`, "not-hex", ""} {
		if err := a.ReserveClientID(context.Background(), bad, "10.200.13.150"); err == nil {
			t.Errorf("ReserveClientID %q accepted", bad)
		}
	}
	if _, err := a.SetDNSOption(context.Background(), "x; reboot"); err == nil {
		t.Error("SetDNSOption accepted a bad address")
	}
	if len(r.calls) != 0 {
		t.Fatalf("a bad value reached the runner: %q", r.calls)
	}
}

// ShortenLeaseTime, NarrowPool, Renumber and the user-class pool would
// give a verdict on a server whose range they never changed (FTL ignores a
// second dhcp-range); they refuse with the reason and run nothing.
func TestPiholeRefusesWhatFTLOwns(t *testing.T) {
	const reason = "Pi-hole's FTL owns dhcp-range and lease time in pihole.toml; the lab does not edit the toml."
	r := &fakeRunner{}
	a := &PiholeAdapter{Runner: r}
	ctx := context.Background()
	_, e1 := a.ShortenLeaseTime(ctx, 40)
	_, e2 := a.NarrowPool(ctx, "10.200.13.201", "10.200.13.202")
	_, e3 := a.Renumber(ctx, "10.200.113.0/24", "10.200.113.2", "10.200.113.100", "10.200.113.200")
	_, e4 := a.EnableFeature(ctx, FeatureUserClassPool, FeatureParams{Class: "lab-uc-f1", PoolStart: "10.200.13.203", PoolEnd: "10.200.13.210"})
	for i, err := range []error{e1, e2, e3, e4} {
		if err == nil || !strings.Contains(err.Error(), reason) {
			t.Errorf("refusal %d = %v, want the reason %q", i, err, reason)
		}
	}
	if len(r.calls) != 0 {
		t.Fatalf("a refused call ran %q", r.calls)
	}
}

// Every scenario edit reads and writes the lab-owned file only, anchors on
// the header the template seeds, and restore writes the captured bytes
// back (D6c, D12).
func TestPiholeEditsOnlyThe90LabFile(t *testing.T) {
	ctx := context.Background()
	for name, edit := range map[string]func(*PiholeAdapter) (func(context.Context) error, error){
		"dns": func(a *PiholeAdapter) (func(context.Context) error, error) {
			return a.SetDNSOption(ctx, "10.200.13.253")
		},
		"108": func(a *PiholeAdapter) (func(context.Context) error, error) {
			return a.EnableFeature(ctx, FeatureOffer108, FeatureParams{Seconds: 1800})
		},
		"rapid": func(a *PiholeAdapter) (func(context.Context) error, error) {
			return a.EnableFeature(ctx, FeatureRapidCommit4, FeatureParams{})
		},
	} {
		r := baselineRunner(t, "pihole")
		orig := r.cfg
		var seen []string
		a := &PiholeAdapter{Runner: spyRunner{r, &seen}}
		restore, err := edit(a)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.HasPrefix(r.cfg, piholeLabHeader) || r.cfg == orig {
			t.Errorf("%s: config after edit\n%s", name, r.cfg)
		}
		if err := restore(ctx); err != nil {
			t.Fatal(err)
		}
		if r.cfg != orig || r.restarts != 2 {
			t.Errorf("%s: restore left cfg equal=%v restarts=%d", name, r.cfg == orig, r.restarts)
		}
		for _, c := range seen {
			if strings.HasPrefix(c, "sudo cat ") && c != "sudo cat "+piholeLabConf || strings.HasPrefix(c, "sudo tee ") && !strings.HasPrefix(c, "sudo tee "+piholeLabConf+" ") {
				t.Errorf("%s: %q reaches a file other than %s", name, c, piholeLabConf)
			}
		}
		assertNeverTouchesFTLOwnedFiles(t, name, seen)
	}
	r := baselineRunner(t, "pihole")
	a := &PiholeAdapter{Runner: r}
	if _, err := a.SetDNSOption(ctx, "10.200.13.253"); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "pihole dns", r.cfg, "\ndhcp-option=6,10.200.13.253\n")
}

type spyRunner struct {
	Runner
	seen *[]string
}

func (s spyRunner) Run(ctx context.Context, cmd string) (string, error) {
	*s.seen = append(*s.seen, cmd)
	return s.Runner.Run(ctx, cmd)
}

func TestPiholeFeatureSnippets(t *testing.T) {
	mustContain(t, "pihole 108", enabled(t, "pihole", FeatureOffer108, FeatureParams{Seconds: 1800}), "\ndhcp-option=108,00:00:07:08\n")
	mustContain(t, "pihole force", enabled(t, "pihole", FeatureForce108, FeatureParams{Seconds: 1800, ClientID: f1ID}),
		"dhcp-host=id:"+f1ID+",set:f2b\n", "dhcp-option-force=tag:f2b,108,")
	mustContain(t, "pihole rc", enabled(t, "pihole", FeatureRapidCommit4, FeatureParams{}), "\ndhcp-rapid-commit\n")
	mustContain(t, "pihole f8", enabled(t, "pihole", FeatureForceRenewNonce, FeatureParams{ClientID: f1ID, Nonce: katNonce}),
		"dhcp-host=id:"+f1ID+",set:f8\n", "dhcp-match=set:f8sel,option:requested-address\n", "dhcp-option-force=tag:f8,145,01\n", "dhcp-option-force=tag:f8,tag:f8sel,90,")
}

// Ready takes the lab file as its baseline, so a leftover scenario edit in
// 90-lab.conf is refused and Recover puts the baseline back (D6d).
func TestPiholeReadyHoldsTheLabFileToItsBaseline(t *testing.T) {
	ctx := context.Background()
	h := healthyHost()
	h.cfg = baselineConfig(t, "pihole-user-data.tmpl.yaml", "LABEOF")
	orig := h.cfg
	a := &PiholeAdapter{Runner: h}
	if err := a.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	h.cfg += "dhcp-option=6,10.200.13.253\n"
	if err := a.Ready(ctx); err == nil || !strings.Contains(err.Error(), piholeLabConf) {
		t.Fatalf("Ready over a changed lab file = %v, want it to name %s", err, piholeLabConf)
	}
	if err := a.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if h.written != orig {
		t.Fatalf("Recover wrote %q, want %q", h.written, orig)
	}
	var restarted bool
	for _, c := range h.calls {
		if c == "sudo systemctl restart pihole-FTL" {
			restarted = true
		}
		if strings.Contains(c, "systemctl") && strings.Contains(c, " dnsmasq") {
			t.Errorf("%q names the Debian dnsmasq unit", c)
		}
	}
	if !restarted {
		t.Fatal("Recover never restarted pihole-FTL")
	}
	if err := a.Ready(ctx); err != nil {
		t.Fatalf("Ready after Recover: %v", err)
	}
}

func TestPiholeTemplateOrdersTomlInstallerMarker(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cloud-init", "pihole-user-data.tmpl.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := string(raw)
	at := func(s string) int {
		i := strings.Index(tmpl, s)
		if i < 0 {
			t.Fatalf("template lacks %q", s)
		}
		return i
	}
	toml, installer, marker := at("cat >/etc/pihole/pihole.toml <<'TOMLEOF'"), at("bash /root/pihole-install.sh --unattended"), at("touch /var/lib/cloud/lab-bootstrap-done")
	if !(toml < installer && installer < marker) {
		t.Errorf("order toml=%d installer=%d marker=%d, want toml < installer < marker (the installer ignores --unattended without the toml)", toml, installer, marker)
	}
	// Anything that can fail between the installer and the marker must stop the script.
	if !regexp.MustCompile(`(?m)^    set -e$`).MatchString(tmpl) || at("set -e") > toml {
		t.Error("the script does not start with set -e")
	}
	body := tmpl[toml:installer]
	for _, want := range []string{`interface = "eth1"`, `listeningMode = "BIND"`, "active = true", `start = "__POOL_START__"`, `end = "__POOL_END__"`, `router = "__SEG_GATEWAY__"`, `netmask = "__SEG_NETMASK__"`, "etc_dnsmasq_d = true", "touch /etc/dnsmasq.d/lab-reservations.conf"} {
		if !strings.Contains(body, want) {
			t.Errorf("before the installer: %q missing", want)
		}
	}
	if !strings.Contains(tmpl, piholeLabHeader) {
		t.Errorf("template does not seed the %q header the adapter anchors on", piholeLabHeader)
	}
	if strings.Contains(tmpl, "install -y dnsmasq ") || regexp.MustCompile(`install -y[^\n]* dnsmasq( |$)`).MatchString(tmpl) {
		t.Error("the template installs the Debian dnsmasq package, which fights FTL for port 67")
	}
	for _, want := range []string{"dnsmasq-base", "iputils-arping", "python3", "### CHANGED"} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("template lacks %q", want)
		}
	}
}
