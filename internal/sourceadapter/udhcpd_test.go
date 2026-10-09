package sourceadapter

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func udhcpdBaseline(t *testing.T) string {
	return baselineConfig(t, "udhcpd-user-data.tmpl.yaml", udhcpdConf)
}

// dumpleases -a as measured in M1: expired rows stay in the table, a client
// without a hostname leaves the column blank.
const dumpFixture = `Mac Address       IP Address      Host Name           Expires at
02:aa:bb:cc:dd:03 10.200.12.138                       Fri Oct  9 22:20:33 2026
02:aa:bb:cc:dd:02 10.200.12.137   labhost             Fri Oct  9 22:25:01 2026
02:aa:bb:cc:dd:04 10.200.12.139   gone                expired
`

func TestParseUdhcpdLeases(t *testing.T) {
	got, err := parseUdhcpdLeases(dumpFixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want the 2 active rows, got %+v", got)
	}
	if got[0].MAC != "02:aa:bb:cc:dd:03" || got[0].Address != "10.200.12.138" || got[0].Hostname != "" {
		t.Errorf("row without hostname: %+v", got[0])
	}
	if got[1].Hostname != "labhost" || got[1].Address != "10.200.12.137" {
		t.Errorf("row with hostname: %+v", got[1])
	}
	if want := time.Date(2026, 10, 9, 22, 25, 1, 0, time.UTC); !got[1].Expires.Equal(want) {
		t.Errorf("expiry %v, want %v", got[1].Expires, want)
	}
	if got[0].ClientID != "" {
		t.Errorf("udhcpd records no client id, got %q", got[0].ClientID)
	}
}

func TestParseUdhcpdLeasesEmptyTableIsNotAnError(t *testing.T) {
	got, err := parseUdhcpdLeases("Mac Address       IP Address      Host Name           Expires at\n")
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("header-only output: %v, %v", got, err)
	}
}

func TestParseUdhcpdLeasesRefusesWhatItCannotRead(t *testing.T) {
	const head = "Mac Address       IP Address      Host Name           Expires at\n"
	for name, raw := range map[string]string{
		"no header":     "02:aa:bb:cc:dd:03 10.200.12.138 Fri Oct  9 22:20:33 2026\n",
		"empty":         "",
		"short row":     head + "02:aa:bb:cc:dd:03 10.200.12.138\n",
		"bad mac":       head + "zz:aa:bb:cc:dd:03 10.200.12.138      Fri Oct  9 22:20:33 2026\n",
		"bad address":   head + "02:aa:bb:cc:dd:03 not-an-ip         Fri Oct  9 22:20:33 2026\n",
		"bad expiry":    head + "02:aa:bb:cc:dd:03 10.200.12.138      Fri Foo  9 22:20:33 2026\n",
		"truncated row": head + "02:aa:bb:cc:dd:03 10.200.12.138      22:20:33 2026\n",
	} {
		if _, err := parseUdhcpdLeases(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// D2: the lease file is written on USR1, SIGTERM or every auto_time, so a
// read without the signal is stale. The signal must come first, and the
// read must wait for the file to change.
func TestUdhcpdLeasesSignalsBeforeReadingAndWaitsForTheWrite(t *testing.T) {
	r := &fakeRunner{reply: dumpFixture}
	a := &UdhcpdAdapter{Runner: r}
	if _, err := a.Leases(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("want one remote command, got %d", len(r.calls))
	}
	c := r.calls[0]
	usr1 := strings.Index(c, "kill -s USR1 udhcpd")
	dump := strings.Index(c, "busybox dumpleases -a -f "+udhcpdLeaseFile)
	if usr1 < 0 || dump < 0 || usr1 > dump {
		t.Fatalf("USR1 must be sent before dumpleases reads the file:\n%s", c)
	}
	stat := strings.Index(c, "stat -c")
	wait := strings.Index(c, `[ "$m1" != "$m0" ] ||`)
	if stat < 0 || wait < 0 || wait > dump {
		t.Fatalf("the read must wait for the file's mtime to move first:\n%s", c)
	}
	if !strings.Contains(c, "TZ=UTC") {
		t.Fatalf("the expiry column prints no zone; TZ must be pinned:\n%s", c)
	}
}

func TestUdhcpdLeasesPropagatesARunnerError(t *testing.T) {
	a := &UdhcpdAdapter{Runner: &fakeRunner{err: context.DeadlineExceeded}}
	if _, err := a.Leases(context.Background()); err == nil {
		t.Fatal("a failed read returned no error")
	}
}

func TestUdhcpdReserveMACWritesAStaticLeaseAndRestarts(t *testing.T) {
	r := &fakeRunner{}
	a := &UdhcpdAdapter{Runner: r}
	if err := a.ReserveMAC(context.Background(), "AA:BB:CC:DD:EE:FF", "10.200.12.150"); err != nil {
		t.Fatal(err)
	}
	c := strings.Join(r.calls, "\n")
	for _, want := range []string{"static_lease aa:bb:cc:dd:ee:ff 10.200.12.150", "sed -i '/^static_lease[[:space:]]\\+aa:bb:cc:dd:ee:ff[[:space:]]/Id' /etc/udhcpd.conf", "systemctl restart udhcpd"} {
		if !strings.Contains(c, want) {
			t.Errorf("command lacks %q:\n%s", want, c)
		}
	}
}

func TestUdhcpdReserveMACRejectsInjectionBeforeAnySSH(t *testing.T) {
	for _, mac := range []string{`aa:bb:cc:dd:ee:ff'; rm -rf / #`, "not-a-mac", ""} {
		r := &fakeRunner{}
		if err := (&UdhcpdAdapter{Runner: r}).ReserveMAC(context.Background(), mac, "10.200.12.150"); err == nil || len(r.calls) != 0 {
			t.Errorf("ReserveMAC(%q): err=%v calls=%d", mac, err, len(r.calls))
		}
	}
	r := &fakeRunner{}
	if err := (&UdhcpdAdapter{Runner: r}).ReserveMAC(context.Background(), "aa:bb:cc:dd:ee:ff", "10.200.12.150; reboot"); err == nil || len(r.calls) != 0 {
		t.Errorf("a bad address reached the runner: err=%v calls=%d", err, len(r.calls))
	}
}

// D1/X6: what udhcpd cannot do fails loudly, naming why, and reaches no
// remote host.
func TestUdhcpdRefusesWhatItCannotDo(t *testing.T) {
	r := &fakeRunner{}
	a := &UdhcpdAdapter{Runner: r}
	ctx := context.Background()
	if err := a.ReserveClientID(ctx, "01:aa:bb:cc:dd:ee:ff", "10.200.12.150"); err == nil || !strings.Contains(err.Error(), "MAC only") {
		t.Errorf("ReserveClientID: %v", err)
	}
	if _, err := a.EnableFeature(ctx, FeatureRapidCommit4, FeatureParams{}); err == nil {
		t.Error("EnableFeature succeeded")
	}
	if _, err := a.SendForceRenew(ctx, []byte("x\n"), ForceRenewParams{}); err == nil {
		t.Error("SendForceRenew succeeded")
	}
	if len(r.calls) != 0 {
		t.Errorf("a refused call reached the runner: %v", r.calls)
	}
}

// X3: every capability the adapter does not declare among those the lab
// knows has a printed reason, and a declared one has none.
func TestUdhcpdNAReasonCoversEveryUndeclaredCapabilityItKnows(t *testing.T) {
	a := &UdhcpdAdapter{}
	declared := map[Capability]bool{}
	for _, c := range a.Capabilities() {
		declared[c] = true
		if _, ok := a.NAReason(c); ok {
			t.Errorf("declared capability %q carries a N/A reason", c)
		}
	}
	for _, c := range []Capability{CapReserveClientID, CapVendorClassPool, CapUserClassPool, CapOption108, CapDNSRegistration, CapRapidCommit4, CapForceRenewNonce, CapV6} {
		if declared[c] {
			t.Errorf("%q is declared", c)
		}
		if why, ok := a.NAReason(c); !ok || why == "" {
			t.Errorf("no N/A reason for %q", c)
		}
	}
	if why, _ := a.NAReason(CapReserveClientID); !strings.Contains(why, "not a plugin fault") {
		t.Errorf("the client-id reason must put the collision on the server: %q", why)
	}
	_, pair := a.NAReason(CapFailoverPair)
	_, relay := a.NAReason(CapRelay)
	if pair || relay {
		t.Error("failover and relay reasons belong to the shared table")
	}
}

func TestUdhcpdTemplateConfigCarriesWhatTheAdapterEdits(t *testing.T) {
	cfg := udhcpdBaseline(t)
	for _, re := range []interface{ MatchString(string) bool }{udhcpdInterfaceRE, udhcpdOptionLeaseRE, udhcpdMinLeaseRE, udhcpdRouterOptionRE, udhcpdStartRE, udhcpdEndRE, udhcpdLeaseFileLineRE} {
		if !re.MatchString(cfg) {
			t.Errorf("the template config lacks a line the adapter anchors on:\n%s", cfg)
		}
	}
	if !strings.Contains(cfg, "interface eth1\n") {
		t.Errorf("the cell must serve the segment leg, not management:\n%s", cfg)
	}
}

func udhcpdRunner(t *testing.T) *cfgRunner { return &cfgRunner{cfg: udhcpdBaseline(t)} }

// D3: a 40 s lease must be real whether or not the client asks for one,
// so option lease and min_lease both move, and restore is byte for byte.
func TestUdhcpdShortenSetsOptionLeaseAndMinLeaseAndRestores(t *testing.T) {
	r := udhcpdRunner(t)
	orig := r.cfg
	restore, err := (&UdhcpdAdapter{Runner: r}).ShortenLeaseTime(context.Background(), 40)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"option lease 40\n", "min_lease 40\n"} {
		if !strings.Contains(r.cfg, want) {
			t.Errorf("shortened config lacks %q:\n%s", want, r.cfg)
		}
	}
	if strings.Count(r.cfg, "\n") != strings.Count(orig, "\n") || !strings.Contains(r.cfg, "interface eth1\n") {
		t.Errorf("shorten moved more than the two lines:\n%s", r.cfg)
	}
	if err := restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.cfg != orig || r.restarts != 2 {
		t.Errorf("restore left %q after %d restarts", r.cfg, r.restarts)
	}
}

func TestUdhcpdShortenRefusesAConfigMissingEitherLease(t *testing.T) {
	for name, drop := range map[string]string{"min_lease": "min_lease 60\n", "option lease": "option lease 43200\n"} {
		r := udhcpdRunner(t)
		r.cfg = strings.Replace(r.cfg, drop, "", 1)
		if _, err := (&UdhcpdAdapter{Runner: r}).ShortenLeaseTime(context.Background(), 40); err == nil {
			t.Errorf("without %s: accepted", name)
		}
		if len(r.writes) != 0 || r.restarts != 0 {
			t.Errorf("without %s: config was changed", name)
		}
	}
	for _, bad := range []int{0, -5} {
		if _, err := (&UdhcpdAdapter{Runner: udhcpdRunner(t)}).ShortenLeaseTime(context.Background(), bad); err == nil {
			t.Errorf("ShortenLeaseTime(%d) accepted", bad)
		}
	}
}

func TestUdhcpdSetDNSOptionAddsOneLineAfterTheRouterAndRestores(t *testing.T) {
	r := udhcpdRunner(t)
	orig := r.cfg
	restore, err := (&UdhcpdAdapter{Runner: r}).SetDNSOption(context.Background(), "10.200.12.54")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.cfg, "option router 10.200.1.1\noption dns 10.200.12.54\n") {
		t.Fatalf("no dns line after the router:\n%s", r.cfg)
	}
	if _, err := (&UdhcpdAdapter{Runner: r}).SetDNSOption(context.Background(), "10.200.12.55"); err == nil {
		t.Error("a second DNS option was accepted")
	}
	if err := restore(context.Background()); err != nil || r.cfg != orig {
		t.Errorf("restore: %v, %q", err, r.cfg)
	}
}

func TestUdhcpdNarrowPoolChangesOnlyStartAndEnd(t *testing.T) {
	r := udhcpdRunner(t)
	orig := r.cfg
	a := &UdhcpdAdapter{Runner: r}
	restore, err := a.NarrowPool(context.Background(), "10.200.1.201", "10.200.1.202")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.cfg, "start 10.200.1.201\nend 10.200.1.202\n") || strings.Contains(r.cfg, "10.200.1.100") {
		t.Fatalf("pool not narrowed:\n%s", r.cfg)
	}
	if _, err := a.NarrowPool(context.Background(), "10.200.1.201", "10.200.1.202"); err == nil {
		t.Error("a second NarrowPool passed")
	}
	if err := restore(context.Background()); err != nil || r.cfg != orig {
		t.Errorf("restore: %v", err)
	}
	if _, err := a.NarrowPool(context.Background(), "10.200.1.202", "10.200.1.201"); err == nil {
		t.Error("a backwards pool passed")
	}
}

func TestUdhcpdRenumberKeepsTimesAndRestoresInOrder(t *testing.T) {
	r := &segRunner{cfgRunner: cfgRunner{cfg: udhcpdBaseline(t)}, addrs: []string{"10.200.1.2/24"}}
	orig := r.cfg
	r.cfg = strings.Replace(r.cfg, "option lease 43200", "option lease 120", 1) + "static_lease aa:bb:cc:dd:ee:ff 10.200.1.150\n"
	shortened := r.cfg
	restore, err := (&UdhcpdAdapter{Runner: r}).Renumber(context.Background(), "10.200.101.0/24", "10.200.101.2", "10.200.101.100", "10.200.101.200")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.ops, "; "); got != "addr 10.200.101.2/24; write; restart" {
		t.Fatalf("ops %q", got)
	}
	for _, want := range []string{"interface eth1\n", "start 10.200.101.100\nend 10.200.101.200\n", "option subnet 255.255.255.0\n", "option router 10.200.101.2\n", "option lease 120\n", "min_lease 60\n", "lease_file /var/lib/misc/udhcpd.leases\n"} {
		if !strings.Contains(r.cfg, want) {
			t.Errorf("renumbered config lacks %q:\n%s", want, r.cfg)
		}
	}
	for _, gone := range []string{"10.200.1.", "static_lease"} {
		if strings.Contains(r.cfg, gone) {
			t.Errorf("renumbered config still carries %q:\n%s", gone, r.cfg)
		}
	}
	r.ops = nil
	if err := restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.ops, "; "); got != "addr 10.200.1.2/24; write; restart" || r.cfg != shortened {
		t.Errorf("restore ran %q, config equal to the captured one: %v (orig %d bytes)", got, r.cfg == shortened, len(orig))
	}
}

func TestUdhcpdRenumberRefusesAConfigItCannotRender(t *testing.T) {
	r := &segRunner{cfgRunner: cfgRunner{cfg: "start 10.200.1.100\n"}, addrs: []string{"10.200.1.2/24"}}
	if _, err := (&UdhcpdAdapter{Runner: r}).Renumber(context.Background(), "10.200.101.0/24", "10.200.101.2", "10.200.101.100", "10.200.101.200"); err == nil {
		t.Fatal("rendered from a config without interface or lease lines")
	}
	if len(r.ops) != 0 {
		t.Errorf("a refused render changed something: %v", r.ops)
	}
}

func TestUdhcpdServiceControlAndReset(t *testing.T) {
	r := &fakeRunner{}
	a := &UdhcpdAdapter{Runner: r}
	ctx := context.Background()
	for _, op := range []func(context.Context) error{a.Restart, a.Stop, a.Start} {
		if err := op(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.ResetLeases(ctx); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(r.calls, "\n")
	for _, want := range []string{"systemctl restart udhcpd", "systemctl stop udhcpd", "systemctl start udhcpd", "systemctl stop udhcpd && sudo truncate -s 0 " + udhcpdLeaseFile + " && sudo systemctl start udhcpd"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}

// confRunner models the source's /etc/udhcpd.conf: a reservation appends
// its static_lease line, the state read and a plain cat return the file.
type confRunner struct {
	conf string
	cats int
}

func (c *confRunner) Run(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "dumpleases"):
		return dumpFixture, nil
	case strings.Contains(cmd, "echo 'cfg:'"):
		return "netns:\nlinks:\nprocs:0\nnetem:0\naddr:10.200.12.2/24 \naddr6:\ncfg:\n" + c.conf, nil
	case strings.HasPrefix(cmd, "sudo cat "):
		c.cats++
		return c.conf, nil
	case strings.Contains(cmd, "tee -a"):
		start := strings.Index(cmd, "echo '") + len("echo '")
		line := cmd[start : start+strings.Index(cmd[start:], "'")]
		c.conf += line + "\n"
	}
	return "", nil
}

// Lab #10: ReserveMAC appends to the file the Ready baseline holds;
// the next Ready must not read that as drift and restart the source.
func TestUdhcpdReserveMACKeepsTheNextReadyFreeOfDrift(t *testing.T) {
	r := &confRunner{conf: udhcpdBaseline(t)}
	a := &UdhcpdAdapter{Runner: r}
	if err := a.Ready(context.Background()); err != nil {
		t.Fatalf("first Ready: %v", err)
	}
	if err := a.ReserveMAC(context.Background(), "aa:bb:cc:dd:ee:ff", "10.200.12.150"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.conf, "static_lease aa:bb:cc:dd:ee:ff 10.200.12.150") {
		t.Fatalf("the fake never saw the reservation:\n%s", r.conf)
	}
	if err := a.Ready(context.Background()); err != nil {
		t.Fatalf("Ready after a reservation reads it as drift: %v", err)
	}
}

// Before any Ready there is no baseline to refresh: ReserveMAC must leave
// it untaken, so the first Ready still records the file as it stands.
func TestUdhcpdReserveMACBeforeAnyReadyLeavesTheBaselineUntaken(t *testing.T) {
	r := &confRunner{conf: udhcpdBaseline(t)}
	a := &UdhcpdAdapter{Runner: r}
	if err := a.ReserveMAC(context.Background(), "aa:bb:cc:dd:ee:ff", "10.200.12.150"); err != nil {
		t.Fatal(err)
	}
	if a.base.taken || r.cats != 0 {
		t.Fatalf("taken=%v cats=%d: a baseline was touched before the first Ready", a.base.taken, r.cats)
	}
}

// The leases wait must outlast a burst of fresh OFFERs: each blocks
// about 2.1 s in udhcpd's ARP probe (M1), so the bound is derived from
// that, not the 5 s a single lease needs.
func TestUdhcpdLeasesWaitOutlastsABurstOfArpProbedOffers(t *testing.T) {
	r := &fakeRunner{reply: dumpFixture}
	a := &UdhcpdAdapter{Runner: r}
	if _, err := a.Leases(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`seq 1 (\d+)\).*sleep ([0-9.]+)`).FindStringSubmatch(r.calls[0])
	if m == nil {
		t.Fatalf("no bounded wait in %q", r.calls[0])
	}
	n, _ := strconv.Atoi(m[1])
	gap, _ := strconv.ParseFloat(m[2], 64)
	if wait := float64(n) * gap; wait < 3*2.1*2 {
		t.Fatalf("the wait is %.1f s, under twice three ARP-probed OFFERs", wait)
	}
}
