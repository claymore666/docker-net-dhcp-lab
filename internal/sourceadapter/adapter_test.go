package sourceadapter

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRunner records every command it was asked to run and replays a
// canned reply, so every adapter test below runs with no network and no
// real source VM at all.
type fakeRunner struct {
	reply string
	err   error
	calls []string
}

func (f *fakeRunner) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	return f.reply, f.err
}

// A MAC or address carrying shell/JSON metacharacters must never reach
// the runner at all: this is the injection guard issue #2 asks for, driven
// against all three adapters, not just asserted for one.
func TestReserveMACRejectsInjectionBeforeAnySSH(t *testing.T) {
	bad := []string{
		`aa:bb:cc:dd:ee:ff'; rm -rf / #`,
		`aa:bb:cc:dd:ee:ff" && curl evil.example`,
		"not-a-mac",
		"",
	}
	adapters := map[string]Adapter{
		"kea":      &KeaAdapter{},
		"isc-dhcp": &ISCDHCPAdapter{},
		"dnsmasq":  &DnsmasqAdapter{},
	}
	for name, a := range adapters {
		for _, mac := range bad {
			r := &fakeRunner{}
			switch v := a.(type) {
			case *KeaAdapter:
				v.Runner = r
			case *ISCDHCPAdapter:
				v.Runner = r
			case *DnsmasqAdapter:
				v.Runner = r
			}
			if err := a.ReserveMAC(context.Background(), mac, "10.200.1.100"); err == nil {
				t.Errorf("%s: ReserveMAC(%q, ...) was accepted, want rejected", name, mac)
			}
			if len(r.calls) != 0 {
				t.Errorf("%s: ReserveMAC(%q, ...) reached the runner (%d call(s)) before validation failed", name, mac, len(r.calls))
			}
		}
	}
}

func TestReserveMACRejectsBadAddress(t *testing.T) {
	r := &fakeRunner{}
	a := &KeaAdapter{Runner: r}
	bad := []string{"10.200.1.999", "not-an-ip", "fd42:200::1", "10.200.1.100; reboot"}
	for _, addr := range bad {
		if err := a.ReserveMAC(context.Background(), "aa:bb:cc:dd:ee:ff", addr); err == nil {
			t.Errorf("ReserveMAC(..., %q) was accepted, want rejected", addr)
		}
	}
	if len(r.calls) != 0 {
		t.Fatalf("bad address reached the runner: %v", r.calls)
	}
}

// Preservation: a real MAC and address still reach the runner once
// validated, and the values on the command line are the normalized form
// validateMAC/validateAddr produced, not the raw input.
func TestReserveMACSendsNormalizedValues(t *testing.T) {
	r := &fakeRunner{reply: ""}
	a := &KeaAdapter{Runner: r}
	if err := a.ReserveMAC(context.Background(), "AA:BB:CC:DD:EE:FF", "10.200.1.100"); err != nil {
		t.Fatalf("valid reservation rejected: %v", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(r.calls))
	}
	if !strings.Contains(r.calls[0], "aa:bb:cc:dd:ee:ff") || !strings.Contains(r.calls[0], "10.200.1.100") {
		t.Fatalf("call did not carry the normalized MAC/address: %s", r.calls[0])
	}
}

// Reachable's addr round-trips through the same validateAddr guard as
// ReserveMAC (issue #3): a bad or injection-bearing address must never
// reach the runner at all, across
// every adapter, not just one.
func TestReachableRejectsInjectionBeforeAnySSH(t *testing.T) {
	bad := []string{"10.200.1.100; reboot", "not-an-ip", "fd42:200::1", ""}
	adapters := map[string]Adapter{
		"kea":      &KeaAdapter{},
		"isc-dhcp": &ISCDHCPAdapter{},
		"dnsmasq":  &DnsmasqAdapter{},
	}
	for name, a := range adapters {
		for _, addr := range bad {
			r := &fakeRunner{}
			switch v := a.(type) {
			case *KeaAdapter:
				v.Runner = r
			case *ISCDHCPAdapter:
				v.Runner = r
			case *DnsmasqAdapter:
				v.Runner = r
			}
			if err := a.Reachable(context.Background(), addr); err == nil {
				t.Errorf("%s: Reachable(%q) was accepted, want rejected", name, addr)
			}
			if len(r.calls) != 0 {
				t.Errorf("%s: Reachable(%q) reached the runner before validation failed", name, addr)
			}
		}
	}
}

// Preservation: a real address reaches the runner as a single ping,
// carrying the normalized form, and the adapter reports the runner's
// own error rather than swallowing it.
func TestReachableSendsPingAndPropagatesRunnerError(t *testing.T) {
	r := &fakeRunner{err: context.DeadlineExceeded}
	a := &KeaAdapter{Runner: r}
	if err := a.Reachable(context.Background(), "10.200.1.100"); err == nil {
		t.Fatal("runner error was swallowed instead of propagated")
	}
	if len(r.calls) != 1 || !strings.Contains(r.calls[0], "ping") || !strings.Contains(r.calls[0], "10.200.1.100") {
		t.Fatalf("want one ping call naming the address, got %v", r.calls)
	}
}

func TestKeaParsesEmptyResultAsEmptyTable(t *testing.T) {
	leases, err := parseKeaLeases(`[{"result":3,"text":"no leases"}]`)
	if err != nil {
		t.Fatalf("a Kea 'no leases' reply must not error: %v", err)
	}
	if len(leases) != 0 {
		t.Fatalf("want 0 leases, got %d", len(leases))
	}
}

func TestKeaParsesLeases(t *testing.T) {
	body := `[{"result":0,"arguments":{"leases":[{"ip-address":"10.200.1.100","hw-address":"aa:bb:cc:dd:ee:ff","hostname":"box"}]}}]`
	leases, err := parseKeaLeases(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Address != "10.200.1.100" || leases[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

// Drive the absence: a truncated/garbage control-agent reply must error,
// never read as an empty table (issue #2).
func TestKeaRejectsGarbageReply(t *testing.T) {
	for _, raw := range []string{``, `not json`, `{"result":0}`, `[{"result":0`} {
		if _, err := parseKeaLeases(raw); err == nil {
			t.Errorf("garbage reply %q was accepted as valid", raw)
		}
	}
}

func TestKeaRejectsErrorResult(t *testing.T) {
	if _, err := parseKeaLeases(`[{"result":1,"text":"command not supported"}]`); err == nil {
		t.Fatal("a Kea error result was accepted as a lease table")
	}
}

// Kea reports client-id (option 61) as its own colon-hex string; the
// adapter must carry it through and normalize it to lowercase (#3) --
// this is the format ipvlan lookup keys on, since ipvlan slaves share
// the parent NIC's MAC.
func TestKeaParsesClientID(t *testing.T) {
	body := `[{"result":0,"arguments":{"leases":[{"ip-address":"10.200.1.100","hw-address":"aa:bb:cc:dd:ee:ff","hostname":"box","client-id":"00:97:CE:0D:FD:01:6F:AE:55"}]}}]`
	leases, err := parseKeaLeases(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].ClientID != "00:97:ce:0d:fd:01:6f:ae:55" {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

func TestISCParsesActiveLeaseAndDropsFreed(t *testing.T) {
	raw := `
lease 10.200.2.100 {
  starts 1 2026/09/25 10:00:00;
  ends 1 2026/09/25 22:00:00;
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "box1";
  binding state active;
}
lease 10.200.2.101 {
  hardware ethernet aa:bb:cc:dd:ee:00;
  binding state free;
}
`
	leases, err := parseISCLeases(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Address != "10.200.2.100" || leases[0].Hostname != "box1" {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

// A fresh dhcpd.leases with no lease blocks at all is a genuine empty
// table, distinct from a truncated one (next test).
func TestISCEmptyFileIsEmptyTable(t *testing.T) {
	raw := "# The format of this file is documented in the dhcpd.leases(5) manual page.\n"
	leases, err := parseISCLeases(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Fatalf("want 0 leases, got %d", len(leases))
	}
}

func TestISCRejectsTruncatedBlock(t *testing.T) {
	raw := `
lease 10.200.2.100 {
  hardware ethernet aa:bb:cc:dd:ee:ff;
  binding state active;
`
	if _, err := parseISCLeases(raw); err == nil {
		t.Fatal("a lease block missing its closing brace was accepted")
	}
}

// Renewal history: the same address appears twice, the later block wins
// (dhcpd appends, never rewrites in place).
func TestISCLatestBlockWinsOnRenewal(t *testing.T) {
	raw := `
lease 10.200.2.100 {
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "old-name";
  binding state active;
}
lease 10.200.2.100 {
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "new-name";
  binding state active;
}
`
	leases, err := parseISCLeases(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Hostname != "new-name" {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

// dhcpd prints the uid (client-id, option 61) with C-style quoting: a
// printable ASCII byte literally, everything else as a three-digit
// octal escape. This fixture is the real byte sequence measured against
// a live Kea/ISC pair sharing the same client (#3): type
// byte 0x00, then 0x97 0xce 0x0d 0xfd 0x01
// 'o' 0xae 'U' -- two of those eight bytes (0x6f, 0x55) are printable
// and appear as literal "o" and "U", the rest as octal escapes.
func TestISCParsesClientIDFromUID(t *testing.T) {
	raw := `
lease 10.200.2.100 {
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "box1";
  uid "\000\227\316\015\375\001o\256U";
  binding state active;
}
`
	leases, err := parseISCLeases(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 {
		t.Fatalf("unexpected leases: %+v", leases)
	}
	if want := "00:97:ce:0d:fd:01:6f:ae:55"; leases[0].ClientID != want {
		t.Fatalf("ClientID = %q, want %q", leases[0].ClientID, want)
	}
}

// A lease with no uid field carries no client-id -- must not error and
// must not fabricate one.
func TestISCLeaseWithNoUIDHasEmptyClientID(t *testing.T) {
	raw := `
lease 10.200.2.100 {
  hardware ethernet aa:bb:cc:dd:ee:ff;
  binding state active;
}
`
	leases, err := parseISCLeases(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].ClientID != "" {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

func TestISCRejectsBadOctalEscapeInUID(t *testing.T) {
	raw := `
lease 10.200.2.100 {
  hardware ethernet aa:bb:cc:dd:ee:ff;
  uid "\99z";
  binding state active;
}
`
	if _, err := parseISCLeases(raw); err == nil {
		t.Fatal("a malformed octal escape in uid was accepted")
	}
}

func TestDnsmasqParsesLeases(t *testing.T) {
	raw := "1735000000 aa:bb:cc:dd:ee:ff 10.200.3.100 box1 *\n"
	leases, err := parseDnsmasqLeases(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].Address != "10.200.3.100" || leases[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

func TestDnsmasqEmptyFileIsEmptyTable(t *testing.T) {
	leases, err := parseDnsmasqLeases("")
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 0 {
		t.Fatalf("want 0 leases, got %d", len(leases))
	}
}

func TestDnsmasqRejectsShortLine(t *testing.T) {
	if _, err := parseDnsmasqLeases("1735000000 aa:bb:cc:dd:ee:ff\n"); err == nil {
		t.Fatal("a truncated lease line was accepted")
	}
}

func TestDnsmasqRejectsBadMAC(t *testing.T) {
	if _, err := parseDnsmasqLeases("1735000000 not-a-mac 10.200.3.100 box1 *\n"); err == nil {
		t.Fatal("a malformed MAC field was accepted")
	}
}

// dnsmasq's own fifth field is the client-id (option 61) in its own
// colon-hex encoding; "*" means the client sent none (#3).
func TestDnsmasqParsesClientID(t *testing.T) {
	raw := "1735000000 aa:bb:cc:dd:ee:ff 10.200.3.100 box1 00:97:CE:0D:FD:01:6F:AE:55\n"
	leases, err := parseDnsmasqLeases(raw)
	if err != nil {
		t.Fatal(err)
	}
	if want := "00:97:ce:0d:fd:01:6f:ae:55"; len(leases) != 1 || leases[0].ClientID != want {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

func TestDnsmasqStarClientIDIsEmpty(t *testing.T) {
	leases, err := parseDnsmasqLeases("1735000000 aa:bb:cc:dd:ee:ff 10.200.3.100 box1 *\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].ClientID != "" {
		t.Fatalf("unexpected leases: %+v", leases)
	}
}

// Preservation: every adapter's declared capabilities are a fixed, known
// set -- a change here is a deliberate claim, not an accident. Group B
// (#23) added four; only dnsmasq serves DNS from its own leases. Group C
// (#23) adds CapImpair to all three; none declares a failover pair or a
// relay, so C5 and C12 stay N/A.
func TestDeclaredCapabilities(t *testing.T) {
	base := []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease, CapReserveClientID}
	cases := map[string]struct {
		got  []Capability
		want []Capability
	}{
		"kea":      {(&KeaAdapter{}).Capabilities(), append(append([]Capability{}, base...), CapVendorClassPool, CapOptionChange, CapImpair)},
		"isc-dhcp": {(&ISCDHCPAdapter{}).Capabilities(), append(append([]Capability{}, base...), CapVendorClassPool, CapOptionChange, CapImpair)},
		"dnsmasq":  {(&DnsmasqAdapter{}).Capabilities(), append(append([]Capability{}, base...), CapDNSRegistration, CapVendorClassPool, CapOptionChange, CapImpair)},
	}
	for name, c := range cases {
		if len(c.got) != len(c.want) {
			t.Fatalf("%s: want %d capabilities, got %d (%v)", name, len(c.want), len(c.got), c.got)
		}
		for i := range c.want {
			if c.got[i] != c.want[i] {
				t.Fatalf("%s: capability %d = %s, want %s", name, i, c.got[i], c.want[i])
			}
		}
		for _, have := range c.got {
			if have == CapFailoverPair || have == CapRelay {
				t.Fatalf("%s declares %s, which needs a cell that does not exist yet", name, have)
			}
		}
	}
}

func TestSystemctlActionsUseFixedServiceNames(t *testing.T) {
	cases := []struct {
		name string
		a    Adapter
		svc  string
	}{
		{"kea", &KeaAdapter{}, "kea-dhcp4-server"},
		{"isc-dhcp", &ISCDHCPAdapter{}, "isc-dhcp-server"},
		{"dnsmasq", &DnsmasqAdapter{}, "dnsmasq"},
	}
	for _, c := range cases {
		r := &fakeRunner{}
		switch v := c.a.(type) {
		case *KeaAdapter:
			v.Runner = r
		case *ISCDHCPAdapter:
			v.Runner = r
		case *DnsmasqAdapter:
			v.Runner = r
		}
		for _, op := range []struct {
			name string
			fn   func(context.Context) error
			verb string
		}{
			{"restart", c.a.Restart, "restart"},
			{"stop", c.a.Stop, "stop"},
			{"start", c.a.Start, "start"},
		} {
			r.calls = nil
			if err := op.fn(context.Background()); err != nil {
				t.Fatalf("%s %s: %v", c.name, op.name, err)
			}
			if len(r.calls) != 1 || !strings.Contains(r.calls[0], op.verb+" "+c.svc) {
				t.Fatalf("%s %s: want a call containing %q, got %v", c.name, op.name, op.verb+" "+c.svc, r.calls)
			}
		}
	}
}

func TestShortenLeaseTimeRejectsNonPositiveSeconds(t *testing.T) {
	for name, a := range map[string]Adapter{
		"kea":      &KeaAdapter{Runner: &fakeRunner{}},
		"isc-dhcp": &ISCDHCPAdapter{Runner: &fakeRunner{}},
		"dnsmasq":  &DnsmasqAdapter{Runner: &fakeRunner{}},
	} {
		for _, bad := range []int{0, -1} {
			if _, err := a.ShortenLeaseTime(context.Background(), bad); err == nil {
				t.Errorf("%s: ShortenLeaseTime(%d) was accepted, want rejected", name, bad)
			}
		}
	}
}

func TestShortenLeaseTimeFailsWhenPatternMissing(t *testing.T) {
	cases := []struct {
		name string
		a    Adapter
		r    *fakeRunner
	}{
		{"kea", &KeaAdapter{}, &fakeRunner{reply: "{\"Dhcp4\": {}}"}},
		{"isc-dhcp", &ISCDHCPAdapter{}, &fakeRunner{reply: "subnet 10.0.0.0 netmask 255.255.255.0 {}"}},
		{"dnsmasq", &DnsmasqAdapter{}, &fakeRunner{reply: "port=0\n"}},
	}
	for _, c := range cases {
		switch v := c.a.(type) {
		case *KeaAdapter:
			v.Runner = c.r
		case *ISCDHCPAdapter:
			v.Runner = c.r
		case *DnsmasqAdapter:
			v.Runner = c.r
		}
		if _, err := c.a.ShortenLeaseTime(context.Background(), 40); err == nil {
			t.Errorf("%s: ShortenLeaseTime found nothing to substitute yet was accepted", c.name)
		}
		if len(c.r.calls) != 1 {
			t.Errorf("%s: want exactly one call (the read) before refusing, got %d", c.name, len(c.r.calls))
		}
	}
}

// TestShortenLeaseTimeSubstitutesAndRestores drives each adapter's real
// ShortenLeaseTime against a config shaped like this cell's own
// generated one (never the packaged .stock default -- issue #3, A14):
// the short value must land in the write, a restart must follow, and
// the returned restore closure must write back byte-for-byte what the
// read call saw, including a reservation ReserveMAC could already have
// added, then restart again.
func TestShortenLeaseTimeSubstitutesAndRestores(t *testing.T) {
	cases := []struct {
		name       string
		makeA      func(r Runner) Adapter
		orig       string
		wantShort  string
		configPath string
		svc        string
	}{
		{
			name:       "dnsmasq",
			makeA:      func(r Runner) Adapter { return &DnsmasqAdapter{Runner: r} },
			orig:       "port=0\ndhcp-range=10.200.1.100,10.200.1.150,12h\ndhcp-host=aa:bb:cc:dd:ee:ff,10.200.1.100\n",
			wantShort:  "dhcp-range=10.200.1.100,10.200.1.150,40",
			configPath: "/etc/dnsmasq.conf",
			svc:        "dnsmasq",
		},
		{
			name:  "kea",
			makeA: func(r Runner) Adapter { return &KeaAdapter{Runner: r} },
			orig: `{
"Dhcp4": {
  "valid-lifetime": 3600,
  "subnet4": [ { "id": 1 } ]
}
}
`,
			wantShort:  `"valid-lifetime": 40,`,
			configPath: "/etc/kea/kea-dhcp4.conf",
			svc:        "kea-dhcp4-server",
		},
		{
			name:       "isc-dhcp",
			makeA:      func(r Runner) Adapter { return &ISCDHCPAdapter{Runner: r} },
			orig:       "default-lease-time 600;\nmax-lease-time 7200;\ninclude \"/etc/dhcp/lab-reservations.conf\";\n",
			wantShort:  "default-lease-time 40;",
			configPath: "/etc/dhcp/dhcpd.conf",
			svc:        "isc-dhcp-server",
		},
	}
	for _, c := range cases {
		r := &fakeRunner{reply: c.orig}
		a := c.makeA(r)

		restore, err := a.ShortenLeaseTime(context.Background(), 40)
		if err != nil {
			t.Fatalf("%s: ShortenLeaseTime: %v", c.name, err)
		}
		if len(r.calls) != 3 {
			t.Fatalf("%s: want 3 calls (read, write, restart), got %d: %v", c.name, len(r.calls), r.calls)
		}
		if !strings.Contains(r.calls[0], "cat "+c.configPath) {
			t.Errorf("%s: call 0 = %q, want a read of %s", c.name, r.calls[0], c.configPath)
		}
		if !strings.Contains(r.calls[1], c.configPath) || !strings.Contains(r.calls[1], c.wantShort) {
			t.Errorf("%s: write call = %q, want it to target %s and contain %q", c.name, r.calls[1], c.configPath, c.wantShort)
		}
		if !strings.Contains(r.calls[2], "restart "+c.svc) {
			t.Errorf("%s: call 2 = %q, want a restart of %s", c.name, r.calls[2], c.svc)
		}

		r.calls = nil
		if err := restore(context.Background()); err != nil {
			t.Fatalf("%s: restore: %v", c.name, err)
		}
		if len(r.calls) != 2 {
			t.Fatalf("%s: restore: want 2 calls (write, restart), got %d: %v", c.name, len(r.calls), r.calls)
		}
		if !strings.Contains(r.calls[0], c.configPath) || !strings.Contains(r.calls[0], c.orig) {
			t.Errorf("%s: restore write = %q, want it to write the original config back byte-for-byte", c.name, r.calls[0])
		}
		if !strings.Contains(r.calls[1], "restart "+c.svc) {
			t.Errorf("%s: restore call 1 = %q, want a restart of %s", c.name, r.calls[1], c.svc)
		}
	}
}

// TestResetLeasesStopsTruncatesAndStarts drives each adapter's real
// ResetLeases (issue #3 part 2): one chained remote command that stops
// the service, truncates its own lease file, and starts the service
// again, in that order, so nothing else can read a half-cleared table
// in between.
func TestResetLeasesStopsTruncatesAndStarts(t *testing.T) {
	cases := []struct {
		name string
		a    Adapter
		svc  string
		file string
	}{
		{"kea", &KeaAdapter{}, "kea-dhcp4-server", keaLeaseFile},
		{"isc-dhcp", &ISCDHCPAdapter{}, "isc-dhcp-server", iscLeaseFile},
		{"dnsmasq", &DnsmasqAdapter{}, "dnsmasq", dnsmasqLeaseFile},
	}
	for _, c := range cases {
		r := &fakeRunner{}
		switch v := c.a.(type) {
		case *KeaAdapter:
			v.Runner = r
		case *ISCDHCPAdapter:
			v.Runner = r
		case *DnsmasqAdapter:
			v.Runner = r
		}
		if err := c.a.ResetLeases(context.Background()); err != nil {
			t.Fatalf("%s: ResetLeases: %v", c.name, err)
		}
		if len(r.calls) != 1 {
			t.Fatalf("%s: want 1 chained call, got %d: %v", c.name, len(r.calls), r.calls)
		}
		call := r.calls[0]
		stopAt := strings.Index(call, "stop "+c.svc)
		truncAt := strings.Index(call, "truncate -s 0 "+c.file)
		startAt := strings.Index(call, "start "+c.svc)
		if stopAt < 0 || truncAt < 0 || startAt < 0 {
			t.Fatalf("%s: call = %q, want it to stop %s, truncate %s and start %s", c.name, call, c.svc, c.file, c.svc)
		}
		if !(stopAt < truncAt && truncAt < startAt) {
			t.Fatalf("%s: call = %q, want stop before truncate before start", c.name, call)
		}
	}
}

// TestResetLeasesPropagatesRunnerError: a failing remote command must
// surface as an error, never a silent no-op that leaves the caller
// believing the pool is now empty when it is not.
func TestResetLeasesPropagatesRunnerError(t *testing.T) {
	for name, a := range map[string]Adapter{
		"kea":      &KeaAdapter{Runner: &fakeRunner{err: errors.New("boom")}},
		"isc-dhcp": &ISCDHCPAdapter{Runner: &fakeRunner{err: errors.New("boom")}},
		"dnsmasq":  &DnsmasqAdapter{Runner: &fakeRunner{err: errors.New("boom")}},
	} {
		if err := a.ResetLeases(context.Background()); err == nil {
			t.Errorf("%s: ResetLeases with a failing runner was accepted, want an error", name)
		}
	}
}
