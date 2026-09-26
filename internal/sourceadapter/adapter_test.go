package sourceadapter

import (
	"context"
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
// set -- a change here is a deliberate claim, not an accident.
func TestDeclaredCapabilities(t *testing.T) {
	want := []Capability{CapV4, CapReserveMAC, CapRestart}
	for name, caps := range map[string][]Capability{
		"kea":      (&KeaAdapter{}).Capabilities(),
		"isc-dhcp": (&ISCDHCPAdapter{}).Capabilities(),
		"dnsmasq":  (&DnsmasqAdapter{}).Capabilities(),
	} {
		if len(caps) != len(want) {
			t.Fatalf("%s: want %d capabilities, got %d (%v)", name, len(want), len(caps), caps)
		}
		for i := range want {
			if caps[i] != want[i] {
				t.Fatalf("%s: capability %d = %s, want %s", name, i, caps[i], want[i])
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
