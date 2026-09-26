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
