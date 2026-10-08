package sourceadapter

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func groupBAdapters(r Runner) map[string]Adapter {
	return map[string]Adapter{
		"kea":      &KeaAdapter{Runner: r},
		"isc-dhcp": &ISCDHCPAdapter{Runner: r},
		"dnsmasq":  &DnsmasqAdapter{Runner: r},
	}
}

// A client id carrying shell or JSON metacharacters must never reach the
// runner (B2, #23): the same guard ReserveMAC has.
func TestReserveClientIDRejectsInjectionBeforeAnySSH(t *testing.T) {
	bad := []string{
		`00:aa'; rm -rf / #`,
		`00:aa" && curl evil.example`,
		"not-hex",
		"0:aa",
		"00:aa:",
		"",
	}
	for name := range groupBAdapters(nil) {
		for _, id := range bad {
			r := &fakeRunner{}
			if err := groupBAdapters(r)[name].ReserveClientID(context.Background(), id, "10.200.1.211"); err == nil {
				t.Errorf("%s: client id %q was accepted", name, id)
			}
			if len(r.calls) != 0 {
				t.Errorf("%s: client id %q reached the runner: %v", name, id, r.calls)
			}
		}
		r := &fakeRunner{}
		if err := groupBAdapters(r)[name].ReserveClientID(context.Background(), "00:aa", "10.200.1.211; id"); err == nil || len(r.calls) != 0 {
			t.Errorf("%s: a bad address was accepted or reached the runner", name)
		}
	}
}

// Each adapter's reservation spelling for an option 61 value, and that a
// rerun replaces the old row instead of adding a second one (defeat
// list: a half-finished earlier run).
func TestReserveClientIDCommandShapes(t *testing.T) {
	const id, ip = "00:6C:61:62", "10.200.1.216"
	want := map[string][]string{
		"kea":      {`.["client-id"] != "00:6c:61:62"`, `"client-id":"00:6c:61:62","ip-address":"10.200.1.216"`, "kill -s HUP kea-dhcp4-server"},
		"isc-dhcp": {"sed -i '/^host lab-cid-006c6162 /d'", "host lab-cid-006c6162 { option dhcp-client-identifier 00:6c:61:62; fixed-address 10.200.1.216; }", "restart isc-dhcp-server"},
		"dnsmasq":  {"sed -i '/^dhcp-host=id:00:6c:61:62,/d'", "dhcp-host=id:00:6c:61:62,10.200.1.216", "restart dnsmasq"},
	}
	for name, a := range groupBAdapters(nil) {
		r := &fakeRunner{}
		switch v := a.(type) {
		case *KeaAdapter:
			v.Runner = r
		case *ISCDHCPAdapter:
			v.Runner = r
		case *DnsmasqAdapter:
			v.Runner = r
		}
		if err := a.ReserveClientID(context.Background(), id, ip); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r.calls) != 1 {
			t.Fatalf("%s: want 1 call, got %v", name, r.calls)
		}
		for _, w := range want[name] {
			if !strings.Contains(r.calls[0], w) {
				t.Errorf("%s: call %q lacks %q", name, r.calls[0], w)
			}
		}
	}
}

// ReserveMAC is idempotent too now: the delete of the old row precedes
// the append, on all three sources.
func TestReserveMACReplacesTheOldRow(t *testing.T) {
	const mac, ip = "aa:bb:cc:dd:ee:01", "10.200.1.211"
	want := map[string][]string{
		"kea":      {`.["hw-address"] != "aa:bb:cc:dd:ee:01"`, `"hw-address":"aa:bb:cc:dd:ee:01","ip-address":"10.200.1.211"`},
		"isc-dhcp": {"sed -i '/^host lab-aabbccddee01 /d'", "hardware ethernet aa:bb:cc:dd:ee:01; fixed-address 10.200.1.211"},
		"dnsmasq":  {"sed -i '/^dhcp-host=aa:bb:cc:dd:ee:01,/d'", "dhcp-host=aa:bb:cc:dd:ee:01,10.200.1.211"},
	}
	for name := range want {
		r := &fakeRunner{}
		a := groupBAdapters(r)[name]
		if err := a.ReserveMAC(context.Background(), mac, ip); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		call := r.calls[0]
		for _, w := range want[name] {
			if !strings.Contains(call, w) {
				t.Errorf("%s: call %q lacks %q", name, call, w)
			}
		}
		if name != "kea" && strings.Index(call, "sed -i") > strings.Index(call, "tee -a") {
			t.Errorf("%s: the delete must come before the append: %q", name, call)
		}
	}
}

// The three configs below are shaped like each cell's generated one; the
// DNS option must land beside the routers entry, a restart must follow,
// and restore must write the original bytes back, then restart.
func TestSetDNSOptionSubstitutesAndRestores(t *testing.T) {
	cases := []struct {
		name, orig, want, path, svc string
	}{
		{
			"kea",
			"{\n\"Dhcp4\": { \"subnet4\": [ {\n  \"option-data\": [ { \"name\": \"routers\", \"data\": \"10.200.1.1\" } ],\n} ] }\n}\n",
			`"option-data": [ { "name": "routers", "data": "10.200.1.1" }, { "name": "domain-name-servers", "data": "10.200.1.253" } ]`,
			"/etc/kea/kea-dhcp4.conf", "kea-dhcp4-server",
		},
		{
			"isc-dhcp",
			"subnet 10.200.1.0 netmask 255.255.255.0 {\n  option routers 10.200.1.1;\n  range 10.200.1.100 10.200.1.150;\n}\n",
			"  option routers 10.200.1.1;\n  option domain-name-servers 10.200.1.253;\n",
			"/etc/dhcp/dhcpd.conf", "isc-dhcp-server",
		},
		{
			"dnsmasq",
			"port=0\ndhcp-option=3,10.200.1.1\ndhcp-range=10.200.1.100,10.200.1.150,12h\n",
			"dhcp-option=3,10.200.1.1\ndhcp-option=6,10.200.1.253\n",
			"/etc/dnsmasq.conf", "dnsmasq",
		},
	}
	for _, c := range cases {
		r := &fakeRunner{reply: c.orig}
		a := groupBAdapters(r)[c.name]
		restore, err := a.SetDNSOption(context.Background(), "10.200.1.253")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(r.calls) != 3 {
			t.Fatalf("%s: want read, write, restart, got %v", c.name, r.calls)
		}
		if !strings.Contains(r.calls[0], "cat "+c.path) {
			t.Errorf("%s: call 0 = %q", c.name, r.calls[0])
		}
		if !strings.Contains(r.calls[1], c.path) || !strings.Contains(r.calls[1], c.want) {
			t.Errorf("%s: write = %q, want %q", c.name, r.calls[1], c.want)
		}
		if !strings.Contains(r.calls[2], "restart "+c.svc) {
			t.Errorf("%s: call 2 = %q", c.name, r.calls[2])
		}
		r.calls = nil
		if err := restore(context.Background()); err != nil {
			t.Fatalf("%s: restore: %v", c.name, err)
		}
		if len(r.calls) != 2 || !strings.Contains(r.calls[0], c.orig) || !strings.Contains(r.calls[1], "restart "+c.svc) {
			t.Errorf("%s: restore calls = %v, want the original bytes written back and a restart", c.name, r.calls)
		}
	}
}

// Preservation control: a config that already carries a DNS option, or
// has no routers anchor, is refused without a write; a bad address never
// reaches the runner.
func TestSetDNSOptionRefusals(t *testing.T) {
	already := map[string]string{
		"kea":      `"option-data": [ { "name": "routers", "data": "10.200.1.1" }, { "name": "domain-name-servers", "data": "9.9.9.9" } ]`,
		"isc-dhcp": "option routers 10.200.1.1;\noption domain-name-servers 9.9.9.9;\n",
		"dnsmasq":  "dhcp-option=3,10.200.1.1\ndhcp-option=6,9.9.9.9\n",
	}
	for name, cfg := range already {
		r := &fakeRunner{reply: cfg}
		if _, err := groupBAdapters(r)[name].SetDNSOption(context.Background(), "10.200.1.253"); err == nil {
			t.Errorf("%s: a config with a DNS option was accepted", name)
		}
		if len(r.calls) != 1 {
			t.Errorf("%s: want only the read, got %v", name, r.calls)
		}
		r = &fakeRunner{reply: "nothing to anchor on\n"}
		if _, err := groupBAdapters(r)[name].SetDNSOption(context.Background(), "10.200.1.253"); err == nil {
			t.Errorf("%s: a config without the routers anchor was accepted", name)
		}
		if len(r.calls) != 1 {
			t.Errorf("%s: no-anchor case wrote: %v", name, r.calls)
		}
		r = &fakeRunner{}
		if _, err := groupBAdapters(r)[name].SetDNSOption(context.Background(), "x; reboot"); err == nil || len(r.calls) != 0 {
			t.Errorf("%s: a bad address reached the runner: %v", name, r.calls)
		}
	}
}

// B7 reads absence as released, so each parser must drop what its source
// marks released, with the live row kept beside it (preservation).
func TestParsersDropReleasedLeases(t *testing.T) {
	keaRaw := `[{"result":0,"arguments":{"leases":[
{"ip-address":"10.200.1.100","hw-address":"aa:bb:cc:dd:ee:01","hostname":"","client-id":"","state":0,"cltt":1000,"valid-lft":3600},
{"ip-address":"10.200.1.101","hw-address":"aa:bb:cc:dd:ee:02","hostname":"","client-id":"","state":2,"cltt":1000,"valid-lft":3600},
{"ip-address":"10.200.1.102","hw-address":"aa:bb:cc:dd:ee:03","hostname":"","client-id":"","state":0,"cltt":1000,"valid-lft":0}]}}]`
	got, err := parseKeaLeases(keaRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Address != "10.200.1.100" {
		t.Errorf("kea: want only the live row, got %+v", got)
	}
	if want := time.Unix(4600, 0).UTC(); !got[0].Expires.Equal(want) {
		t.Errorf("kea: Expires = %v, want %v", got[0].Expires, want)
	}

	iscRaw := `lease 10.200.1.100 {
  starts 4 2026/10/08 10:00:00;
  ends 4 2026/10/08 11:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:01;
}
lease 10.200.1.101 {
  ends 4 2026/10/08 11:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:02;
}
lease 10.200.1.101 {
  ends 4 2026/10/08 10:30:00;
  binding state free;
  hardware ethernet aa:bb:cc:dd:ee:02;
}
`
	isc, err := parseISCLeases(iscRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(isc) != 1 || isc[0].Address != "10.200.1.100" {
		t.Errorf("isc-dhcp: want only the live row, got %+v", isc)
	}
	if want := time.Date(2026, 10, 8, 11, 0, 0, 0, time.UTC); !isc[0].Expires.Equal(want) {
		t.Errorf("isc-dhcp: Expires = %v, want %v", isc[0].Expires, want)
	}

	dn, err := parseDnsmasqLeases("1790000000 aa:bb:cc:dd:ee:01 10.200.1.100 box1 *\n0 aa:bb:cc:dd:ee:02 10.200.1.101 box2 *\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(dn) != 2 || !dn[0].Expires.Equal(time.Unix(1790000000, 0).UTC()) || !dn[1].Expires.IsZero() {
		t.Errorf("dnsmasq: epoch 0 must give a zero Expires and a real epoch its time, got %+v", dn)
	}
}

// A14 still shortens a tagged range, since B5 puts a tag on one of the
// two dhcp-range lines (#23): both ranges must take the short value.
func TestDnsmasqShortenCoversTaggedRange(t *testing.T) {
	orig := "dhcp-range=tag:!b5,10.200.1.100,10.200.1.150,12h\ndhcp-range=tag:b5,10.200.1.221,10.200.1.230,12h\n"
	got := dnsmasqRangeRE.ReplaceAllString(orig, "${1}40")
	want := "dhcp-range=tag:!b5,10.200.1.100,10.200.1.150,40\ndhcp-range=tag:b5,10.200.1.221,10.200.1.230,40\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Every capability constant is distinct, so a Needs list means one thing.
func TestCapabilityNamesAreDistinct(t *testing.T) {
	seen := map[Capability]bool{}
	for _, c := range []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease, CapReserveClientID, CapDNSRegistration, CapVendorClassPool, CapOptionChange} {
		if seen[c] || c == "" {
			t.Fatalf("capability %q is empty or repeated", c)
		}
		seen[c] = true
	}
}

// The range pattern must stay on its own line: a line after the last
// range that carries no comma is not part of the lease time.
func TestDnsmasqShortenStaysOnItsLine(t *testing.T) {
	orig := "dhcp-range=10.200.1.100,10.200.1.150,12h\nlog-dhcp\nport=53\n"
	got := dnsmasqRangeRE.ReplaceAllString(orig, "${1}40")
	if want := "dhcp-range=10.200.1.100,10.200.1.150,40\nlog-dhcp\nport=53\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The Kea command is a jq program; reading its text proves little. Run it
// on a file that already holds the same identifier and demand one row
// for it, the new address, and every other row kept (#23).
func TestKeaReserveJQProgramReplacesTheRowItRuns(t *testing.T) {
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not installed; the reserve command cannot be executed here")
	}
	for _, field := range []string{"hw-address", "client-id"} {
		r := &fakeRunner{}
		a := &KeaAdapter{Runner: r}
		if err := a.keaReserve(context.Background(), field, "aa:bb", "10.200.1.216"); err != nil {
			t.Fatal(err)
		}
		cmd := r.calls[0]
		i := strings.Index(cmd, "jq '")
		j := strings.Index(cmd, "' /etc/kea/reservations.json")
		if i < 0 || j < i {
			t.Fatalf("no jq program in %q", cmd)
		}
		prog := cmd[i+len("jq '") : j]
		in := `[{"` + field + `":"aa:bb","ip-address":"10.200.1.211"},{"hw-address":"cc:dd","ip-address":"10.200.1.212"}]`
		c := exec.Command(jq, "-c", prog)
		c.Stdin = strings.NewReader(in)
		got, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: jq: %v: %s", field, err, got)
		}
		want := `[{"hw-address":"cc:dd","ip-address":"10.200.1.212"},{"` + field + `":"aa:bb","ip-address":"10.200.1.216"}]`
		if strings.TrimSpace(string(got)) != want {
			t.Errorf("%s: got %s want %s", field, got, want)
		}
	}
}
