package sourceadapter

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture6(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "testdata", "v6", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const fixtureDUID = "00:03:00:01:02:00:00:00:23:d1"

func want6(t *testing.T, got []Lease6, want []Lease6) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d lease(s) %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.Type != w.Type || g.Address != w.Address || g.DUID != w.DUID || g.IAID != w.IAID ||
			g.Preferred != w.Preferred || g.Valid != w.Valid || !g.Expires.Equal(w.Expires) {
			t.Fatalf("lease %d = %+v, want %+v", i, g, w)
		}
	}
}

// The agent's array and the dhcp6 socket's bare object both parse, from
// the reply kea-dhcp6 2.6.3 gave on 2026-10-09 (#23).
func TestParseKeaLeases6Fixture(t *testing.T) {
	raw := fixture6(t, "kea-lease6-get-all.json")
	want := []Lease6{{Type: Lease6NA, Address: netip.MustParseAddr("fd42:200:0:100::101"), DUID: fixtureDUID, IAID: 1,
		Preferred: time.Hour, Valid: 2 * time.Hour, Expires: time.Unix(1791568749+7200, 0).UTC()}}
	for name, in := range map[string]string{"bare": raw, "agent array": "[" + raw + "]"} {
		t.Run(name, func(t *testing.T) {
			got, err := parseKeaLeases6(in)
			if err != nil {
				t.Fatal(err)
			}
			want6(t, got, want)
		})
	}
}

func TestParseKeaLeases6SkipsInactiveAndRejectsBadReplies(t *testing.T) {
	got, err := parseKeaLeases6(`[{"result":0,"arguments":{"leases":[
		{"ip-address":"fd42:200:0:100::102","duid":"AA:BB","iaid":2,"type":"IA_TA","state":0,"cltt":10,"valid-lft":60,"preferred-lft":30},
		{"ip-address":"fd42:200:0:100::103","duid":"aa:bb","iaid":3,"type":"IA_NA","state":1,"cltt":10,"valid-lft":60},
		{"ip-address":"fd42:200:0:100::104","duid":"aa:bb","iaid":4,"type":"IA_NA","state":0,"cltt":10,"valid-lft":0},
		{"ip-address":"fd42:200:0:1ff::","duid":"aa:bb","iaid":5,"type":"IA_PD","state":0,"cltt":10,"valid-lft":60}]}}]`)
	if err != nil {
		t.Fatal(err)
	}
	want6(t, got, []Lease6{{Type: Lease6TA, Address: netip.MustParseAddr("fd42:200:0:100::102"), DUID: "aa:bb", IAID: 2,
		Preferred: 30 * time.Second, Valid: time.Minute, Expires: time.Unix(70, 0).UTC()}})
	if got, err := parseKeaLeases6(`[{"result":3,"text":"0 IPv6 lease(s) found."}]`); err != nil || len(got) != 0 {
		t.Fatalf("result 3 = %v, %v; want an empty table", got, err)
	}
	for _, bad := range []string{"", `[]`, `[{"result":1}]`, `{"result":0,"arguments":{"leases":[{"ip-address":"10.0.0.1","type":"IA_NA"}]}}`, `[{"result":0,"argu`} {
		if _, err := parseKeaLeases6(bad); err == nil {
			t.Errorf("parseKeaLeases6(%q) accepted a bad reply", bad)
		}
	}
}

// ISC's key is the IAID in authoring-byte-order, then the DUID; the
// fixture's two IAs carry IAID 1 and 2 (#23).
func TestParseISCLeases6Fixture(t *testing.T) {
	got, err := parseISCLeases6(fixture6(t, "dhcpd6.leases"))
	if err != nil {
		t.Fatal(err)
	}
	ends := time.Date(2026, 10, 9, 19, 57, 1, 0, time.UTC)
	want6(t, got, []Lease6{
		{Type: Lease6NA, Address: netip.MustParseAddr("fd42:200:0:200::1aa"), DUID: fixtureDUID, IAID: 1, Preferred: time.Hour, Valid: 2 * time.Hour, Expires: ends},
		{Type: Lease6TA, Address: netip.MustParseAddr("fd42:200:0:200::22f"), DUID: fixtureDUID, IAID: 2, Preferred: time.Hour, Valid: 2 * time.Hour, Expires: ends},
	})
}

func TestParseISCLeases6LastBlockWinsAndTruncationFails(t *testing.T) {
	raw := fixture6(t, "dhcpd6.leases")
	released := "\nia-na \"\\001\\000\\000\\000\\000\\003\\000\\001\\002\\000\\000\\000#\\321\" {\n  iaaddr fd42:200:0:200::1aa {\n    binding state released;\n  }\n}\n"
	got, err := parseISCLeases6(raw + released)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Type != Lease6TA {
		t.Fatalf("a later released block left %+v, want only the IA_TA", got)
	}
	big := strings.Replace(raw, "little-endian", "big-endian", 1)
	if got, err := parseISCLeases6(big); err != nil || got[0].IAID != 0x01000000 {
		t.Fatalf("big-endian file read IAID %+v, %v", got, err)
	}
	cut := raw[:strings.LastIndex(raw, "  }\n}")]
	if _, err := parseISCLeases6(cut); err == nil {
		t.Fatal("a truncated dhcpd6.leases parsed")
	}
	if got, err := parseISCLeases6(""); err != nil || len(got) != 0 {
		t.Fatalf("empty file = %v, %v", got, err)
	}
}

func TestParseDnsmasqLeases6Fixture(t *testing.T) {
	raw := fixture6(t, "dnsmasq6.leases")
	got, err := parseDnsmasqLeases6(raw)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Unix(1791575846, 0).UTC()
	want6(t, got, []Lease6{
		{Type: Lease6TA, Address: netip.MustParseAddr("fd42:200:0:300::12d"), DUID: fixtureDUID, IAID: 2, Expires: exp},
		{Type: Lease6NA, Address: netip.MustParseAddr("fd42:200:0:300::1f1"), DUID: fixtureDUID, IAID: 1, Expires: exp},
	})
	for _, bad := range []string{"duid 00:01\n1 x fd42:200:0:300::1 * 00:03\n", "duid 00:01\n1 1 10.0.0.1 * 00:03\n", "duid 00:01\n1 1 fd42:200:0:300::1\n"} {
		if _, err := parseDnsmasqLeases6(bad); err == nil {
			t.Errorf("parseDnsmasqLeases6(%q) accepted a bad line", bad)
		}
	}
}

// One dnsmasq.leases holds both tables; v4 must keep parsing once DHCPv6
// serves and must not pick up a v6 row (#23).
func TestDnsmasqMixedFileSplitsAtDUID(t *testing.T) {
	mixed := "1791575846 02:00:00:00:23:d1 10.200.3.120 c1 01:02:00:00:00:23:d1\n" + fixture6(t, "dnsmasq6.leases")
	v4, err := parseDnsmasqLeases(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if len(v4) != 1 || v4[0].Address != "10.200.3.120" {
		t.Fatalf("v4 read %+v from a mixed file", v4)
	}
	v6, err := parseDnsmasqLeases6(mixed)
	if err != nil || len(v6) != 2 {
		t.Fatalf("v6 read %+v, %v from a mixed file", v6, err)
	}
}

func TestLeases6CommandsAndSetRA(t *testing.T) {
	for name, want := range map[string]string{"kea": keaLease6Cmd, "isc-dhcp": "sudo cat " + iscLease6File, "dnsmasq": "sudo cat " + dnsmasqLeaseFile} {
		r := &fakeRunner{reply: `[{"result":3}]`}
		_, _ = groupBAdapters(r)[name].Leases6(context.Background())
		if len(r.calls) != 1 || r.calls[0] != want {
			t.Errorf("%s Leases6 ran %q, want %q", name, r.calls, want)
		}
	}
	for _, name := range []string{"kea", "isc-dhcp"} {
		r := &fakeRunner{}
		a := groupBAdapters(r)[name]
		if _, err := a.SetRA(context.Background(), RAParams{}); err == nil || len(r.calls) != 0 {
			t.Fatalf("%s: SetRA without Off ran %q, err %v", name, r.calls, err)
		}
		restore, err := a.SetRA(context.Background(), RAParams{Off: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		if strings.Join(r.calls, "|") != "sudo systemctl stop radvd|sudo systemctl start radvd" {
			t.Fatalf("%s SetRA ran %q", name, r.calls)
		}
	}
}

func TestReachableTakesIPv6(t *testing.T) {
	r := &fakeRunner{}
	if err := reachable(context.Background(), r, "fd42:200:0:300::1f1"); err != nil {
		t.Fatal(err)
	}
	if r.calls[0] != "ping -6 -c1 -W2 fd42:200:0:300::1f1" {
		t.Fatalf("ran %q", r.calls[0])
	}
	for _, bad := range []string{"fe80::1%eth1", "::ffff:10.0.0.1", "fd42::1;id"} {
		if err := reachable(context.Background(), &fakeRunner{}, bad); err == nil {
			t.Errorf("reachable(%q) accepted", bad)
		}
	}
}
