package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

var eventsSince = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func fmtEvents(evs []ServerEvent) []string {
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = fmt.Sprintf("%s %s %s %s %s", e.At.UTC().Format("15:04:05"), e.Type, e.MAC, dash(e.IP), dash(e.TID))
	}
	return out
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const (
	m1 = "02:aa:bb:cc:dd:01"
	m2 = "02:aa:bb:cc:dd:02"
	m3 = "02:aa:bb:cc:dd:03"
	m4 = "02:aa:bb:cc:dd:04"
)

type journalCase struct {
	name    string
	file    string
	unit    string
	adapter func(Runner) Adapter
	want    []string
}

var journalCases = []journalCase{
	{"kea", "journal-kea.txt", "kea-dhcp4-server", func(r Runner) Adapter { return &KeaAdapter{Runner: r} }, []string{
		"12:00:05 OFFER " + m1 + " 10.200.1.150 0x4f1a2b3c",
		"12:00:05 ACK " + m1 + " 10.200.1.150 0x4f1a2b3c",
		"12:00:06 OFFER " + m2 + " 10.200.1.151 0x0a0b0c0d",
		"12:00:06 ACK " + m2 + " 10.200.1.151 0x0a0b0c0d",
		"12:30:05 ACK " + m1 + " 10.200.1.150 0x5d6e7f80",
		"12:40:00 NAK " + m3 + " - 0x77889900",
		"12:45:00 DECLINE " + m2 + " 10.200.1.151 -",
		"12:50:00 RELEASE " + m1 + " 10.200.1.150 0x1c2d3e4f",
	}},
	{"isc-dhcp", "journal-isc.txt", "isc-dhcp-server", func(r Runner) Adapter { return &ISCDHCPAdapter{Runner: r} }, []string{
		"12:00:05 DISCOVER " + m1 + " - -",
		"12:00:06 OFFER " + m1 + " 10.200.1.150 -",
		"12:00:06 REQUEST " + m1 + " 10.200.1.150 -",
		"12:00:06 ACK " + m1 + " 10.200.1.150 -",
		"12:00:09 DISCOVER " + m2 + " - -",
		"12:05:06 REQUEST " + m1 + " 10.200.1.150 -",
		"12:05:06 ACK " + m1 + " 10.200.1.150 -",
		"12:06:00 REQUEST " + m3 + " 10.200.1.160 -",
		"12:06:00 NAK " + m3 + " 10.200.1.160 -",
		"12:07:00 DECLINE " + m2 + " 10.200.1.151 -",
		"12:08:00 RELEASE " + m1 + " 10.200.1.150 -",
	}},
	{"dnsmasq", "journal-dnsmasq.txt", "dnsmasq", func(r Runner) Adapter { return &DnsmasqAdapter{Runner: r} }, []string{
		"12:00:05 DISCOVER " + m1 + " - -",
		"12:00:05 OFFER " + m1 + " 10.200.1.150 -",
		"12:00:05 REQUEST " + m1 + " 10.200.1.150 -",
		"12:00:05 ACK " + m1 + " 10.200.1.150 -",
		"12:06:00 REQUEST " + m1 + " 10.200.1.150 -",
		"12:06:00 ACK " + m1 + " 10.200.1.150 -",
		"12:07:00 REQUEST " + m3 + " 10.200.1.160 -",
		"12:07:00 NAK " + m3 + " 10.200.1.160 -",
		"12:08:00 DECLINE " + m2 + " 10.200.1.151 -",
		"12:09:00 INFORM " + m4 + " 10.200.1.170 -",
		"12:10:00 RELEASE " + m1 + " 10.200.1.150 -",
	}},
}

// The fixture slices are INFERRED from the vendors' documented message
// formats, not measured on the lab host (lab #15 PR 1).
func TestServerEventsParseTheJournalSlicePerServer(t *testing.T) {
	for _, c := range journalCases {
		t.Run(c.name, func(t *testing.T) {
			r := &fakeRunner{reply: fixture(t, c.file)}
			got, err := c.adapter(r).ServerEvents(context.Background(), eventsSince, "")
			if err != nil {
				t.Fatal(err)
			}
			if g := fmtEvents(got); !slices.Equal(g, c.want) {
				t.Errorf("events\n got %q\nwant %q", g, c.want)
			}
		})
	}
}

// The Kea stdout form puts its own timestamp and severity between the
// journal prefix and the message identifier; the parser must not care.
func TestKeaJournalAcceptsTheStdoutForm(t *testing.T) {
	line := "2026-10-11T12:00:05+0000 lab-kea kea-dhcp4[612]: 2026-10-11 12:00:05.123 INFO  [kea-dhcp4.leases/612.14] DHCP4_LEASE_ALLOC [hwtype=1 " + m1 + "], cid=[01:02:aa:bb:cc:dd:01], tid=0x4f1a2b3c: lease 10.200.1.150 has been allocated for 3600 seconds\n"
	got, err := (&KeaAdapter{Runner: &fakeRunner{reply: line}}).ServerEvents(context.Background(), eventsSince, "")
	if err != nil || len(got) != 1 || got[0].IP != "10.200.1.150" || got[0].Type != "ACK" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestServerEventsMACFilter(t *testing.T) {
	for _, c := range journalCases {
		t.Run(c.name, func(t *testing.T) {
			r := &fakeRunner{reply: fixture(t, c.file)}
			// Upper case in the argument and, for the declines, in the journal.
			got, err := c.adapter(r).ServerEvents(context.Background(), eventsSince, strings.ToUpper(m2))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) == 0 {
				t.Fatal("the filter dropped every event of the MAC")
			}
			for _, e := range got {
				if e.MAC != m2 {
					t.Errorf("event for %s passed the %s filter", e.MAC, m2)
				}
			}
			var all []string
			for _, w := range c.want {
				if strings.Contains(w, m2) {
					all = append(all, w)
				}
			}
			if g := fmtEvents(got); !slices.Equal(g, all) {
				t.Errorf("filtered\n got %q\nwant %q", g, all)
			}
		})
	}
}

// Defeat 3: the reader neither sorts nor merges by time.
func TestServerEventsKeepJournalOrder(t *testing.T) {
	for _, c := range journalCases {
		t.Run(c.name, func(t *testing.T) {
			lines := strings.Split(strings.TrimSpace(fixture(t, c.file)), "\n")
			slices.Reverse(lines)
			r := &fakeRunner{reply: strings.Join(lines, "\n") + "\n"}
			got, err := c.adapter(r).ServerEvents(context.Background(), eventsSince, "")
			if err != nil {
				t.Fatal(err)
			}
			want := slices.Clone(c.want)
			slices.Reverse(want)
			if g := fmtEvents(got); !slices.Equal(g, want) {
				t.Errorf("order changed\n got %q\nwant %q", g, want)
			}
		})
	}
}

// Defeat 6: dropped lines make every later count short.
func TestServerEventsSuppressedFailsLoudly(t *testing.T) {
	for _, c := range journalCases {
		t.Run(c.name, func(t *testing.T) {
			reply := fixture(t, c.file) + "2026-10-11T12:11:00+0000 lab systemd-journald[200]: Suppressed 42 messages from " + c.unit + ".service\n"
			got, err := c.adapter(&fakeRunner{reply: reply}).ServerEvents(context.Background(), eventsSince, "")
			if !errors.Is(err, ErrJournalSuppressed) {
				t.Fatalf("err = %v", err)
			}
			if got != nil {
				t.Errorf("a partial list came back with the error: %q", fmtEvents(got))
			}
		})
	}
}

// A line of a shape the parser knows that it cannot read is a finding,
// not noise.
func TestServerEventsKnownShapeThatDoesNotParseIsAnError(t *testing.T) {
	ts := "2026-10-11T12:00:05+0000 lab x[1]: "
	cases := []struct {
		name string
		a    func(Runner) Adapter
		line string
	}{
		{"kea without hwtype", journalCases[0].adapter, ts + "INFO  DHCP4_LEASE_ALLOC lease 10.200.1.150 has been allocated for 3600 seconds"},
		{"kea without timestamp", journalCases[0].adapter, "garbage DHCP4_LEASE_ALLOC [hwtype=1 " + m1 + "], cid=[01], tid=0x1: lease 10.200.1.150"},
		{"isc without mac", journalCases[1].adapter, ts + "DHCPACK on 10.200.1.150 to nobody via eth1"},
		{"isc without timestamp", journalCases[1].adapter, "garbage DHCPACK on 10.200.1.150 to " + m1 + " via eth1"},
		{"dnsmasq without mac", journalCases[2].adapter, ts + "DHCPACK(eth1) 10.200.1.150 nobody"},
		{"dnsmasq without timestamp", journalCases[2].adapter, "garbage DHCPACK(eth1) 10.200.1.150 " + m1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.a(&fakeRunner{reply: c.line + "\n"}).ServerEvents(context.Background(), eventsSince, "")
			if err == nil || got != nil {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func TestServerEventsEmptyJournalIsAnEmptyListNotAnError(t *testing.T) {
	for _, c := range journalCases {
		got, err := c.adapter(&fakeRunner{reply: "-- No entries --\n"}).ServerEvents(context.Background(), eventsSince, "")
		if err != nil || len(got) != 0 {
			t.Errorf("%s: got %+v, %v", c.name, got, err)
		}
	}
}

func TestServerEventsPropagatesTheJournalFailure(t *testing.T) {
	boom := errors.New("ssh: connection refused")
	for _, c := range journalCases {
		if _, err := c.adapter(&fakeRunner{err: boom}).ServerEvents(context.Background(), eventsSince, ""); !errors.Is(err, boom) {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

func TestServerEventsCommandCarriesNoCallerText(t *testing.T) {
	// A non-UTC zone: the command must render the UTC instant.
	since := time.Date(2026, 10, 11, 14, 0, 0, 0, time.FixedZone("x", 2*3600))
	for _, c := range journalCases {
		t.Run(c.name, func(t *testing.T) {
			r := &fakeRunner{reply: fixture(t, c.file)}
			if _, err := c.adapter(r).ServerEvents(context.Background(), since, m1); err != nil {
				t.Fatal(err)
			}
			want := "sudo journalctl -u " + c.unit + " -o short-iso --no-pager --since '2026-10-11 12:00:00 UTC'"
			if len(r.calls) != 1 || r.calls[0] != want {
				t.Fatalf("calls %q, want [%q]", r.calls, want)
			}
		})
	}
	for _, c := range journalCases {
		for _, bad := range []string{`02:aa:bb:cc:dd:01'; rm -rf / #`, "$(reboot)", "not-a-mac"} {
			r := &fakeRunner{reply: fixture(t, c.file)}
			if _, err := c.adapter(r).ServerEvents(context.Background(), eventsSince, bad); err == nil || len(r.calls) != 0 {
				t.Errorf("%s: mac %q: err %v, calls %q", c.name, bad, err, r.calls)
			}
		}
	}
}

func TestServerEventsRefusesZeroSince(t *testing.T) {
	for _, c := range journalCases {
		r := &fakeRunner{reply: fixture(t, c.file)}
		if _, err := c.adapter(r).ServerEvents(context.Background(), time.Time{}, ""); err == nil || len(r.calls) != 0 {
			t.Errorf("%s: err %v, calls %q", c.name, err, r.calls)
		}
	}
}

func TestJournalTimeAcceptsTheShortISOForms(t *testing.T) {
	want := time.Date(2026, 10, 11, 10, 0, 5, 0, time.UTC)
	for _, f := range []string{"2026-10-11T12:00:05+0200", "2026-10-11T12:00:05+02:00", "2026-10-11T10:00:05+0000", "2026-10-11T10:00:05.000000+0000"} {
		got, err := journalTime(f + " host unit[1]: x")
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: %v, %v", f, got, err)
		}
	}
	if _, err := journalTime("Oct 11 12:00:05 host unit[1]: x"); err == nil {
		t.Error("a syslog-form stamp was accepted as short-iso")
	}
}

// Capability scope (lab #15): the three Debian sources declare it, the
// appliances and the pairs do not and say why, a relay forwards it.
func TestServerEventsCapabilityScope(t *testing.T) {
	ctx := context.Background()
	for _, c := range journalCases {
		if !slices.Contains(c.adapter(nil).Capabilities(), CapServerEvents) {
			t.Errorf("%s does not declare %s", c.name, CapServerEvents)
		}
	}
	absent := map[string]Adapter{
		"udhcpd":   &UdhcpdAdapter{},
		"pihole":   &PiholeAdapter{},
		"openwrt":  &OpenwrtAdapter{},
		"routeros": &RouterOSAdapter{},
		"windows":  &WindowsAdapter{},
	}
	for name, a := range absent {
		if slices.Contains(a.Capabilities(), CapServerEvents) {
			t.Errorf("%s declares %s", name, CapServerEvents)
		}
		why, ok := a.(NAExplainer).NAReason(CapServerEvents)
		if !ok || why == "" {
			t.Errorf("%s gives no reason for the absent %s", name, CapServerEvents)
		}
		if got, err := a.ServerEvents(ctx, eventsSince, ""); err == nil || got != nil {
			t.Errorf("%s answered ServerEvents: %v, %v", name, got, err)
		}
	}

	ra, rb := &fakeRunner{}, &fakeRunner{}
	for name, p := range map[string]*PairAdapter{"kea pair": NewKeaPair(ra, rb, "a", "b"), "isc pair": NewISCPair(ra, rb, "a", "b")} {
		if slices.Contains(p.Capabilities(), CapServerEvents) {
			t.Errorf("%s declares %s", name, CapServerEvents)
		}
		if why, ok := p.NAReason(CapServerEvents); !ok || !strings.Contains(why, "two journals") {
			t.Errorf("%s reason: %q, %v", name, why, ok)
		}
		if _, err := p.ServerEvents(ctx, eventsSince, ""); err == nil {
			t.Errorf("%s answered ServerEvents", name)
		}
	}
	if len(ra.calls)+len(rb.calls) != 0 {
		t.Errorf("a pair read a peer's journal: %q %q", ra.calls, rb.calls)
	}

	rr := &fakeRunner{reply: fixture(t, "journal-kea.txt")}
	relayed := WithRelay(&KeaAdapter{Runner: rr}, &fakeRunner{}, RelayParams{})
	if !slices.Contains(relayed.Capabilities(), CapServerEvents) {
		t.Error("a relayed Kea lost " + string(CapServerEvents))
	}
	got, err := relayed.ServerEvents(ctx, eventsSince, m1)
	if err != nil || len(got) == 0 || len(rr.calls) != 1 {
		t.Errorf("relayed ServerEvents: %d events, %v, calls %q", len(got), err, rr.calls)
	}
}

// The filter compares lower case on both sides whatever case the source
// prints (the ledger and Kea differ), so an upper-case journal MAC still
// matches a lower-case argument.
func TestServerEventsMACCaseIsNormalisedOnTheJournalSide(t *testing.T) {
	up := strings.ToUpper(m1)
	ts := "2026-10-11T12:00:05+0000 lab x[1]: "
	lines := map[string]string{
		"kea":      ts + "INFO  DHCP4_LEASE_ALLOC [hwtype=1 " + up + "], cid=[01], tid=0x1: lease 10.200.1.150 has been allocated",
		"isc-dhcp": ts + "DHCPACK on 10.200.1.150 to " + up + " via eth1",
		"dnsmasq":  ts + "DHCPACK(eth1) 10.200.1.150 " + up + " h",
	}
	for _, c := range journalCases {
		got, err := c.adapter(&fakeRunner{reply: lines[c.name] + "\n"}).ServerEvents(context.Background(), eventsSince, m1)
		if err != nil || len(got) != 1 || got[0].MAC != m1 {
			t.Errorf("%s: %+v, %v", c.name, got, err)
		}
	}
}

// Newer Kea names the offer DHCP4_LEASE_OFFER; the lease-cache message
// DHCP4_LEASE_REUSE has no measured packet type, so it fails the read
// instead of dropping an ACK silently.
func TestKeaJournalRenamedOfferAndUnmappedReuse(t *testing.T) {
	ts := "2026-10-11T12:00:05+0000 lab x[1]: INFO  "
	offer := ts + "DHCP4_LEASE_OFFER [hwtype=1 " + m1 + "], cid=[01], tid=0x1: lease 10.200.1.150 will be offered\n"
	got, err := (&KeaAdapter{Runner: &fakeRunner{reply: offer}}).ServerEvents(context.Background(), eventsSince, "")
	if err != nil || len(got) != 1 || got[0].Type != "OFFER" || got[0].IP != "10.200.1.150" {
		t.Errorf("offer: %+v, %v", got, err)
	}
	reuse := ts + "DHCP4_LEASE_REUSE [hwtype=1 " + m1 + "], cid=[01], tid=0x2: lease 10.200.1.150 has been reused\n"
	got, err = (&KeaAdapter{Runner: &fakeRunner{reply: reuse}}).ServerEvents(context.Background(), eventsSince, "")
	if err == nil || got != nil {
		t.Errorf("reuse: %+v, %v", got, err)
	}
}

// dnsmasq logs DHCPv6 REQUEST, RELEASE and DECLINE under the v4 names with
// a DUID or v6 address after the interface; none is a v4 event, and none
// fails the read.
func TestDnsmasqJournalIgnoresDHCPv6WithTheV4Names(t *testing.T) {
	ts := "2026-10-11T12:00:05+0000 lab x[1]: "
	duid := "00:01:00:01:2a:bb:cc:dd:02:aa:bb:cc:dd:01"
	for _, l := range []string{
		ts + "DHCPREQUEST(eth1) " + duid + " h",
		ts + "DHCPRELEASE(eth1) 00:03:00:01:02:aa:bb:cc:dd:01",
		ts + "DHCPDECLINE(eth1) fd42:200::1:5 " + duid,
		ts + "DHCPSOLICIT(eth1) " + duid,
	} {
		got, err := (&DnsmasqAdapter{Runner: &fakeRunner{reply: l + "\n"}}).ServerEvents(context.Background(), eventsSince, "")
		if err != nil || len(got) != 0 {
			t.Errorf("%q: %+v, %v", l, got, err)
		}
	}
}
