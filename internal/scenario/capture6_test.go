package scenario

import (
	"context"
	"net/netip"
	"os/exec"
	"path/filepath"
	"testing"
)

// The Go reader parses what the shell decoder prints for the real and
// built captures, so the two never drift (#23 group D).
func TestMessages6ReadsTheDecoderOutput(t *testing.T) {
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Fatal("tcpdump not installed; verify.yml installs it")
	}
	root, _ := filepath.Abs("../..")
	run := func(pcap, ident string) ([]DHCP6Msg, []RAMsg) {
		out, err := exec.CommandContext(context.Background(), "bash", "-c", `. "$1"; dhcp6_message_log "$2" "$3"`,
			"t", root+"/scripts/dhcp-exchange-check.sh", root+"/scripts/testdata/v6/"+pcap, ident).Output()
		if err != nil {
			t.Fatal(err)
		}
		m, r, err := parseMessageLog6(string(out))
		if err != nil {
			t.Fatal(err)
		}
		return m, r
	}
	msgs, ras := run("isc-rapid-ta.pcap", "fe80::ff:fe00:23d1")
	if len(msgs) != 2 || len(ras) != 2 {
		t.Fatalf("isc: %d messages, %d RAs", len(msgs), len(ras))
	}
	r := msgs[1]
	if r.Type != "REPLY" || !r.Rapid || r.TA[0].Addr != netip.MustParseAddr("fd42:200:0:200::22f") || r.NA[0].Valid != 7200 || r.NA[0].Pref != 3600 || !HasAddr(r.TA) {
		t.Fatalf("isc Reply read as %+v", r)
	}
	if !ras[0].Managed || ras[0].Other || ras[0].RouterLifetime != 1800 || ras[1].RouterLifetime != 0 || !ras[0].PIOs[0].Auto ||
		ras[0].PIOs[0].Prefix != netip.MustParsePrefix("fd42:200:0:200::/64") {
		t.Fatalf("isc RAs read as %+v", ras)
	}
	msgs, ras = run("synth-mixed.pcap", "*")
	if len(ras) != 1 || len(ras[0].PIOs) != 2 || ras[0].PIOs[1].Auto || ras[0].Pref64[0] != netip.MustParsePrefix("64:ff9b::/96") || ras[0].Pref64Lifetimes[0] != 600 {
		t.Fatalf("synthetic RA read as %+v", ras)
	}
	a := msgs[3]
	if HasAddr(a.TA) || a.TA[0].IAID != 2 || a.PD[0].Prefix != netip.MustParsePrefix("fd42:200:0:9f0::/60") || a.PD[0].Valid != 3600 {
		t.Fatalf("synthetic Reply read as %+v", a)
	}
	if msgs[4].ClientDUID != "" {
		t.Fatalf("a Reply without option 1 read a DUID %q", msgs[4].ClientDUID)
	}
}

func TestParseMessageLog6RejectsMalformedLines(t *testing.T) {
	for _, bad := range []string{
		"1.0 REPLY ab - - 0 - - - fe80::1",
		"x REPLY ab - - 0 - - - fe80::1 fe80::2",
		"1.0 REPLY ab - - 0 1|fd42::1|3600 - - fe80::1 fe80::2",
		"1.0 REPLY ab - - 0 1|notanaddr|1|2 - - fe80::1 fe80::2",
		"1.0 RA fe80::1 1 1 1800 fd42::/64|1|7200 -",
		"1.0 RA fe80::1 1 1 1800 - 64:ff9b::/96",
		"1.0 RA fe80::1 1 1",
	} {
		if _, _, err := parseMessageLog6(bad); err == nil {
			t.Errorf("parseMessageLog6(%q) accepted", bad)
		}
	}
}
