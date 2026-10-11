package sourceadapter

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// iscRunner answers each command by substring and records the calls, so
// a test can feed the lease file, the reservation include and dhcpd's
// log separately (#70).
type iscRunner struct {
	leases, resv, journal string
	resvErr, journalErr   error
	calls                 []string
}

func (r *iscRunner) Run(_ context.Context, cmd string) (string, error) {
	r.calls = append(r.calls, cmd)
	switch {
	case strings.Contains(cmd, "journalctl"):
		return r.journal, r.journalErr
	case strings.Contains(cmd, "lab-reservations.conf"):
		return r.resv, r.resvErr
	case strings.Contains(cmd, "dhcpd.leases"):
		return r.leases, nil
	}
	return "", nil
}

const (
	iscResvMAC = "host lab-021122334455 { hardware ethernet 02:11:22:33:44:55; fixed-address 10.200.1.211; }\n"
	iscResvCID = "host lab-cid-006c61622d663262 { option dhcp-client-identifier 00:6c:61:62:2d:66:32:62; fixed-address 10.200.1.212; }\n"
	iscAckMAC  = "DHCPDISCOVER from 02:11:22:33:44:55 via eth1\nDHCPOFFER on 10.200.1.211 to 02:11:22:33:44:55 via eth1\nDHCPREQUEST for 10.200.1.211 (10.200.1.2) from 02:11:22:33:44:55 via eth1\nDHCPACK on 10.200.1.211 to 02:11:22:33:44:55 via eth1\n"
)

func iscLeases(t *testing.T, r *iscRunner) []Lease {
	t.Helper()
	got, err := (&ISCDHCPAdapter{Runner: r}).Leases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// 4a: the run's shape, a lease file with no block for the reserved
// address, the host block in the include, an ACK in dhcpd's log.
func TestISCLeasesReturnsAHeldReservation(t *testing.T) {
	got := iscLeases(t, &iscRunner{leases: "# dhcpd.leases\n", resv: iscResvMAC, journal: iscAckMAC})
	if len(got) != 1 || got[0].Address != "10.200.1.211" || got[0].MAC != "02:11:22:33:44:55" || !got[0].Reserved {
		t.Fatalf("held reservation not returned as a reserved row: %+v", got)
	}
}

// 4b: a dynamic lease is the lease file's row, untouched, and a host
// with no reservations costs no log read.
func TestISCLeasesKeepsDynamicRowsUnchanged(t *testing.T) {
	raw := "lease 10.200.1.100 {\n  binding state active;\n  hardware ethernet 02:aa:bb:cc:dd:01;\n  ends 3 2026/10/11 12:00:00;\n}\n"
	want, err := parseISCLeases(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := &iscRunner{leases: raw}
	got := iscLeases(t, r)
	if len(got) != 1 || got[0] != want[0] || got[0].Reserved {
		t.Fatalf("dynamic row changed: %+v want %+v", got, want)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "journalctl") {
			t.Fatalf("log read without any reservation: %q", c)
		}
	}
}

// 4c: a reservation nobody holds is not a lease (B1/B2 would pass on it).
func TestISCLeasesOmitsAReservationNoClientHolds(t *testing.T) {
	got := iscLeases(t, &iscRunner{leases: "", resv: iscResvMAC + iscResvCID, journal: "DHCPDISCOVER from 02:11:22:33:44:55 via eth1\nDHCPOFFER on 10.200.1.211 to 02:11:22:33:44:55 via eth1\n"})
	if len(got) != 0 {
		t.Fatalf("unheld reservation shown as a lease: %+v", got)
	}
}

// 4d: the last event decides (C6 asserts no active lease after DECLINE).
func TestISCLeasesDropsAReservationAfterReleaseOrDecline(t *testing.T) {
	mac := "02:11:22:33:44:55"
	ack := "DHCPACK on 10.200.1.211 to " + mac + " via eth1\n"
	cases := []struct {
		name, journal string
		want          int
	}{
		{"ack", ack, 1},
		{"ack then release", ack + "DHCPRELEASE of 10.200.1.211 from " + mac + " via eth1 (found)\n", 0},
		{"ack then decline", ack + "DHCPDECLINE of 10.200.1.211 from " + mac + " via eth1: abandoned\n", 0},
		{"ack release ack", ack + "DHCPRELEASE of 10.200.1.211 from " + mac + " via eth1 (found)\n" + ack, 1},
		{"ack to another client", "DHCPACK on 10.200.1.211 to 02:de:ad:be:ef:01 via eth1\n", 0},
	}
	for _, c := range cases {
		if got := iscLeases(t, &iscRunner{resv: iscResvMAC, journal: c.journal}); len(got) != c.want {
			t.Errorf("%s: %d rows, want %d: %+v", c.name, len(got), c.want, got)
		}
	}
}

// 4e: a client-id reservation carries the same spelling a uid lease row
// does (lowercase colon-hex, type byte included), which findLeaseByClientID compares.
func TestISCReservedRowClientIDMatchesTheUIDSpelling(t *testing.T) {
	uid, err := parseISCLeases("lease 10.200.1.100 {\n  binding state active;\n  uid \"\\000lab-f2b\";\n}\n")
	if err != nil {
		t.Fatal(err)
	}
	got := iscLeases(t, &iscRunner{resv: iscResvCID, journal: "DHCPACK on 10.200.1.212 to 02:11:22:33:44:56 via eth1\n"})
	if len(got) != 1 || got[0].ClientID != uid[0].ClientID || got[0].MAC != "02:11:22:33:44:56" {
		t.Fatalf("cid row %+v, uid spelling %q", got, uid[0].ClientID)
	}
}

// 4f, 4g: failures are loud, and the log is read from the unit's
// current activation only (a restart or ResetLeases starts a new one).
func TestISCLeasesLogReadIsScopedAndItsErrorsPropagate(t *testing.T) {
	r := &iscRunner{resv: iscResvMAC, journal: iscAckMAC}
	iscLeases(t, r)
	j := r.calls[len(r.calls)-1]
	for _, w := range []string{"ActiveEnterTimestamp", "isc-dhcp-server", "--since"} {
		if !strings.Contains(j, w) {
			t.Errorf("log read %q lacks %q", j, w)
		}
	}
	for name, rr := range map[string]*iscRunner{
		"reservations": {resv: iscResvMAC, resvErr: errors.New("boom")},
		"journal":      {resv: iscResvMAC, journalErr: errors.New("boom")},
	} {
		if _, err := (&ISCDHCPAdapter{Runner: rr}).Leases(context.Background()); err == nil {
			t.Errorf("%s read error swallowed", name)
		}
	}
}

// refuseReservationReads fails the two reads Leases adds to the lease file.
type refuseReservationReads struct{ Runner }

func (r refuseReservationReads) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "lab-reservations.conf") || strings.Contains(cmd, "journalctl") {
		return "", errors.New("reservation read reached Ready")
	}
	return r.Runner.Run(ctx, cmd)
}

// Ready only needs the lease file readable; the log read never decides it.
func TestISCReadyDoesNotReadTheReservationLog(t *testing.T) {
	a := &ISCDHCPAdapter{Runner: refuseReservationReads{healthyHost()}}
	if err := a.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// 5a, 5b, 5d: the run's config (the template) after the shorten holds
// both directives, once, in the file isc reads, written before the restart.
func TestISCShortenSetsDefaultAndMinLeaseTime(t *testing.T) {
	orig := baselineConfig(t, baselines["isc-dhcp"].tmpl, "/etc/dhcp/dhcpd.conf")
	r2 := &fakeRunner{reply: orig}
	restore, err := (&ISCDHCPAdapter{Runner: r2}).ShortenLeaseTime(context.Background(), 120)
	if err != nil {
		t.Fatal(err)
	}
	var write, restart = -1, -1
	for i, c := range r2.calls {
		if strings.HasPrefix(c, "sudo tee /etc/dhcp/dhcpd.conf") {
			write = i
			if w := "default-lease-time 120;\nmin-lease-time 120;\nmax-lease-time 7200;\n"; !strings.Contains(c, w) {
				t.Errorf("shortened conf lacks %q:\n%s", w, c)
			}
		}
		if c == "sudo systemctl restart isc-dhcp-server" {
			restart = i
		}
	}
	if write < 0 || restart < write {
		t.Fatalf("write at %d, restart at %d: %q", write, restart, r2.calls)
	}
	r2.calls = nil
	if err := restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r2.calls[0]; got != "sudo tee /etc/dhcp/dhcpd.conf >/dev/null <<'LABEOF'\n"+orig+"LABEOF\n" {
		t.Fatalf("restore is not the captured config byte for byte: %q", got)
	}
}

// 5b: a config that already has a min-lease-time line gets it rewritten, not a second one.
func TestISCShortenRewritesAnExistingMinLeaseTime(t *testing.T) {
	got := shortenISCConf("default-lease-time 600;\nmin-lease-time 30;\nmax-lease-time 7200;\n", 120)
	if got != "default-lease-time 120;\nmin-lease-time 120;\nmax-lease-time 7200;\n" {
		t.Fatalf("got %q", got)
	}
	if shortenISCConf("authoritative;\n", 120) != "authoritative;\n" {
		t.Fatal("a conf without default-lease-time must come back unchanged")
	}
}
