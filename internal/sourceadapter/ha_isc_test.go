package sourceadapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func isc(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "isc-failover", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Defeat 1 (lab #12): dhcpd appends a state block at every change, so
// the LAST block is the live state; the first is history. The fixtures
// are trimmed excerpts of files measured on dhcpd 4.4.3-P1.
func TestParseISCHAStateReadsTheLastBlock(t *testing.T) {
	for _, tc := range []struct{ file, want string }{
		{"primary-normal.leases", ISCNormal},
		{"partner-normal.leases", ISCNormal},
		{"primary-recover.leases", "recover"},
		{"partner-comm-interrupted.leases", ISCCommunicationsInterrupted},
		{"primary-partner-down.leases", ISCPartnerDown},
	} {
		st, err := parseISCHAState(isc(t, tc.file))
		if err != nil || st.State != tc.want {
			t.Errorf("%s: state %q, err %v, want %q", tc.file, st.State, err, tc.want)
		}
	}
	two := "failover peer \"lab\" state {\n  my state normal at 6 2026/10/10 15:00:00;\n}\nfailover peer \"lab\" state {\n  my state startup at 6 2026/10/10 15:01:00;\n}\n"
	if st, err := parseISCHAState(two); err != nil || st.State != "startup" {
		t.Errorf("two blocks: %q %v, want the second", st.State, err)
	}
}

func TestParseISCHAStateRefusesATruncatedBlock(t *testing.T) {
	raw := isc(t, "partner-comm-interrupted.leases")
	cut := raw[:strings.LastIndex(raw, "failover peer \"lab\" state {")] + "failover peer \"lab\" state {\n  my state normal at 6 2026/10/10 1"
	if st, err := parseISCHAState(cut); err == nil {
		t.Fatalf("a cut block returned %q", st.State)
	}
}

// A state block wins over the live query; only a file with none asks
// omshell, once.
func TestISCHAStateFallsBackToOmshellOnlyWithoutABlock(t *testing.T) {
	ctx := context.Background()
	r := &scriptRunner{replies: map[string]string{"sudo cat": isc(t, "primary-normal.leases"), "printf": isc(t, "omshell-ci.txt")}}
	st, err := ISCHAState(ctx, r)
	if err != nil || st.State != ISCNormal {
		t.Fatalf("with a block: %q %v", st.State, err)
	}
	if omshellRuns(r) != 0 {
		t.Errorf("omshell ran %d time(s) beside a state block", omshellRuns(r))
	}
	r = &scriptRunner{replies: map[string]string{"sudo cat": isc(t, "no-block.leases"), "printf": isc(t, "omshell-ci.txt")}}
	st, err = ISCHAState(ctx, r)
	if err != nil || st.State != ISCCommunicationsInterrupted || omshellRuns(r) != 1 {
		t.Errorf("without a block: %q %v, omshell runs %d", st.State, err, omshellRuns(r))
	}
	r = &scriptRunner{replies: map[string]string{"sudo cat": isc(t, "no-block.leases")}, fail: map[string]bool{"printf": true}}
	if _, err = ISCHAState(ctx, r); err == nil {
		t.Error("a failed omshell passed")
	}
}

func omshellRuns(r *scriptRunner) int {
	n := 0
	for _, c := range r.calls {
		if strings.Contains(c, "omshell") {
			n++
		}
	}
	return n
}

func TestParseISCOmshell(t *testing.T) {
	for _, tc := range []struct{ file, want string }{
		{"omshell-recover.txt", "startup"}, {"omshell-normal.txt", ISCNormal}, {"omshell-ci.txt", ISCCommunicationsInterrupted},
	} {
		st, err := parseISCOmshell(isc(t, tc.file))
		if err != nil || st.State != tc.want {
			t.Errorf("%s: %q %v, want %q", tc.file, st.State, err, tc.want)
		}
	}
	if _, err := parseISCOmshell("local-state = 00:00:00:63"); err == nil {
		t.Error("an unknown local-state code passed")
	}
	if _, err := parseISCOmshell("connection refused"); err == nil {
		t.Error("a reply without local-state passed")
	}
}

// The primary's backup addresses are the partner's half (split 128).
func TestParseISCBackupAddrs(t *testing.T) {
	got, err := parseISCBackupAddrs(isc(t, "primary-normal.leases"))
	if err != nil || len(got) == 0 {
		t.Fatalf("backup addrs: %v %v", got, err)
	}
	if !slices.IsSorted(got) {
		t.Errorf("not sorted: %v", got)
	}
	for _, a := range got {
		if !strings.Contains(isc(t, "primary-normal.leases"), "lease "+a+" {") {
			t.Errorf("%s is not a lease in the file", a)
		}
	}
	none, err := parseISCBackupAddrs(isc(t, "no-block.leases"))
	if err != nil || len(none) != 0 {
		t.Errorf("a file without backup leases gave %v %v", none, err)
	}
	if _, err := parseISCBackupAddrs("lease 10.0.0.1 {\n  binding state backup;\n"); err == nil {
		t.Error("a truncated lease block passed")
	}
}

// Defeat 2 (lab #12): parseISCLeases keeps active leases from a
// failover file and drops expired, free and backup ones.
func TestParseISCLeasesAcceptsFailoverFiles(t *testing.T) {
	for _, f := range []string{"primary-normal.leases", "partner-normal.leases", "partner-comm-interrupted.leases", "primary-recover.leases", "primary-partner-down.leases"} {
		ls, err := parseISCLeases(isc(t, f))
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		raw := isc(t, f)
		for _, l := range ls {
			if !strings.Contains(raw, "lease "+l.Address+" {") {
				t.Errorf("%s: lease %s is not in the file", f, l.Address)
			}
		}
	}
	ls, _ := parseISCLeases(isc(t, "partner-comm-interrupted.leases"))
	var got []string
	for _, l := range ls {
		got = append(got, l.Address)
	}
	if !slices.Contains(got, "10.200.9.149") {
		t.Errorf("active 10.200.9.149 missing from %v", got)
	}
	if slices.Contains(got, "10.200.9.150") {
		t.Errorf("expired 10.200.9.150 listed: %v", got)
	}
	p, _ := parseISCLeases(isc(t, "primary-normal.leases"))
	back, _ := parseISCBackupAddrs(isc(t, "primary-normal.leases"))
	for _, l := range p {
		if slices.Contains(back, l.Address) {
			t.Errorf("backup address %s listed as a lease", l.Address)
		}
	}
}

func TestNewISCPairShape(t *testing.T) {
	p := NewISCPair(&fakeRunner{}, &fakeRunner{}, "10.200.9.2", "10.200.9.3")
	if got := p.PeerNames(); !slices.Equal(got, []string{"primary", "partner"}) {
		t.Fatalf("peers %v", got)
	}
	pr, pa := p.Peers[0].Adapter.(*ISCDHCPAdapter), p.Peers[1].Adapter.(*ISCDHCPAdapter)
	if pr.V4Only || !pa.V4Only || !pr.Failover || !pa.Failover {
		t.Errorf("primary v4only %v failover %v; partner v4only %v failover %v", pr.V4Only, pr.Failover, pa.V4Only, pa.Failover)
	}
	if id, _ := p.PeerServerID("partner"); id != "10.200.9.3" {
		t.Errorf("partner server id %q", id)
	}
	prof := p.Profile()
	if prof.Normal != ISCNormal || prof.Survivor != ISCCommunicationsInterrupted || prof.StandbySilent || !prof.SplitPool {
		t.Errorf("profile %+v", prof)
	}
	if p.NormalWait != 60*time.Second || p.NormalPoll != time.Second {
		t.Errorf("wait %s poll %s", p.NormalWait, p.NormalPoll)
	}
}

// The pair declares what isc-dhcp declares, less impair and renumber
// (a lone peer's edit would break the pair), with v6 from the primary
// alone; the partner is v4-only.
func TestISCPairCapabilities(t *testing.T) {
	p := NewISCPair(&fakeRunner{}, &fakeRunner{}, "a", "b")
	caps := p.Capabilities()
	for _, c := range []Capability{CapImpair, CapRenumber} {
		if slices.Contains(caps, c) {
			t.Errorf("pair declares %s", c)
		}
	}
	if !slices.Contains(caps, CapFailoverPair) {
		t.Error("pair lacks CapFailoverPair")
	}
	for _, c := range (&ISCDHCPAdapter{}).Capabilities() {
		if c != CapImpair && c != CapRenumber && !slices.Contains(caps, c) {
			t.Errorf("pair lost isc-dhcp's %s", c)
		}
	}
	for _, c := range p.Peers[1].Adapter.Capabilities() {
		if v6Capabilities[c] {
			t.Errorf("partner declares v6 capability %s", c)
		}
	}
}

// Defeat 4 (lab #12): a reset peer must not pull the partner's old
// table back through the failover sync, so both stop before either
// is truncated and started.
func TestISCPairResetLeasesStopsBothFirst(t *testing.T) {
	var log []string
	rr := func(name string) Runner { return logRunner{name: name, log: &log} }
	p := NewISCPair(rr("primary"), rr("partner"), "a", "b")
	p.NormalWait = 0
	_ = p.ResetLeases(context.Background())
	idx := func(sub string) int {
		for i, l := range log {
			if strings.Contains(l, sub) {
				return i
			}
		}
		return -1
	}
	stop := func(n string) int { return idx(n + ": sudo systemctl stop") }
	for _, n := range []string{"primary", "partner"} {
		if stop(n) < 0 {
			t.Fatalf("%s was never stopped: %v", n, log)
		}
	}
	firstTrunc := -1
	for i, l := range log {
		if strings.Contains(l, "truncate") {
			firstTrunc = i
			break
		}
	}
	if firstTrunc < 0 || stop("primary") > firstTrunc || stop("partner") > firstTrunc {
		t.Errorf("a peer was truncated before both were stopped: %v", log)
	}
}

type logRunner struct {
	name string
	log  *[]string
}

func (l logRunner) Run(_ context.Context, cmd string) (string, error) {
	*l.log = append(*l.log, l.name+": "+cmd)
	return "", nil
}

func TestISCPairPeerBackupAddrs(t *testing.T) {
	p := NewISCPair(&fakeRunner{reply: isc(t, "primary-normal.leases")}, &fakeRunner{}, "a", "b")
	got, err := p.PeerBackupAddrs(context.Background(), "primary")
	if err != nil || len(got) == 0 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := p.PeerBackupAddrs(context.Background(), "nobody"); err == nil {
		t.Error("an unknown peer passed")
	}
	k := NewKeaPair(&fakeRunner{}, &fakeRunner{}, "a", "b")
	if _, err := k.PeerBackupAddrs(context.Background(), "primary"); err == nil || errors.Is(err, nil) {
		t.Error("a kea peer answered a backup-half read")
	}
}

// A restarted peer's lease file still ends in its pre-stop normal block
// (lab #12): Restart must not pass on the file alone, only on
// the daemon's own answer.
func TestISCPairRestartIgnoresAStaleNormalBlock(t *testing.T) {
	mk := func(file, om string) *scriptRunner {
		return &scriptRunner{replies: map[string]string{"sudo cat": isc(t, file), "printf": isc(t, om)}}
	}
	pr, pa := mk("primary-normal.leases", "omshell-recover.txt"), mk("partner-normal.leases", "omshell-normal.txt")
	p := NewISCPair(pr, pa, "a", "b")
	p.NormalWait, p.NormalPoll = 20*time.Millisecond, time.Millisecond
	for i, r := range []*scriptRunner{pr, pa} {
		if st, err := ISCHAState(context.Background(), r); err != nil || st.State != ISCNormal {
			t.Fatalf("peer %d: the fixture's file must read normal, got %q %v", i, st.State, err)
		}
	}
	err := p.Restart(context.Background())
	if err == nil || !strings.Contains(err.Error(), "primary: startup") {
		t.Fatalf("a primary the daemon reports in startup passed on its stale file: %v", err)
	}
	pr.replies["printf"] = isc(t, "omshell-normal.txt")
	if err := p.Restart(context.Background()); err != nil {
		t.Errorf("both daemons normal: %v", err)
	}
}

func TestISCLiveStateNeedsARunningDaemon(t *testing.T) {
	r := &scriptRunner{replies: map[string]string{"printf": "can't connect to OMAPI server\n"}}
	if st, err := ISCLiveState(context.Background(), r); err == nil {
		t.Errorf("no daemon answered, got %q", st.State)
	}
	r = &scriptRunner{fail: map[string]bool{"printf": true}}
	if _, err := ISCLiveState(context.Background(), r); err == nil {
		t.Error("a failed omshell passed")
	}
}
