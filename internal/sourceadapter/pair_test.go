package sourceadapter

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// fakePeer is one scripted pair member: every call lands in a shared
// log as "<name> <method>", and fail names the methods that error.
type fakePeer struct {
	name   string
	log    *[]string
	fail   map[string]bool
	leases []Lease
	caps   []Capability
}

func (f *fakePeer) rec(m string) error {
	*f.log = append(*f.log, f.name+" "+m)
	if f.fail[m] {
		return errors.New(f.name + " " + m + " failed")
	}
	return nil
}

func (f *fakePeer) restorable(m string) (func(context.Context) error, error) {
	if err := f.rec(m); err != nil {
		return nil, err
	}
	return func(context.Context) error { return f.rec("restore-" + m) }, nil
}

func (f *fakePeer) Capabilities() []Capability { return f.caps }
func (f *fakePeer) Leases(context.Context) ([]Lease, error) {
	if err := f.rec("Leases"); err != nil {
		return nil, err
	}
	return f.leases, nil
}
func (f *fakePeer) ReserveMAC(context.Context, string, string) error { return f.rec("ReserveMAC") }
func (f *fakePeer) ReserveClientID(context.Context, string, string) error {
	return f.rec("ReserveClientID")
}
func (f *fakePeer) SetDNSOption(context.Context, string) (func(context.Context) error, error) {
	return f.restorable("SetDNSOption")
}
func (f *fakePeer) Restart(context.Context) error           { return f.rec("Restart") }
func (f *fakePeer) Stop(context.Context) error              { return f.rec("Stop") }
func (f *fakePeer) Start(context.Context) error             { return f.rec("Start") }
func (f *fakePeer) Reachable(context.Context, string) error { return f.rec("Reachable") }
func (f *fakePeer) ResetLeases(context.Context) error       { return f.rec("ResetLeases") }
func (f *fakePeer) Ready(context.Context) error             { return f.rec("Ready") }
func (f *fakePeer) Recover(context.Context) error           { return f.rec("Recover") }
func (f *fakePeer) ShortenLeaseTime(context.Context, int) (func(context.Context) error, error) {
	return f.restorable("ShortenLeaseTime")
}
func (f *fakePeer) Impair(context.Context, time.Duration, int) (func(context.Context) error, error) {
	return f.restorable("Impair")
}
func (f *fakePeer) EnableFeature(context.Context, Feature, FeatureParams) (func(context.Context) error, error) {
	return f.restorable("EnableFeature")
}
func (f *fakePeer) SendForceRenew(context.Context, []byte, ForceRenewParams) (string, error) {
	return "sent", f.rec("SendForceRenew")
}
func (f *fakePeer) Squat(context.Context, string, bool) (func(context.Context) error, error) {
	return f.restorable("Squat")
}
func (f *fakePeer) StartRogue(context.Context, string, string, string) (func(context.Context) error, error) {
	return f.restorable("StartRogue")
}
func (f *fakePeer) RogueLeases(context.Context) ([]Lease, error) { return nil, f.rec("RogueLeases") }
func (f *fakePeer) NarrowPool(context.Context, string, string) (func(context.Context) error, error) {
	return f.restorable("NarrowPool")
}
func (f *fakePeer) Renumber(context.Context, string, string, string, string) (func(context.Context) error, error) {
	return f.restorable("Renumber")
}

type fakePair struct {
	log    []string
	a, b   *fakePeer
	states [2][]string // successive State() answers per peer; the last repeats
	pair   *PairAdapter
}

func newFakePair() *fakePair {
	fp := &fakePair{}
	fp.a = &fakePeer{name: "primary", log: &fp.log, fail: map[string]bool{}, caps: (&KeaAdapter{}).Capabilities()}
	fp.b = &fakePeer{name: "partner", log: &fp.log, fail: map[string]bool{}, caps: (&KeaAdapter{}).Capabilities()}
	fp.states = [2][]string{{KeaHotStandby}, {KeaHotStandby}}
	st := func(i int) func(context.Context) (HAState, error) {
		return func(context.Context) (HAState, error) {
			s := fp.states[i]
			cur := s[0]
			if len(s) > 1 {
				fp.states[i] = s[1:]
			}
			if cur == "ERR" {
				return HAState{}, errors.New("agent down")
			}
			return HAState{State: cur}, nil
		}
	}
	fp.pair = &PairAdapter{
		Peers: [2]PairPeer{
			{Name: "primary", Adapter: fp.a, ServerID: "10.200.8.2", State: st(0)},
			{Name: "partner", Adapter: fp.b, ServerID: "10.200.8.3", State: st(1)},
		},
		Normal: KeaHotStandby, NormalWait: 50 * time.Millisecond, NormalPoll: time.Millisecond,
	}
	return fp
}

func (fp *fakePair) calls() string { return strings.Join(fp.log, ",") }

// Defeat 1 (lab #12): a partner failure on each restorable change runs
// the primary's restore, and the error names the partner.
func TestPairFanOutPartnerFailureRestoresPrimary(t *testing.T) {
	ctx := context.Background()
	for _, m := range []string{"SetDNSOption", "ShortenLeaseTime", "EnableFeature", "NarrowPool"} {
		fp := newFakePair()
		fp.b.fail[m] = true
		var err error
		switch m {
		case "NarrowPool":
			_, err = fp.pair.NarrowPool(ctx, "10.200.8.100", "10.200.8.101")
		case "SetDNSOption":
			_, err = fp.pair.SetDNSOption(ctx, "10.200.8.253")
		case "ShortenLeaseTime":
			_, err = fp.pair.ShortenLeaseTime(ctx, 60)
		case "EnableFeature":
			_, err = fp.pair.EnableFeature(ctx, FeatureOffer108, FeatureParams{})
		}
		if err == nil || !strings.Contains(err.Error(), "partner") {
			t.Fatalf("%s: err %v, want one naming the partner", m, err)
		}
		want := "primary " + m + ",partner " + m + ",primary restore-" + m
		if fp.calls() != want {
			t.Fatalf("%s: calls %q, want %q", m, fp.calls(), want)
		}
	}
}

func TestPairFanOutRestoresInReverse(t *testing.T) {
	fp := newFakePair()
	restore, err := fp.pair.ShortenLeaseTime(context.Background(), 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "primary ShortenLeaseTime,partner ShortenLeaseTime,partner restore-ShortenLeaseTime,primary restore-ShortenLeaseTime"
	if fp.calls() != want {
		t.Fatalf("calls %q, want %q", fp.calls(), want)
	}
}

// The restore returns only when both peers are back in Normal.
func TestPairFanOutRestoreWaitsForNormal(t *testing.T) {
	fp := newFakePair()
	restore, err := fp.pair.ShortenLeaseTime(context.Background(), 60)
	if err != nil {
		t.Fatal(err)
	}
	fp.states[1] = []string{"syncing"}
	if err := restore(context.Background()); err == nil || !strings.Contains(err.Error(), "syncing") {
		t.Fatalf("restore returned %v with the partner still syncing", err)
	}
}

// A primary failure never touches the partner and needs no restore.
func TestPairFanOutPrimaryFailureStopsThere(t *testing.T) {
	fp := newFakePair()
	fp.a.fail["SetDNSOption"] = true
	if _, err := fp.pair.SetDNSOption(context.Background(), "10.200.8.253"); err == nil || !strings.Contains(err.Error(), "primary") {
		t.Fatalf("err %v", err)
	}
	if fp.calls() != "primary SetDNSOption" {
		t.Fatalf("calls %q", fp.calls())
	}
}

// The change landed on both but the pair never got back to normal: the
// change is undone and the call fails.
func TestPairFanOutNotNormalAfterChangeUndoes(t *testing.T) {
	fp := newFakePair()
	fp.states[1] = []string{"waiting"}
	if _, err := fp.pair.ShortenLeaseTime(context.Background(), 60); err == nil || !strings.Contains(err.Error(), "waiting") {
		t.Fatalf("err %v", err)
	}
	if !strings.HasSuffix(fp.calls(), "partner restore-ShortenLeaseTime,primary restore-ShortenLeaseTime") {
		t.Fatalf("calls %q", fp.calls())
	}
}

func TestPairStopPartnerFailureStartsPrimary(t *testing.T) {
	fp := newFakePair()
	fp.b.fail["Stop"] = true
	if err := fp.pair.Stop(context.Background()); err == nil || !strings.Contains(err.Error(), "partner") {
		t.Fatalf("err %v", err)
	}
	if fp.calls() != "primary Stop,partner Stop,primary Start" {
		t.Fatalf("calls %q", fp.calls())
	}
}

func TestPairStartPartnerFailureStopsPrimary(t *testing.T) {
	fp := newFakePair()
	fp.b.fail["Start"] = true
	if err := fp.pair.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "partner") {
		t.Fatalf("err %v", err)
	}
	if fp.calls() != "primary Start,partner Start,primary Stop" {
		t.Fatalf("calls %q", fp.calls())
	}
}

func TestPairStartWaitsForNormal(t *testing.T) {
	fp := newFakePair()
	fp.states[0] = []string{"waiting", "ready", KeaHotStandby}
	if err := fp.pair.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fp = newFakePair()
	fp.states[0] = []string{"waiting"}
	if err := fp.pair.Start(context.Background()); err == nil {
		t.Fatal("Start returned with the primary still waiting")
	}
}

func TestPairRestartBothThenNormal(t *testing.T) {
	fp := newFakePair()
	if err := fp.pair.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fp.calls() != "primary Restart,partner Restart" {
		t.Fatalf("calls %q", fp.calls())
	}
	fp = newFakePair()
	fp.states[1] = []string{"syncing"}
	if err := fp.pair.Restart(context.Background()); err == nil {
		t.Fatal("Restart returned with the partner still syncing")
	}
	fp = newFakePair()
	fp.b.fail["Restart"] = true
	if err := fp.pair.Restart(context.Background()); err == nil || !strings.Contains(err.Error(), "partner") {
		t.Fatalf("err %v", err)
	}
}

// Defeat 15: both peers stop before either table is cleared.
func TestPairResetLeasesStopsBothFirst(t *testing.T) {
	fp := newFakePair()
	if err := fp.pair.ResetLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fp.calls() != "primary Stop,partner Stop,primary ResetLeases,partner ResetLeases" {
		t.Fatalf("calls %q", fp.calls())
	}
	fp = newFakePair()
	fp.states[1] = []string{"syncing"}
	if err := fp.pair.ResetLeases(context.Background()); err == nil {
		t.Fatal("ResetLeases returned before the pair was normal")
	}
}

func TestPairReserveNamesFailingPeer(t *testing.T) {
	fp := newFakePair()
	fp.b.fail["ReserveMAC"] = true
	if err := fp.pair.ReserveMAC(context.Background(), "aa:bb:cc:dd:ee:ff", "10.200.8.211"); err == nil || !strings.Contains(err.Error(), "partner") {
		t.Fatalf("err %v", err)
	}
	fp = newFakePair()
	fp.a.fail["ReserveClientID"] = true
	if err := fp.pair.ReserveClientID(context.Background(), "01:aa", "10.200.8.211"); err == nil || !strings.Contains(err.Error(), "primary") {
		t.Fatalf("err %v", err)
	}
	if fp.calls() != "primary ReserveClientID" {
		t.Fatalf("calls %q", fp.calls())
	}
}

// Defeat 2: two identities on one address stay two entries; one
// identity on both tables is one entry with the later Expires.
func TestPairLeasesUnion(t *testing.T) {
	t0 := time.Unix(1000, 0)
	fp := newFakePair()
	fp.a.leases = []Lease{
		{MAC: "aa:00:00:00:00:01", Address: "10.200.8.100", Expires: t0},
		{MAC: "aa:00:00:00:00:02", Address: "10.200.8.101", ClientID: "ff:01", Expires: t0},
	}
	fp.b.leases = []Lease{
		{MAC: "aa:00:00:00:00:01", Address: "10.200.8.100", Expires: t0.Add(time.Minute)},
		{MAC: "aa:00:00:00:00:09", Address: "10.200.8.101", ClientID: "ff:09", Expires: t0},
		{MAC: "aa:00:00:00:00:03", Address: "10.200.8.102", Expires: t0},
	}
	ls, err := fp.pair.Leases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 4 {
		t.Fatalf("got %d entries, want 4: %+v", len(ls), ls)
	}
	if !ls[0].Expires.Equal(t0.Add(time.Minute)) {
		t.Fatalf("kept the earlier Expires: %v", ls[0].Expires)
	}
	n := 0
	for _, l := range ls {
		if l.Address == "10.200.8.101" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("two identities on 10.200.8.101 collapsed to %d", n)
	}
}

// A client id that differs while the MAC is shared (ipvlan) is a second
// identity, never merged into the first.
func TestPairLeasesKeysOnClientIDBeforeMAC(t *testing.T) {
	fp := newFakePair()
	fp.a.leases = []Lease{{MAC: "aa:00:00:00:00:01", Address: "10.200.8.100", ClientID: "ff:01"}}
	fp.b.leases = []Lease{{MAC: "aa:00:00:00:00:01", Address: "10.200.8.100", ClientID: "ff:02"}}
	ls, err := fp.pair.Leases(context.Background())
	if err != nil || len(ls) != 2 {
		t.Fatalf("got %v %+v, want 2 entries", err, ls)
	}
}

func TestPairLeasesOnePeerDown(t *testing.T) {
	fp := newFakePair()
	fp.a.fail["Leases"] = true
	fp.b.leases = []Lease{{MAC: "aa:00:00:00:00:01", Address: "10.200.8.100"}}
	ls, err := fp.pair.Leases(context.Background())
	if err != nil || len(ls) != 1 {
		t.Fatalf("one stopped peer blanked the union: %v %+v", err, ls)
	}
	fp.b.fail["Leases"] = true
	if _, err := fp.pair.Leases(context.Background()); err == nil {
		t.Fatal("no peer readable, yet no error")
	}
}

// Defeat 3: Ready needs both inner Ready and both peers normal.
func TestPairReady(t *testing.T) {
	ctx := context.Background()
	fp := newFakePair()
	if err := fp.pair.Ready(ctx); err != nil {
		t.Fatalf("both normal: %v", err)
	}
	for _, st := range []string{"waiting", "syncing", "ready", "partner-down", "ERR"} {
		fp = newFakePair()
		fp.states[1] = []string{st}
		if err := fp.pair.Ready(ctx); err == nil {
			t.Fatalf("partner %s read as ready", st)
		}
	}
	fp = newFakePair()
	fp.b.fail["Ready"] = true
	if err := fp.pair.Ready(ctx); err == nil || !strings.Contains(err.Error(), "partner") {
		t.Fatalf("err %v", err)
	}
}

func TestPairRecoverRunsBothThenWaits(t *testing.T) {
	fp := newFakePair()
	fp.a.fail["Recover"] = true
	if err := fp.pair.Recover(context.Background()); err == nil {
		t.Fatal("a failed Recover returned nil")
	}
	if fp.calls() != "primary Recover,partner Recover" {
		t.Fatalf("calls %q", fp.calls())
	}
	fp = newFakePair()
	fp.states[0] = []string{"waiting"}
	if err := fp.pair.Recover(context.Background()); err == nil {
		t.Fatal("Recover returned with the primary not normal")
	}
}

func TestPairCapabilities(t *testing.T) {
	fp := newFakePair()
	fp.b.caps = []Capability{CapV4, CapImpair, CapReserveMAC, CapRenumber, CapNarrowPool}
	got := fp.pair.Capabilities()
	want := []Capability{CapV4, CapReserveMAC, CapNarrowPool, CapFailoverPair}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if why, ok := fp.pair.NAReason(CapImpair); !ok || !strings.Contains(why, "split brain") {
		t.Fatalf("no C10 reason: %q", why)
	}
	if why, ok := fp.pair.NAReason(CapRenumber); !ok || !strings.Contains(why, "without the HA hook") {
		t.Fatalf("no C9 reason: %q", why)
	}
	if _, err := fp.pair.Impair(context.Background(), time.Second, 10); err == nil || fp.calls() != "" {
		t.Fatalf("impair reached a peer: err %v, calls %q", err, fp.calls())
	}
	if _, err := fp.pair.Renumber(context.Background(), "10.200.9.0/24", "10.200.9.2", "10.200.9.100", "10.200.9.199"); err == nil || fp.calls() != "" {
		t.Fatalf("renumber reached a peer: err %v, calls %q", err, fp.calls())
	}
	if _, ok := fp.pair.NAReason(CapV6); ok {
		t.Fatal("explained a capability it does not leave out")
	}
}

// Defeat 17: FORCERENEW leaves from the peer whose server-id it claims.
func TestPairSendForceRenewRoutesByServerID(t *testing.T) {
	fp := newFakePair()
	if _, err := fp.pair.SendForceRenew(context.Background(), nil, ForceRenewParams{Server: "10.200.8.3"}); err != nil {
		t.Fatal(err)
	}
	if fp.calls() != "partner SendForceRenew" {
		t.Fatalf("calls %q", fp.calls())
	}
	if _, err := fp.pair.SendForceRenew(context.Background(), nil, ForceRenewParams{Server: "10.200.8.9"}); err == nil {
		t.Fatal("an unknown server-id was sent from some peer")
	}
}

func TestPairReachableFallsBack(t *testing.T) {
	fp := newFakePair()
	fp.a.fail["Reachable"] = true
	if err := fp.pair.Reachable(context.Background(), "10.200.8.100"); err != nil {
		t.Fatal(err)
	}
	fp.b.fail["Reachable"] = true
	if err := fp.pair.Reachable(context.Background(), "10.200.8.100"); err == nil {
		t.Fatal("unreachable from both, yet nil")
	}
}

func TestPairControlByName(t *testing.T) {
	ctx := context.Background()
	fp := newFakePair()
	if n := fp.pair.PeerNames(); len(n) != 2 || n[0] != "primary" || n[1] != "partner" {
		t.Fatalf("names %v", n)
	}
	if id, err := fp.pair.PeerServerID("partner"); err != nil || id != "10.200.8.3" {
		t.Fatalf("%q %v", id, err)
	}
	if err := fp.pair.StopPeer(ctx, "partner"); err != nil {
		t.Fatal(err)
	}
	if err := fp.pair.StartPeer(ctx, "primary"); err != nil {
		t.Fatal(err)
	}
	if err := fp.pair.StartPeer(ctx, "partner"); err != nil {
		t.Fatal(err)
	}
	if _, err := fp.pair.PeerLeases(ctx, "partner"); err != nil {
		t.Fatal(err)
	}
	if fp.calls() != "partner Stop,primary Start,partner Start,partner Leases" {
		t.Fatalf("calls %q", fp.calls())
	}
	fp.states[1] = []string{KeaPartnerDown}
	if st, err := fp.pair.PeerState(ctx, "primary"); err != nil || st.State != KeaHotStandby {
		t.Fatalf("%+v %v", st, err)
	}
	if st, err := fp.pair.PeerState(ctx, "partner"); err != nil || st.State != KeaPartnerDown {
		t.Fatalf("%+v %v", st, err)
	}
	if err := fp.pair.StopPeer(ctx, "tertiary"); err == nil {
		t.Fatal("unknown peer accepted")
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/kea-ha/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The measured Kea 2.6.3 replies (lab #12, local run): each state reads
// back as itself, and only hot-standby is normal.
func TestParseKeaHAStateFixtures(t *testing.T) {
	for _, st := range []string{"waiting", "ready", "hot-standby", "partner-down"} {
		got, err := parseKeaHAState(readFixture(t, "status-get-"+st+".json"), readFixture(t, "ha-heartbeat-"+st+".json"))
		if err != nil {
			t.Fatalf("%s: %v", st, err)
		}
		if got.State != st || got.Clock.IsZero() || got.Raw == "" {
			t.Fatalf("%s: got %+v", st, got)
		}
	}
}

func TestParseKeaHAStateDisagreementIsAnError(t *testing.T) {
	_, err := parseKeaHAState(readFixture(t, "status-get-waiting.json"), readFixture(t, "ha-heartbeat-ready.json"))
	if err == nil || !strings.Contains(err.Error(), "ha-heartbeat says") {
		t.Fatalf("err %v", err)
	}
}

func TestParseKeaHAStateRejectsNonHAReplies(t *testing.T) {
	hb := readFixture(t, "ha-heartbeat-hot-standby.json")
	for _, sg := range []string{"", "[]", `[{"result":1,"text":"unsupported"}]`, `[{"result":0,"arguments":{"high-availability":[]}}]`} {
		if _, err := parseKeaHAState(sg, hb); err == nil {
			t.Fatalf("status-get %q read as a state", sg)
		}
	}
	sg := readFixture(t, "status-get-hot-standby.json")
	for _, h := range []string{"", `[{"result":1}]`, `[{"result":0,"arguments":{"state":"hot-standby","date-time":"yesterday"}}]`} {
		if _, err := parseKeaHAState(sg, h); err == nil {
			t.Fatalf("heartbeat %q read as a state", h)
		}
	}
}

func TestKeaHAStateIssuesBothCommands(t *testing.T) {
	r := &fakeRunner{err: errors.New("ssh down")}
	if _, err := KeaHAState(context.Background(), r); err == nil {
		t.Fatal("transport error swallowed")
	}
	if len(r.calls) != 1 || !strings.Contains(r.calls[0], `"command":"status-get"`) || !strings.Contains(r.calls[0], "127.0.0.1:8000") {
		t.Fatalf("calls %q", r.calls)
	}
	if !strings.Contains(keaHeartbeatCmd, `"command":"ha-heartbeat"`) {
		t.Fatal("heartbeat command lost")
	}
}

func TestKeaPairProfile(t *testing.T) {
	got := NewKeaPair(nil, nil, "a", "b").Profile()
	if got != (PairProfile{Normal: "hot-standby", Survivor: "partner-down", StandbySilent: true}) {
		t.Errorf("profile %+v", got)
	}
}

// The group C actors are hosts on the segment: one, from the primary's VM.
func TestPairActorsRunFromThePrimary(t *testing.T) {
	ctx := context.Background()
	fp := newFakePair()
	if _, err := fp.pair.Squat(ctx, "10.200.8.150", true); err != nil {
		t.Fatal(err)
	}
	if _, err := fp.pair.StartRogue(ctx, "10.200.8.254", "10.200.8.240", "10.200.8.245"); err != nil {
		t.Fatal(err)
	}
	if _, err := fp.pair.RogueLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if want := "primary Squat,primary StartRogue,primary RogueLeases"; fp.calls() != want {
		t.Fatalf("calls %q, want %q", fp.calls(), want)
	}
}
