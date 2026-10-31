package sourceadapter

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// winRunner decodes each -EncodedCommand back to its script and answers
// by the first substring of the script it finds in replies.
type winRunner struct {
	t       *testing.T
	replies []winReply
	scripts []string
}

type winReply struct {
	has string
	out string
	err error
}

func winDecode(t *testing.T, cmd string) string {
	t.Helper()
	const pre = "powershell -NonInteractive -NoProfile -EncodedCommand "
	if !strings.HasPrefix(cmd, pre) {
		t.Fatalf("not an encoded PowerShell command: %q", cmd)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(cmd, pre))
	if err != nil || len(b)%2 != 0 {
		t.Fatalf("encoded command %q: %v", cmd, err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func (w *winRunner) Run(_ context.Context, cmd string) (string, error) {
	s := winDecode(w.t, cmd)
	w.scripts = append(w.scripts, s)
	for _, r := range w.replies {
		if strings.Contains(s, r.has) {
			return r.out, r.err
		}
	}
	return "", nil
}

func newWin(t *testing.T, replies ...winReply) (*WindowsAdapter, *winRunner) {
	r := &winRunner{t: t, replies: replies}
	return &WindowsAdapter{Runner: r}, r
}

func TestWinPSStopsOnEveryError(t *testing.T) {
	s := winDecode(t, winPS("Get-Thing -Name 'x'"))
	if !strings.HasPrefix(s, "$ErrorActionPreference = 'Stop';") || !strings.HasSuffix(s, "; if (-not $?) { exit 1 }") || !strings.Contains(s, "Get-Thing -Name 'x'") {
		t.Errorf("wrapped script: %q", s)
	}
	if winPS("ä€") == winPS("??") {
		t.Error("non-ASCII text lost in the encoding")
	}
}

const winLeaseFixture = `1761870000
[{"IPAddress":"10.200.16.150","ClientId":"52-54-00-aa-bb-01","HostName":"c1","AddressState":"Active","Expiry":1761870600},` +
	`{"IPAddress":"10.200.16.211","ClientId":"01-52-54-00-aa-bb-02","HostName":"","AddressState":"ActiveReservation","Expiry":0},` +
	`{"IPAddress":"10.200.16.216","ClientId":"ff-00-00-00-01-00-01-2c-aa","HostName":"c3","AddressState":"Active","Expiry":1761873600},` +
	`{"IPAddress":"10.200.16.212","ClientId":"52-54-00-aa-bb-04","HostName":"","AddressState":"InactiveReservation","Expiry":0},` +
	`{"IPAddress":"10.200.16.160","ClientId":"52-54-00-aa-bb-05","HostName":"","AddressState":"Declined","Expiry":1761870100}]`

func TestParseWindowsLeasesReadsIDsStatesAndTheGuestClock(t *testing.T) {
	now := time.Unix(1761870100, 0) // the host runs 100 s ahead of the guest
	got, err := parseWindowsLeases(winLeaseFixture, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []Lease{
		{MAC: "52:54:00:aa:bb:01", Address: "10.200.16.150", Hostname: "c1", ClientID: "52:54:00:aa:bb:01", Expires: now.Add(600 * time.Second)},
		{MAC: "52:54:00:aa:bb:02", Address: "10.200.16.211", ClientID: "01:52:54:00:aa:bb:02"},
		{Address: "10.200.16.216", Hostname: "c3", ClientID: "ff:00:00:00:01:00:01:2c:aa", Expires: now.Add(3600 * time.Second)},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d leases %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("lease %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseWindowsLeasesZeroOneAndBroken(t *testing.T) {
	now := time.Unix(1761870000, 0)
	if got, err := parseWindowsLeases("1761870000\n[]", now); err != nil || len(got) != 0 {
		t.Errorf("empty table: %v, %v", got, err)
	}
	one := "1761870000\n" + `[{"IPAddress":"10.200.16.150","ClientId":"52-54-00-aa-bb-01","HostName":"","AddressState":"Active","Expiry":1761870600}]`
	if got, err := parseWindowsLeases(one, now); err != nil || len(got) != 1 {
		t.Errorf("one row: %v, %v", got, err)
	}
	for name, out := range map[string]string{
		"nothing":     "",
		"clock only":  "1761870000",
		"null":        "1761870000\nnull",
		"object":      "1761870000\n" + `{"IPAddress":"10.200.16.150","AddressState":"Active"}`,
		"error text":  "1761870000\nGet-DhcpServerv4Lease : Failed to get leases",
		"bad clock":   "noon\n[]",
		"bad address": "1761870000\n" + `[{"IPAddress":"10.200.16.999","AddressState":"Active"}]`,
		"bad id":      "1761870000\n" + `[{"IPAddress":"10.200.16.150","ClientId":"52:54:00","AddressState":"Active"}]`,
	} {
		if got, err := parseWindowsLeases(out, now); err == nil {
			t.Errorf("%s: accepted as %+v", name, got)
		}
	}
}

func TestWindowsRunFailureIsNeverAnEmptyTable(t *testing.T) {
	a, _ := newWin(t, winReply{has: "Get-DhcpServerv4Lease", out: "Get-DhcpServerv4Lease : access denied", err: errors.New("exit status 1")})
	if got, err := a.Leases(context.Background()); err == nil {
		t.Errorf("a failed read gave %+v", got)
	}
}

func TestWindowsReservationsRefuseBadInputBeforeAnyCommand(t *testing.T) {
	a, r := newWin(t)
	ctx := context.Background()
	for _, err := range []error{
		a.ReserveMAC(ctx, "aa:bb:cc:dd:ee:ff'; Remove-Item C:\\ #", "10.200.16.211"),
		a.ReserveMAC(ctx, "52:54:00:aa:bb:01", "10.200.16.211'; exit"),
		a.ReserveClientID(ctx, "01:52:54'", "10.200.16.216"),
		a.ReserveClientID(ctx, "01:52:54:00:aa:bb:01", "not-an-address"),
	} {
		if err == nil {
			t.Error("bad input accepted")
		}
	}
	if len(r.scripts) != 0 {
		t.Errorf("a refused call ran %q", r.scripts)
	}
	if err := a.ReserveClientID(ctx, "FF:00:00:00:01:00:01:2C:AA", "10.200.16.216"); err != nil {
		t.Fatal(err)
	}
	if err := a.ReserveMAC(ctx, "52:54:00:AA:BB:01", "10.200.16.211"); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"-IPAddress '10.200.16.216' -ClientId 'ff-00-00-00-01-00-01-2c-aa'", "-IPAddress '10.200.16.211' -ClientId '52-54-00-aa-bb-01'"} {
		if s := r.scripts[i]; !strings.Contains(s, want) || !strings.Contains(s, "Remove-DhcpServerv4Reservation") || !strings.Contains(s, "Remove-DhcpServerv4Lease") {
			t.Errorf("reservation %d: %q lacks %q or the clean-up", i, s, want)
		}
	}
}

func TestWindowsRestoresWriteBackWhatWasRead(t *testing.T) {
	ctx := context.Background()
	a, r := newWin(t, winReply{has: "-join ','", out: "10.200.16.2\r\n"}, winReply{has: "LeaseDuration.TotalSeconds", out: "3600\r\n"})
	undo, err := a.SetDNSOption(ctx, "10.200.16.253")
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	if s := r.scripts[1]; !strings.Contains(s, "-OptionId 6 -Value '10.200.16.253'") {
		t.Errorf("set: %q", s)
	}
	if s := r.scripts[2]; !strings.Contains(s, "Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId 6 -Value '10.200.16.2'") {
		t.Errorf("restore: %q", s)
	}
	undo, err = a.ShortenLeaseTime(ctx, 60)
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	if s := r.scripts[4]; !strings.Contains(s, "FromSeconds(60)") {
		t.Errorf("shorten: %q", s)
	}
	if s := r.scripts[5]; !strings.Contains(s, "FromSeconds(3600)") {
		t.Errorf("lease restore: %q", s)
	}

	a, r = newWin(t, winReply{has: "-join ','", out: "-"})
	undo, _ = a.SetDNSOption(ctx, "10.200.16.253")
	_ = undo(ctx)
	if s := r.scripts[2]; !strings.Contains(s, "Remove-DhcpServerv4OptionValue -ScopeId $sid -OptionId 6") {
		t.Errorf("no option 6 before, restore: %q", s)
	}
	a, r = newWin(t, winReply{has: "-join ','", out: "10.200.16.2'; Remove-Item C:\\"})
	if _, err := a.SetDNSOption(ctx, "10.200.16.253"); err == nil || len(r.scripts) != 1 {
		t.Errorf("an option value that cannot be written back was accepted: %v %q", err, r.scripts)
	}
}

func TestWindowsFailedChangeRestoresAtOnce(t *testing.T) {
	ctx := context.Background()
	a, r := newWin(t, winReply{has: "LeaseDuration.TotalSeconds", out: "3600"}, winReply{has: "FromSeconds(60)", err: errors.New("exit status 1")})
	if undo, err := a.ShortenLeaseTime(ctx, 60); err == nil || undo != nil {
		t.Fatalf("a failed change returned undo %t, err %v", undo != nil, err)
	}
	if n := len(r.scripts); n != 3 || !strings.Contains(r.scripts[2], "FromSeconds(3600)") {
		t.Errorf("the failed change was not undone: %q", r.scripts)
	}
}

func addrs(s ...string) []netip.Addr {
	var a []netip.Addr
	for _, x := range s {
		a = append(a, netip.MustParseAddr(x))
	}
	return a
}

func TestNarrowRangesExcludeUpToTheClassBand(t *testing.T) {
	p := addrs("10.200.16.100", "10.200.16.230", "10.200.16.201", "10.200.16.220", "10.200.16.110", "10.200.16.120")
	band := [][2]netip.Addr{{p[2], p[3]}}
	got, err := narrowRanges(p[0], p[1], band, p[4], p[5])
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]netip.Addr{{p[0], netip.MustParseAddr("10.200.16.109")}, {netip.MustParseAddr("10.200.16.121"), netip.MustParseAddr("10.200.16.200")}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
	if got, err := narrowRanges(p[0], p[1], band, p[0], netip.MustParseAddr("10.200.16.200")); err != nil || len(got) != 0 {
		t.Errorf("the whole main pool: %v, %v", got, err)
	}
	if got, err := narrowRanges(p[0], p[5], nil, p[4], p[5]); err != nil || len(got) != 1 {
		t.Errorf("no band, pool ends at the scope end: %v, %v", got, err)
	}
	for name, c := range map[string][2]netip.Addr{
		"below the scope":    {netip.MustParseAddr("10.200.16.90"), p[4]},
		"into the band":      {p[4], netip.MustParseAddr("10.200.16.205")},
		"past the scope":     {netip.MustParseAddr("10.200.16.221"), netip.MustParseAddr("10.200.16.240")},
		"band below the end": {netip.MustParseAddr("10.200.16.110"), netip.MustParseAddr("10.200.16.225")},
	} {
		if got, err := narrowRanges(p[0], p[1], band, c[0], c[1]); err == nil {
			t.Errorf("%s: accepted as %v", name, got)
		}
	}
}

const winShapeFixture = `{"start":"10.200.16.100","end":"10.200.16.230","ex":[{"s":"10.200.16.201","e":"10.200.16.220"}]}`

func TestWindowsNarrowPoolAddsAndRemovesTheSameRanges(t *testing.T) {
	ctx := context.Background()
	a, r := newWin(t, winReply{has: "StartRange.IPAddressToString", out: winShapeFixture})
	undo, err := a.NarrowPool(ctx, "10.200.16.110", "10.200.16.120")
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	for _, rg := range []string{"-StartRange '10.200.16.100' -EndRange '10.200.16.109'", "-StartRange '10.200.16.121' -EndRange '10.200.16.200'"} {
		if !strings.Contains(r.scripts[1], "Add-DhcpServerv4ExclusionRange -ScopeId $sid "+rg) || !strings.Contains(r.scripts[2], "Remove-DhcpServerv4ExclusionRange -ScopeId $sid "+rg) {
			t.Errorf("range %s not added and removed: %q / %q", rg, r.scripts[1], r.scripts[2])
		}
	}
	a, r = newWin(t, winReply{has: "StartRange.IPAddressToString", out: `{"start":"10.200.16.100","end":"10.200.16.230","ex":[{"s":"10.200.16.201'","e":"x"}]}`})
	if _, err := a.NarrowPool(ctx, "10.200.16.110", "10.200.16.120"); err == nil || len(r.scripts) != 1 {
		t.Errorf("a scope read that does not parse was used: %v %q", err, r.scripts)
	}
}

func TestWindowsRenumberPointsOptionsAtItselfAndImportsBack(t *testing.T) {
	ctx := context.Background()
	a, r := newWin(t, winReply{has: "$n[0].PrefixLength", out: "10.200.16.0\r\n10.200.16.2\r\n24\r\n3600\r\n"})
	undo, err := a.Renumber(ctx, "10.201.16.0/24", "10.201.16.2", "10.201.16.100", "10.201.16.200")
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(ctx); err != nil {
		t.Fatal(err)
	}
	do := r.scripts[1]
	for _, w := range []string{"-IPAddress '10.201.16.2' -PrefixLength 24", "-StartRange '10.201.16.100' -EndRange '10.201.16.200' -SubnetMask '255.255.255.0'", "-ScopeId '10.201.16.0' -OptionId 3 -Value '10.201.16.2'", "-ScopeId '10.201.16.0' -OptionId 6 -Value '10.201.16.2'", "FromSeconds(3600)", "Restart-Service"} {
		if !strings.Contains(do, w) {
			t.Errorf("renumber lacks %q: %q", w, do)
		}
	}
	back := r.scripts[2]
	for _, w := range []string{"-IPAddress '10.200.16.2' -PrefixLength 24", "Import-DhcpServer -File '" + winBaseline + "'", "-ScopeId '10.200.16.0' -ScopeOverwrite", "Set-DhcpServerv4Scope -ScopeId '10.200.16.0' -LeaseDuration ([TimeSpan]::FromSeconds(3600))"} {
		if !strings.Contains(back, w) {
			t.Errorf("restore lacks %q: %q", w, back)
		}
	}
	a, r = newWin(t, winReply{has: "$n[0].PrefixLength", out: "10.200.16.0\n10.200.16.2\n24"})
	if _, err := a.Renumber(ctx, "10.201.16.0/24", "10.201.16.2", "10.201.16.100", "10.201.16.200"); err == nil || len(r.scripts) != 1 {
		t.Errorf("a short state read was used: %v", err)
	}
}

func TestWindowsFeatures(t *testing.T) {
	ctx := context.Background()
	a, r := newWin(t, winReply{has: "StartRange.IPAddressToString", out: winShapeFixture})
	undo, err := a.EnableFeature(ctx, FeatureUserClassPool, FeatureParams{Class: "lab-f1", PoolStart: "10.200.16.203", PoolEnd: "10.200.16.210"})
	if err != nil {
		t.Fatal(err)
	}
	_ = undo(ctx)
	do, back := r.scripts[1], r.scripts[2]
	for _, w := range []string{"Remove-DhcpServerv4ExclusionRange -ScopeId $sid -StartRange '10.200.16.201' -EndRange '10.200.16.220'",
		"Add-DhcpServerv4ExclusionRange -ScopeId $sid -StartRange '10.200.16.201' -EndRange '10.200.16.202'",
		"Add-DhcpServerv4ExclusionRange -ScopeId $sid -StartRange '10.200.16.211' -EndRange '10.200.16.220'",
		"-Data ([string][char]6 + 'lab-f1')", "-UserClass EQ, 'labf77'", "-StartRange '10.200.16.203' -EndRange '10.200.16.210'"} {
		if !strings.Contains(do, w) {
			t.Errorf("user class pool lacks %q: %q", w, do)
		}
	}
	if !strings.Contains(back, "Remove-DhcpServerv4Policy -Name 'labf77'") || !strings.HasSuffix(strings.TrimSuffix(back, "; if (-not $?) { exit 1 }"), "Add-DhcpServerv4ExclusionRange -ScopeId $sid -StartRange '10.200.16.201' -EndRange '10.200.16.220'; $true") {
		t.Errorf("user class undo: %q", back)
	}
	if _, err := a.EnableFeature(ctx, FeatureUserClassPool, FeatureParams{Class: "lab-f1", PoolStart: "10.200.16.150", PoolEnd: "10.200.16.160"}); err == nil {
		t.Error("a user class pool outside every excluded band was accepted")
	}

	a, r = newWin(t)
	undo, err = a.EnableFeature(ctx, FeatureForce108, FeatureParams{Seconds: 300, ClientID: "01:52:54:00:AA:BB:01"})
	if err != nil {
		t.Fatal(err)
	}
	_ = undo(ctx)
	if s := r.scripts[0]; !strings.Contains(s, "-ClientId EQ, '01-52-54-00-aa-bb-01'") || !strings.Contains(s, "-PolicyName 'labf108f' -OptionId 108 -Value 300") || !strings.Contains(s, "-OptionId 108 -Type DWord") {
		t.Errorf("force 108: %q", s)
	}
	if s := r.scripts[1]; !strings.Contains(s, "Remove-DhcpServerv4Policy -Name 'labf108f'") || !strings.Contains(s, "Remove-DhcpServerv4OptionDefinition -OptionId 108") {
		t.Errorf("force 108 undo: %q", s)
	}
	a, r = newWin(t)
	if _, err := a.EnableFeature(ctx, FeatureOffer108, FeatureParams{Seconds: 300}); err != nil || !strings.Contains(r.scripts[0], "Set-DhcpServerv4OptionValue -ScopeId $sid -OptionId 108 -Value 300") {
		t.Errorf("offer 108: %v %q", err, r.scripts)
	}

	a, r = newWin(t)
	for f, want := range map[Feature]string{FeatureRapidCommit4: "DHCPv6 only", FeatureForceRenewNonce: "no FORCERENEW", FeatureRapidCommit6: "DHCPv4 only", FeaturePD: "DHCPv4 only"} {
		if _, err := a.EnableFeature(ctx, f, FeatureParams{Nonce: make([]byte, ForceRenewNonceLen), ClientID: "01:02", PDPool: netip.MustParsePrefix("fd00:16::/48")}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", f, err)
		}
	}
	if len(r.scripts) != 0 {
		t.Errorf("a refused feature ran %q", r.scripts)
	}
}

const winStateFixture = "conflict 0\r\nexcl 10.200.16.0 10.200.16.201-10.200.16.220\r\nscope 10.200.16.0 255.255.255.0 10.200.16.100-10.200.16.230 Active 08:00:00\r\n"

func TestWindowsReadyHoldsMarkerServiceLicenseAndConfig(t *testing.T) {
	ctx := context.Background()
	healthy := winReply{has: "bootstrap-done", out: "2026-10-31T00:40:00Z\r\nRunning\r\n2 259200\r\n"}
	leases := winReply{has: "Get-DhcpServerv4Lease", out: "1761870000\r\n[]"}
	state := winReply{has: "System.Collections.Generic.List", out: winStateFixture}
	a, r := newWin(t, healthy, leases, state)
	if err := a.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Ready(ctx); err != nil {
		t.Fatalf("an unchanged server: %v", err)
	}
	r.replies[2].out = winStateFixture + "policy 10.200.16.0 labf77 True 2 OR vc= uc=labf77 cid=\r\n"
	if err := a.Ready(ctx); err == nil || !strings.Contains(err.Error(), "+ policy 10.200.16.0 labf77") {
		t.Errorf("a left-over policy: %v", err)
	}
	for name, h := range map[string]string{
		"no marker":   "\r\nRunning\r\n2 259200\r\n",
		"stopped":     "x\r\nStopped\r\n2 259200\r\n",
		"expired":     "x\r\nRunning\r\n5 0\r\n",
		"grace spent": "x\r\nRunning\r\n2 0\r\n",
		"garbled":     "x\r\nRunning\r\nlicensed\r\n",
	} {
		a, _ := newWin(t, winReply{has: "bootstrap-done", out: h}, leases, state)
		if err := a.Ready(ctx); err == nil {
			t.Errorf("%s: ready", name)
		}
	}
	a, _ = newWin(t, winReply{has: "bootstrap-done", out: "x\r\nRunning\r\n5 0\r\n"})
	if err := a.Ready(ctx); err == nil || !strings.Contains(err.Error(), "dated copy") {
		t.Errorf("an expired evaluation does not name the way back: %v", err)
	}
	a, _ = newWin(t, winReply{has: "bootstrap-done", out: "x\r\nRunning\r\n1 0\r\n"}, leases, state)
	if err := a.Ready(ctx); err != nil {
		t.Errorf("a licensed server: %v", err)
	}
}

func TestWindowsRecoverClearsLabObjectsThenImports(t *testing.T) {
	a, r := newWin(t)
	if err := a.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := r.scripts[0]
	order := []string{"Remove-DhcpServerv4Scope", "-like 'labf*'", "netconfig.ps1", "Import-DhcpServer -File '" + winBaseline + "'", "-ConflictDetectionAttempts 0", "Restart-Service"}
	at := 0
	for _, w := range order {
		i := strings.Index(s[at:], w)
		if i < 0 {
			t.Fatalf("recover lacks %q after offset %d: %q", w, at, s)
		}
		at += i
	}
}

func TestWindowsRefusesActorsAndV6BeforeAnyCommand(t *testing.T) {
	a, r := newWin(t)
	ctx := context.Background()
	var errs []error
	_, err := a.Impair(ctx, time.Second, 1)
	errs = append(errs, err)
	_, err = a.Squat(ctx, "10.200.16.150", true)
	errs = append(errs, err)
	_, err = a.StartRogue(ctx, "10.200.16.3", "10.200.16.10", "10.200.16.20")
	errs = append(errs, err)
	_, err = a.RogueLeases(ctx)
	errs = append(errs, err)
	_, err = a.SendForceRenew(ctx, nil, ForceRenewParams{})
	errs = append(errs, err)
	_, err = a.Leases6(ctx)
	errs = append(errs, err)
	_, err = a.SetRA(ctx, RAParams{})
	errs = append(errs, err)
	_, err = a.StopV6Server(ctx)
	errs = append(errs, err)
	_, err = a.ServerEvents(ctx, time.Now(), "")
	errs = append(errs, err)
	for i, err := range errs {
		if err == nil {
			t.Errorf("call %d was not refused", i)
		}
	}
	if !strings.Contains(errs[0].Error(), "windows source") || !strings.Contains(errs[5].Error(), "DHCPv4 only") {
		t.Errorf("refusals do not say why: %v / %v", errs[0], errs[5])
	}
	if err := a.Reachable(ctx, "10.200.16.150'; exit"); err == nil {
		t.Error("a bad address reached Reachable")
	}
	if len(r.scripts) != 0 {
		t.Errorf("a refused call ran %q", r.scripts)
	}
}

func TestWindowsNAReasonCoversEveryUndeclaredCapabilityItKnows(t *testing.T) {
	a := &WindowsAdapter{}
	declared := map[Capability]bool{}
	for _, c := range a.Capabilities() {
		declared[c] = true
		if _, ok := a.NAReason(c); ok {
			t.Errorf("declared capability %q carries a N/A reason", c)
		}
	}
	for _, c := range []Capability{CapV4, CapReserveMAC, CapReserveClientID, CapRestart, CapShortLease, CapOptionChange, CapVendorClassPool, CapUserClassPool, CapOption108, CapNarrowPool, CapRenumber} {
		if !declared[c] {
			t.Errorf("%q is not declared", c)
		}
	}
	for _, c := range []Capability{CapImpair, CapSquatter, CapRogueServer, CapForceRenewNonce, CapRapidCommit4, CapDNSRegistration, CapV6, CapServerEvents, CapVLANPool} {
		if declared[c] {
			t.Errorf("%q is declared", c)
		}
		if why, ok := a.NAReason(c); !ok || why == "" {
			t.Errorf("no N/A reason for %q", c)
		}
	}
}
