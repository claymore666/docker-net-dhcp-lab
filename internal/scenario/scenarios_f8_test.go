package scenario

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// ---- F8-forcerenew judges (#21) ----

const f8Lease, f8Server = "10.200.1.150", "10.200.1.2"

var f8Nonce = bytes.Repeat([]byte{0x5a}, sourceadapter.ForceRenewNonceLen)

func f8Opts(present bool, ack90 []byte) []OptMsg {
	var c map[int][]byte
	if present {
		c = map[int][]byte{145: {1}}
	}
	ack := map[int][]byte{54: {10, 200, 1, 2}, 145: {1}}
	if ack90 != nil {
		ack[90] = ack90
	}
	return []OptMsg{om("DISCOVER", "1", c), om("OFFER", "1", nil), om("REQUEST", "1", c), om("ACK", "1", ack)}
}

func TestJudgeF8AckReadsTheNonceAndOption145(t *testing.T) {
	want := sourceadapter.ForceRenewNonceOption(f8Nonce)
	if ack, o := judgeF8Ack(true, f8Opts(true, want), want); o.Result != PASS || ack.XID != "1" {
		t.Fatalf("clean ACK = %+v", o)
	}
	if _, o := judgeF8Ack(false, f8Opts(false, want), want); o.Result != PASS {
		t.Fatalf("old plugin, no 145 = %+v", o)
	}
	other := sourceadapter.ForceRenewNonceOption(bytes.Repeat([]byte{1}, 16))
	cases := map[string]struct {
		present bool
		opts    []OptMsg
		want    Result
	}{
		// defeat 9: no nonce on the wire, or not the one the lab wrote.
		"ACK without 90":           {true, f8Opts(true, nil), BLOCKED},
		"ACK with another nonce":   {true, f8Opts(true, other), BLOCKED},
		"no ACK":                   {true, f8Opts(true, want)[:3], BLOCKED},
		"no 145 from a new plugin": {true, f8Opts(false, want), FAIL},
		"145 from an old plugin":   {false, f8Opts(true, want), BLOCKED},
	}
	for name, c := range cases {
		if _, o := judgeF8Ack(c.present, c.opts, want); o.Result != c.want {
			t.Errorf("%s: got %s (%s), want %s", name, o.Result, o.Reason, c.want)
		}
	}
	noSrv := f8Opts(true, want)
	delete(noSrv[3].Opts, 54)
	if _, o := judgeF8Ack(true, noSrv, want); o.Result != BLOCKED {
		t.Errorf("no option 54: %+v", o)
	}
}

// f8Base is a run that PASSes: three frames seen, the two drops dropped,
// the signed one answered by a unicast REQUEST and an ACK within 3 s.
func f8Base() f8Obs {
	bind := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return bind.Add(time.Duration(s) * time.Second) }
	o := f8Obs{present: true, lease: f8Lease, addr: f8Lease, addrAfter: f8Lease, bind: bind, signedWait: 10 * time.Second}
	o.sends = [3]f8Send{{"unsigned", at(20), "000000a1"}, {"badkey", at(35), "000000a2"}, {"signed", at(50), "000000a3"}}
	for _, s := range o.sends {
		o.msgs = append(o.msgs, DHCPMsg{At: s.At, Type: "FORCERENEW", XID: s.XID, CIAddr: f8Lease, Dst: f8Lease})
		om := om("FORCERENEW", s.XID, nil)
		if s.Mode != "unsigned" {
			om.Opts[90] = make([]byte, 28)
		}
		o.opts = append(o.opts, om)
	}
	o.msgs = append(o.msgs, DHCPMsg{At: at(53), Type: "REQUEST", XID: "000000b1", CIAddr: f8Lease, Dst: f8Server},
		DHCPMsg{At: at(53), Type: "ACK", XID: "000000b1", Dst: f8Lease})
	e0 := at(600)
	o.expires = [4]time.Time{e0, e0, e0, at(653)}
	return o
}

func TestJudgeF8(t *testing.T) {
	if o := judgeF8(f8Base()); o.Result != PASS {
		t.Fatalf("base = %s: %s", o.Result, o.Reason)
	}
	req := func(s int, ci, dst string) DHCPMsg {
		return DHCPMsg{At: f8Base().bind.Add(time.Duration(s) * time.Second), Type: "REQUEST", XID: "000000c1", CIAddr: ci, Dst: dst}
	}
	cases := map[string]struct {
		mut  func(*f8Obs)
		want Result
	}{
		// defeat 11: a send past half the lease could meet a natural renewal.
		"last send after lease/2": {func(o *f8Obs) {
			o.expires[0] = o.bind.Add(90 * time.Second)
			o.expires[1], o.expires[2] = o.expires[0], o.expires[0]
		}, BLOCKED},
		"no expiry in the table": {func(o *f8Obs) { o.expires[0] = time.Time{} }, BLOCKED},
		// defeat 12: the drops count only next to an obeyed signed send.
		"signed never answered": {func(o *f8Obs) { o.msgs = o.msgs[:3] }, BLOCKED},
		"signed answered late":  {func(o *f8Obs) { o.msgs[3].At = o.sends[2].At.Add(11 * time.Second) }, BLOCKED},
		"signed frame unseen":   {func(o *f8Obs) { o.msgs = append(o.msgs[:2:2], o.msgs[3:]...) }, BLOCKED},
		"unsigned frame unseen": {func(o *f8Obs) { o.msgs[0].XID = "ffffffff" }, BLOCKED},
		"frame to the wrong IP": {func(o *f8Obs) { o.msgs[1].Dst = "255.255.255.255" }, BLOCKED},
		"unsigned carries 90":   {func(o *f8Obs) { o.opts[0].Opts[90] = []byte{3} }, BLOCKED},
		"signed lacks 90":       {func(o *f8Obs) { delete(o.opts[2].Opts, 90) }, BLOCKED},
		// the drops.
		"REQUEST after unsigned":   {func(o *f8Obs) { o.msgs = append(o.msgs, req(25, f8Lease, f8Server)) }, FAIL},
		"REQUEST after badkey":     {func(o *f8Obs) { o.msgs = append(o.msgs, req(40, f8Lease, f8Server)) }, FAIL},
		"expiry moved by unsigned": {func(o *f8Obs) { o.expires[1] = o.expires[0].Add(time.Minute) }, FAIL},
		"expiry moved by badkey":   {func(o *f8Obs) { o.expires[2] = o.expires[0].Add(time.Minute) }, FAIL},
		// the signed renewal.
		"broadcast REQUEST":      {func(o *f8Obs) { o.msgs[3].Dst = "255.255.255.255" }, FAIL},
		"REQUEST without ciaddr": {func(o *f8Obs) { o.msgs[3].CIAddr = "" }, FAIL},
		"REQUEST not ACKed":      {func(o *f8Obs) { o.msgs = o.msgs[:4] }, FAIL},
		"expiry not moved":       {func(o *f8Obs) { o.expires[3] = o.expires[0] }, FAIL},
		"address changed":        {func(o *f8Obs) { o.addrAfter = "10.200.1.151" }, FAIL},
	}
	for name, c := range cases {
		o := f8Base()
		c.mut(&o)
		if got := judgeF8(o); got.Result != c.want {
			t.Errorf("%s: got %s (%s), want %s", name, got.Result, got.Reason, c.want)
		}
	}
}

// A frame the observer never saw is named as unseen, not as misaddressed.
func TestJudgeF8NamesAnUnseenFrame(t *testing.T) {
	o := f8Base()
	o.msgs = o.msgs[1:]
	if got := judgeF8(o); got.Result != BLOCKED || !strings.Contains(got.Reason, "did not see the unsigned") {
		t.Errorf("unseen unsigned frame = %+v", got)
	}
}

// An old plugin is judged on the unsigned drop only; the signed outcome
// is recorded, and a REQUEST after badkey is not held against it.
func TestJudgeF8OldPluginJudgesTheUnsignedDropOnly(t *testing.T) {
	o := f8Base()
	o.present = false
	o.msgs = o.msgs[:3]
	if got := judgeF8(o); got.Result != PASS || !strings.Contains(got.Reason, "0 REQUEST") {
		t.Errorf("no answer at all = %+v", got)
	}
	o = f8Base()
	o.present = false
	o.msgs = append(o.msgs, DHCPMsg{At: o.sends[1].At.Add(time.Second), Type: "REQUEST", XID: "c2", CIAddr: f8Lease, Dst: f8Server})
	if got := judgeF8(o); got.Result != PASS {
		t.Errorf("REQUEST after badkey on an old plugin = %+v", got)
	}
	o.msgs = append(o.msgs, DHCPMsg{At: o.sends[0].At.Add(time.Second), Type: "REQUEST", XID: "c3", CIAddr: f8Lease, Dst: f8Server})
	if got := judgeF8(o); got.Result != FAIL {
		t.Errorf("REQUEST after unsigned on an old plugin = %+v", got)
	}
}

func TestJudgeF8Control(t *testing.T) {
	if o := judgeF8Control(fFour("2", nil, nil)); o.Result != PASS {
		t.Errorf("clean control = %+v", o)
	}
	if o := judgeF8Control(nil); o.Result != BLOCKED {
		t.Errorf("unseen control = %+v", o)
	}
	for _, code := range []int{90, 145} {
		for _, i := range []int{1, 3} {
			m := fFour("2", nil, nil)
			m[i] = om(m[i].Type, "2", map[int][]byte{code: {1}})
			if o := judgeF8Control(m); o.Result != BLOCKED {
				t.Errorf("%d on the control's %s = %+v", code, m[i].Type, o)
			}
		}
	}
}

// ---- runF8 ----

// f8Capture is the F8-forcerenew fake observer: the ACK exchange, then each frame
// the fake adapter sends and the client's answer to it, as both readers
// see them.
type f8Capture struct {
	opts []OptMsg
	msgs []DHCPMsg
	ctl  []OptMsg
}

func (c *f8Capture) Messages(context.Context, string, string) ([]DHCPMsg, error) {
	return append([]DHCPMsg{}, c.msgs...), nil
}
func (c *f8Capture) Options(_ context.Context, ident, _ string, _ []int) ([]OptMsg, error) {
	if ident == "aa:bb:cc:00:00:02" {
		out := append([]OptMsg{}, c.ctl...)
		for i := range out {
			out[i].At = time.Now()
		}
		return out, nil
	}
	return append([]OptMsg{}, c.opts...), nil
}

type f8Fix struct {
	*fFix
	cap     *f8Capture
	obey    map[string]bool // modes the fake client renews on
	renewed bool
	expires time.Time
}

// readyOrder records, at each Ready, how many restores had run.
type readyOrder struct {
	*bAdapter
	atReady []int
}

func (r *readyOrder) Ready(ctx context.Context) error {
	r.atReady = append(r.atReady, r.featureRestores)
	return r.bAdapter.Ready(ctx)
}

func newF8Fix(t *testing.T, tag string) *f8Fix {
	f := &f8Fix{fFix: newFFix(t, ShapeBridge, tag, f8Lease), cap: &f8Capture{}, obey: map[string]bool{"signed": true}}
	g, w, r := f8Gap, f8SignedWait, f8Rand
	f8Gap, f8SignedWait = 20*time.Millisecond, 20*time.Millisecond
	f8Rand = func(b []byte) (int, error) { return copy(b, f8Nonce), nil }
	t.Cleanup(func() { f8Gap, f8SignedWait, f8Rand = g, w, r })
	f.e.Capture = f.cap
	f.e.RepoRoot = "../.."
	present := tag == tagNew
	now := time.Now()
	for i, m := range f8Opts(present, sourceadapter.ForceRenewNonceOption(f8Nonce)) {
		m.At = now
		f.cap.opts = append(f.cap.opts, m)
		f.cap.msgs = append(f.cap.msgs, DHCPMsg{At: now, Type: m.Type, XID: "1", CHAddr: "aa:bb:cc:00:00:01", Dst: []string{"255.255.255.255", f8Lease, "255.255.255.255", f8Lease}[i]})
	}
	f.cap.ctl = fFour("2", nil, nil)
	f.expires = now.Add(600 * time.Second)
	wire := b2WireClientID("lab-f8-" + string(ShapeBridge))
	f.src.fn = func(int) []sourceadapter.Lease {
		e := f.expires
		if f.renewed {
			e = e.Add(time.Minute)
		}
		return []sourceadapter.Lease{{MAC: "aa:bb:cc:00:00:01", ClientID: wire, Address: f8Lease, Expires: e}}
	}
	f.src.onForceRenew = func(p sourceadapter.ForceRenewParams) (string, error) {
		n := len(f.src.forceRenews)
		xid := fmt.Sprintf("0000f00%d", n)
		at := time.Now()
		f.cap.msgs = append(f.cap.msgs, DHCPMsg{At: at, Type: "FORCERENEW", XID: xid, CIAddr: p.Addr, Dst: p.Addr})
		fr := OptMsg{At: at, Type: "FORCERENEW", XID: xid, Opts: map[int][]byte{}}
		if p.Mode != "unsigned" {
			fr.Opts[90] = make([]byte, 28)
		}
		f.cap.opts = append(f.cap.opts, fr)
		if f.obey[p.Mode] {
			r := fmt.Sprintf("0000e00%d", n)
			f.cap.msgs = append(f.cap.msgs, DHCPMsg{At: at, Type: "REQUEST", XID: r, CIAddr: f8Lease, Dst: f8Server},
				DHCPMsg{At: at, Type: "ACK", XID: r, Dst: f8Lease})
			f.renewed = true
		}
		return fmt.Sprintf("forcerenew mode=%s xid=0x%s replay=%d dst=x/%s len=300", p.Mode, xid, p.AckReplay, p.Addr), nil
	}
	return f
}

func TestRunF8PassesAndSendsTheThreeFramesInOrder(t *testing.T) {
	f := newF8Fix(t, tagNew)
	ro := &readyOrder{bAdapter: f.src}
	f.e.Source = ro
	v := runF8(context.Background(), f.e)
	needResult(t, v, PASS)
	if got := f.src.features; len(got) != 1 || got[0] != sourceadapter.FeatureForceRenewNonce {
		t.Fatalf("features = %v", got)
	}
	wire := b2WireClientID("lab-f8-" + string(ShapeBridge))
	if p := f.src.featureParams[0]; p.ClientID != wire || !bytes.Equal(p.Nonce, f8Nonce) {
		t.Errorf("feature params %+v", p)
	}
	if !f.h.has("client_id=lab-f8-" + string(ShapeBridge)) {
		t.Errorf("network lacks client_id: %v", f.h.cmds)
	}
	var modes []string
	for _, p := range f.src.forceRenews {
		modes = append(modes, p.Mode)
		if p.Addr != f8Lease || p.Server != f8Server || p.CHAddr != "aa:bb:cc:00:00:01" || p.ClientID != wire || !bytes.Equal(p.Nonce, f8Nonce) || p.AckReplay != 1 {
			t.Errorf("send params %+v", p)
		}
	}
	if strings.Join(modes, ",") != "unsigned,badkey,signed" {
		t.Errorf("modes = %v", modes)
	}
	// defeat 13 and 15: one restore, and Ready after it.
	if f.src.featureRestores != 1 || len(ro.atReady) != 1 || ro.atReady[0] != 1 {
		t.Errorf("restores %d, ready saw %v", f.src.featureRestores, ro.atReady)
	}
	needCleanup(t, f.h, "f8", containerName(f.e, NameF8))
	needCleanup(t, f.h, "f8", containerName(f.e, NameF8)+"-ctl")
	for _, k := range []string{"capture-options", "capture-forcerenew", "capture-messages", "capture-control", "leases-after-signed"} {
		if v.Evidence[k] == "" {
			t.Errorf("evidence %q missing: %v", k, v.Evidence)
		}
	}
}

func TestRunF8Paths(t *testing.T) {
	cases := map[string]struct {
		tag  string
		set  func(*f8Fix)
		want Result
		why  string
	}{
		"unsigned obeyed":   {tagNew, func(f *f8Fix) { f.obey["unsigned"] = true }, FAIL, "must discard"},
		"badkey obeyed":     {tagNew, func(f *f8Fix) { f.obey["badkey"] = true }, FAIL, "must discard"},
		"signed not obeyed": {tagNew, func(f *f8Fix) { f.obey["signed"] = false }, BLOCKED, "cannot count"},
		"no nonce in ACK":   {tagNew, func(f *f8Fix) { delete(f.cap.opts[3].Opts, 90) }, BLOCKED, "option 90"},
		"leaky control":     {tagNew, func(f *f8Fix) { f.cap.ctl[1] = om("OFFER", "2", map[int][]byte{90: {1}}) }, BLOCKED, "not scoped"},
		"not ready after":   {tagNew, func(f *f8Fix) { f.src.readyErrs = []error{errors.New("dnsmasq down")} }, BLOCKED, "not ready after F8-forcerenew"},
		"restore fails":     {tagNew, func(f *f8Fix) { f.src.featureRestoreEr = errors.New("no") }, BLOCKED, "put back"},
		"send fails": {tagNew, func(f *f8Fix) {
			f.src.onForceRenew = func(sourceadapter.ForceRenewParams) (string, error) { return "", errors.New("no neigh") }
		}, BLOCKED, "could not be sent"},
		"no xid reported": {tagNew, func(f *f8Fix) {
			f.src.onForceRenew = func(sourceadapter.ForceRenewParams) (string, error) { return "ok", nil }
		}, BLOCKED, "no xid"},
		"no expiry":                   {tagNew, func(f *f8Fix) { f.expires = time.Time{} }, BLOCKED, "no expiry"},
		"old plugin, signed":          {tagOld, nil, PASS, "recorded, not judged"},
		"old plugin, unsigned obeyed": {tagOld, func(f *f8Fix) { f.obey["unsigned"] = true }, FAIL, "must discard"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newF8Fix(t, c.tag)
			if c.set != nil {
				c.set(f)
			}
			v := runF8(context.Background(), f.e)
			needResult(t, v, c.want)
			if !strings.Contains(v.Reason, c.why) {
				t.Errorf("reason %q lacks %q", v.Reason, c.why)
			}
			if f.src.featureRestores != 1 || f.src.readyCalls != 1 {
				t.Errorf("restores %d, ready calls %d", f.src.featureRestores, f.src.readyCalls)
			}
		})
	}
}

func TestRunF8BlocksWhenTheFeatureCannotBeEnabled(t *testing.T) {
	f := newF8Fix(t, tagNew)
	f.src.featureErr = errors.New("refused")
	needResult(t, runF8(context.Background(), f.e), BLOCKED)
	if len(f.h.cmds) != 0 || len(f.src.forceRenews) != 0 || f.src.readyCalls != 1 {
		t.Errorf("cmds %v, sends %d, ready %d", f.h.cmds, len(f.src.forceRenews), f.src.readyCalls)
	}
}

func TestRunF8IsNAOnIPAMShapesWithoutTouchingTheHost(t *testing.T) {
	for _, sh := range []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		f := newFFix(t, sh, tagNew, f8Lease)
		needResult(t, runF8(context.Background(), f.e), NA)
		if len(f.h.cmds) != 0 || len(f.src.features) != 0 || len(f.src.forceRenews) != 0 || f.src.readyCalls != 0 {
			t.Errorf("%s touched the host or source", sh)
		}
	}
}
