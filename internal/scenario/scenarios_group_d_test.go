package scenario

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// d6Cap is the fake V6Reader: every message is stamped with the time of
// the first read, which falls after the scenario's t0 and before its
// settled read.
type d6Cap struct {
	fCapture
	msgs  []DHCP6Msg
	ras   []RAMsg
	first time.Time
	reads int
	// raAt, when set, stamps the RAs instead: an RA heard before the
	// start read, as SLAAC needs.
	raAt time.Time
}

func (c *d6Cap) Messages6(context.Context, string, string) ([]DHCP6Msg, []RAMsg, error) {
	c.reads++
	if c.first.IsZero() {
		c.first = time.Now()
	}
	msgs := make([]DHCP6Msg, len(c.msgs))
	for i, m := range c.msgs {
		m.At = c.first.Add(time.Duration(i) * time.Millisecond)
		msgs[i] = m
	}
	ras := make([]RAMsg, len(c.ras))
	for i, r := range c.ras {
		r.At = c.first
		if !c.raAt.IsZero() {
			r.At = c.raAt
		}
		ras[i] = r
	}
	return msgs, ras, nil
}

// d6Host answers the container's v6 reads on top of bRunner.
type d6Host struct {
	*bRunner
	start, settled, route, inspect, health string
	addrReads                              int
}

func (h *d6Host) Run(ctx context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "ip -6 -o addr show"):
		h.cmds = append(h.cmds, cmd)
		h.addrReads++
		if h.addrReads == 1 {
			return h.start, nil
		}
		return h.settled, nil
	case strings.Contains(cmd, "ip -6 route show default"):
		h.cmds = append(h.cmds, cmd)
		return h.route, nil
	case strings.Contains(cmd, "GlobalIPv6Address"):
		h.cmds = append(h.cmds, cmd)
		return h.inspect, nil
	case strings.Contains(cmd, "Plugin.Health"):
		h.cmds = append(h.cmds, cmd)
		return h.health, nil
	}
	return h.bRunner.Run(ctx, cmd)
}

func addrLine(a string, bits int, scope, valid, pref string) string {
	return fmt.Sprintf("42: eth0    inet6 %s/%d scope %s \\       valid_lft %s preferred_lft %s\n", a, bits, scope, valid, pref)
}

type d6Fix struct {
	h   *d6Host
	src *bAdapter
	cap *d6Cap
	e   Env
}

func newD6Fix(t *testing.T, shape Shape, tag string, caps ...sourceadapter.Capability) *d6Fix {
	t.Helper()
	fFast(t)
	s := dSettle
	dSettle = 10 * time.Millisecond
	t.Cleanup(func() { dSettle = s })
	ll := addrLine(d6LL.Addr.String(), 64, "link", "forever", "forever")
	h := &d6Host{bRunner: newBRunner(),
		start:   ll + addrLine(d6NA.String(), 128, "global", "forever", "forever"),
		settled: ll + addrLine(d6NA.String(), 128, "global", "7200sec", "3600sec"),
		route:   "default via fe80::1 dev eth0 metric 1024 pref medium\n",
		inspect: d6NA.String(),
	}
	src := &bAdapter{fakeAdapter: &fakeAdapter{caps: caps}}
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.101"})
	src.leases6 = []sourceadapter.Lease6{{Type: sourceadapter.Lease6NA, Address: d6NA, DUID: d6DUID, IAID: 1}}
	e := bEnv(t, h, src, shape)
	e.PluginTag = tagNew
	if tag != "" {
		e.PluginTag = tag
	}
	c := &d6Cap{msgs: goodD1().Msgs, ras: goodD1().RAs}
	e.Capture = c
	return &d6Fix{h: h, src: src, cap: c, e: e}
}

func (f *d6Fix) cmdCount(sub string) (n int) {
	for _, c := range f.h.cmds {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func TestRunD1PassesAndCleansUpAfterThePing(t *testing.T) {
	for _, run := range []func(context.Context, Env) Verdict{runD1, runD1b} {
		f := newD6Fix(t, ShapeMacvlan, "")
		v := run(context.Background(), f.e)
		needResult(t, v, PASS)
		if f.h.addrReads != 2 || f.cmdCount("ip -6 route show default") != 1 {
			t.Errorf("addr reads %d, route reads %d; want a start and a settled read", f.h.addrReads, f.cmdCount("ip -6 route"))
		}
		if len(f.h.containers) != 0 {
			t.Errorf("container left behind: %v", f.h.containers)
		}
	}
}

func TestRunD1FailsWhenInspectDisagreesWithTheLink(t *testing.T) {
	f := newD6Fix(t, ShapeMacvlan, "")
	f.h.inspect = ""
	needResult(t, runD1(context.Background(), f.e), FAIL)
}

func TestRunD1FailsWhenTheLeaseAnswersNoPing(t *testing.T) {
	f := newD6Fix(t, ShapeBridge, "")
	f.src.reachErr = errors.New("100% loss")
	needResult(t, runD1(context.Background(), f.e), FAIL)
}

func TestRunD1BlocksOnACaptureWithoutTheV6Reader(t *testing.T) {
	f := newD6Fix(t, ShapeMacvlan, "")
	f.e.Capture = plainCapture{}
	needResult(t, runD1(context.Background(), f.e), BLOCKED)
}

func TestGroupDIsNABeforeV220AndOnIPAMShapes(t *testing.T) {
	runs := map[string]func(context.Context, Env) Verdict{NameD1: runD1, NameD1b: runD1b, NameD1c: runD1c, NameD2: runD2, NameD2b: runD2b, NameF4: runF4, NameF5: runF5,
		NameD3a: runD3a, NameD3b: runD3b, NameD3c: runD3c, NameD3d: runD3d, NameD4: runD4, NameD4m: runD4m, NameD4b: runD4b, NameF6: runF6, NameF7: runF7}
	swapped := map[string]bool{NameD1: true, NameD1b: true, NameD2: true}
	for name, run := range runs {
		f := newD6Fix(t, ShapeMacvlan, "ghcr.io/claymore666/docker-net-dhcp:v2.1.3", sourceadapter.CapV6ServerStop, sourceadapter.CapPD, sourceadapter.CapPref64)
		needResult(t, run(context.Background(), f.e), NA)
		if !swapped[name] {
			f = newD6Fix(t, ShapeMacvlanIPAM, "", sourceadapter.CapV6ServerStop, sourceadapter.CapPD, sourceadapter.CapPref64)
			needResult(t, run(context.Background(), f.e), NA)
		}
		f = newD6Fix(t, ShapeMacvlan, "ghcr.io/claymore666/docker-net-dhcp:dev", sourceadapter.CapV6ServerStop, sourceadapter.CapPD, sourceadapter.CapPref64)
		if v := run(context.Background(), f.e); v.Result != BLOCKED {
			t.Errorf("%s on an unparsable tag: %s", name, v.Result)
		}
		if f.cmdCount("docker run") != 0 || f.src.raOffs != 0 || f.src.featureEnabled() != 0 || f.src.v6Stops != 0 {
			t.Errorf("%s touched the host or the source before its gate", name)
		}
	}
}

// restoreFails fails the main network's rebuild, the create without
// ipv6_mode that NetworkUp runs.
type restoreFails struct{ *d6Host }

func (h restoreFails) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "docker network create") && !strings.Contains(cmd, "ipv6_mode") {
		h.cmds = append(h.cmds, cmd)
		return "", errors.New("create refused")
	}
	return h.d6Host.Run(ctx, cmd)
}

// On an IPAM shape D1, D1b and D2 recreate the cell's main network with
// ipv6_mode and rebuild it afterwards; a failed rebuild is BLOCKED.
func TestD1AndD2SwapTheMainNetworkOnIPAMShapes(t *testing.T) {
	f := newD6Fix(t, ShapeMacvlanIPAM, "")
	needResult(t, runD1(context.Background(), f.e), BLOCKED)
	if f.cmdCount("docker network rm") != 0 {
		t.Error("a main network NetworkUp cannot rebuild was removed")
	}
	f = newD6Fix(t, ShapeMacvlanIPAM, "")
	f.e.Network = NetworkName(f.e.Cell, f.e.Shape)
	needResult(t, runD1(context.Background(), f.e), PASS)
	var seq []string
	for _, c := range f.h.cmds {
		if strings.Contains(c, "docker network") && strings.HasSuffix(c, " "+f.e.Network) {
			seq = append(seq, c)
		}
	}
	if len(seq) < 3 || !strings.Contains(seq[0], "network rm") || !strings.Contains(seq[1], "-o ipv6_mode=dhcp") ||
		!strings.Contains(seq[len(seq)-1], "network create") || strings.Contains(seq[len(seq)-1], "ipv6_mode") {
		t.Errorf("main network commands %q: want rm, create with ipv6_mode, then the plain rebuild", seq)
	}
	if f.cmdCount(f.e.Network+"-d1") != 0 {
		t.Error("a second network was created on an IPAM shape")
	}
	f = newD6Fix(t, ShapeMacvlanIPAM, "")
	f.e.Network = NetworkName(f.e.Cell, f.e.Shape)
	f.e.Host = restoreFails{f.h}
	v := runD1(context.Background(), f.e)
	needResult(t, v, BLOCKED)
	if !strings.Contains(v.Reason, "must be recovered") || !strings.Contains(v.Reason, "PASS") {
		t.Errorf("reason %q", v.Reason)
	}
}

func TestRunD1cTurnsTheRAsOffAndPutsThemBack(t *testing.T) {
	// The RA stays, stamped before SetRA's two-second margin: radvd's
	// final RA on stop must not block the row.
	f := newD6Fix(t, ShapeMacvlan, "")
	f.cap.msgs = nil
	f.h.start = addrLine(d6LL.Addr.String(), 64, "link", "forever", "forever")
	f.h.inspect = ""
	needResult(t, runD1c(context.Background(), f.e), PASS)
	if f.src.raOffs != 1 || f.src.raRestores != 1 {
		t.Errorf("SetRA off %d, restored %d", f.src.raOffs, f.src.raRestores)
	}
	f = newD6Fix(t, ShapeMacvlan, "")
	f.cap.msgs, f.cap.first = nil, time.Now().Add(5*time.Second)
	needResult(t, runD1c(context.Background(), f.e), BLOCKED)
	if f.src.raRestores != 1 {
		t.Errorf("an RA on the wire skipped the restore")
	}
}

func TestRunD2bFailsWhenTheContainerStarts(t *testing.T) {
	f := newD6Fix(t, ShapeBridge, "")
	f.cap.msgs, f.cap.ras = nil, nil
	needResult(t, runD2b(context.Background(), f.e), FAIL)
	f = newD6Fix(t, ShapeBridge, "")
	f.cap.msgs, f.cap.ras = nil, nil
	f.h.runErr = errors.New("exit 125")
	needResult(t, runD2b(context.Background(), f.e), PASS)
	f = newD6Fix(t, ShapeIpvlan, "")
	needResult(t, runD2b(context.Background(), f.e), NA)
}

func TestRunD2OnIpvlanJudgesTheRefusal(t *testing.T) {
	f := newD6Fix(t, ShapeIpvlan, "")
	f.h.netErr = errors.New("ipv6_mode=slaac is not supported in ipvlan mode")
	needResult(t, runD2(context.Background(), f.e), PASS)
	f = newD6Fix(t, ShapeIpvlan, "")
	needResult(t, runD2(context.Background(), f.e), FAIL)
}

func TestRunD2PassesOnTheEUI64Address(t *testing.T) {
	f := newD6Fix(t, ShapeMacvlan, "")
	o, want := goodD2(t)
	f.h.forceMAC = d2MAC
	f.cap.msgs, f.cap.ras, f.cap.raAt = nil, o.RAs[:1], time.Now()
	ll := addrLine(d6LL.Addr.String(), 64, "link", "forever", "forever")
	f.h.start = ll + addrLine(want.String(), 64, "global", "7200sec", "3600sec")
	f.h.settled = ll + addrLine(want.String(), 64, "global", "7200sec", "3600sec")
	f.h.inspect = want.String()
	f.src.leases6 = nil
	needResult(t, runD2(context.Background(), f.e), PASS)
	f.h.addrReads = 0
	f.h.settled = ll + addrLine("fd42:200:0:100::77", 64, "global", "7200sec", "3600sec")
	f.h.start = f.h.settled
	needResult(t, runD2(context.Background(), f.e), FAIL)
}

func TestRunF4ExpectsTwoMessagesAndRestoresTheSource(t *testing.T) {
	f := newD6Fix(t, ShapeMacvlan, "", sourceadapter.CapRapidCommit6)
	f.cap.msgs = []DHCP6Msg{d6Msg(0, "SOLICIT", true, []IA6{{IAID: 1}}, nil), d6Msg(0, "REPLY", true, d6IA(d6NA), nil)}
	needResult(t, runF4(context.Background(), f.e), PASS)
	if f.src.featureEnabled() != 1 || f.src.features[0] != sourceadapter.FeatureRapidCommit6 || f.src.featureRestores != 1 {
		t.Errorf("features %v, restores %d", f.src.features, f.src.featureRestores)
	}
	if f.cmdCount("rapid_commit=true") != 1 {
		t.Errorf("the network was not created with rapid_commit=true")
	}
	f = newD6Fix(t, ShapeMacvlan, "", sourceadapter.CapRapidCommit6)
	f.cap.msgs[0].Rapid = true
	needResult(t, runF4(context.Background(), f.e), FAIL)
	if f.src.featureRestores != 1 {
		t.Errorf("a FAIL skipped the restore")
	}
}

func TestRunF4OnAnOldPluginExpectsFourMessagesWithoutTheOption(t *testing.T) {
	f := newD6Fix(t, ShapeMacvlan, tagOld, sourceadapter.CapRapidCommit6)
	needResult(t, runF4(context.Background(), f.e), PASS)
	if f.cmdCount("rapid_commit") != 0 {
		t.Errorf("an old plugin's network was created with rapid_commit")
	}
}

func TestRunF5JudgesTheGrantedTAAndTheKeaFallback(t *testing.T) {
	health := func(ep, ta string) string {
		return fmt.Sprintf(`{"endpoints":[{"endpoint":%q,"ipv6_temporary_address":%q}]}`, ep, ta)
	}
	ep := fmt.Sprintf("%016x%048x", 1, 0)
	ll := addrLine(d6LL.Addr.String(), 64, "link", "forever", "forever")

	f := newD6Fix(t, ShapeMacvlan, "", sourceadapter.CapTemporary6)
	g := goodF5()
	f.cap.msgs = g.Msgs
	f.src.leases6 = g.Leases
	f.h.start = ll + addrLine(d6NA.String(), 128, "global", "forever", "forever") + addrLine(d6TA.String(), 128, "global", "forever", "forever")
	f.h.settled = ll + addrLine(d6NA.String(), 128, "global", "7200sec", "3600sec") + addrLine(d6TA.String(), 128, "global", "7200sec", "3600sec")
	f.h.health = health(ep, d6TA.String()+"/128")
	needResult(t, runF5(context.Background(), f.e), PASS)
	if f.src.featureRestores != 1 || f.cmdCount("ipv6_temporary=true") != 1 {
		t.Errorf("restores %d, network with ipv6_temporary %d", f.src.featureRestores, f.cmdCount("ipv6_temporary=true"))
	}

	f = newD6Fix(t, ShapeMacvlan, "")
	f.cap.msgs = keaF5().Msgs
	f.h.health = health(ep, "")
	needResult(t, runF5(context.Background(), f.e), PASS)
	if f.src.featureEnabled() != 0 {
		t.Errorf("a source without CapTemporary6 had the feature enabled")
	}

	f = newD6Fix(t, ShapeMacvlan, "")
	f.cap.msgs = keaF5().Msgs
	f.h.health = "not json"
	needResult(t, runF5(context.Background(), f.e), BLOCKED)
}
