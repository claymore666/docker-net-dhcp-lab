package scenario

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// D3a sets M=1 A=0, judges the wire's flags and restores the RA on every
// verdict (#23 group D part 2, defeat 6).
func TestRunD3aSetsTheManagedRAAndRestoresIt(t *testing.T) {
	f := newD6Fix(t, ShapeMacvlan, "")
	needResult(t, runD3a(context.Background(), f.e), PASS)
	if len(f.src.raParams) != 1 || !f.src.raParams[0].Managed || f.src.raParams[0].Autonomous || f.src.raRestores != 1 {
		t.Errorf("RA params %+v, restores %d", f.src.raParams, f.src.raRestores)
	}
	if f.cmdCount("ipv6_mode=auto") != 1 {
		t.Error("the network was not created with ipv6_mode=auto")
	}
	f = newD6Fix(t, ShapeMacvlan, "")
	f.cap.ras[0].PIOs = []PIO{{Prefix: netip.MustParsePrefix("fd42:200:0:100::/64"), Auto: true, Valid: 1800, Pref: 900}}
	needResult(t, runD3a(context.Background(), f.e), BLOCKED)
	if f.src.raRestores != 1 {
		t.Error("a BLOCKED skipped the RA restore")
	}
	f = newD6Fix(t, ShapeMacvlan, "")
	f.src.raErr = errors.New("radvd refused")
	needResult(t, runD3a(context.Background(), f.e), BLOCKED)
	if f.cmdCount("docker network create") != 0 {
		t.Error("a network was created on an RA the source refused")
	}
}

// D3c stops the DHCPv6 server once and starts it again whatever the auto
// leg finds; a server that still answers is BLOCKED, not judged.
func TestRunD3cStopsTheV6ServerOnceAndRestoresIt(t *testing.T) {
	f := newD6Fix(t, ShapeMacvlan, "", sourceadapter.CapV6ServerStop)
	needResult(t, runD3c(context.Background(), f.e), BLOCKED)
	if f.src.v6Stops != 1 || f.src.v6StopRestores != 1 {
		t.Errorf("stops %d, restores %d", f.src.v6Stops, f.src.v6StopRestores)
	}
	f = newD6Fix(t, ShapeMacvlan, "")
	needResult(t, runD3c(context.Background(), f.e), NA)
	if f.src.v6Stops != 0 {
		t.Error("a source without CapV6ServerStop was stopped")
	}
}

// The create refusals on ipvlan are judged, PASS only on the refusal.
func TestRunF6AndD3OnIpvlanJudgeTheRefusal(t *testing.T) {
	for name, run := range map[string]func(context.Context, Env) Verdict{NameF6: runF6, NameD3a: runD3a, NameD3c: runD3c} {
		f := newD6Fix(t, ShapeIpvlan, "", sourceadapter.CapPD, sourceadapter.CapV6ServerStop)
		f.h.netErr = errors.New("not supported in ipvlan mode")
		if v := run(context.Background(), f.e); v.Result != PASS {
			t.Errorf("%s refused: %s %q", name, v.Result, v.Reason)
		}
		f = newD6Fix(t, ShapeIpvlan, "", sourceadapter.CapPD, sourceadapter.CapV6ServerStop)
		if v := run(context.Background(), f.e); v.Result != FAIL {
			t.Errorf("%s accepted: %s %q", name, v.Result, v.Reason)
		}
		if f.src.raOffs != 0 || f.src.v6Stops != 0 || f.src.featureEnabled() != 0 {
			t.Errorf("%s touched the source on ipvlan", name)
		}
	}
	f := newD6Fix(t, ShapeIpvlan, "", sourceadapter.CapPref64)
	needResult(t, runF7(context.Background(), f.e), NA)
}

// D4 asks for the second prefix and restores it on every verdict.
func TestRunD4AsksForTheSecondPrefixAndRestoresIt(t *testing.T) {
	for _, run := range []func(context.Context, Env) Verdict{runD4, runD4m} {
		f := newD6Fix(t, ShapeMacvlan, "")
		f.e.Subnet6 = "fd42:200:0:100::/64"
		// d4Row reads RAs from after its SetRA only.
		f.cap.msgs, f.cap.raAt = nil, time.Now().Add(100*time.Millisecond)
		f.cap.ras = []RAMsg{{Src: d6Router, RouterLifetime: 1800, PIOs: []PIO{{Prefix: netip.MustParsePrefix("fd42:200:0:100::/64"), Auto: true, Valid: 1800, Pref: 900}}}}
		v := run(context.Background(), f.e)
		if v.Result != BLOCKED || !strings.Contains(v.Reason, "prefix") {
			t.Errorf("one advertised prefix: %s %q", v.Result, v.Reason)

		}
		if len(f.src.raParams) != 1 || !f.src.raParams[0].Second.IsValid() || f.src.raRestores != 1 {
			t.Errorf("RA params %+v, restores %d", f.src.raParams, f.src.raRestores)
		}
	}
}

// f7Host answers the route reads with after once the fake SetRA ran,
// before otherwise, stamps the cell's RA at the network create and notes
// whether the second container started after SetRA (#23 row F7-pref64).
type f7Host struct {
	*d6Host
	src           *bAdapter
	cap           *d6Cap
	before, after string
	bindAfterSet  *bool
}

func (h f7Host) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "docker network create") {
		h.cap.raAt = time.Now()
	}
	if strings.Contains(cmd, "docker run") && strings.Contains(cmd, "-bind") {
		*h.bindAfterSet = len(h.src.raParams) > 0
	}
	if strings.HasSuffix(cmd, "ip -6 route show") {
		if len(h.src.raParams) > 0 {
			return h.after, nil
		}
		return h.before, nil
	}
	return h.d6Host.Run(ctx, cmd)
}

// f7Cap adds an RA carrying the SetRA's PREF64, stamped at each read
// after the fake SetRA ran (#23 row F7-pref64).
type f7Cap struct {
	*d6Cap
	src *bAdapter
}

func (c *f7Cap) Messages6(ctx context.Context, ident, snap string) ([]DHCP6Msg, []RAMsg, error) {
	msgs, ras, err := c.d6Cap.Messages6(ctx, ident, snap)
	if err != nil || len(c.src.raParams) == 0 || len(ras) == 0 {
		return msgs, ras, err
	}
	ra := ras[0]
	ra.At, ra.Pref64 = time.Now(), []netip.Prefix{c.src.raParams[0].Pref64}
	return msgs, append(ras, ra), nil
}

// F7-pref64 follows plugin docs/reference.md:2027-2031: a PREF64-only RA
// is no lease event, so the first endpoint may still lack nat64_prefixes
// and a second container bound after the RA must show it; the routes
// baseline is the first container's read before the RA (#23).
func TestRunF7JudgesTheBindAfterPref64(t *testing.T) {
	s := f7Settle
	f7Settle = 10 * time.Millisecond
	t.Cleanup(func() { f7Settle = s })
	const base = "fd42:200:0:100::/64 dev eth0 proto kernel metric 256 pref medium\ndefault via fe80::1 dev eth0 proto ra metric 1024 pref medium\n"
	first, second := fmt.Sprintf("%016x%048x", 1, 0), fmt.Sprintf("%016x%048x", 2, 0)
	entry := func(ep string, p64 bool) string {
		if p64 {
			return fmt.Sprintf(`{"endpoint":%q,"nat64_prefixes":["fd42:200:0:164::/96"]}`, ep)
		}
		return fmt.Sprintf(`{"endpoint":%q}`, ep)
	}
	wrong := func(ep string) string {
		return fmt.Sprintf(`{"endpoint":%q,"nat64_prefixes":["fd42:200:0:165::/96"]}`, ep)
	}
	for _, tc := range []struct {
		name, after, health string
		want                Result
		reason              string
	}{
		{"documented", base, entry(first, false) + "," + entry(second, true), PASS, "bound after PREF64"},
		{"both show it", base, entry(first, true) + "," + entry(second, true), PASS, "bound after PREF64"},
		{"bind lacks it", base, entry(first, true) + "," + entry(second, false), FAIL, "bound after PREF64 was advertised, the RA carried"},
		{"bind shows another prefix", base, entry(first, false) + "," + wrong(second), FAIL, "bound after PREF64 was advertised, the RA carried"},
		{"bind not listed", base, entry(first, true), FAIL, "no entry"},
		{"route added", base + "fd42:200:0:99::/64 via fe80::1 dev eth0 metric 1024 pref medium\n", entry(first, false) + "," + entry(second, true), FAIL, "routes changed"},
	} {
		f := newD6Fix(t, ShapeMacvlan, "", sourceadapter.CapPref64)
		f.e.Subnet6 = "fd42:200:0:100::/64"
		o, want := goodD2(t)
		f.h.forceMAC = d2MAC
		f.cap.msgs, f.cap.ras = nil, o.RAs[:1]
		ll := addrLine(d6LL.Addr.String(), 64, "link", "forever", "forever")
		f.h.start = ll + addrLine(want.String(), 64, "global", "7200sec", "3600sec")
		f.h.settled = f.h.start
		f.h.inspect = want.String()
		f.h.health = `{"endpoints":[` + tc.health + `]}`
		f.src.leases6 = nil
		var bindAfterSet bool
		f.e.Host = f7Host{d6Host: f.h, src: f.src, cap: f.cap, before: base, after: tc.after, bindAfterSet: &bindAfterSet}
		f.e.Capture = &f7Cap{d6Cap: f.cap, src: f.src}
		v := runF7(context.Background(), f.e)
		if v.Result != tc.want || !strings.Contains(v.Reason, tc.reason) {
			t.Errorf("%s: %s %q", tc.name, v.Result, v.Reason)
		}
		if !bindAfterSet {
			t.Errorf("%s: the second container did not start after the PREF64 RA was set", tc.name)
		}
	}
}
