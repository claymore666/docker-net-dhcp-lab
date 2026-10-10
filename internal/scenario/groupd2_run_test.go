package scenario

import (
	"context"
	"errors"
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
