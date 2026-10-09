package scenario

import (
	"context"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// reasoningAdapter is a fakeAdapter that also names why it lacks a capability.
type reasoningAdapter struct {
	*fakeAdapter
	why map[sourceadapter.Capability]string
}

func (r reasoningAdapter) NAReason(c sourceadapter.Capability) (string, bool) {
	why, ok := r.why[c]
	return why, ok
}

// DESIGN-910 5.2: the adapter's own reason comes first, then the shared
// table, then the bare "does not declare".
func TestApplicableConsultsTheAdaptersNAReasonFirst(t *testing.T) {
	s := Scenario{Name: "needs-relay", Needs: []sourceadapter.Capability{sourceadapter.CapRelay}}
	bare := &fakeAdapter{}
	_, shared := Applicable(s, bare)
	if !strings.Contains(shared, "relay cell") {
		t.Fatalf("shared-table reason lost: %q", shared)
	}
	own := reasoningAdapter{bare, map[sourceadapter.Capability]string{sourceadapter.CapRelay: "this source has no relay at all"}}
	ok, got := Applicable(s, own)
	if ok || !strings.Contains(got, "this source has no relay at all") || strings.Contains(got, "relay cell") {
		t.Fatalf("own reason not preferred: ok=%v %q", ok, got)
	}
	silent := reasoningAdapter{bare, nil}
	if _, got := Applicable(s, silent); got != shared {
		t.Fatalf("an adapter with no reason for the capability must fall through: %q", got)
	}
	both := reasoningAdapter{&fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapRelay}}, map[sourceadapter.Capability]string{sourceadapter.CapRelay: "x"}}
	if ok, _ := Applicable(s, both); !ok {
		t.Fatal("a declared capability was refused because the adapter had a reason string")
	}
}

// The matrix cell for ReserveClientID on udhcpd names the server's
// behaviour (D1); the real adapter and the real catalog together.
func TestUdhcpdNAScenariosNameTheServerBehaviour(t *testing.T) {
	a := &sourceadapter.UdhcpdAdapter{}
	seen := 0
	for _, s := range Catalog {
		for _, need := range s.Needs {
			if need != sourceadapter.CapReserveClientID {
				continue
			}
			ok, reason := Applicable(s, a)
			if ok {
				t.Errorf("%s runs on udhcpd", s.Name)
			}
			if !strings.Contains(reason, "MAC only") {
				t.Errorf("%s: reason %q does not name the server behaviour", s.Name, reason)
			}
			seen++
		}
	}
	if seen == 0 {
		t.Fatal("no catalog scenario needs reserve-client-id; the test checks nothing")
	}
}

// udhcpdLike is a fake source whose table has udhcpd's shape (MAC and
// address, never a client identifier) and whose shape verdicts are the
// real adapter's, so a gate removed from RunOne shows as a FAIL, not a panic.
type udhcpdLike struct {
	*fakeAdapter
	real *sourceadapter.UdhcpdAdapter
}

func (u *udhcpdLike) NAShapeReason(shape, scenario string) string {
	return u.real.NAShapeReason(shape, scenario)
}

func udhcpdEnv(shape Shape) Env {
	src := &udhcpdLike{real: &sourceadapter.UdhcpdAdapter{}, fakeAdapter: &fakeAdapter{
		caps:   []sourceadapter.Capability{sourceadapter.CapV4},
		leases: []sourceadapter.Lease{{MAC: "02:aa:bb:cc:dd:03", Address: "10.200.12.138"}},
	}}
	return Env{Host: &fakeRunOneHostRunner{installed: true, pgrepOK: true}, Source: src, Cell: "udhcpd", Shape: shape}
}

func scenarioNamed(t *testing.T, name string) Scenario {
	t.Helper()
	for _, s := range Catalog {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no catalog scenario %q", name)
	return Scenario{}
}

// D1 (DESIGN-910, lab #10): udhcpd's table has no client
// identifier, so the ipvlan shape and A2 on the IPAM shapes cannot be
// judged there. Through the real RunOne gate and the real catalog the
// verdict is N/A naming the server's MAC-only leasing, never a FAIL that
// reads as a plugin fault.
func TestUdhcpdIpvlanAndIPAMA2AreNANotFail(t *testing.T) {
	for _, c := range []struct {
		scenario string
		shape    Shape
	}{
		{NameA1, ShapeIpvlan}, {NameA2, ShapeIpvlan},
		{NameA2, ShapeMacvlanIPAM},
	} {
		v := RunOne(context.Background(), scenarioNamed(t, c.scenario), udhcpdEnv(c.shape))
		if v.Result != NA {
			t.Errorf("%s on %s: want N/A, got %s (%s)", c.scenario, c.shape, v.Result, v.Reason)
			continue
		}
		if !strings.Contains(v.Reason, "MAC only") && !strings.Contains(v.Reason, "no client identifiers") {
			t.Errorf("%s on %s: reason %q does not name udhcpd's MAC-only leasing", c.scenario, c.shape, v.Reason)
		}
		if strings.Contains(v.Reason, "no lease for client-id") {
			t.Errorf("%s on %s: reason reads as a plugin fault: %q", c.scenario, c.shape, v.Reason)
		}
	}
}

// The gate is narrow: udhcpd still runs A1 and A2 where the MAC is the key.
func TestUdhcpdShapeGateLeavesTheMACKeyedRunsAlone(t *testing.T) {
	a := &sourceadapter.UdhcpdAdapter{}
	for _, c := range []struct{ shape, scenario string }{
		{"bridge", NameA1}, {"macvlan", NameA2}, {"bridge", NameA2},
		{"bridge-ipam", NameA1}, {"macvlan-ipam", NameA1}, {"bridge-ipam", NameA3}, {"macvlan-ipam", NameA4},
	} {
		if why := a.NAShapeReason(c.shape, c.scenario); why != "" {
			t.Errorf("%s on %s refused: %s", c.scenario, c.shape, why)
		}
	}
	if why := a.NAShapeReason(string(ShapeBridgeIPAM), NameA2); !strings.Contains(why, "client identifiers") {
		t.Errorf("A2 on bridge-ipam: %q", why)
	}
	for _, s := range Catalog {
		if why := a.NAShapeReason("ipvlan", s.Name); why == "" {
			t.Errorf("%s on ipvlan is not refused on udhcpd", s.Name)
		}
	}
}

// Group D stays off udhcpd through Applicable, with the DHCPv4-only reason
// (lab #10, #23): the adapter declares no CapV6 and says why.
func TestUdhcpdKeepsEveryV6ScenarioOffWithTheReason(t *testing.T) {
	a := &sourceadapter.UdhcpdAdapter{}
	seen := 0
	for _, s := range Catalog {
		for _, need := range s.Needs {
			if need != sourceadapter.CapV6 {
				continue
			}
			seen++
			ok, reason := Applicable(s, a)
			if ok {
				t.Errorf("%s runs on udhcpd", s.Name)
			}
			if !strings.Contains(reason, "DHCPv4 only") {
				t.Errorf("%s: reason %q does not name udhcpd's v4-only service", s.Name, reason)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no catalog scenario needs v6; the test checks nothing")
	}
	if _, err := a.Leases6(context.Background()); err == nil || !strings.Contains(err.Error(), "DHCPv4 only") {
		t.Fatalf("Leases6 must refuse with the reason: %v", err)
	}
	if _, err := a.SetRA(context.Background(), sourceadapter.RAParams{}); err == nil || !strings.Contains(err.Error(), "DHCPv4 only") {
		t.Fatalf("SetRA must refuse with the reason: %v", err)
	}
}
