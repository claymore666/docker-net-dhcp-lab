package scenario

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// hRunner is cRunner plus the two reads the hostile scenarios add: the
// docker host's link count and a container's /proc/net/route.
type hRunner struct {
	*cRunner
	hmu   sync.Mutex
	links func(call int) int
	calls int
	gw    map[string]string
}

func (h *hRunner) Run(ctx context.Context, cmd string) (string, error) {
	switch {
	case strings.Contains(cmd, "ip -o link show | wc -l"):
		h.hmu.Lock()
		defer h.hmu.Unlock()
		h.calls++
		n := 12
		if h.links != nil {
			n = h.links(h.calls)
		}
		return fmt.Sprintf("%d\n", n), nil
	case strings.Contains(cmd, "cat /proc/net/route"):
		h.hmu.Lock()
		defer h.hmu.Unlock()
		gw := h.gw[strings.Fields(cmd)[3]]
		if gw == "" {
			return "Iface\tDestination\tGateway\n", nil
		}
		b := netip.MustParseAddr(gw).As4()
		return fmt.Sprintf("Iface\tDestination\tGateway\neth0\t00000000\t%02X%02X%02X%02X\n", b[3], b[2], b[1], b[0]), nil
	}
	return h.cRunner.Run(ctx, cmd)
}

func (h *hRunner) setGW(name, gw string) {
	h.hmu.Lock()
	defer h.hmu.Unlock()
	h.gw[name] = gw
}

type hRig struct {
	*cRig
	host *hRunner
}

func hSetup(t *testing.T, shape Shape) *hRig {
	t.Helper()
	r := cSetup(t, shape)
	h := &hRunner{cRunner: r.h, gw: map[string]string{}}
	r.e.Host = h
	return &hRig{cRig: r, host: h}
}

// leaseOf is the table row the source would hold for a running container.
func (r *hRig) leaseOf(name, addr string) (sourceadapter.Lease, bool) {
	c, _, ok := r.h.container(name)
	if !ok {
		return sourceadapter.Lease{}, false
	}
	l := sourceadapter.Lease{MAC: c.mac, Address: addr, Expires: time.Now().Add(time.Hour)}
	if r.e.Shape == ShapeIpvlan {
		l.ClientID, _ = ipvlanClientID(c.endpointID)
	}
	return l, true
}

func (r *hRig) identOf(name string) string {
	c, _, _ := r.h.container(name)
	id, _ := cIdent(r.e.Shape, c.mac, c.endpointID)
	return id
}

func needStops(t *testing.T, what string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s: %d stop(s) or restore(s), want %d", what, got, want)
	}
}

func lease(clientID, addr string) sourceadapter.Lease {
	return sourceadapter.Lease{ClientID: clientID, Address: addr, Expires: time.Now().Add(time.Hour)}
}

// ---- address bands (defeat 13) and the renumber target (defeat 10) ----

func TestGroupCAddressesStayClearOfEveryOtherBand(t *testing.T) {
	e := bEnv(t, newBRunner(), &fakeAdapter{}, ShapeBridge)
	used := map[int]string{}
	for i := range Shapes {
		used[reserveBaseHost+i] = "B1"
		used[reserveBaseHost+len(Shapes)+i] = "B2"
	}
	for h := userClassFirstHost; h <= userClassLastHost; h++ {
		used[h] = "user-class pool"
	}
	for h := classPoolFirstHost; h <= classPoolLastHost; h++ {
		used[h] = "class pool"
	}
	used[dnsOptionHost] = "DNS"
	var ours []int
	for i := range Shapes {
		ours = append(ours, c6BaseHost+i)
	}
	ours = append(ours, c8FirstHost, c8LastHost, rogueHost)
	for h := rogueFirstHost; h <= rogueLastHost; h++ {
		ours = append(ours, h)
	}
	for _, h := range ours {
		if what, ok := used[h]; ok {
			t.Errorf(".%d is also %s", h, what)
		}
		used[h] = "group C"
		a, err := groupCAddr(e, h)
		if err != nil {
			t.Errorf(".%d: %v", h, err)
			continue
		}
		if inMainPool(e, a) {
			t.Errorf("%s lies in the main pool", a)
		}
	}
	for _, h := range []int{userClassFirstHost, reserveBaseHost + 2*len(Shapes) - 1, classPoolLastHost, dnsOptionHost, 150, 1} {
		if _, err := groupCAddr(e, h); err == nil {
			t.Errorf("groupCAddr accepted .%d", h)
		}
	}
}

func TestC9TargetCollidesWithNoLabYAMLSubnet(t *testing.T) {
	cfg, err := labyaml.Load(filepath.Join("..", "..", "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lab := netip.MustParsePrefix("10.200.0.0/16")
	var taken []netip.Prefix
	for _, c := range cfg.Cells {
		taken = append(taken, netip.MustParsePrefix(c.Segment.Subnet))
		// A relay cell's server segment is a subnet too (#11, r2 finding 2).
		if c.Relay != nil {
			taken = append(taken, netip.MustParsePrefix(c.Relay.ServerSegment.Subnet))
		}
	}
	taken = append(taken, netip.MustParsePrefix(cfg.Management.Subnet))
	seen := 0
	for _, c := range cfg.Cells {
		// A relay cell's source is not on its client segment and its
		// adapter declares no renumber, so C9 never runs there (#11).
		if c.Source == nil || c.Relay != nil {
			continue
		}
		seen++
		e := Env{SegSubnet: c.Segment.Subnet, SourceAddr: strings.SplitN(c.Source.SegAddress, "/", 2)[0], PoolStart: c.Source.PoolStart, PoolEnd: c.Source.PoolEnd}
		subnet, addr, first, last, err := c9Target(e)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		s := netip.MustParsePrefix(subnet)
		if !lab.Contains(s.Addr()) {
			t.Errorf("%s: %s leaves the lab's own range", c.Name, s)
		}
		for _, o := range taken {
			if o.Overlaps(s) {
				t.Errorf("%s: %s overlaps %s", c.Name, s, o)
			}
		}
		for _, a := range []string{addr, first, last} {
			if !s.Contains(netip.MustParseAddr(a)) {
				t.Errorf("%s: %s is not in %s", c.Name, a, s)
			}
		}
		if a, f, l := netip.MustParseAddr(addr), netip.MustParseAddr(first), netip.MustParseAddr(last); a.Compare(f) >= 0 && a.Compare(l) <= 0 {
			t.Errorf("%s: the source's new address %s is inside its new pool", c.Name, a)
		}
	}
	if seen < 3 {
		t.Fatalf("lab.yaml holds %d cells with a source", seen)
	}
}

func TestC9TargetRefusesWhatItCannotMove(t *testing.T) {
	for _, e := range []Env{
		{SegSubnet: "10.200.200.0/24", SourceAddr: "10.200.200.2", PoolStart: "10.200.200.100", PoolEnd: "10.200.200.200"},
		{SegSubnet: "10.200.1.0/25", SourceAddr: "10.200.1.2", PoolStart: "10.200.1.100", PoolEnd: "10.200.1.120"},
		{SegSubnet: "10.200.1.0/24", SourceAddr: "10.200.9.2", PoolStart: "10.200.1.100", PoolEnd: "10.200.1.200"},
	} {
		if _, _, _, _, err := c9Target(e); err == nil {
			t.Errorf("%+v: no error", e)
		}
	}
}

// ---- IPAM shapes (D4) ----

func TestHostileScenariosAreNotApplicableOnTheIPAMShapes(t *testing.T) {
	runs := map[string]func(context.Context, Env, cTiming) Verdict{
		NameC6: runC6Tuned, NameC6b: runC6bTuned, NameC7: runC7Tuned, NameC8: runC8Tuned, NameC9: runC9Tuned,
	}
	for _, shape := range []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		for name, run := range runs {
			r := hSetup(t, shape)
			v := run(context.Background(), r.e, cFast)
			needResult(t, v, NA)
			if name == NameC9 {
				needReason(t, v, c9NetworkWhat)
			} else {
				needReason(t, v, "the option-carrying network")
			}
			f := r.src.fakeAdapter
			if n := len(f.squats) + len(f.rogues) + len(f.narrows) + len(f.renumbers) + len(f.reservedID); n != 0 || len(r.h.cmds) != 0 {
				t.Errorf("%s on %s: %d actor call(s), %d docker command(s)", name, shape, n, len(r.h.cmds))
			}
		}
	}
}

// ---- C6 ----

// c6Rig: the source offers the reserved X, the client DECLINEs it and is
// ACKed on .101, which the table leases to the network's client id.
func c6Rig(t *testing.T, shape Shape) (*hRig, string, string) {
	r := hSetup(t, shape)
	i, _ := shapeIndex(shape)
	x, err := groupCAddr(r.e, c6BaseHost+i)
	if err != nil {
		t.Fatal(err)
	}
	wire := b2WireClientID("lab-c6-" + string(shape))
	r.cap.fn = func(string) []DHCPMsg {
		now := time.Now()
		decl := dmsg(now, "DECLINE", "a", wire, "", "255.255.255.255")
		decl.Requested = x
		return []DHCPMsg{dmsg(now, "OFFER", "a", wire, x, x), decl, dmsg(now, "ACK", "b", wire, "10.200.1.101", "10.200.1.101")}
	}
	r.src.fn = staticLeases(lease(wire, "10.200.1.101"))
	return r, x, wire
}

func TestRunC6PassesWhenTheClientDeclinesTheSquattedAddress(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan} {
		t.Run(string(shape), func(t *testing.T) {
			r, x, wire := c6Rig(t, shape)
			v := runC6Tuned(context.Background(), r.e, cFast)
			needResult(t, v, PASS)
			needWritten(t, r.e, v)
			needReason(t, v, "branch other-address")
			f := r.src.fakeAdapter
			if fmt.Sprint(f.reservedID) != fmt.Sprintf("[%s=%s]", wire, x) || fmt.Sprint(f.squats) != fmt.Sprintf("[%s/false]", x) {
				t.Errorf("reserved %v squats %v", f.reservedID, f.squats)
			}
			if !r.h.has("client_id=lab-c6-"+string(shape)) || !r.h.has("conflict_check=wait") {
				t.Error("the c6 network does not carry client_id and conflict_check=wait")
			}
			needStops(t, "squatter", f.squatStops, 1)
			needCleanup(t, r.h.bRunner, "c6", containerName(r.e, NameC6))
		})
	}
}

func TestRunC6PassesWhenTheRunFailsAfterTheDecline(t *testing.T) {
	r, _, _ := c6Rig(t, ShapeMacvlan)
	r.h.rc[containerName(r.e, NameC6)] = 1
	v := runC6Tuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needReason(t, v, "branch run-failed")
}

func TestRunC6Judges(t *testing.T) {
	cases := []struct {
		name   string
		result Result
		want   string
		stops  int
		edit   func(r *hRig, x, wire string)
	}{
		{"no OFFER of X", BLOCKED, "never tested", 1, func(r *hRig, _, wire string) {
			r.cap.fn = func(string) []DHCPMsg { return []DHCPMsg{dmsg(time.Now(), "ACK", "b", wire, "10.200.1.101", "")} }
		}},
		{"an OFFER and no DECLINE", FAIL, "no DECLINE", 1, func(r *hRig, x, wire string) {
			r.cap.fn = func(string) []DHCPMsg { return []DHCPMsg{dmsg(time.Now(), "OFFER", "a", wire, x, x)} }
		}},
		{"a DECLINE of another address", FAIL, "no DECLINE", 1, func(r *hRig, x, wire string) {
			r.cap.fn = func(string) []DHCPMsg {
				d := dmsg(time.Now(), "DECLINE", "a", wire, "", "")
				d.Requested = "10.200.1.150"
				return []DHCPMsg{dmsg(time.Now(), "OFFER", "a", wire, x, x), d}
			}
		}},
		{"a DECLINE before the run", FAIL, "no DECLINE", 1, func(r *hRig, x, wire string) {
			r.cap.fn = func(string) []DHCPMsg {
				d := dmsg(time.Now().Add(-time.Hour), "DECLINE", "a", wire, "", "")
				d.Requested = x
				return []DHCPMsg{dmsg(time.Now(), "OFFER", "a", wire, x, x), d}
			}
		}},
		{"the table still leases X", FAIL, "still holds an active lease", 1, func(r *hRig, x, wire string) {
			r.src.fn = staticLeases(lease(wire, x), lease(wire, "10.200.1.101"))
		}},
		{"the container carries X", FAIL, "carries the squatted", 1, func(r *hRig, x, _ string) {
			r.h.setAddrs(containerName(r.e, NameC6), x)
		}},
		{"the container's address is not its lease", FAIL, "none of it an active lease", 1, func(r *hRig, _, wire string) {
			r.src.fn = staticLeases(lease(wire, "10.200.1.150"))
		}},
		{"the reservation fails", BLOCKED, "could not reserve", 0, func(r *hRig, _, _ string) { r.src.reserveErr = errors.New("x") }},
		{"the squatter fails", BLOCKED, "could not put a squatter", 0, func(r *hRig, _, _ string) { r.src.squatErr = errors.New("x") }},
		{"the network fails", BLOCKED, "could not create the c6 network", 1, func(r *hRig, _, _ string) { r.h.netErr = errors.New("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, x, wire := c6Rig(t, ShapeMacvlan)
			c.edit(r, x, wire)
			v := runC6Tuned(context.Background(), r.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			needStops(t, "squatter", r.src.squatStops, c.stops)
		})
	}
}

// ---- C6b ----

// c6bRig: the container comes up on .101; once the squatter takes it the
// client DECLINEs .101 and the source leases it .150.
func c6bRig(t *testing.T, shape Shape) *hRig {
	r := hSetup(t, shape)
	name := containerName(r.e, NameC6b)
	var squatted bool
	r.src.onSquat = func() {
		squatted = true
		r.h.setAddrs(name, "10.200.1.150")
	}
	r.cap.fn = func(ident string) []DHCPMsg {
		if !squatted {
			return nil
		}
		d := dmsg(time.Now(), "DECLINE", "a", ident, "", "")
		d.Requested = "10.200.1.101"
		return []DHCPMsg{d}
	}
	r.src.fn = func(int) []sourceadapter.Lease {
		if l, ok := r.leaseOf(name, "10.200.1.150"); ok && squatted {
			return []sourceadapter.Lease{l}
		}
		l, _ := r.leaseOf(name, "10.200.1.101")
		return []sourceadapter.Lease{l}
	}
	return r
}

func TestRunC6bPassesWhenTheClientMovesOffTheSquattedAddress(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan} {
		t.Run(string(shape), func(t *testing.T) {
			r := c6bRig(t, shape)
			v := runC6bTuned(context.Background(), r.e, cFast)
			needResult(t, v, PASS)
			needWritten(t, r.e, v)
			needReason(t, v, r.identOf(containerName(r.e, NameC6b))+" DECLINEd 10.200.1.101")
			if fmt.Sprint(r.src.squats) != "[10.200.1.101/true]" || !r.h.has("conflict_check=async") {
				t.Errorf("squats %v", r.src.squats)
			}
			needStops(t, "squatter", r.src.squatStops, 1)
			needCleanup(t, r.h.bRunner, "c6b", containerName(r.e, NameC6b))
		})
	}
}

func TestRunC6bJudges(t *testing.T) {
	cases := []struct {
		name   string
		result Result
		want   string
		stops  int
		edit   func(r *hRig)
	}{
		{"no DECLINE", FAIL, "DECLINE of 10.200.1.101 seen: false", 1, func(r *hRig) { r.cap.fn = nil }},
		{"still carries X", FAIL, "carries [10.200.1.101 10.200.1.150]", 1, func(r *hRig) {
			on := r.src.onSquat
			r.src.onSquat = func() { on(); r.h.setAddrs(containerName(r.e, NameC6b), "10.200.1.101", "10.200.1.150") }
		}},
		{"the table keeps X beside Y", FAIL, "are [10.200.1.101 10.200.1.150]", 1, func(r *hRig) {
			name := containerName(r.e, NameC6b)
			r.src.fn = func(int) []sourceadapter.Lease {
				x, _ := r.leaseOf(name, "10.200.1.101")
				y, _ := r.leaseOf(name, "10.200.1.150")
				return []sourceadapter.Lease{x, y}
			}
		}},
		{"the squatter fails", BLOCKED, "could not put a squatter", 0, func(r *hRig) { r.src.squatErr = errors.New("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c6bRig(t, ShapeMacvlan)
			c.edit(r)
			v := runC6bTuned(context.Background(), r.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			needStops(t, "squatter", r.src.squatStops, c.stops)
		})
	}
}

// ---- C7 ----

const c7Rogue = "10.200.1.240"

// c7Rig: the rogue and the source both offer; the client requests from
// the source, which leases each container the address it carries.
func c7Rig(t *testing.T, shape Shape) *hRig {
	r := hSetup(t, shape)
	r.cap.fn = func(ident string) []DHCPMsg {
		now := time.Now()
		ro := dmsg(now, "OFFER", "a", ident, "10.200.1.245", "")
		ro.Server = c7Rogue
		so := dmsg(now, "OFFER", "a", ident, "10.200.1.101", "")
		so.Server = r.e.SourceAddr
		rq := dmsg(now, "REQUEST", "a", ident, "", "")
		rq.Server = r.e.SourceAddr
		return []DHCPMsg{ro, so, rq}
	}
	r.src.fn = func(int) []sourceadapter.Lease {
		var out []sourceadapter.Lease
		for _, s := range []string{"-c7", "-c7b"} {
			name := containerName(r.e, NameC7) + s
			if c, _, ok := r.h.container(name); ok {
				l, _ := r.leaseOf(name, c.addr)
				out = append(out, l)
			}
		}
		return out
	}
	return r
}

func TestRunC7PassesWhenBothNetworksLeaseFromTheSource(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan} {
		t.Run(string(shape), func(t *testing.T) {
			r := c7Rig(t, shape)
			v := runC7Tuned(context.Background(), r.e, cFast)
			needResult(t, v, PASS)
			needWritten(t, r.e, v)
			if fmt.Sprint(r.src.rogues) != "[10.200.1.240 10.200.1.241-10.200.1.250]" {
				t.Errorf("rogues %v", r.src.rogues)
			}
			if !r.h.has("dhcp_deny_servers="+c7Rogue) || !r.h.has("dhcp_servers="+r.e.SourceAddr) {
				t.Error("the networks do not carry dhcp_deny_servers and dhcp_servers")
			}
			needStops(t, "rogue", r.src.rogueStops, 1)
			needCleanup(t, r.h.bRunner, "c7", containerName(r.e, NameC7)+"-c7")
			needCleanup(t, r.h.bRunner, "c7b", containerName(r.e, NameC7)+"-c7b")
		})
	}
}

// A relay cell routes via an address that is not the source (#11): C7
// must name and credit the source, never the router.
func TestRunC7NamesTheSourceNotTheRouter(t *testing.T) {
	r := c7Rig(t, ShapeMacvlan)
	r.e.SegGateway = "10.200.1.254"
	v := runC7Tuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	if !r.h.has("dhcp_servers="+r.e.SourceAddr) || r.h.has("dhcp_servers="+r.e.SegGateway) {
		t.Error("c7b's dhcp_servers does not name the source alone")
	}
	r = c7Rig(t, ShapeMacvlan)
	r.e.SegGateway = "10.200.1.254"
	f := r.cap.fn
	r.cap.fn = func(ident string) []DHCPMsg {
		m := f(ident)
		m[2].Server = r.e.SegGateway
		return m
	}
	v = runC7Tuned(context.Background(), r.e, cFast)
	needResult(t, v, FAIL)
	needReason(t, v, "no REQUEST from")
}

func TestC9TargetMovesTheSourceNotTheRouter(t *testing.T) {
	e := Env{SegSubnet: "10.200.1.0/24", PoolStart: "10.200.1.100", PoolEnd: "10.200.1.200", SegGateway: "10.200.1.1", SourceAddr: "10.200.1.2"}
	if _, addr, _, _, err := c9Target(e); err != nil || addr != "10.200.101.2" {
		t.Errorf("c9Target addr %q, %v; want 10.200.101.2", addr, err)
	}
}

func TestRunC7Judges(t *testing.T) {
	cases := []struct {
		name   string
		result Result
		want   string
		stops  int
		edit   func(r *hRig)
	}{
		{"the rogue never offered", BLOCKED, "the rogue never competed", 1, func(r *hRig) {
			f := r.cap.fn
			r.cap.fn = func(ident string) []DHCPMsg { return f(ident)[1:] }
		}},
		{"a REQUEST names the rogue", FAIL, "a REQUEST naming the rogue", 1, func(r *hRig) {
			f := r.cap.fn
			r.cap.fn = func(ident string) []DHCPMsg {
				m := f(ident)
				m[2].Server = c7Rogue
				return m
			}
		}},
		{"no REQUEST to the source", FAIL, "no REQUEST from", 1, func(r *hRig) {
			f := r.cap.fn
			r.cap.fn = func(ident string) []DHCPMsg { return f(ident)[:2] }
		}},
		{"an address from the rogue's pool", FAIL, "outside the source's pool", 1, func(r *hRig) {
			r.h.addrFn = func(string, string) string { return "10.200.1.245" }
		}},
		{"the source holds no lease", FAIL, "c7: ", 1, func(r *hRig) { r.src.fn = staticLeases() }},
		{"the rogue leased it", FAIL, "the rogue's lease file holds", 1, func(r *hRig) {
			r.src.rogueLeases = []sourceadapter.Lease{{MAC: "aa:bb:cc:00:00:01", ClientID: "aa:bb:cc:00:00:01", Address: "10.200.1.245"}}
		}},
		{"the rogue will not start", BLOCKED, "could not start the rogue", 0, func(r *hRig) { r.src.rogueErr = errors.New("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c7Rig(t, ShapeMacvlan)
			c.edit(r)
			v := runC7Tuned(context.Background(), r.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			needStops(t, "rogue", r.src.rogueStops, c.stops)
		})
	}
}

// ---- C8 ----

// c8Rig: the fills take .201 and .202, the third run fails after its
// DISCOVERs, the fourth container gets .150 once the pool is back.
func c8Rig(t *testing.T, shape Shape) (*hRig, string) {
	r := hSetup(t, shape)
	base := containerName(r.e, NameC8)
	r.h.rc[base+"-c8"] = 1
	r.h.addrFn = func(name, _ string) string {
		switch name {
		case base + "-fill1":
			return "10.200.1.201"
		case base + "-fill2":
			return "10.200.1.202"
		}
		return "10.200.1.150"
	}
	wire := b2WireClientID("lab-c8-" + string(shape))
	r.cap.fn = func(string) []DHCPMsg {
		return []DHCPMsg{dmsg(time.Now(), "DISCOVER", "a", wire, "", "255.255.255.255")}
	}
	r.src.fn = func(int) []sourceadapter.Lease {
		l, ok := r.leaseOf(base+"-4", "10.200.1.150")
		if !ok {
			return nil
		}
		return []sourceadapter.Lease{l}
	}
	return r, wire
}

func TestRunC8PassesWhenTheThirdRunFailsCleanly(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan} {
		t.Run(string(shape), func(t *testing.T) {
			r, wire := c8Rig(t, shape)
			v := runC8Tuned(context.Background(), r.e, cFast)
			needResult(t, v, PASS)
			needWritten(t, r.e, v)
			needReason(t, v, wire+" failed")
			if fmt.Sprint(r.src.narrows) != "[10.200.1.201-10.200.1.202]" || !r.h.has("client_id=lab-c8-"+string(shape)) {
				t.Errorf("narrows %v", r.src.narrows)
			}
			needStops(t, "pool", r.src.narrowRestores, 1)
			needCleanup(t, r.h.bRunner, "c8", containerName(r.e, NameC8)+"-c8")
		})
	}
}

func TestRunC8Judges(t *testing.T) {
	cases := []struct {
		name   string
		result Result
		want   string
		stops  int
		edit   func(r *hRig, wire string)
	}{
		{"the fills miss the narrowed pool", BLOCKED, "the pool was not narrowed", 1, func(r *hRig, _ string) {
			r.h.addrFn = func(string, string) string { return "10.200.1.150" }
		}},
		{"the source offers", BLOCKED, "the pool was not exhausted", 1, func(r *hRig, wire string) {
			r.cap.fn = func(string) []DHCPMsg { return []DHCPMsg{dmsg(time.Now(), "OFFER", "a", wire, "10.200.1.203", "")} }
		}},
		{"the third run starts", FAIL, "started on", 1, func(r *hRig, _ string) { r.h.rc[containerName(r.e, NameC8)+"-c8"] = 0 }},
		{"no DISCOVER", FAIL, "no DISCOVER", 1, func(r *hRig, _ string) { r.cap.fn = nil }},
		{"an endpoint is left", FAIL, "endpoint(s) after the failed run", 1, func(r *hRig, _ string) { r.h.endpoints["net1-c8"] = 1 }},
		{"a link is left", FAIL, "links", 1, func(r *hRig, _ string) {
			r.host.links = func(call int) int { return 12 + min(call-1, 1) }
		}},
		{"a lease outlives the failed run", FAIL, "an acquisition outlived the failed endpoint", 1, func(r *hRig, wire string) {
			f := r.src.fn
			r.src.fn = func(c int) []sourceadapter.Lease { return append(f(c), lease(wire, "10.200.1.160")) }
		}},
		{"the fourth container is not leased", FAIL, "fourth container", 1, func(r *hRig, _ string) { r.src.fn = staticLeases() }},
		{"the pool will not narrow", BLOCKED, "could not narrow", 0, func(r *hRig, _ string) { r.src.narrowErr = errors.New("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, wire := c8Rig(t, ShapeMacvlan)
			c.edit(r, wire)
			v := runC8Tuned(context.Background(), r.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			needStops(t, "pool", r.src.narrowRestores, c.stops)
		})
	}
}

func TestRunC8LinkCountMaySettle(t *testing.T) {
	r, _ := c8Rig(t, ShapeMacvlan)
	r.host.links = func(call int) int {
		if call == 2 {
			return 13
		}
		return 12
	}
	needResult(t, runC8Tuned(context.Background(), r.e, cFast), PASS)
}

// ---- C9 ----

// c9Rig: the container binds .101; on the renumber it moves to
// 10.200.101.150 with its default route via the source's new address.
func c9Rig(t *testing.T, shape Shape) *hRig {
	r := hSetup(t, shape)
	name := containerName(r.e, NameC9)
	var moved bool
	r.host.setGW(name, r.e.SegGateway)
	r.src.onRenumber = func() {
		moved = true
		r.h.setAddrs(name, "10.200.101.150")
		r.host.setGW(name, "10.200.101.1")
	}
	r.cap.fn = func(ident string) []DHCPMsg {
		out := []DHCPMsg{dmsg(time.Now().Add(-time.Second), "ACK", "a", ident, "10.200.1.101", "10.200.1.101")}
		if moved {
			out = append(out, dmsg(time.Now(), "NAK", "b", ident, "", ""))
		}
		return out
	}
	r.src.fn = func(int) []sourceadapter.Lease {
		a := "10.200.1.101"
		if moved {
			a = "10.200.101.150"
		}
		l, _ := r.leaseOf(name, a)
		return []sourceadapter.Lease{l}
	}
	return r
}

func TestRunC9PassesWhenTheContainerFollowsTheNewSubnet(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan} {
		t.Run(string(shape), func(t *testing.T) {
			r := c9Rig(t, shape)
			v := runC9Tuned(context.Background(), r.e, cFast)
			needResult(t, v, PASS)
			needWritten(t, r.e, v)
			needReason(t, v, "NAKs on the wire: 1")
			if fmt.Sprint(r.src.renumbers) != "[10.200.101.0/24 10.200.101.1 10.200.101.100-10.200.101.200]" {
				t.Errorf("renumbers %v", r.src.renumbers)
			}
			needStops(t, "renumber", r.src.renumberRests, 1)
			if r.src.resets != 1 || !r.src.restored {
				t.Errorf("resets %d, lease time restored %t", r.src.resets, r.src.restored)
			}
			needCleanup(t, r.h.bRunner, "c9", containerName(r.e, NameC9))
		})
	}
}

func TestRunC9Judges(t *testing.T) {
	cases := []struct {
		name   string
		result Result
		want   string
		stops  int
		edit   func(r *hRig)
	}{
		{"the namespace keeps the old address", FAIL, "by bind +", 1, func(r *hRig) {
			on := r.src.onRenumber
			r.src.onRenumber = func() { on(); r.h.setAddrs(containerName(r.e, NameC9), "10.200.1.101", "10.200.101.150") }
		}},
		{"the namespace never gets the new address", FAIL, "carries [10.200.1.101]", 1, func(r *hRig) {
			on := r.src.onRenumber
			r.src.onRenumber = func() { on(); r.h.setAddrs(containerName(r.e, NameC9), "10.200.1.101") }
		}},
		{"the route stays on the old source", FAIL, `via "10.200.1.1"`, 1, func(r *hRig) {
			on := r.src.onRenumber
			r.src.onRenumber = func() { on(); r.host.setGW(containerName(r.e, NameC9), r.e.SegGateway) }
		}},
		{"the table keeps the old lease", FAIL, "are [10.200.1.101]", 1, func(r *hRig) {
			name := containerName(r.e, NameC9)
			r.src.fn = func(int) []sourceadapter.Lease {
				l, _ := r.leaseOf(name, "10.200.1.101")
				return []sourceadapter.Lease{l}
			}
		}},
		{"the namespace carries another new address", FAIL, "carries [10.200.101.151]", 1, func(r *hRig) {
			on := r.src.onRenumber
			r.src.onRenumber = func() { on(); r.h.setAddrs(containerName(r.e, NameC9), "10.200.101.151") }
		}},
		{"the new lease stays on the old subnet", FAIL, "are [10.200.1.150]", 1, func(r *hRig) {
			name := containerName(r.e, NameC9)
			on := r.src.onRenumber
			r.src.onRenumber = func() { on(); r.h.setAddrs(name, "10.200.1.150") }
			r.src.fn = func(int) []sourceadapter.Lease {
				l, _ := r.leaseOf(name, "10.200.1.150")
				return []sourceadapter.Lease{l}
			}
		}},
		{"no bind on the wire", BLOCKED, "no bind time", 0, func(r *hRig) { r.cap.fn = nil }},
		{"the renumber fails", BLOCKED, "could not renumber", 0, func(r *hRig) { r.src.renumberErr = errors.New("x") }},
		{"the reset fails", BLOCKED, "could not reset", 1, func(r *hRig) { r.src.resetErr = errors.New("x") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := c9Rig(t, ShapeMacvlan)
			c.edit(r)
			v := runC9Tuned(context.Background(), r.e, cFast)
			needResult(t, v, c.result)
			needReason(t, v, c.want)
			needWritten(t, r.e, v)
			needStops(t, "renumber", r.src.renumberRests, c.stops)
			if !r.src.restored {
				t.Error("the lease time was not restored")
			}
		})
	}
}

func TestHostLinkCountRefusesANonNumber(t *testing.T) {
	r := newCRunner()
	if _, err := hostLinkCount(context.Background(), r); err == nil {
		t.Fatal("an empty answer counted")
	}
}
