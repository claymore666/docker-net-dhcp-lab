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

// e3Host is a docker host with a link table: it makes and removes the
// links the plugin would, so a runner test reads real `ip -d -o link`
// text and a leak shows as a link left in the table. (#15)
type e3Host struct {
	*bRunner
	kernel   string
	links    []e3Link
	nets     map[string]string // network name -> create command
	vlanOf   map[string]bool   // networks that made the eth1.100 link
	applied  int
	failures int
	ct       map[string]string // container -> network
	leakDH   bool              // keep dh- links after the container goes
	linger   int               // link-table reads the removed container's links stay visible for
	pending  []string          // links waiting for their last read
	pendLeft int
	failOn   string // an ip command containing this fails
	refuse   string // network create containing this option fails with this text
}

type e3Link struct {
	name, master, kind, alias, alt string
	vlanID                         int
	parent                         string
}

func newE3Host(kernel string) *e3Host {
	h := &e3Host{bRunner: newBRunner(), kernel: kernel, nets: map[string]string{}, vlanOf: map[string]bool{}, ct: map[string]string{}}
	h.links = []e3Link{{name: "eth1", kind: ""}}
	return h
}

func (h *e3Host) render() string {
	var b strings.Builder
	for i, l := range h.links {
		name := l.name
		if l.parent != "" {
			name += "@" + l.parent
		}
		fmt.Fprintf(&b, "%d: %s: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue", i+2, name)
		if l.master != "" {
			b.WriteString(" master " + l.master)
		}
		b.WriteString(" state UP mode DEFAULT group default qlen 1000")
		if l.alias != "" {
			b.WriteString(" alias " + l.alias)
		}
		b.WriteString(`\    link/ether 52:54:00:aa:bb:cc brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 68 maxmtu 65535 `)
		switch {
		case l.kind == "vlan":
			fmt.Fprintf(&b, `\    vlan protocol 802.1Q id %d <REORDER_HDR> addrgenmode eui64`, l.vlanID)
		case l.kind != "":
			fmt.Fprintf(&b, `\    %s addrgenmode eui64`, l.kind)
		}
		if l.alt != "" {
			b.WriteString(`\    altname ` + l.alt)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (h *e3Host) find(name string) int {
	for i, l := range h.links {
		if l.name == name {
			return i
		}
	}
	return -1
}

func (h *e3Host) del(name string) {
	if i := h.find(name); i >= 0 {
		h.links = append(h.links[:i], h.links[i+1:]...)
	}
}

func (h *e3Host) Run(ctx context.Context, cmd string) (string, error) {
	f := strings.Fields(cmd)
	switch {
	case cmd == "uname -r":
		h.cmds = append(h.cmds, cmd)
		return h.kernel + "\n", nil
	case cmd == "ip -d -o link show":
		h.cmds = append(h.cmds, cmd)
		out := h.render()
		if len(h.pending) > 0 {
			if h.pendLeft--; h.pendLeft <= 0 {
				for _, n := range h.pending {
					h.del(n)
				}
				h.pending = nil
			}
		}
		return out, nil
	case strings.Contains(cmd, "/Plugin.Health"):
		h.cmds = append(h.cmds, cmd)
		return fmt.Sprintf(`{"instance_id":"i","active_endpoints":0,"host_ifnames_applied":%d,"host_ifname_failures":%d,"host_ifname_conflicts":0}`, h.applied, h.failures), nil
	case strings.HasPrefix(cmd, "sudo ip link "):
		h.cmds = append(h.cmds, cmd)
		if h.failOn != "" && strings.Contains(cmd, h.failOn) {
			return "", errors.New("ip: RTNETLINK answers: File exists")
		}
		switch f[3] {
		case "add":
			if h.find(f[4]) >= 0 {
				return "", errors.New("RTNETLINK answers: File exists")
			}
			if strings.Contains(cmd, "type dummy") {
				h.links = append(h.links, e3Link{name: f[4], kind: "dummy"})
			} else {
				h.links = append(h.links, e3Link{name: f[4], kind: "vlan", vlanID: 100, parent: "eth1"})
			}
		case "del":
			// ip(8) does not refuse a link of another kind here (measured).
			h.del(f[4])
		}
		return "", nil
	case strings.Contains(cmd, "docker network create"):
		h.cmds = append(h.cmds, cmd)
		name := f[len(f)-1]
		if h.refuse != "" && strings.Contains(cmd, h.refuse) {
			return "", fmt.Errorf("ssh host: err: Error response from daemon: %s", h.refuseText(cmd))
		}
		if strings.Contains(cmd, "vlan=100") {
			if err := h.makeVLAN(cmd); err != nil {
				return "", fmt.Errorf("ssh host: err: Error response from daemon: %w", err)
			}
			h.vlanOf[name] = true
		}
		h.nets[name] = cmd
		return "", nil
	case strings.Contains(cmd, "docker network rm"):
		h.cmds = append(h.cmds, cmd)
		name := f[len(f)-1]
		if h.vlanOf[name] {
			h.del("eth1.100")
			delete(h.vlanOf, name)
		}
		delete(h.nets, name)
		return "", nil
	case strings.Contains(cmd, "docker rm -f"):
		name := f[len(f)-1]
		if net, ok := h.ct[name]; ok {
			delete(h.ct, name)
			if !h.leakDH {
				for i := len(h.links) - 1; i >= 0; i-- {
					l := h.links[i]
					if l.master == hostBridgeName("net1") && (strings.HasPrefix(l.name, "dh-") || strings.Contains(l.alt, "dh-") || l.name == name) {
						if h.linger > 0 {
							h.pending = append(h.pending, l.name)
							h.pendLeft = h.linger
							continue
						}
						h.links = append(h.links[:i], h.links[i+1:]...)
					}
				}
			}
			_ = net
		}
		return h.bRunner.Run(ctx, cmd)
	case strings.Contains(cmd, "docker run"):
		out, err := h.bRunner.Run(ctx, cmd)
		if err != nil {
			return out, err
		}
		name := bNameRE.FindStringSubmatch(cmd)[1]
		c := h.containers[name]
		c.endpointID = fmt.Sprintf("a%03xfedcba98%052x", h.n, 0)
		net := f[indexOf(f, "--network")+1]
		h.ct[name] = net
		if strings.Contains(h.nets[net], "vlan=100") {
			c.addr = "10.200.151.150"
		}
		if strings.Contains(h.nets[net], "-o bridge=") {
			h.addBridgeLink(name, c.endpointID, net)
		}
		return out, nil
	}
	return h.bRunner.Run(ctx, cmd)
}

func indexOf(f []string, s string) int {
	for i, x := range f {
		if x == s {
			return i
		}
	}
	return -1
}

func (h *e3Host) addBridgeLink(name, ep, net string) {
	def := "dh-" + ep[:12]
	l := e3Link{name: def, master: hostBridgeName("net1"), kind: "veth"}
	if strings.Contains(h.nets[net], "host_ifname=container_name") {
		if strings.HasPrefix(h.kernel, "6.1.") || strings.HasPrefix(h.kernel, "5.") {
			h.failures++
		} else {
			h.applied++
			l = e3Link{name: name, master: hostBridgeName("net1"), kind: "veth", alt: def}
		}
	}
	h.links = append(h.links, l)
}

func (h *e3Host) refuseText(cmd string) string {
	switch {
	case strings.Contains(cmd, "host_ifname"):
		mode := "macvlan"
		if strings.Contains(cmd, "mode=ipvlan") {
			mode = "ipvlan"
		}
		return "host_ifname cannot be set in mode=" + mode
	}
	return "refused"
}

// makeVLAN is the plugin's -o vlan=100 on eth1: a VLAN link named
// eth1.100, or the documented refusal when something is in the way. (#15)
func (h *e3Host) makeVLAN(cmd string) error {
	if i := h.find("eth1.100"); i >= 0 {
		if h.links[i].kind != "vlan" {
			return errors.New("eth1.100 exists and is a dummy link, not a vlan; remove it")
		}
		return nil
	}
	if i := h.find("vlan100"); i >= 0 {
		return errors.New("vlan 100 already exists on eth1 as vlan100, and the kernel takes one per parent and ID")
	}
	h.links = append(h.links, e3Link{name: "eth1.100", kind: "vlan", vlanID: 100, parent: "eth1", alias: "docker-net-dhcp"})
	return nil
}

// e3Adapter serves a lease for every container the host runs, by MAC
// and by the client-id an ipvlan container presents. (#15)
type e3Adapter struct {
	*fakeAdapter
	host *e3Host
}

func (a *e3Adapter) Leases(context.Context) ([]sourceadapter.Lease, error) {
	var out []sourceadapter.Lease
	for _, c := range a.host.containers {
		cid, _ := ipvlanClientID(c.endpointID)
		out = append(out, sourceadapter.Lease{MAC: c.mac, Address: c.addr, ClientID: cid, Expires: time.Now().Add(time.Hour)})
	}
	return out, nil
}

type e3VLAN struct {
	h         *e3Host
	filtering string
	ferr      error
	silent    bool
	late      int  // reads that come back empty before the capture shows
	untagged  bool // the reply is tagged but grants an address from the untagged pool
}

func (v *e3VLAN) Filtering(context.Context) (string, error) { return v.filtering, v.ferr }

func (v *e3VLAN) Tagged(context.Context, string) (string, error) {
	if v.silent {
		return "", nil
	}
	if v.late > 0 {
		v.late--
		return "", nil
	}
	var b strings.Builder
	for _, c := range v.h.containers {
		addr := c.addr
		fmt.Fprintf(&b, "10:00:01.000000 52:54:00:11:22:33 > %s, ethertype 802.1Q (0x8100), length 346: vlan 100, p 0, ethertype IPv4 (0x0800), (tos 0x0)\n    10.200.151.2.67 > %s.68: BOOTP/DHCP, Reply, length 300\n\t  Your-IP %s\n\t  Client-Ethernet-Address %s\n\t    DHCP-Message (53), length 1: ACK\n", c.mac, addr, addr, c.mac)
	}
	return b.String(), nil
}

var e3Fast = e3Tune{poll: time.Millisecond, linkWait: 5 * time.Millisecond, captureWait: 5 * time.Millisecond, parentWindow: 5 * time.Millisecond}

type e3Rig struct {
	h *e3Host
	v *e3VLAN
	e Env
}

func e3Setup(t *testing.T, shape Shape, kernel string) *e3Rig {
	t.Helper()
	h := newE3Host(kernel)
	src := &e3Adapter{fakeAdapter: &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapVLANPool}}, host: h}
	e := bEnv(t, h, src, shape)
	v := &e3VLAN{h: h, filtering: "0"}
	e.VLAN = v
	return &e3Rig{h: h, v: v, e: e}
}

func (r *e3Rig) leftover(t *testing.T) {
	t.Helper()
	for _, l := range r.h.links {
		if l.name != "eth1" {
			t.Errorf("link %s (%s) left on the host", l.name, l.kind)
		}
	}
	if len(r.h.nets) != 0 {
		t.Errorf("networks left: %v", r.h.nets)
	}
	if len(r.h.containers) != 0 {
		t.Errorf("containers left: %v", r.h.containers)
	}
}

func TestRunE3aBridgeOnBothKernels(t *testing.T) {
	for _, kernel := range []string{"6.12.113+deb13", "6.1.0-13-amd64"} {
		t.Run(kernel, func(t *testing.T) {
			r := e3Setup(t, ShapeBridge, kernel)
			needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), PASS)
			r.leftover(t)
		})
	}
}

// Defeat a: a dh- link the plugin leaves behind is found whatever its ID. (#15)
func TestRunE3aFindsALeakedLink(t *testing.T) {
	r := e3Setup(t, ShapeBridge, "6.12.1")
	r.h.leakDH = true
	needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), FAIL)
}

// Issue #15: the engine drops the host link a moment after the container;
// a judge that reads once calls that a leak.
func TestRunE3aWaitsForALinkThatIsStillGoing(t *testing.T) {
	r := e3Setup(t, ShapeBridge, "6.12.1")
	r.h.linger = 2
	t3 := e3Fast
	t3.linkWait = 200 * time.Millisecond
	needResult(t, runE3aTuned(context.Background(), r.e, t3), PASS)
}

// Row 8: an old kernel that RENAMES is a FAIL, not a pass of either kind. (#15)
func TestRunE3aOldKernelThatRenamedFails(t *testing.T) {
	r := e3Setup(t, ShapeBridge, "6.1.0")
	r.h.kernel = "6.12.1" // the link behaves as on a new kernel
	r.e.Host = &kernelLiar{r.h, "6.1.0"}
	needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), FAIL)
}

// kernelLiar answers uname with another kernel than the links behave as. (#15)
type kernelLiar struct {
	*e3Host
	say string
}

func (k *kernelLiar) Run(ctx context.Context, cmd string) (string, error) {
	if cmd == "uname -r" {
		return k.say + "\n", nil
	}
	return k.e3Host.Run(ctx, cmd)
}

func TestRunE3aUnreadableKernelIsBlocked(t *testing.T) {
	r := e3Setup(t, ShapeBridge, "???")
	needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), BLOCKED)
}

func TestRunE3aParentModes(t *testing.T) {
	for _, shape := range []Shape{ShapeMacvlan, ShapeIpvlan} {
		t.Run(string(shape), func(t *testing.T) {
			r := e3Setup(t, shape, "6.12.1")
			r.h.refuse = "host_ifname"
			needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), PASS)
			r.leftover(t)
		})
	}
}

// Defeat d: a refusal text that is not the documented one fails. (#15)
func TestRunE3aParentAnotherErrorFails(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.h.refuse = "host_ifname"
	r.h.bRunner.netErr = nil
	r.e.Host = &refuseAs{r.h, "network already exists"}
	needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), FAIL)
}

type refuseAs struct {
	*e3Host
	text string
}

func (k *refuseAs) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "docker network create") && strings.Contains(cmd, "host_ifname") {
		k.cmds = append(k.cmds, cmd)
		return "", errors.New("ssh host: err: " + k.text)
	}
	return k.e3Host.Run(ctx, cmd)
}

func TestRunE3aIPAMShapesAreNA(t *testing.T) {
	for _, shape := range []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		r := e3Setup(t, shape, "6.12.1")
		needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), NA)
		if len(r.h.cmds) != 0 {
			t.Errorf("%s: commands ran: %v", shape, r.h.cmds)
		}
	}
}

func TestRunE3bPassesOnMacvlanAndIpvlan(t *testing.T) {
	for _, shape := range []Shape{ShapeMacvlan, ShapeIpvlan} {
		t.Run(string(shape), func(t *testing.T) {
			r := e3Setup(t, shape, "6.12.1")
			needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), PASS)
			r.leftover(t)
		})
	}
}

func TestRunE3bBridgeAndIPAMShapesAreNA(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		r := e3Setup(t, shape, "6.12.1")
		needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), NA)
		if len(r.h.cmds) != 0 {
			t.Errorf("%s: commands ran: %v", shape, r.h.cmds)
		}
	}
}

// Row 10: a filtering bridge, an unreadable flag or no witness is BLOCKED
// and nothing is created. (#15)
func TestRunE3bVlanFilteringBlocksBeforeAnythingIsCreated(t *testing.T) {
	for name, mod := range map[string]func(*e3Rig){
		"filtering on":  func(r *e3Rig) { r.v.filtering = "1" },
		"unreadable":    func(r *e3Rig) { r.v.ferr = errors.New("no such file") },
		"no witness":    func(r *e3Rig) { r.e.VLAN = nil },
		"garbage value": func(r *e3Rig) { r.v.filtering = "" },
	} {
		t.Run(name, func(t *testing.T) {
			r := e3Setup(t, ShapeMacvlan, "6.12.1")
			mod(r)
			needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), BLOCKED)
			for _, c := range r.h.cmds {
				if strings.Contains(c, "network create") || strings.Contains(c, "ip link add") {
					t.Errorf("created something before the flag was read: %s", c)
				}
			}
		})
	}
}

// Row 9: the scenario dies after it pre-created a link and the link is
// gone anyway. The first case fails the explicit removal of vlan100, the
// second the read that follows the dummy's refusal. (#15)
func TestRunE3bCleansPrecreatedLinksWhenItFailsMidway(t *testing.T) {
	for _, midway := range []string{"vlan100", "dummy"} {
		t.Run(midway, func(t *testing.T) {
			r := e3Setup(t, ShapeMacvlan, "6.12.1")
			r.e.Host = &diesMidway{e3Host: r.h, at: midway}
			v := runE3bTuned(context.Background(), r.e, e3Fast)
			if v.Result == PASS {
				t.Fatalf("a run cut off midway passed")
			}
			if midway == "vlan100" && !strings.Contains(v.Reason, "vlan100") {
				t.Errorf("the run did not die where the test says: %q", v.Reason)
			}
			for _, l := range r.h.links {
				if l.name != "eth1" {
					t.Errorf("pre-created %s (%s) survived the failed run", l.name, l.kind)
				}
			}
		})
	}
}

// diesMidway fails one step once: the first `ip link del vlan100`, or the
// link read after the user's dummy is in place. (#15)
type diesMidway struct {
	*e3Host
	at   string
	done bool
}

func (d *diesMidway) Run(ctx context.Context, cmd string) (string, error) {
	switch {
	case d.at == "vlan100" && !d.done && strings.HasPrefix(cmd, "sudo ip link del vlan100"):
		d.done = true
		d.cmds = append(d.cmds, cmd)
		return "", errors.New("ssh dropped")
	case d.at == "dummy" && cmd == "ip -d -o link show" && d.find("eth1.100") >= 0 && d.links[d.find("eth1.100")].kind == "dummy":
		return "", errors.New("ssh dropped")
	}
	return d.e3Host.Run(ctx, cmd)
}

// The cleanup never removes a VLAN the plugin made: `type` guards it. (#15)
func TestRunE3bCleanupNamesTheKindOfEachLink(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), PASS)
	for _, c := range r.h.cmds {
		if strings.HasPrefix(c, "sudo ip link del") && !strings.HasSuffix(c, "type vlan") && !strings.HasSuffix(c, "type dummy") {
			t.Errorf("an ip link del without a type guard: %s", c)
		}
	}
}

// A link already named eth1.100 or vlan100 is not ours: BLOCKED, and the
// run removes nothing. (#15)
func TestRunE3bExistingLinkIsBlockedAndKept(t *testing.T) {
	for _, pre := range []e3Link{{name: "eth1.100", kind: "dummy"}, {name: "vlan100", kind: "vlan", vlanID: 100, parent: "eth1"}} {
		r := e3Setup(t, ShapeMacvlan, "6.12.1")
		r.h.links = append(r.h.links, pre)
		needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), BLOCKED)
		if r.h.find(pre.name) < 0 {
			t.Errorf("%s was removed", pre.name)
		}
	}
}

// Defeat b: a lease from the untagged pool, even with a tagged reply on
// the wire, is a FAIL. (#15)
func TestRunE3bUntaggedPoolLeaseFails(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.h.addrFn = func(string, string) string { return "10.200.1.150" }
	r.e.Host = &untaggedAddr{r.h}
	needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), FAIL)
}

type untaggedAddr struct{ *e3Host }

func (u *untaggedAddr) Run(ctx context.Context, cmd string) (string, error) {
	out, err := u.e3Host.Run(ctx, cmd)
	if strings.Contains(cmd, "docker run") {
		for _, c := range u.containers {
			c.addr = "10.200.1.150"
		}
	}
	return out, err
}

// Defeat f: nothing tagged on the observer is a FAIL. (#15)
func TestRunE3bSilentObserverFails(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.v.silent = true
	needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), FAIL)
}

// Defeat c: a plugin that removes the user's dummy fails the run. (#15)
func TestRunE3bPluginRemovingTheUserDummyFails(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.e.Host = &eatsDummy{r.h}
	needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), FAIL)
}

type eatsDummy struct{ *e3Host }

func (u *eatsDummy) Run(ctx context.Context, cmd string) (string, error) {
	out, err := u.e3Host.Run(ctx, cmd)
	if strings.Contains(cmd, "docker network create") && strings.Contains(cmd, "-r2") {
		u.del("eth1.100")
	}
	return out, err
}

// The link a network leaves behind after its removal is a FAIL, and the
// run stops there rather than building refusals on a dirty host. (#15)
func TestRunE3bLinkLeftAfterNetworkRemovalFails(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.e.Host = &keepsVLAN{r.h}
	needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), FAIL)
}

type keepsVLAN struct{ *e3Host }

func (u *keepsVLAN) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "docker network rm") {
		u.cmds = append(u.cmds, cmd)
		return "", nil
	}
	return u.e3Host.Run(ctx, cmd)
}

func TestE3Catalog(t *testing.T) {
	var a, b *Scenario
	for i := range Catalog {
		switch Catalog[i].Name {
		case NameE3a:
			a = &Catalog[i]
		case NameE3b:
			b = &Catalog[i]
		}
	}
	if a == nil || b == nil {
		t.Fatal("E3a or E3b missing from the catalog")
	}
	if len(a.Needs) != 1 || a.Needs[0] != sourceadapter.CapV4 {
		t.Errorf("E3a needs %v, want only v4: it takes no server input", a.Needs)
	}
	if !strings.Contains(fmt.Sprint(b.Needs), string(sourceadapter.CapVLANPool)) {
		t.Errorf("E3b needs %v, want the VLAN pool capability", b.Needs)
	}
}

// Issue #15: a plugin that accepts the create it must refuse is a FAIL,
// for each of the two documented refusals.
func TestRunE3bAcceptedRefusalFails(t *testing.T) {
	for _, suffix := range []string{"-r1", "-r2"} {
		t.Run(suffix, func(t *testing.T) {
			r := e3Setup(t, ShapeMacvlan, "6.12.1")
			r.e.Host = &acceptsCreate{r.h, suffix}
			needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), FAIL)
		})
	}
}

type acceptsCreate struct {
	*e3Host
	suffix string
}

func (u *acceptsCreate) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "docker network create") && strings.Contains(cmd, u.suffix) {
		u.cmds = append(u.cmds, cmd)
		return "", nil
	}
	return u.e3Host.Run(ctx, cmd)
}

// Issue #15: a macvlan child the refusal leg leaves on the parent is a FAIL.
func TestRunE3aParentChildLeftBehindFails(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.h.refuse = "host_ifname"
	r.e.Host = &leavesChild{r.h}
	needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), FAIL)
}

type leavesChild struct{ *e3Host }

func (u *leavesChild) Run(ctx context.Context, cmd string) (string, error) {
	out, err := u.e3Host.Run(ctx, cmd)
	if strings.Contains(cmd, "docker network rm") && u.find("mv-left") < 0 {
		u.links = append(u.links, e3Link{name: "mv-left", kind: "macvlan", parent: "eth1"})
	}
	return out, err
}

// Issue #15: the observer writes the tagged reply a moment after the lease
// shows; one read at once would call that silence.
func TestRunE3bWaitsForTheTaggedCapture(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.v.late = 2
	t3 := e3Fast
	t3.captureWait = 200 * time.Millisecond
	needResult(t, runE3bTuned(context.Background(), r.e, t3), PASS)
}

// Row 9, measured: `ip link del NAME type dummy` deletes a VLAN of that
// name too, so the cleanup must not run it for a name that is not ours.
// Here the plugin wrongly accepted refusal 1 and left an eth1.100 VLAN;
// the dummy pre-create then fails on it and nothing of ours is on the host.
func TestRunE3bCleanupKeepsALinkItDidNotMake(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.e.Host = &acceptsAndLeaves{r.h}
	v := runE3bTuned(context.Background(), r.e, e3Fast)
	if v.Result == PASS {
		t.Fatalf("a wrongly accepted create passed")
	}
	if r.h.find("eth1.100") < 0 {
		t.Errorf("the cleanup deleted an eth1.100 it did not make")
	}
}

type acceptsAndLeaves struct{ *e3Host }

func (u *acceptsAndLeaves) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "docker network create") && strings.Contains(cmd, "-r1") {
		u.cmds = append(u.cmds, cmd)
		u.links = append(u.links, e3Link{name: "eth1.100", kind: "vlan", vlanID: 100, parent: "eth1", alias: "docker-net-dhcp"})
		return "", nil
	}
	return u.e3Host.Run(ctx, cmd)
}

// Row 8, counters: a plugin that has counted renames before this run is
// judged on the change, not on the total.
func TestRunE3aJudgesCounterChangesNotTotals(t *testing.T) {
	for _, kernel := range []string{"6.12.1", "6.1.0"} {
		t.Run(kernel, func(t *testing.T) {
			r := e3Setup(t, ShapeBridge, kernel)
			r.h.applied, r.h.failures = 5, 7
			needResult(t, runE3aTuned(context.Background(), r.e, e3Fast), PASS)
		})
	}
}

// Row 9: the plugin swaps the user's dummy for its own VLAN under the
// same name; the verdict is FAIL and the cleanup leaves the VLAN alone
// instead of deleting it by name. (#15)
func TestRunE3bCleanupKeepsAVLANThatTookTheDummysName(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.e.Host = &swapsDummy{r.h}
	if v := runE3bTuned(context.Background(), r.e, e3Fast); v.Result != FAIL {
		t.Fatalf("got %s %q, want FAIL", v.Result, v.Reason)
	}
	if i := r.h.find("eth1.100"); i < 0 || r.h.links[i].kind != "vlan" {
		t.Errorf("the cleanup deleted the plugin's VLAN")
	}
}

type swapsDummy struct{ *e3Host }

func (u *swapsDummy) Run(ctx context.Context, cmd string) (string, error) {
	out, err := u.e3Host.Run(ctx, cmd)
	if strings.Contains(cmd, "docker network create") && strings.Contains(cmd, "-r2") {
		u.del("eth1.100")
		u.links = append(u.links, e3Link{name: "eth1.100", kind: "vlan", vlanID: 100, parent: "eth1", alias: "docker-net-dhcp"})
	}
	return out, err
}

// Row 9: a link that is already gone is not deleted again. (#15)
func TestRunE3bCleanupSkipsALinkThatIsGone(t *testing.T) {
	r := e3Setup(t, ShapeMacvlan, "6.12.1")
	r.e.Host = &eatsDummy{r.h}
	needResult(t, runE3bTuned(context.Background(), r.e, e3Fast), FAIL)
	for _, c := range r.h.cmds {
		if strings.HasPrefix(c, "sudo ip link del eth1.100") {
			t.Errorf("a delete for a link that was gone: %s", c)
		}
	}
}
