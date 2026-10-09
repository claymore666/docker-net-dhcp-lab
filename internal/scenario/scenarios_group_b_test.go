package scenario

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// bRunner is a scripted docker host for the group B tests: it records
// every command, answers docker run/inspect from a small container
// table, and replays canned nslookup and resolv.conf output.
type bRunner struct {
	cmds       []string
	containers map[string]*bIdent
	n          int
	addrFn     func(name, mac string) string
	forceMAC   string
	netErr     error
	nslookup   string
	resolv     []string
	resolvN    int
	runErr     error
	own        map[string][]string // ip addr inside a container, else its address (#21)
	ownErr     error
}

type bIdent struct{ mac, addr, endpointID string }

var (
	bNameRE = regexp.MustCompile(`--name (\S+)`)
	bMACRE  = regexp.MustCompile(`--mac-address (\S+)`)
)

func newBRunner() *bRunner { return &bRunner{containers: map[string]*bIdent{}} }

func (f *bRunner) has(sub string) bool {
	for _, c := range f.cmds {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func (f *bRunner) Run(_ context.Context, cmd string) (string, error) {
	f.cmds = append(f.cmds, cmd)
	switch {
	case strings.Contains(cmd, "docker network create"):
		return "", f.netErr
	case strings.Contains(cmd, "docker rm -f"):
		delete(f.containers, strings.Fields(cmd)[len(strings.Fields(cmd))-1])
		return "", nil
	case strings.Contains(cmd, "docker run"):
		if f.runErr != nil {
			return "", f.runErr
		}
		f.n++
		name := bNameRE.FindStringSubmatch(cmd)[1]
		mac := fmt.Sprintf("aa:bb:cc:00:00:%02x", f.n)
		if m := bMACRE.FindStringSubmatch(cmd); m != nil {
			mac = m[1]
		}
		if f.forceMAC != "" {
			mac = f.forceMAC
		}
		addr := fmt.Sprintf("10.200.1.%d", 100+f.n)
		if f.addrFn != nil {
			addr = f.addrFn(name, mac)
		}
		ep := fmt.Sprintf("%016x%048x", f.n, 0)
		f.containers[name] = &bIdent{mac: mac, addr: addr, endpointID: ep}
		return "", nil
	case strings.Contains(cmd, "docker inspect"):
		name := strings.Fields(cmd)[len(strings.Fields(cmd))-1]
		c := f.containers[name]
		if c == nil {
			return "", errors.New("no such container " + name)
		}
		switch {
		case strings.Contains(cmd, ".MacAddress"):
			return c.mac, nil
		case strings.Contains(cmd, ".IPAddress"):
			return c.addr, nil
		default:
			return c.endpointID, nil
		}
	case strings.Contains(cmd, "ip -4 -o addr show"):
		name := strings.Fields(cmd)[3]
		addrs, ok := f.own[name]
		if c := f.containers[name]; !ok && c != nil {
			addrs = []string{c.addr}
		}
		var b strings.Builder
		for _, a := range addrs {
			fmt.Fprintf(&b, "2: eth0    inet %s/24 scope global eth0\n", a)
		}
		return b.String(), f.ownErr
	case strings.Contains(cmd, "nslookup"):
		return f.nslookup, nil
	case strings.Contains(cmd, "cat /etc/resolv.conf"):
		if len(f.resolv) == 0 {
			return "", nil
		}
		i := f.resolvN
		if i >= len(f.resolv) {
			i = len(f.resolv) - 1
		}
		f.resolvN++
		return f.resolv[i], nil
	}
	return "", nil
}

// bAdapter serves a lease table computed from the call number.
type bAdapter struct {
	*fakeAdapter
	fn    func(call int) []sourceadapter.Lease
	calls int
}

func (a *bAdapter) Leases(_ context.Context) ([]sourceadapter.Lease, error) {
	a.calls++
	return a.fn(a.calls), nil
}

func bEnv(t *testing.T, host sourceadapter.Runner, src sourceadapter.Adapter, shape Shape) Env {
	t.Helper()
	return Env{
		Host: host, Source: src, Cell: "dnsmasq", Shape: shape, Network: "net1",
		EvidenceDir: t.TempDir(), GitSHA: "sha",
		SegSubnet: "10.200.1.0/24", PoolStart: "10.200.1.100", PoolEnd: "10.200.1.200", SegGateway: "10.200.1.1",
		SourceAddr: "10.200.1.1",
	}
}

func staticLeases(ls ...sourceadapter.Lease) func(int) []sourceadapter.Lease {
	return func(int) []sourceadapter.Lease { return ls }
}

func needResult(t *testing.T, v Verdict, want Result) {
	t.Helper()
	if v.Result != want {
		t.Fatalf("want %s, got %s (reason %q)", want, v.Result, v.Reason)
	}
}

// Defeat list 1: whatever the verdict, the scenario's own network and
// container are removed, the network after the container.
func needCleanup(t *testing.T, h *bRunner, suffix, container string) {
	t.Helper()
	netRm := -1
	ctRm := -1
	for i, c := range h.cmds {
		if strings.Contains(c, "docker network rm net1-"+suffix) {
			netRm = i
		}
		if container != "" && strings.HasSuffix(c, "docker rm -f "+container) {
			ctRm = i
		}
	}
	if suffix != "" && netRm < 0 {
		t.Errorf("net1-%s was never removed", suffix)
	}
	if container != "" && ctRm < 0 {
		t.Errorf("container %s was never removed", container)
	}
	if netRm >= 0 && ctRm >= 0 && ctRm > netRm {
		t.Errorf("the network was removed before the container")
	}
	for _, c := range h.cmds {
		if strings.HasSuffix(c, "docker network rm net1") {
			t.Errorf("the cell's main network was touched: %q", c)
		}
	}
}

func TestCatalogRegistersGroupBWithTheNeedsOfTheDesign(t *testing.T) {
	want := map[string][]sourceadapter.Capability{
		NameB1: {sourceadapter.CapV4, sourceadapter.CapReserveMAC},
		NameB2: {sourceadapter.CapV4, sourceadapter.CapReserveClientID},
		NameB3: {sourceadapter.CapV4, sourceadapter.CapDNSRegistration},
		NameB4: {sourceadapter.CapV4},
		NameB5: {sourceadapter.CapV4, sourceadapter.CapVendorClassPool},
		NameB6: {sourceadapter.CapV4, sourceadapter.CapShortLease, sourceadapter.CapOptionChange},
		NameB7: {sourceadapter.CapV4},
		NameB8: {sourceadapter.CapV4},
	}
	got := map[string][]sourceadapter.Capability{}
	for _, s := range Catalog {
		if _, ok := want[s.Name]; ok {
			got[s.Name] = s.Needs
			if s.Run == nil {
				t.Errorf("%s has no Run", s.Name)
			}
		}
	}
	for n, w := range want {
		if fmt.Sprint(got[n]) != fmt.Sprint(w) {
			t.Errorf("%s: Needs = %v, want %v", n, got[n], w)
		}
	}
}

// B3 needs dnsmasq's own DNS: Kea and ISC are N/A through Applicable,
// not failed (defeat list 7).
func TestB3AppliesToDnsmasqOnly(t *testing.T) {
	var b3 Scenario
	for _, s := range Catalog {
		if s.Name == NameB3 {
			b3 = s
		}
	}
	for name, a := range map[string]sourceadapter.Adapter{
		"kea": &sourceadapter.KeaAdapter{}, "isc-dhcp": &sourceadapter.ISCDHCPAdapter{}, "dnsmasq": &sourceadapter.DnsmasqAdapter{},
	} {
		got, _ := Applicable(b3, a)
		if want := name == "dnsmasq"; got != want {
			t.Errorf("%s: Applicable(B3) = %v, want %v", name, got, want)
		}
	}
}

// The pool demand a cell is checked against must equal what the group B
// scenarios actually take (defeat list 8).
func TestPoolDemandSumsToMinPoolAddresses(t *testing.T) {
	total := 0
	for _, s := range Catalog {
		n, ok := poolDemand[s.Name]
		if !ok {
			t.Errorf("%s has no poolDemand entry", s.Name)
		}
		total += n
	}
	for n := range poolDemand {
		found := false
		for _, s := range Catalog {
			found = found || s.Name == n
		}
		if !found {
			t.Errorf("poolDemand names %q, which is not in the catalog", n)
		}
	}
	if total != MinPoolAddresses {
		t.Errorf("poolDemand sums to %d, MinPoolAddresses is %d", total, MinPoolAddresses)
	}
}

func TestGroupBAddrRefusals(t *testing.T) {
	e := bEnv(t, nil, nil, ShapeBridge)
	if _, err := groupBAddr(e, 150); err == nil {
		t.Error("an address inside the main pool was accepted")
	}
	if _, err := groupBAddr(e, 1); err == nil {
		t.Error("the source's own segment address was accepted")
	}
	if _, err := groupBAddr(e, 0); err == nil {
		t.Error("host octet 0 was accepted")
	}
	if _, err := groupBAddr(e, 255); err == nil {
		t.Error("host octet 255 was accepted")
	}
	e.SegSubnet = "10.200.0.0/16"
	if _, err := groupBAddr(e, 211); err == nil {
		t.Error("a /16 was accepted")
	}
	e.SegSubnet = "garbage"
	if _, err := groupBAddr(e, 211); err == nil {
		t.Error("an unparsable subnet was accepted")
	}
	e = bEnv(t, nil, nil, ShapeBridge)
	if a, err := groupBAddr(e, 211); err != nil || a != "10.200.1.211" {
		t.Errorf("good address: %q, %v", a, err)
	}
}

func TestReservationAddrsAreDistinctPerShapeAndScenario(t *testing.T) {
	seen := map[string]string{}
	for _, shape := range Shapes {
		e := bEnv(t, nil, nil, shape)
		for _, n := range []string{NameB1, NameB2} {
			a, err := reservationAddr(e, n)
			if err != nil {
				t.Fatalf("%s %s: %v", n, shape, err)
			}
			if prev, dup := seen[a]; dup {
				t.Errorf("%s/%s and %s share %s", n, shape, prev, a)
			}
			seen[a] = n + "/" + string(shape)
			if in, _ := inClassPool(e, a); in {
				t.Errorf("%s is inside the class pool", a)
			}
		}
	}
}

// The class pool's host octets live in two places; this test is the
// link between them (defeat list 9).
func TestClassPoolBandMatchesUpSource(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "up-source.sh"))
	if err != nil {
		t.Fatal(err)
	}
	get := func(name string) int {
		m := regexp.MustCompile(`(?m)^\s*` + name + `=(\d+)`).FindStringSubmatch(string(raw))
		if m == nil {
			t.Fatalf("scripts/up-source.sh defines no %s", name)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	if get("class_first_host") != classPoolFirstHost || get("class_last_host") != classPoolLastHost {
		t.Fatalf("up-source.sh class pool %d-%d differs from groupb_addrs.go %d-%d",
			get("class_first_host"), get("class_last_host"), classPoolFirstHost, classPoolLastHost)
	}
}

func TestNetworkUpExtraBuildsItsOwnNetworkWithOptions(t *testing.T) {
	for _, shape := range Shapes {
		r := &fakeShapeRunner{}
		net, err := NetworkUpExtra(context.Background(), r, "net1", shape, "b2", []string{"client_id=lab-b2-x"})
		if err != nil {
			t.Fatalf("%s: %v", shape, err)
		}
		if net != "net1-b2" {
			t.Errorf("%s: net = %q", shape, net)
		}
		joined := strings.Join(r.calls, "\n")
		if !strings.Contains(joined, "network rm net1-b2") {
			t.Errorf("%s: no stale-network removal first", shape)
		}
		if !strings.Contains(joined, "client_id=lab-b2-x") {
			t.Errorf("%s: option missing from %q", shape, joined)
		}
		hasIgnore := strings.Contains(joined, "ignore_conflicts=true")
		if want := usesHostBridge(shape); hasIgnore != want {
			t.Errorf("%s: ignore_conflicts present=%v, want %v", shape, hasIgnore, want)
		}
	}
}

func TestNetworkUpExtraRefusesAnOptionOutsideTheGrammar(t *testing.T) {
	for _, bad := range []string{"client_id=a;rm", "client_id=a b", "=x", "no-equals", "a=$(id)", "a='x'"} {
		r := &fakeShapeRunner{}
		if _, err := NetworkUpExtra(context.Background(), r, "net1", ShapeBridge, "b2", []string{bad}); err == nil {
			t.Errorf("option %q was accepted", bad)
		}
		for _, c := range r.calls {
			if strings.Contains(c, "network create") {
				t.Errorf("option %q reached a create command: %q", bad, c)
			}
		}
	}
}

// NetworkUp with no extra options builds the same command as before the
// options slice existed (preservation).
func TestNetworkUpCommandUnchangedWithoutOptions(t *testing.T) {
	r := &fakeShapeRunner{}
	if _, err := NetworkUp(context.Background(), r, "net1", ShapeMacvlan); err != nil {
		t.Fatal(err)
	}
	var create string
	for _, c := range r.calls {
		if strings.Contains(c, "network create") {
			create = c
		}
	}
	if create == "" || strings.Contains(create, "ignore_conflicts") || strings.Contains(create, "client_id") {
		t.Fatalf("create command = %q", create)
	}
}

// ---- B1 ----

func b1Setup(t *testing.T, shape Shape) (*bRunner, *bAdapter, Env, string) {
	t.Helper()
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, shape)
	reserved, err := reservationAddr(e, NameB1)
	if err != nil {
		t.Fatal(err)
	}
	return h, src, e, reserved
}

func TestRunB1PassesWhenTheReservedAddressIsLeasedToTheMAC(t *testing.T) {
	h, src, e, reserved := b1Setup(t, ShapeBridge)
	mac := fixedMACForScenario(e.Cell, e.Shape, "b1")
	h.addrFn = func(string, string) string { return reserved }
	src.fn = staticLeases(sourceadapter.Lease{MAC: mac, Address: reserved})
	v := runB1(context.Background(), e)
	needResult(t, v, PASS)
	if len(src.reservedMAC) != 1 || src.reservedMAC[0] != mac+"="+reserved {
		t.Fatalf("reserved %v, want %s=%s", src.reservedMAC, mac, reserved)
	}
	needCleanup(t, h, "", containerName(e, NameB1))
}

// Drive the absence (defeat list 2): the container leasing an address
// other than the reserved one must FAIL even though a lease exists.
func TestRunB1FailsWhenAnotherAddressIsLeased(t *testing.T) {
	h, src, e, _ := b1Setup(t, ShapeBridge)
	mac := fixedMACForScenario(e.Cell, e.Shape, "b1")
	h.addrFn = func(string, string) string { return "10.200.1.120" }
	src.fn = staticLeases(sourceadapter.Lease{MAC: mac, Address: "10.200.1.120"})
	v := runB1(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "reserved") {
		t.Errorf("reason %q does not name the reservation", v.Reason)
	}
	needCleanup(t, h, "", containerName(e, NameB1))
}

func TestRunB1FailsWhenTheTableHasNoRowForTheReservedAddress(t *testing.T) {
	h, src, e, reserved := b1Setup(t, ShapeBridge)
	h.addrFn = func(string, string) string { return reserved }
	src.fn = staticLeases()
	needResult(t, runB1(context.Background(), e), FAIL)
}

func TestRunB1FailsWhenTheReservationIsRefused(t *testing.T) {
	h, src, e, _ := b1Setup(t, ShapeBridge)
	src.reserveErr = errors.New("ssh down")
	src.fn = staticLeases()
	needResult(t, runB1(context.Background(), e), FAIL)
	if h.has("docker run") {
		t.Error("a container was started although the reservation failed")
	}
}

func TestRunB1IsNotApplicableOnIpvlan(t *testing.T) {
	h, src, e, _ := b1Setup(t, ShapeIpvlan)
	src.fn = staticLeases()
	needResult(t, runB1(context.Background(), e), NA)
	if h.has("docker run") {
		t.Error("N/A must not start a container")
	}
}

func TestRunB1FailsOnAnAddressInsideTheMainPool(t *testing.T) {
	h, src, e, _ := b1Setup(t, ShapeBridge)
	e.PoolStart, e.PoolEnd = "10.200.1.200", "10.200.1.254"
	src.fn = staticLeases()
	needResult(t, runB1(context.Background(), e), FAIL)
	if h.has("docker run") {
		t.Error("started a container with no usable reservation address")
	}
}

// ---- B2 ----

func b2Fixture(t *testing.T, shape Shape) (*bRunner, *bAdapter, Env, string, string) {
	t.Helper()
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, shape)
	reserved, _ := reservationAddr(e, NameB2)
	return h, src, e, reserved, b2WireClientID(b2ClientID(shape))
}

func TestB2WireClientIDIsTheTypeByteThenTheString(t *testing.T) {
	if got, want := b2WireClientID("ab"), "00:61:62"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestRunB2PassesWhenTheClientIDRowHoldsTheReservedAddress(t *testing.T) {
	h, src, e, reserved, wire := b2Fixture(t, ShapeBridge)
	h.addrFn = func(string, string) string { return reserved }
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: reserved, ClientID: wire})
	needResult(t, runB2(context.Background(), e), PASS)
	if len(src.reservedID) != 1 || src.reservedID[0] != wire+"="+reserved {
		t.Fatalf("reserved %v", src.reservedID)
	}
	if !h.has("client_id=lab-b2-bridge") {
		t.Errorf("network create lacks client_id: %v", h.cmds)
	}
	needCleanup(t, h, "b2", containerName(e, NameB2))
}

func TestRunB2FailsWhenTheRowCarriesAnotherAddress(t *testing.T) {
	h, src, e, reserved, wire := b2Fixture(t, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.130" }
	src.fn = staticLeases(sourceadapter.Lease{Address: "10.200.1.130", ClientID: wire})
	v := runB2(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, reserved) {
		t.Errorf("reason %q does not name %s", v.Reason, reserved)
	}
	needCleanup(t, h, "b2", containerName(e, NameB2))
}

// Each half of the B2 verdict alone: the table's row and the container's
// own report must both name the reserved address.
func TestRunB2FailsWhenOnlyTheContainerReportsAnotherAddress(t *testing.T) {
	h, src, e, reserved, wire := b2Fixture(t, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.131" }
	src.fn = staticLeases(sourceadapter.Lease{Address: reserved, ClientID: wire})
	needResult(t, runB2(context.Background(), e), FAIL)
}

func TestRunB2FailsWhenOnlyTheTableRowCarriesAnotherAddress(t *testing.T) {
	h, src, e, reserved, wire := b2Fixture(t, ShapeBridge)
	h.addrFn = func(string, string) string { return reserved }
	src.fn = staticLeases(sourceadapter.Lease{Address: "10.200.1.132", ClientID: wire})
	needResult(t, runB2(context.Background(), e), FAIL)
}

func TestRunB2FailsWhenNoRowCarriesTheClientID(t *testing.T) {
	h, src, e, reserved, _ := b2Fixture(t, ShapeBridge)
	h.addrFn = func(string, string) string { return reserved }
	src.fn = staticLeases(sourceadapter.Lease{Address: reserved, ClientID: "00:de:ad"})
	needResult(t, runB2(context.Background(), e), FAIL)
}

// Defeat list 1: a network create that fails still removes the network.
func TestRunB2RemovesTheNetworkWhenTheCreateFails(t *testing.T) {
	h, src, e, _, _ := b2Fixture(t, ShapeBridge)
	h.netErr = errors.New("refused")
	src.fn = staticLeases()
	needResult(t, runB2(context.Background(), e), FAIL)
	needCleanup(t, h, "b2", "")
	if h.has("docker run") {
		t.Error("a container was started on a network that failed to create")
	}
}

func TestRunB2RunsOnEveryShapeButTheIPAMOnes(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan} {
		h, src, e, reserved, wire := b2Fixture(t, shape)
		h.addrFn = func(string, string) string { return reserved }
		src.fn = staticLeases(sourceadapter.Lease{Address: reserved, ClientID: wire})
		needResult(t, runB2(context.Background(), e), PASS)
	}
}

// ---- B3 ----

const nslookupOK = "Server:\t\t10.200.1.1\nAddress:\t10.200.1.1:53\n\nName:\tlabb3-dnsmasq-bridge\nAddress: 10.200.1.101\n"

func b3Fixture(t *testing.T, shape Shape) (*bRunner, *bAdapter, Env) {
	t.Helper()
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, shape)
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.101"})
	return h, src, e
}

func TestDNSAnswerAddrsSkipsTheServerHeader(t *testing.T) {
	got := dnsAnswerAddrs(nslookupOK)
	if len(got) != 1 || got[0] != "10.200.1.101" {
		t.Fatalf("got %v", got)
	}
	if got := dnsAnswerAddrs("Server: 10.200.1.1\nAddress: 10.200.1.1:53\n** server can't find x: NXDOMAIN\n"); len(got) != 0 {
		t.Fatalf("a header alone must give no answer, got %v", got)
	}
}

func TestRunB3PassesWhenTheSourceAnswersWithTheLeasedAddress(t *testing.T) {
	h, _, e := b3Fixture(t, ShapeBridge)
	h.nslookup = nslookupOK
	v := runB3Tuned(context.Background(), e, 2, time.Millisecond)
	needResult(t, v, PASS)
	// Defeat list 6: the query names the source's own segment address.
	if !h.has("nslookup labb3-dnsmasq-bridge 10.200.1.1") {
		t.Errorf("the query does not name the source as server: %v", h.cmds)
	}
	if !h.has("--hostname labb3-dnsmasq-bridge") || !h.has("register_dns=true") {
		t.Errorf("hostname or register_dns missing: %v", h.cmds)
	}
	needCleanup(t, h, "b3", containerName(e, NameB3))
}

func TestRunB3FailsWhenTheAnswerIsAnotherAddress(t *testing.T) {
	h, _, e := b3Fixture(t, ShapeBridge)
	h.nslookup = strings.Replace(nslookupOK, "10.200.1.101", "10.200.1.77", 1)
	needResult(t, runB3Tuned(context.Background(), e, 2, time.Millisecond), FAIL)
}

func TestRunB3FailsWhenTheHostnameDoesNotResolve(t *testing.T) {
	h, _, e := b3Fixture(t, ShapeBridge)
	h.nslookup = "Server: 10.200.1.1\nAddress: 10.200.1.1:53\n\n** server can't find labb3: NXDOMAIN\n"
	needResult(t, runB3Tuned(context.Background(), e, 2, time.Millisecond), FAIL)
	needCleanup(t, h, "b3", containerName(e, NameB3))
}

func TestRunB3FailsWithoutASourceAddress(t *testing.T) {
	h, _, e := b3Fixture(t, ShapeBridge)
	e.SegGateway = ""
	needResult(t, runB3Tuned(context.Background(), e, 1, time.Millisecond), FAIL)
	if h.has("nslookup") {
		t.Error("queried with no server address")
	}
}

// ---- B4 ----

func TestRunB4PassesWhenTheSameMACKeepsOneLease(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	mac := fixedMACForScenario(e.Cell, e.Shape, "b4")
	h.addrFn = func(string, string) string { return "10.200.1.140" }
	src.fn = staticLeases(sourceadapter.Lease{MAC: mac, Address: "10.200.1.140"})
	v := runB4(context.Background(), e)
	needResult(t, v, PASS)
	if v.Evidence["leases-before"] == "" || v.Evidence["leases-after"] == "" {
		t.Errorf("both snapshots must be in the evidence: %v", v.Evidence)
	}
	needCleanup(t, h, "", containerName(e, NameB4))
}

// One lease for the MAC both times, but the address moved.
func TestRunB4FailsWhenTheSingleLeaseMovesToAnotherAddress(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	mac := fixedMACForScenario(e.Cell, e.Shape, "b4")
	runs := 0
	h.addrFn = func(string, string) string { runs++; return fmt.Sprintf("10.200.1.%d", 140+runs) }
	src.fn = func(call int) []sourceadapter.Lease {
		return []sourceadapter.Lease{{MAC: mac, Address: fmt.Sprintf("10.200.1.%d", 140+call)}}
	}
	v := runB4(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "same mac got") {
		t.Errorf("reason %q", v.Reason)
	}
}

func TestRunB4FailsWhenTheAddressChanges(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	mac := fixedMACForScenario(e.Cell, e.Shape, "b4")
	runs := 0
	h.addrFn = func(string, string) string { runs++; return fmt.Sprintf("10.200.1.%d", 140+runs) }
	src.fn = func(int) []sourceadapter.Lease {
		return []sourceadapter.Lease{{MAC: mac, Address: "10.200.1.141"}, {MAC: mac, Address: "10.200.1.142"}}
	}
	needResult(t, runB4(context.Background(), e), FAIL)
}

// A fresh lease that happens to carry the same address is not the same
// lease: two rows for the MAC FAIL (defeat list 3).
func TestRunB4FailsOnASecondLeaseForTheMACWithTheSameAddress(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	mac := fixedMACForScenario(e.Cell, e.Shape, "b4")
	h.addrFn = func(string, string) string { return "10.200.1.140" }
	src.fn = func(call int) []sourceadapter.Lease {
		if call == 1 {
			return []sourceadapter.Lease{{MAC: mac, Address: "10.200.1.140"}}
		}
		return []sourceadapter.Lease{{MAC: mac, Address: "10.200.1.140"}, {MAC: strings.ToUpper(mac), Address: "10.200.1.140"}}
	}
	v := runB4(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "exactly 1") {
		t.Errorf("reason %q", v.Reason)
	}
}

// The table holds two rows for the fixed MAC before the remove.
func TestRunB4FailsWhenTheTableHoldsTwoLeasesBeforeTheRemove(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	mac := fixedMACForScenario(e.Cell, e.Shape, "b4")
	h.addrFn = func(string, string) string { return "10.200.1.140" }
	src.fn = staticLeases(
		sourceadapter.Lease{MAC: mac, Address: "10.200.1.140"},
		sourceadapter.Lease{MAC: mac, Address: "10.200.1.141"},
	)
	v := runB4(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "before the remove") {
		t.Errorf("reason %q", v.Reason)
	}
	needCleanup(t, h, "", containerName(e, NameB4))
}

func TestRunB4IsNotApplicableOnIpvlan(t *testing.T) {
	h := newBRunner()
	e := bEnv(t, h, &bAdapter{fakeAdapter: &fakeAdapter{}}, ShapeIpvlan)
	needResult(t, runB4(context.Background(), e), NA)
}

// ---- B5 ----

func TestRunB5PassesFromTheClassPool(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.225" }
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.225"})
	needResult(t, runB5(context.Background(), e), PASS)
	if !h.has("vendor_class=lab-class-b5") {
		t.Errorf("network create lacks vendor_class: %v", h.cmds)
	}
	needCleanup(t, h, "b5", containerName(e, NameB5))
}

// The preservation control of the class check: an address from the main
// pool is a FAIL, so a source that ignores the class cannot pass.
func TestRunB5FailsFromTheMainPool(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.150" }
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.150"})
	v := runB5(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "rebuilt") {
		t.Errorf("reason %q should say an old source VM needs a rebuild", v.Reason)
	}
	needCleanup(t, h, "b5", containerName(e, NameB5))
}

// Above the class pool's last address, still in the cell's /24.
func TestRunB5FailsAboveTheClassPool(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.231" }
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.231"})
	needResult(t, runB5(context.Background(), e), FAIL)
	needCleanup(t, h, "b5", containerName(e, NameB5))
}

func TestRunB5FailsWhenTheAddressIsInTheClassPoolButNotInTheTable(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.225" }
	src.fn = staticLeases()
	needResult(t, runB5(context.Background(), e), FAIL)
}

// ---- B6 ----

func b6Fixture(t *testing.T) (*bRunner, *bAdapter, Env) {
	t.Helper()
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.101" }
	return h, src, e
}

func b6Leases(first, second time.Time) func(int) []sourceadapter.Lease {
	return func(call int) []sourceadapter.Lease {
		exp := first
		if call > 2 {
			exp = second
		}
		return []sourceadapter.Lease{{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.101", Expires: exp}}
	}
}

var b6T0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func TestRunB6PassesAfterTheRenewalCarriesTheNewServer(t *testing.T) {
	h, src, e := b6Fixture(t)
	src.fn = b6Leases(b6T0, b6T0.Add(time.Minute))
	h.resolv = []string{"nameserver 10.200.1.1\n", "nameserver 10.200.1.253\n"}
	v := runB6Tuned(context.Background(), e, 40, 200*time.Millisecond, time.Millisecond)
	needResult(t, v, PASS)
	if src.dnsSet != "10.200.1.253" || !src.dnsRestored || !src.shortened || !src.restored {
		t.Errorf("dns set=%q restored=%v shortened=%v restored lease=%v", src.dnsSet, src.dnsRestored, src.shortened, src.restored)
	}
	if !h.has("propagate_dns=true") {
		t.Errorf("network create lacks propagate_dns: %v", h.cmds)
	}
	needCleanup(t, h, "b6", containerName(e, NameB6))
}

// Drive the absence (defeat list 4): no renewal, no verdict from
// resolv.conf; the read waits on the table, and a run that never sees
// the renewal FAILs naming that.
func TestRunB6FailsWhenTheLeaseNeverRenews(t *testing.T) {
	h, src, e := b6Fixture(t)
	src.fn = b6Leases(b6T0, b6T0)
	h.resolv = []string{"nameserver 10.200.1.1\n", "nameserver 10.200.1.253\n"}
	v := runB6Tuned(context.Background(), e, 40, 30*time.Millisecond, time.Millisecond)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "no renewal") {
		t.Errorf("reason %q", v.Reason)
	}
	if !src.dnsRestored || !src.restored {
		t.Error("the source was left changed after a FAIL")
	}
	needCleanup(t, h, "b6", containerName(e, NameB6))
}

func TestRunB6FailsWhenResolvConfKeepsTheOldServer(t *testing.T) {
	h, src, e := b6Fixture(t)
	src.fn = b6Leases(b6T0, b6T0.Add(time.Minute))
	h.resolv = []string{"nameserver 10.200.1.1\n"}
	v := runB6Tuned(context.Background(), e, 40, 200*time.Millisecond, time.Millisecond)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "10.200.1.253") {
		t.Errorf("reason %q", v.Reason)
	}
	if v.Evidence["resolv-conf"] == "" {
		t.Error("resolv.conf must be in the evidence")
	}
}

// Preservation control: a resolv.conf that already shows the new server
// before the change proves nothing and is refused.
func TestRunB6FailsWhenTheNewServerWasThereBeforeTheChange(t *testing.T) {
	h, src, e := b6Fixture(t)
	src.fn = b6Leases(b6T0, b6T0.Add(time.Minute))
	h.resolv = []string{"nameserver 10.200.1.253\n"}
	needResult(t, runB6Tuned(context.Background(), e, 40, 50*time.Millisecond, time.Millisecond), FAIL)
	if src.dnsSet != "" {
		t.Error("the source was changed despite a failing control")
	}
}

func TestRunB6FailsWithoutAnExpiryInTheTable(t *testing.T) {
	h, src, e := b6Fixture(t)
	src.fn = b6Leases(time.Time{}, time.Time{})
	h.resolv = []string{"nameserver 10.200.1.1\n"}
	needResult(t, runB6Tuned(context.Background(), e, 40, 50*time.Millisecond, time.Millisecond), FAIL)
}

func TestRunB6FailsWhenTheSourceRefusesTheOptionChange(t *testing.T) {
	h, src, e := b6Fixture(t)
	src.fn = b6Leases(b6T0, b6T0)
	src.dnsErr = errors.New("already carries a DNS option")
	h.resolv = []string{"nameserver 10.200.1.1\n"}
	needResult(t, runB6Tuned(context.Background(), e, 40, 50*time.Millisecond, time.Millisecond), FAIL)
	if !src.restored {
		t.Error("the shortened lease time was not restored")
	}
}

// ---- B7 ----

func b7Fixture(t *testing.T) (*bRunner, *bAdapter, Env) {
	t.Helper()
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.101" }
	return h, src, e
}

func TestRunB7PassesOnceTheLeaseLeavesTheTable(t *testing.T) {
	h, src, e := b7Fixture(t)
	row := sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.101"}
	src.fn = func(call int) []sourceadapter.Lease {
		if call <= 3 {
			return []sourceadapter.Lease{row}
		}
		return nil
	}
	v := runB7Tuned(context.Background(), e, 500*time.Millisecond, time.Millisecond)
	needResult(t, v, PASS)
	if !h.has("release_lease=on_remove") {
		t.Errorf("network create lacks release_lease: %v", h.cmds)
	}
	if v.Evidence["leases-before"] == "" || v.Evidence["leases-after-remove"] == "" {
		t.Errorf("evidence %v", v.Evidence)
	}
	needCleanup(t, h, "b7", containerName(e, NameB7))
}

// The lease staying in the table is the plugin default's behaviour and
// here a FAIL (defeat list 5).
func TestRunB7FailsWhenTheLeaseStays(t *testing.T) {
	h, src, e := b7Fixture(t)
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.101"})
	v := runB7Tuned(context.Background(), e, 20*time.Millisecond, time.Millisecond)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "claymore666/docker-net-dhcp#1288") {
		t.Fatalf("B7 FAIL reason does not name the plugin issue: %q", v.Reason)
	}
	needCleanup(t, h, "b7", containerName(e, NameB7))
}

// A lease that was never in the table before the remove cannot be
// "released": the scenario refuses to pass on absence alone.
func TestRunB7FailsWhenTheLeaseWasNeverInTheTable(t *testing.T) {
	h, src, e := b7Fixture(t)
	src.fn = staticLeases()
	needResult(t, runB7Tuned(context.Background(), e, 20*time.Millisecond, time.Millisecond), FAIL)
	needCleanup(t, h, "b7", containerName(e, NameB7))
}

func TestRunB7FailsWhenTheNetworkIsRefused(t *testing.T) {
	h, src, e := b7Fixture(t)
	h.netErr = errors.New("release_lease refused")
	src.fn = staticLeases()
	v := runB7Tuned(context.Background(), e, 20*time.Millisecond, time.Millisecond)
	needResult(t, v, FAIL)
	needCleanup(t, h, "b7", "")
}

func TestRunB7StopsWhenTheContextEnds(t *testing.T) {
	h, src, e := b7Fixture(t)
	src.fn = staticLeases(sourceadapter.Lease{MAC: "aa:bb:cc:00:00:01", Address: "10.200.1.101"})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	v := runB7Tuned(ctx, e, time.Minute, 5*time.Millisecond)
	needResult(t, v, FAIL)
	needCleanup(t, h, "b7", containerName(e, NameB7))
}

// ---- B8 ----

func b8Lease(shape Shape, h *bRunner, name string) sourceadapter.Lease {
	c := h.containers[name]
	l := sourceadapter.Lease{MAC: c.mac, Address: c.addr}
	if shape == ShapeIpvlan {
		id, _ := ipvlanClientID(c.endpointID)
		l.MAC = "aa:bb:cc:99:99:99"
		l.ClientID = id
	}
	return l
}

func b8Names(e Env) []string {
	var out []string
	for i := 0; i < 3; i++ {
		out = append(out, containerName(e, NameB8)+"-"+strconv.Itoa(i))
	}
	return out
}

func TestRunB8PassesWithThreeDistinctLeasesOnEveryShape(t *testing.T) {
	for _, shape := range Shapes {
		h := newBRunner()
		src := &bAdapter{fakeAdapter: &fakeAdapter{}}
		e := bEnv(t, h, src, shape)
		src.fn = func(int) []sourceadapter.Lease {
			var out []sourceadapter.Lease
			for _, n := range b8Names(e) {
				if _, ok := h.containers[n]; ok {
					out = append(out, b8Lease(shape, h, n))
				}
			}
			return out
		}
		needResult(t, runB8(context.Background(), e), PASS)
		for _, n := range b8Names(e) {
			if !h.has("docker rm -f " + n) {
				t.Errorf("%s: %s was not removed", shape, n)
			}
		}
	}
}

func TestRunB8FailsWhenTwoContainersShareAnAddress(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	h.addrFn = func(string, string) string { return "10.200.1.101" }
	src.fn = func(int) []sourceadapter.Lease {
		var out []sourceadapter.Lease
		for _, n := range b8Names(e) {
			if _, ok := h.containers[n]; ok {
				out = append(out, b8Lease(ShapeBridge, h, n))
			}
		}
		return out
	}
	v := runB8(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "distinct") {
		t.Errorf("reason %q", v.Reason)
	}
}

func TestRunB8FailsWhenOneContainerHasNoLease(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	src.fn = func(int) []sourceadapter.Lease {
		var out []sourceadapter.Lease
		for _, n := range b8Names(e)[:2] {
			if _, ok := h.containers[n]; ok {
				out = append(out, b8Lease(ShapeBridge, h, n))
			}
		}
		return out
	}
	needResult(t, runB8(context.Background(), e), FAIL)
}

func TestRunB8FailsWhenAContainerDoesNotStartAndRemovesTheOthers(t *testing.T) {
	h := newBRunner()
	e := bEnv(t, h, &bAdapter{fakeAdapter: &fakeAdapter{}, fn: staticLeases()}, ShapeBridge)
	h.runErr = errors.New("no space")
	needResult(t, runB8(context.Background(), e), FAIL)
}

func TestRunB8FailsOnIpvlanWhenClientIDsCollide(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeIpvlan)
	src.fn = func(int) []sourceadapter.Lease {
		var out []sourceadapter.Lease
		for _, n := range b8Names(e) {
			if _, ok := h.containers[n]; ok {
				l := b8Lease(ShapeIpvlan, h, n)
				l.ClientID = "00:00:00:00:00:00:00:00:01"
				out = append(out, l)
			}
		}
		return out
	}
	needResult(t, runB8(context.Background(), e), FAIL)
}

// Every container reports one address while the table holds three
// distinct rows under the three client ids.
func TestRunB8FailsOnIpvlanWhenContainersReportOneAddress(t *testing.T) {
	h := newBRunner()
	h.addrFn = func(string, string) string { return "10.200.1.101" }
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeIpvlan)
	src.fn = func(int) []sourceadapter.Lease {
		var out []sourceadapter.Lease
		for i, n := range b8Names(e) {
			if _, ok := h.containers[n]; ok {
				l := b8Lease(ShapeIpvlan, h, n)
				l.Address = fmt.Sprintf("10.200.1.%d", 101+i)
				out = append(out, l)
			}
		}
		return out
	}
	v := runB8(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "reports") {
		t.Errorf("reason %q", v.Reason)
	}
}

func TestRunB8FailsWhenNonIpvlanContainersShareOneMAC(t *testing.T) {
	h := newBRunner()
	h.forceMAC = "aa:bb:cc:77:77:77"
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeBridge)
	src.fn = func(int) []sourceadapter.Lease {
		var out []sourceadapter.Lease
		for _, n := range b8Names(e) {
			if _, ok := h.containers[n]; ok {
				out = append(out, b8Lease(ShapeBridge, h, n))
			}
		}
		return out
	}
	v := runB8(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "distinct macs") {
		t.Errorf("reason %q", v.Reason)
	}
}

func TestRunB8FailsOnIpvlanWhenTheTableShowsMoreThanOneMAC(t *testing.T) {
	h := newBRunner()
	src := &bAdapter{fakeAdapter: &fakeAdapter{}}
	e := bEnv(t, h, src, ShapeIpvlan)
	src.fn = func(int) []sourceadapter.Lease {
		var out []sourceadapter.Lease
		for i, n := range b8Names(e) {
			if _, ok := h.containers[n]; ok {
				l := b8Lease(ShapeIpvlan, h, n)
				l.MAC = fmt.Sprintf("aa:bb:cc:99:99:%02x", i)
				out = append(out, l)
			}
		}
		return out
	}
	v := runB8(context.Background(), e)
	needResult(t, v, FAIL)
	if !strings.Contains(v.Reason, "one shared mac") {
		t.Errorf("reason %q", v.Reason)
	}
}

// ---- docs against code (defeat list 10) ----

func TestReadmeGroupBTableMatchesTheCatalog(t *testing.T) { readmeGroupMatchesCatalog(t, "B") }

func TestReadmeGroupCTableMatchesTheCatalog(t *testing.T) { readmeGroupMatchesCatalog(t, "C") }

func TestReadmeGroupFTableMatchesTheCatalog(t *testing.T) { readmeGroupMatchesCatalog(t, "F") }

func readmeGroupMatchesCatalog(t *testing.T, group string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	i := strings.Index(readme, "Group "+group+" runs today")
	if i < 0 {
		t.Fatalf("README has no 'Group %s runs today' table", group)
	}
	section := readme[i:]
	if j := strings.Index(section, "\n\n|"); j >= 0 {
		if k := strings.Index(section[j+2:], "\n\n"); k >= 0 {
			section = section[:j+2+k]
		}
	}
	rows := regexp.MustCompile(`(?m)^\| (`+group+`\d+[a-z]?) \|`).FindAllStringSubmatch(section, -1)
	inReadme := map[string]bool{}
	for _, m := range rows {
		inReadme[m[1]] = true
	}
	inCatalog := map[string]bool{}
	for _, s := range Catalog {
		if strings.HasPrefix(s.Name, group) {
			inCatalog[strings.SplitN(s.Name, "-", 2)[0]] = true
		}
	}
	for id := range inCatalog {
		if !inReadme[id] {
			t.Errorf("%s is in the catalog but not in the README table", id)
		}
	}
	for id := range inReadme {
		if !inCatalog[id] {
			t.Errorf("%s is in the README table but not in the catalog", id)
		}
	}
}

// ---- IPAM shapes ----

// The lab cannot create the second, option-carrying network in the two
// IPAM shapes (plugin docs/reference.md refuses it), so B2, B5, B6 and B7
// are N/A there, before anything touches the host. B8 still runs.
func TestGroupBSecondNetworkScenariosAreNotApplicableOnIPAMShapes(t *testing.T) {
	runs := map[string]func(context.Context, Env) Verdict{
		NameB2: runB2, NameB5: runB5, NameB6: runB6, NameB7: runB7,
	}
	for _, shape := range []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		for name, run := range runs {
			t.Run(string(shape)+"/"+name, func(t *testing.T) {
				h := newBRunner()
				src := &bAdapter{fakeAdapter: &fakeAdapter{}}
				e := bEnv(t, h, src, shape)
				v := run(context.Background(), e)
				needResult(t, v, NA)
				if !strings.Contains(v.Reason, "derive the same pool identity") {
					t.Errorf("reason does not quote the plugin rule: %q", v.Reason)
				}
				if len(h.cmds) != 0 {
					t.Errorf("N/A touched the host: %v", h.cmds)
				}
			})
		}
	}
}

func TestGroupBSecondNetworkScenariosStillRunOnTheOtherShapes(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan} {
		if _, ok := bIPAMNA(NameB2, Env{Shape: shape}); ok {
			t.Errorf("%s must not be N/A by the IPAM rule", shape)
		}
	}
}
