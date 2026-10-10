package sourceadapter

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// scriptRunner answers by command prefix and records every call.
type scriptRunner struct {
	replies map[string]string
	fail    map[string]bool
	calls   []string
}

func (s *scriptRunner) Run(_ context.Context, cmd string) (string, error) {
	s.calls = append(s.calls, cmd)
	for prefix, failed := range s.fail {
		if failed && strings.HasPrefix(cmd, prefix) {
			return "", errors.New("exit status 3")
		}
	}
	for prefix, out := range s.replies {
		if strings.HasPrefix(cmd, prefix) {
			return out, nil
		}
	}
	return "", nil
}

type innerStub struct {
	Adapter
	readyErr  error
	recovered int
	caps      []Capability
}

func (i *innerStub) Ready(context.Context) error   { return i.readyErr }
func (i *innerStub) Recover(context.Context) error { i.recovered++; return nil }
func (i *innerStub) Capabilities() []Capability    { return i.caps }

var testRelayParams = RelayParams{
	ClientAddr: "10.200.10.1/24", ServerAddr: "10.200.11.1/24", SourceAddr: "10.200.11.2",
	ClientSubnet: "10.200.10.0/24", PoolStart: "10.200.10.100", AgentOptions: true,
}

// measuredRuleset is `nft list ruleset` on Debian 13 (nftables 1.1.3) after
// RelayNftRuleset loads, captured in a netns (#11).
const measuredRuleset = "table inet lab_relay {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n" +
	"\t\tiifname \"eth1\" oifname \"eth2\" accept\n\t\tiifname \"eth2\" oifname \"eth1\" accept\n\t}\n}\n"

func healthyRelay(t *testing.T) (*scriptRunner, *scriptRunner) {
	t.Helper()
	cfg, err := RenderRelayDefaults(testRelayParams)
	if err != nil {
		t.Fatal(err)
	}
	relay := &scriptRunner{replies: map[string]string{
		"sudo systemctl is-active":      "1234\n",
		"sysctl -n":                     "1\n",
		"ip -4 -o addr show dev eth1":   "3: eth1    inet 10.200.10.1/24 brd 10.200.10.255 scope global eth1\\       valid_lft forever preferred_lft forever\n",
		"ip -4 -o addr show dev eth2":   "4: eth2    inet 10.200.11.1/24 brd 10.200.11.255 scope global eth2\\       valid_lft forever preferred_lft forever\n",
		"sudo nft list ruleset":         measuredRuleset,
		"sudo cat " + RelayDefaultsPath: cfg,
	}, fail: map[string]bool{}}
	source := &scriptRunner{replies: map[string]string{
		"ip -4 route get": "10.200.10.100 via 10.200.11.1 dev eth1 src 10.200.11.2 uid 0 \n    cache \n",
	}, fail: map[string]bool{}}
	return relay, source
}

func newTestRelay(relay, source Runner, inner *innerStub) Adapter {
	p := testRelayParams
	p.Source = source
	return WithRelay(inner, relay, p)
}

func TestRelayReadyHealthy(t *testing.T) {
	relay, source := healthyRelay(t)
	if err := newTestRelay(relay, source, &innerStub{}).Ready(context.Background()); err != nil {
		t.Fatalf("healthy relay not ready: %v", err)
	}
}

// One row per Ready check (#11): each edit breaks exactly one input of
// an otherwise healthy relay, and Ready must name it.
func TestRelayReadyChecks(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(relay, source *scriptRunner)
		want   string
	}{
		{"inner source not ready", nil, "inner"},
		{"1 relay service inactive", func(r, _ *scriptRunner) { r.fail["sudo systemctl is-active"] = true }, "pgrep dhcrelay failed"},
		{"2 ip_forward off", func(r, _ *scriptRunner) { r.replies["sysctl -n"] = "0\n" }, "ip_forward"},
		{"3 client leg renumbered", func(r, _ *scriptRunner) {
			r.replies["ip -4 -o addr show dev eth1"] = "3: eth1    inet 10.200.10.9/24 scope global eth1\n"
		}, "eth1 carries"},
		{"3 client leg extra address", func(r, _ *scriptRunner) {
			r.replies["ip -4 -o addr show dev eth1"] += "3: eth1    inet 10.200.255.5/24 scope global eth1\n"
		}, "eth1 carries"},
		{"3 server leg missing", func(r, _ *scriptRunner) { r.replies["ip -4 -o addr show dev eth2"] = "" }, "eth2 carries"},
		{"4 forward policy accept", func(r, _ *scriptRunner) {
			r.replies["sudo nft list ruleset"] = strings.Replace(measuredRuleset, "policy drop", "policy accept", 1)
		}, "nft ruleset"},
		{"4 an extra accept rule", func(r, _ *scriptRunner) {
			r.replies["sudo nft list ruleset"] = strings.Replace(measuredRuleset, "\t}\n}", "\t\tiifname \"eth1\" oifname \"eth0\" accept\n\t}\n}", 1)
		}, "nft ruleset"},
		{"4 ruleset flushed", func(r, _ *scriptRunner) { r.replies["sudo nft list ruleset"] = "" }, "nft ruleset"},
		{"5 defaults drifted", func(r, _ *scriptRunner) {
			r.replies["sudo cat "+RelayDefaultsPath] = strings.Replace(r.replies["sudo cat "+RelayDefaultsPath], " -a", "", 1)
		}, RelayDefaultsPath},
		{"6 source route without via", func(_, s *scriptRunner) {
			s.replies["ip -4 route get"] = "10.200.10.100 dev eth0 src 10.200.255.111 uid 0\n"
		}, "is not routed via"},
		{"6 source route via another next hop", func(_, s *scriptRunner) {
			s.replies["ip -4 route get"] = "10.200.10.100 via 10.200.11.9 dev eth1 src 10.200.11.2 uid 0\n"
		}, "is not routed via"},
		{"6 source route via the wrong device", func(_, s *scriptRunner) {
			s.replies["ip -4 route get"] = "10.200.10.100 via 10.200.11.1 dev eth0 src 10.200.255.111 uid 0\n"
		}, "is not routed via"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay, source := healthyRelay(t)
			inner := &innerStub{}
			if tc.break_ == nil {
				inner.readyErr = errors.New("inner")
			} else {
				tc.break_(relay, source)
			}
			err := newTestRelay(relay, source, inner).Ready(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRenderRelayDefaults(t *testing.T) {
	got, err := RenderRelayDefaults(testRelayParams)
	if err != nil {
		t.Fatal(err)
	}
	want := "SERVERS=\"10.200.11.2\"\nINTERFACES=\"\"\nOPTIONS=\"-4 -a -id eth1 -iu eth2\"\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	p := testRelayParams
	p.AgentOptions = false
	if got, _ := RenderRelayDefaults(p); strings.Contains(got, " -a") {
		t.Fatalf("agent_options false still renders -a: %q", got)
	}
	p = testRelayParams
	p.SourceAddr = `10.200.11.2"; reboot; "`
	if _, err := RenderRelayDefaults(p); err == nil {
		t.Fatal("a non-address SERVERS value was rendered")
	}
}

func TestRelayRecoverPutsEverythingBack(t *testing.T) {
	relay, source := healthyRelay(t)
	inner := &innerStub{}
	if err := newTestRelay(relay, source, inner).Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if inner.recovered != 1 {
		t.Fatalf("inner Recover ran %d times, want 1", inner.recovered)
	}
	joined := strings.Join(relay.calls, "\n")
	for _, want := range []string{"sudo tee " + RelayDefaultsPath, "sudo tee " + RelayNftPath, "policy drop",
		"sudo nft -f " + RelayNftPath, "net.ipv4.ip_forward=1", "sudo systemctl restart isc-dhcp-relay"} {
		if !strings.Contains(joined, want) {
			t.Errorf("relay recover never ran %q", want)
		}
	}
	if last := relay.calls[len(relay.calls)-1]; last != "sudo systemctl restart isc-dhcp-relay" {
		t.Errorf("relay restarted before its config was back: last call %q", last)
	}
	if want := "sudo ip route replace 10.200.10.0/24 via 10.200.11.1 dev eth1"; !slices.Contains(source.calls, want) {
		t.Errorf("source calls %q lack %q", source.calls, want)
	}
}

func TestRelayCapabilities(t *testing.T) {
	// The squatter and the rogue server would sit on the source's server
	// segment, not the client one, and C9 cannot move a source that is
	// not on the client segment: behind a relay C6, C6b, C7 and C9 are
	// N/A (#11, #23). dhcrelay relays v4 only and an RA never crosses a
	// router, so group D is N/A too. The narrowed pool still works.
	all := []Capability{CapV4, CapRestart, CapSquatter, CapRogueServer, CapNarrowPool, CapRenumber, CapV6, CapRapidCommit6, CapTemporary6, CapPD, CapPref64}
	inner := &innerStub{caps: slices.Clone(all)}
	got := WithRelay(inner, &scriptRunner{}, testRelayParams).Capabilities()
	if !slices.Equal(got, []Capability{CapV4, CapRestart, CapNarrowPool, CapRelay}) {
		t.Fatalf("got %v", got)
	}
	if !slices.Equal(inner.caps, all) {
		t.Fatalf("the inner adapter's slice was changed: %v", inner.caps)
	}
	twice := WithRelay(&innerStub{caps: []Capability{CapRelay, CapV4}}, &scriptRunner{}, testRelayParams).Capabilities()
	if !slices.Equal(twice, []Capability{CapV4, CapRelay}) {
		t.Fatalf("an inner relay capability is listed once, got %v", twice)
	}
}

func TestRelayMACs(t *testing.T) {
	r := &scriptRunner{replies: map[string]string{"cat /sys/class/net/eth1/address /sys/class/net/eth2/address": "52:54:00:aa:bb:01\n52:54:00:aa:bb:02\n"}}
	cli, srv, err := RelayMACs(context.Background(), r)
	if err != nil || cli != "52:54:00:aa:bb:01" || srv != "52:54:00:aa:bb:02" {
		t.Fatalf("got %q %q %v", cli, srv, err)
	}
	for _, bad := range []string{"", "52:54:00:aa:bb:01\n", "52:54:00:aa:bb:01\nnot-a-mac\n"} {
		r.replies["cat "] = bad
		delete(r.replies, "cat /sys/class/net/eth1/address /sys/class/net/eth2/address")
		if _, _, err := RelayMACs(context.Background(), r); err == nil {
			t.Errorf("reply %q accepted", bad)
		}
	}
}

// Every capability the relay cell leaves out names a relay-cell reason
// (#11); the group D text names dhcrelay -4 and the RA that never crosses.
func TestRelayNAReasonsCoverEveryDroppedCapability(t *testing.T) {
	a := WithRelay(&innerStub{}, &scriptRunner{}, testRelayParams).(NAExplainer)
	want := map[Capability]string{
		CapSquatter:        "a squatter on the server segment is invisible to clients, by design",
		CapRogueServer:     "a squatter on the server segment is invisible to clients, by design",
		CapRenumber:        "renumbering needs the relay leg renumbered too",
		CapFailoverPair:    "no failover peer",
		CapDNSRegistration: "serves no DNS",
	}
	for _, c := range relayDropped {
		if _, ok := want[c]; !ok {
			want[c] = "dhcrelay -4 relays DHCPv4 only and no router advertisement crosses the relay"
		}
	}
	for c, frag := range want {
		why, ok := a.NAReason(c)
		if !ok || !strings.HasPrefix(why, "relay cell: ") || !strings.Contains(why, frag) {
			t.Errorf("%s: %q %v, want a relay-cell reason containing %q", c, why, ok, frag)
		}
	}
	for _, c := range []Capability{CapV4, CapRelay, CapShortLease} {
		if why, ok := a.NAReason(c); ok {
			t.Errorf("%s is not a relay-cell loss, got %q", c, why)
		}
	}
}

// A reason the inner adapter already gives survives the wrapper.
type reasonInner struct{ innerStub }

func (reasonInner) NAReason(c Capability) (string, bool) {
	if c == CapPD {
		return "inner pd text", true
	}
	return "inner " + string(c), c == CapOption108
}

func TestRelayNAReasonFallsBackToTheInnerAdapter(t *testing.T) {
	a := WithRelay(&reasonInner{}, &scriptRunner{}, testRelayParams).(NAExplainer)
	if why, ok := a.NAReason(CapOption108); !ok || why != "inner option-108" {
		t.Errorf("option-108: %q %v", why, ok)
	}
	if why, _ := a.NAReason(CapPD); !strings.Contains(why, "dhcrelay -4") {
		t.Errorf("a capability the relay drops keeps the relay's own text, got %q", why)
	}
}

// F8 behind a relay (#11): the client is off-link, so the FORCERENEW goes
// to the MAC of the source's next hop, read through the same neighbour
// seam; the container's own MAC is never looked up.
func TestRelayForceRenewGoesToTheNextHop(t *testing.T) {
	const relayMAC, ctrMAC = "02:11:00:00:00:02", "02:42:0a:c8:0a:64"
	r := &scriptRunner{replies: map[string]string{
		"ip route get 10.200.10.100":           "10.200.10.100 via 10.200.11.1 dev eth1 src 10.200.11.2 uid 0 \n    cache \n",
		"ip neigh show 10.200.11.1 dev eth1":   "10.200.11.1 lladdr " + relayMAC + " REACHABLE\n",
		"ip neigh show 10.200.10.100 dev eth1": "10.200.10.100 lladdr " + ctrMAC + " REACHABLE\n",
		"sudo python3":                         "forcerenew mode=signed\n",
	}, fail: map[string]bool{}}
	relayVM, _ := healthyRelay(t)
	p := testRelayParams
	p.Source = r
	a := WithRelay(featureAdapter("kea", r), relayVM, p)
	fp := goodFR()
	fp.Addr, fp.Server = "10.200.10.100", "10.200.11.2"
	if _, err := a.SendForceRenew(context.Background(), []byte("print('x')\n"), fp); err != nil {
		t.Fatal(err)
	}
	last := r.calls[len(r.calls)-1]
	if !strings.Contains(last, "--dst-mac "+relayMAC+" ") || strings.Contains(last, ctrMAC) {
		t.Fatalf("sender ran with %q, want the relay's MAC %s", last, relayMAC)
	}
	for _, c := range r.calls {
		if strings.HasPrefix(c, "ip neigh show 10.200.10.100") {
			t.Fatalf("the container's own neighbour entry was read: %q", r.calls)
		}
	}
	// No next hop behind a relay is a loud error, not a silent guess.
	r2 := &scriptRunner{replies: map[string]string{"ip route get": "10.200.10.100 dev eth1 src 10.200.10.5 uid 0\n"}, fail: map[string]bool{}}
	p.Source = r2
	b := WithRelay(featureAdapter("kea", r2), relayVM, p)
	if _, err := b.SendForceRenew(context.Background(), []byte("print('x')\n"), fp); err == nil || !strings.Contains(err.Error(), "no next hop") {
		t.Fatalf("on-link route behind a relay: %v", err)
	}
}

// Off a relay cell the neighbour lookup is the container's, byte for byte
// as before: no `ip route get` is ever issued.
func TestForceRenewWithoutRelayNeverAsksForARoute(t *testing.T) {
	r := &neighRunner{neigh: "10.200.1.100 lladdr 02:42:0a:c8:01:64 REACHABLE\n"}
	if _, err := featureAdapter("kea", r).SendForceRenew(context.Background(), []byte("print('x')\n"), goodFR()); err != nil {
		t.Fatal(err)
	}
	if r.calls[1] != "ip neigh show 10.200.1.100 dev eth1" {
		t.Fatalf("calls %q", r.calls)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "route get") {
			t.Fatalf("route lookup on a non-relay cell: %q", r.calls)
		}
	}
}
