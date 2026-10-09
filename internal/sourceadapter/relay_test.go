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
		{"1 relay service inactive", func(r, _ *scriptRunner) { r.fail["sudo systemctl is-active"] = true }, "is not active"},
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
	inner := &innerStub{caps: []Capability{CapV4, CapRestart}}
	got := WithRelay(inner, &scriptRunner{}, testRelayParams).Capabilities()
	if !slices.Equal(got, []Capability{CapV4, CapRestart, CapRelay}) {
		t.Fatalf("got %v", got)
	}
	if !slices.Equal(inner.caps, []Capability{CapV4, CapRestart}) {
		t.Fatalf("the inner adapter's slice was changed: %v", inner.caps)
	}
}
