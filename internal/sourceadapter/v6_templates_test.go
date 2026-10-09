package sourceadapter

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// v6Knobs maps each v6 capability to the feature that turns it on and,
// per adapter, the rendered config that feature edits and the line the
// edit must leave there. A dnsmasq row with no path is a feature the
// stock range already serves (rapid commit, IA_TA): its proof is the
// range line in lab-v6.conf (group D defeat 19, #23).
var v6Knobs = map[Capability]struct {
	feature Feature
	cfg     map[string]struct{ path, want string }
}{
	CapRapidCommit6: {FeatureRapidCommit6, map[string]struct{ path, want string }{
		"kea":      {keaDHCP6Conf, `"rapid-commit": true`},
		"isc-dhcp": {iscDHCP6Conf, "\noption dhcp6.rapid-commit; # lab-rapid-commit-on\n"},
		"dnsmasq":  {"", ""},
	}},
	CapTemporary6: {FeatureTemporary6, map[string]struct{ path, want string }{
		"isc-dhcp": {iscDHCP6Conf, "  range6 fd42:200:0:100::200/120 temporary; # lab-temporary-on\n"},
		"dnsmasq":  {"", ""},
	}},
}

var dnsmasqV6Range = regexp.MustCompile(`(?m)^dhcp-range=fd42:200:0:100::100,fd42:200:0:100::1ff,slaac,64,2h$`)

func TestEveryV6CapabilityHasAKnobInTheRenderedConfig(t *testing.T) {
	ctx := context.Background()
	for c, k := range v6Knobs {
		for name, knob := range k.cfg {
			b := baselines[name]
			if knob.path == "" {
				if !dnsmasqV6Range.MatchString(baselineConfig(t, b.tmpl, dnsmasqLabV6Conf)) {
					t.Errorf("%s: %s rests on the v6 range, which lab-v6.conf does not carry", name, c)
				}
				continue
			}
			orig := baselineConfig(t, b.tmpl, knob.path)
			r := &cfgRunner{cfg: orig}
			restore, err := featureAdapter(name, r).EnableFeature(ctx, k.feature, FeatureParams{})
			if err != nil {
				t.Errorf("%s %s on the rendered %s: %v", name, k.feature, knob.path, err)
				continue
			}
			if strings.Contains(orig, knob.want) || !strings.Contains(r.cfg, knob.want) {
				t.Errorf("%s %s: %q not switched on in\n%s", name, k.feature, knob.want, r.cfg)
			}
			if err := restore(ctx); err != nil || r.cfg != orig {
				t.Errorf("%s %s: restore = %v, config back = %v", name, k.feature, err, r.cfg == orig)
			}
		}
	}
}

// The knob table and the declared capabilities agree both ways: a row for
// an adapter that does not declare the cap is a cap the cell cannot prove,
// and a declared v6 cap without a row is a claim nothing renders.
func TestV6KnobRowsMatchDeclaredCapabilities(t *testing.T) {
	for _, name := range []string{"kea", "isc-dhcp", "dnsmasq"} {
		for _, d := range featureAdapter(name, nil).Capabilities() {
			k, isV6Knob := v6Knobs[d]
			if d != CapRapidCommit6 && d != CapTemporary6 {
				continue
			}
			if _, ok := k.cfg[name]; !isV6Knob || !ok {
				t.Errorf("%s declares %s but has no knob row", name, d)
			}
		}
	}
	for c, k := range v6Knobs {
		for name := range k.cfg {
			declared := false
			for _, d := range featureAdapter(name, nil).Capabilities() {
				declared = declared || d == c
			}
			if !declared {
				t.Errorf("knob row %s/%s but %s does not declare it", c, name, name)
			}
		}
	}
}

// dnsmasq's SetRA Off must find both of its anchors in the rendered
// lab-v6.conf, or the scenario runs with RAs still on.
func TestDnsmasqSetRAOffEditsTheRenderedConfig(t *testing.T) {
	ctx := context.Background()
	orig := baselineConfig(t, baselines["dnsmasq"].tmpl, dnsmasqLabV6Conf)
	r := &cfgRunner{cfg: orig}
	restore, err := (&DnsmasqAdapter{Runner: r}).SetRA(ctx, RAParams{Off: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.cfg, "\nenable-ra\n") || strings.HasPrefix(r.cfg, "enable-ra\n") || strings.Contains(r.cfg, "slaac") {
		t.Fatalf("SetRA Off left RA on:\n%s", r.cfg)
	}
	if err := restore(ctx); err != nil || r.cfg != orig {
		t.Fatalf("restore = %v, config back = %v", err, r.cfg == orig)
	}
}

// The source's own network config carries both segment addresses and
// never accepts an RA (its own radvd or dnsmasq sends them).
func TestSourceNetworkConfigCarriesTheV6Address(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "cloud-init", "source-network-config.tmpl.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`addresses: [__SEG_ADDR__, "__SEG_ADDR6__"]`, "accept-ra: false", "dhcp6: false"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("source-network-config lacks %q", want)
		}
	}
}

// Kea's dhcp6 control socket and the control agent's dhcp6 entry must be
// the same path, or Leases6 (lease6-get-all through the agent) has no
// server to reach; both rendered files must parse as JSON.
func TestKeaV6SocketAgreesWithTheControlAgent(t *testing.T) {
	tmpl := baselines["kea"].tmpl
	var d6 struct {
		Dhcp6 struct {
			ControlSocket struct {
				Name string `json:"socket-name"`
			} `json:"control-socket"`
			Subnet6 []struct {
				RapidCommit *bool `json:"rapid-commit"`
			} `json:"subnet6"`
		}
	}
	if err := json.Unmarshal([]byte(baselineConfig(t, tmpl, keaDHCP6Conf)), &d6); err != nil {
		t.Fatalf("kea-dhcp6.conf: %v", err)
	}
	var ca struct {
		ControlAgent struct {
			Sockets map[string]struct {
				Name string `json:"socket-name"`
			} `json:"control-sockets"`
		} `json:"Control-agent"`
	}
	if err := json.Unmarshal([]byte(baselineConfig(t, tmpl, "/etc/kea/kea-ctrl-agent.conf")), &ca); err != nil {
		t.Fatalf("kea-ctrl-agent.conf: %v", err)
	}
	if got := ca.ControlAgent.Sockets["dhcp6"].Name; got == "" || got != d6.Dhcp6.ControlSocket.Name {
		t.Fatalf("agent dhcp6 socket %q, server socket %q", got, d6.Dhcp6.ControlSocket.Name)
	}
	if len(d6.Dhcp6.Subnet6) != 1 || d6.Dhcp6.Subnet6[0].RapidCommit == nil || *d6.Dhcp6.Subnet6[0].RapidCommit {
		t.Fatal("subnet6 must start with rapid-commit false, the DHCPv6 rapid commit baseline")
	}
}

// Every source template stays valid YAML with a runcmd list after the
// v6 heredocs went in; a mis-indented block would drop the whole seed.
func TestSourceTemplatesParseAsYAML(t *testing.T) {
	for name, b := range baselines {
		raw, err := os.ReadFile(filepath.Join("..", "..", "cloud-init", b.tmpl))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runcmd []string `yaml:"runcmd"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil || len(doc.Runcmd) == 0 {
			t.Errorf("%s: %s does not parse to a runcmd list: %v", name, b.tmpl, err)
		}
	}
}
