package sourceadapter

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// goldenRunner is a segRunner that also answers the lease, state, probe
// and neighbour reads, so every Adapter method runs its whole path; cfg6
// holds a drifted v6 config, the rest read "v6 <path>".
type goldenRunner struct {
	segRunner
	leaseCmd string
	leaseOut string
	cfg6     map[string]string
	files    map[string]string
}

var goldenCfg6RE = regexp.MustCompile(`printf 'cfg6:([^:']+):'`)

func (g *goldenRunner) Run(ctx context.Context, cmd string) (string, error) {
	switch {
	case cmd == keaLease6Cmd, cmd == g.leaseCmd && strings.HasPrefix(cmd, "curl "):
		g.calls = append(g.calls, cmd)
		return `[{"result":3,"text":"no leases"}]`, nil
	case cmd == g.leaseCmd, cmd == "sudo cat "+iscLease6File, strings.HasPrefix(cmd, "sudo cat "+rogueLeaseFile):
		g.calls = append(g.calls, cmd)
		if cmd == g.leaseCmd {
			return g.leaseOut, nil
		}
		return "", nil
	case strings.HasPrefix(cmd, "printf 'netns:'"):
		g.calls = append(g.calls, cmd)
		v6 := ""
		for _, m := range goldenCfg6RE.FindAllStringSubmatch(cmd, -1) {
			body, ok := g.cfg6[m[1]]
			if !ok {
				body = "v6 " + m[1] + "\n"
			}
			v6 += "cfg6:" + m[1] + ":" + base64.StdEncoding.EncodeToString([]byte(body)) + "\n"
		}
		return fmt.Sprintf("netns:\nlinks:\nprocs:0\nnetem:0\naddr:%s \naddr6:fd00:200:1::2/64 \n%scfg:\n%s", strings.Join(g.addrs, " "), v6, g.cfg), nil
	case strings.HasPrefix(cmd, "sudo cat ") && g.files[strings.TrimPrefix(cmd, "sudo cat ")] != "":
		g.calls = append(g.calls, cmd)
		return g.files[strings.TrimPrefix(cmd, "sudo cat ")], nil
	case cmd == "sudo cat "+dnsmasqLabV6Conf:
		g.calls = append(g.calls, cmd)
		return "enable-ra\ndhcp-range=fd42:200:0:100::100,fd42:200:0:100::1ff,slaac,64,2h\n", nil
	case strings.HasPrefix(cmd, "ip route get "):
		g.calls = append(g.calls, cmd)
		return "10.200.1.150 via 10.200.1.1 dev eth1 src 10.200.1.2 uid 0 \n", nil
	case strings.HasPrefix(cmd, "ip neigh show "):
		g.calls = append(g.calls, cmd)
		return "10.200.1.150 lladdr 02:aa:bb:cc:dd:ee REACHABLE\n", nil
	}
	return g.segRunner.Run(ctx, cmd)
}

var goldenLeaseCmds = map[string]string{
	"kea":      keaLeaseCmd,
	"isc-dhcp": "sudo cat " + iscLeaseFile,
	"dnsmasq":  "sudo cat " + dnsmasqLeaseFile,
	"udhcpd":   fmt.Sprintf(udhcpdLeasesCmd, udhcpdLeaseFile, "sudo systemctl kill -s USR1 udhcpd"),
	"pihole":   "sudo cat " + piholeLeaseFile,
}

// goldenNames are the five adapters on a Debian source VM (#9, #10).
var goldenNames = []string{"kea", "isc-dhcp", "dnsmasq", "udhcpd", "pihole"}

func goldenAdapter(t *testing.T, name string) (Adapter, *goldenRunner) {
	g := &goldenRunner{leaseCmd: goldenLeaseCmds[name]}
	if name == "udhcpd" {
		g.segRunner = segRunner{cfgRunner: cfgRunner{cfg: udhcpdBaseline(t)}, addrs: []string{"10.200.1.2/24"}}
		g.leaseOut = "Mac Address       IP Address      Host Name           Expires in\n"
		return &UdhcpdAdapter{Runner: g}, g
	}
	g.segRunner = *segBaseline(t, name)
	if path := goldenV6Conf[name]; path != "" {
		g.files = map[string]string{path: baselineConfig(t, baselines[name].tmpl, path)}
	}
	return featureAdapter(name, g), g
}

// goldenV6Conf is the v6 config the rapid-commit-6 and temporary-6 edits
// read, rendered from the adapter's template.
var goldenV6Conf = map[string]string{"kea": keaDHCP6Conf, "isc-dhcp": iscDHCP6Conf}

// goldenV6Features run after the v4 ones, so their lines were appended.
var goldenV6Features = []Feature{FeatureRapidCommit6, FeatureTemporary6}

type goldenStep struct {
	name string
	run  func(ctx context.Context, a Adapter, g *goldenRunner) (func(context.Context) error, error)
}

func noRestore(err error) (func(context.Context) error, error) { return nil, err }

var goldenSteps = []goldenStep{
	{"Leases", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		_, err := a.Leases(ctx)
		return noRestore(err)
	}},
	{"Leases6", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		_, err := a.Leases6(ctx)
		return noRestore(err)
	}},
	{"SetRAOff", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return a.SetRA(ctx, RAParams{Off: true})
	}},
	{"ReserveMAC", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return noRestore(a.ReserveMAC(ctx, "02:11:22:33:44:55", "10.200.1.150"))
	}},
	{"ReserveClientID", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return noRestore(a.ReserveClientID(ctx, f1ID, "10.200.1.151"))
	}},
	{"SetDNSOption", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return a.SetDNSOption(ctx, "10.200.1.53")
	}},
	{"Restart", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return noRestore(a.Restart(ctx))
	}},
	{"Stop", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return noRestore(a.Stop(ctx))
	}},
	{"Start", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return noRestore(a.Start(ctx))
	}},
	{"Reachable", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return noRestore(a.Reachable(ctx, "10.200.1.150"))
	}},
	{"ShortenLeaseTime", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return a.ShortenLeaseTime(ctx, 60)
	}},
	{"ResetLeases", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return noRestore(a.ResetLeases(ctx))
	}},
	{"ReadyTwiceThenRecoverDrifted", func(ctx context.Context, a Adapter, g *goldenRunner) (func(context.Context) error, error) {
		if err := a.Ready(ctx); err != nil {
			return noRestore(err)
		}
		if err := a.Ready(ctx); err != nil {
			return noRestore(err)
		}
		g.addrs = []string{"10.200.9.2/24"}
		g.cfg += "# drifted\n"
		g.cfg6 = map[string]string{radvdConf: "drifted\n", dnsmasqLabV6Conf: "drifted\n"}
		return noRestore(a.Recover(ctx))
	}},
	{"RecoverWithoutBaseline", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return noRestore(a.Recover(ctx))
	}},
	{"Impair", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return a.Impair(ctx, 150*time.Millisecond, 5)
	}},
	{"SendForceRenewUnsigned", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		_, err := a.SendForceRenew(ctx, []byte("print(1)\n"), ForceRenewParams{Mode: "unsigned", Addr: "10.200.1.150", Server: "10.200.1.2", CHAddr: "02:11:22:33:44:55"})
		return noRestore(err)
	}},
	{"SendForceRenewSigned", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		_, err := a.SendForceRenew(ctx, []byte("print(1)\n"), ForceRenewParams{Mode: "signed", Addr: "10.200.1.150", Server: "10.200.1.2", CHAddr: "02:11:22:33:44:55", ClientID: f1ID, Nonce: katNonce, AckReplay: 7})
		return noRestore(err)
	}},
	{"SquatAnnounce", func(ctx context.Context, a Adapter, g *goldenRunner) (func(context.Context) error, error) {
		g.out = squatOut(goodARP, "02:11:22:33:44:55", "1")
		return a.Squat(ctx, "10.200.1.231", true)
	}},
	{"SquatSilent", func(ctx context.Context, a Adapter, g *goldenRunner) (func(context.Context) error, error) {
		g.out = squatOut(goodARP, "02:11:22:33:44:55", "1")
		return a.Squat(ctx, "10.200.1.231", false)
	}},
	{"StartRogue", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return a.StartRogue(ctx, "10.200.1.240", "10.200.1.241", "10.200.1.250")
	}},
	{"RogueLeases", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		_, err := a.RogueLeases(ctx)
		return noRestore(err)
	}},
	{"NarrowPool", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return a.NarrowPool(ctx, "10.200.1.100", "10.200.1.101")
	}},
	{"Renumber", func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
		return a.Renumber(ctx, "10.200.2.0/24", "10.200.2.2", "10.200.2.100", "10.200.2.200")
	}},
}

// renderGolden drives every Adapter method of the Debian adapters and
// prints each command they send, Go-quoted, one per line.
func renderGolden(t *testing.T) string {
	var b strings.Builder
	for _, name := range goldenNames {
		steps := append([]goldenStep(nil), goldenSteps...)
		for _, c := range featureCases {
			c := c
			steps = append(steps, goldenStep{"EnableFeature/" + string(c.feature), func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
				return a.EnableFeature(ctx, c.feature, c.params)
			}})
		}
		for _, f := range goldenV6Features {
			f := f
			steps = append(steps, goldenStep{"EnableFeature/" + string(f), func(ctx context.Context, a Adapter, _ *goldenRunner) (func(context.Context) error, error) {
				return a.EnableFeature(ctx, f, FeatureParams{})
			}})
		}
		for _, s := range steps {
			a, g := goldenAdapter(t, name)
			restore, err := s.run(context.Background(), a, g)
			fmt.Fprintf(&b, "## %s %s err=%v\n", name, s.name, err != nil)
			if restore != nil {
				rerr := restore(context.Background())
				fmt.Fprintf(&b, "# restore err=%v\n", rerr != nil)
			}
			for _, c := range g.calls {
				fmt.Fprintf(&b, "%q\n", c)
			}
		}
	}
	return b.String()
}

const goldenPath = "testdata/debian-commands.golden"

// Every command a Debian adapter sends is pinned byte for byte to the
// copy taken at dev b19470b, before the service, NIC and tc paths
// became adapter fields (#9). LAB_GOLDEN_WRITE=1 rewrites the file.
func TestDebianAdapterCommandsMatchTheGolden(t *testing.T) {
	got := renderGolden(t)
	if os.Getenv("LAB_GOLDEN_WRITE") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) && i < len(wl); i++ {
			if gl[i] != wl[i] {
				t.Fatalf("line %d differs from %s:\n got %s\nwant %s", i+1, goldenPath, gl[i], wl[i])
			}
		}
		t.Fatalf("output has %d lines, %s has %d", len(gl), goldenPath, len(wl))
	}
}

// WithRelay has no host of its own: behind a healthy relay the kea
// source sends, step for step, the commands it sends bare (#9, #11).
func TestKeaBehindTheRelaySendsTheBareCommands(t *testing.T) {
	for _, s := range goldenSteps {
		bare, gb := goldenAdapter(t, "kea")
		inner, gw := goldenAdapter(t, "kea")
		relay, source := healthyRelay(t)
		p := testRelayParams
		p.Source = source
		_, _ = s.run(context.Background(), bare, gb)
		_, _ = s.run(context.Background(), WithRelay(inner, relay, p), gw)
		bareCalls := gb.calls
		if strings.HasPrefix(s.name, "SendForceRenew") {
			// FORCERENEW behind a relay asks for the next hop first (#11).
			bareCalls = nil
			for _, c := range gb.calls {
				if strings.HasPrefix(c, "ip neigh show 10.200.1.150") {
					bareCalls = append(bareCalls, "ip route get 10.200.1.150", "ip neigh show 10.200.1.1 dev eth1")
					continue
				}
				bareCalls = append(bareCalls, c)
			}
		}
		if strings.Join(gw.calls, "\n") != strings.Join(bareCalls, "\n") {
			t.Errorf("%s: behind the relay kea sent\n%q\nbare\n%q", s.name, gw.calls, bareCalls)
		}
	}
}
