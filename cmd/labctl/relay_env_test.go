package main

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Defeat 11 of the relay design (#11): behind a relay the router is the
// relay's client leg and the source keeps its own address; the cells
// without a relay are TestSegAddressesAreEqualWithoutARelay's.
func TestSegAddressesSplitBehindARelay(t *testing.T) {
	cfg, err := labyaml.Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := cfg.CellByName("kea-relay")
	if err != nil {
		t.Fatal(err)
	}
	if gw, src := segAddresses(relay); gw != "10.200.10.1" || src != "10.200.11.2" {
		t.Fatalf("kea-relay: SegGateway %q SourceAddr %q, want 10.200.10.1 and 10.200.11.2", gw, src)
	}
}

func TestResolveRelayRendersTheFilesReadyChecks(t *testing.T) {
	cfg, err := labyaml.Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	relay, _ := cfg.CellByName("kea-relay")
	img, files, err := resolveRelay(relay)
	if err != nil || img == nil || files == nil {
		t.Fatalf("resolveRelay: %v %v %v", img, files, err)
	}
	if files.Defaults != "SERVERS=\"10.200.11.2\"\nINTERFACES=\"\"\nOPTIONS=\"-4 -a -id eth1 -iu eth2\"\n" {
		t.Errorf("defaults %q", files.Defaults)
	}
	if !strings.Contains(files.Nft, "policy drop") {
		t.Errorf("nft %q", files.Nft)
	}
	for i := range cfg.Cells {
		if c := &cfg.Cells[i]; c.Relay == nil {
			if img, files, err := resolveRelay(c); img != nil || files != nil || err != nil {
				t.Errorf("%s has no relay but resolved %v %v %v", c.Name, img, files, err)
			}
		}
	}
}

// Defeat 10 of the relay design (#11): capture-start.sh keys an observer's
// host veth on md5(key)[:5], with key the cell name or, for a relay
// cell's server segment, "<cell>-srv". Every key in lab.yaml must give a
// distinct veth, or one observer's start tears down another's.
func TestObserverVethsAreUniqueAcrossCells(t *testing.T) {
	cfg, err := labyaml.Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	relays := 0
	for _, c := range cfg.Cells {
		keys := []string{c.Name}
		if c.Relay != nil {
			keys = append(keys, c.Name+"-srv")
			relays++
		}
		for _, k := range keys {
			veth := fmt.Sprintf("veth-obs-%xh", md5.Sum([]byte(k)))
			veth = veth[:len("veth-obs-")+5] + "h"
			if other, dup := seen[veth]; dup {
				t.Errorf("observer keys %q and %q share veth %s", other, k, veth)
			}
			seen[veth] = k
		}
	}
	if relays == 0 {
		t.Fatal("no relay cell in lab.yaml")
	}
	// `echo -n kea-relay-srv | md5sum | cut -c1-5` on the controller.
	if seen["veth-obs-f03c5h"] != "kea-relay-srv" {
		t.Errorf("the Go derivation drifted from capture-start.sh's: %v", seen)
	}
}

// fakeHost answers a command with the reply of the first key it contains,
// else reply, or fails every one when down, and records what it was asked.
type fakeHost struct {
	reply   string
	replies map[string]string
	down    bool
	calls   []string
}

func (f *fakeHost) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	if f.down {
		return "", errors.New("unreachable")
	}
	for k, v := range f.replies {
		if strings.Contains(cmd, k) {
			return v, nil
		}
	}
	return f.reply, nil
}

func dialFakes(hosts map[string]*fakeHost) func(string) sourceadapter.Runner {
	return func(h string) sourceadapter.Runner {
		f, ok := hosts[h]
		if !ok {
			f = &fakeHost{down: true}
			hosts[h] = f
		}
		return f
	}
}

// The Env cmdRun runs a relay cell with (#11):
// the router is the relay's client leg, the source keeps its own address,
// and the adapter carries the relay's capability, Ready and Recover, with
// the route repair on the source VM.
func TestCellEnvWiresTheRelay(t *testing.T) {
	cfg, err := labyaml.Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cell, err := cfg.CellByName("kea-relay")
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeHost{replies: map[string]string{
		"lease4-get-all":  `[{"result":3,"text":"0 IPv4 lease(s) found."}]`,
		"lease6-get-all":  `[{"result":3,"text":"0 IPv6 lease(s) found."}]`,
		"printf 'netns:'": "netns:\nlinks:\nprocs:0\nnetem:0\naddr:10.200.11.2/24 \naddr6:fd42:200:0:a00::2/64 \ncfg6:/etc/kea/kea-dhcp6.conf:e30K\ncfg6:/etc/radvd.conf:e30K\ncfg:\n{}\n",
	}}
	relay := &fakeHost{reply: "02:11:00:00:00:01\n02:11:00:00:00:02\n"}
	hosts := map[string]*fakeHost{hostPart(cell.Source.MgmtAddress): src, hostPart(cell.Relay.MgmtAddress): relay}
	work := t.TempDir()
	env, err := cellEnv(context.Background(), cell, "kea-relay", "/repo", work, dialFakes(hosts))
	if err != nil {
		t.Fatal(err)
	}
	if env.SegGateway != "10.200.10.1" || env.SourceAddr != "10.200.11.2" {
		t.Errorf("SegGateway %q SourceAddr %q, want 10.200.10.1 and 10.200.11.2", env.SegGateway, env.SourceAddr)
	}
	if env.RelayClientMAC != "02:11:00:00:00:01" || env.RelayServerMAC != "02:11:00:00:00:02" {
		t.Errorf("relay MACs %q %q", env.RelayClientMAC, env.RelayServerMAC)
	}
	if env.ServerPCAP != filepath.Join(work, "srv", "observer.pcap") {
		t.Errorf("ServerPCAP %q", env.ServerPCAP)
	}
	if c, ok := env.ServerCapture.(scenario.ObserverCapture); !ok || c.Cell != "kea-relay-srv" {
		t.Errorf("ServerCapture %#v, want the kea-relay-srv observer", env.ServerCapture)
	}
	if caps := env.Source.Capabilities(); !slices.Contains(caps, sourceadapter.CapRelay) || slices.Contains(caps, sourceadapter.CapV6) {
		t.Errorf("capabilities %v, want CapRelay and no CapV6", caps)
	}
	// The pre-shape pool check counts only what the wrapped source can
	// run: the group D scenarios the relay declares N/A add nothing (#11, #12).
	plain := &sourceadapter.KeaAdapter{}
	if got, all := scenario.PoolDemand(scenario.Catalog, env.Source), scenario.PoolDemand(scenario.Catalog, plain); got >= all {
		t.Errorf("relay cell pool demand %d, want less than the plain source's %d", got, all)
	}
	if capacity, err := poolCapacity(cell.Source.PoolStart, cell.Source.PoolEnd); err != nil {
		t.Fatal(err)
	} else if ok, reason := poolHasCapacityFor(capacity, 0, scenario.PoolDemand(scenario.Catalog, env.Source)); !ok {
		t.Errorf("relay cell pool: %s", reason)
	}
	if err := env.Source.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if want := "sudo ip route replace 10.200.10.0/24 via 10.200.11.1 dev eth1"; !slices.Contains(src.calls, want) {
		t.Errorf("Recover never repaired the source route; source calls %q", src.calls)
	}
	if !slices.Contains(relay.calls, "sudo systemctl restart isc-dhcp-relay") {
		t.Errorf("Recover never restarted the relay; relay calls %q", relay.calls)
	}
	relay.down = true
	if err := env.Source.Ready(context.Background()); err == nil || !strings.Contains(err.Error(), "relay: is-active") {
		t.Errorf("Ready with the relay down: %v, want the relay service check", err)
	}
}

// A cell with no relay keeps one address for router and source, the plain
// adapter and no second capture.
func TestCellEnvLeavesAPlainCellAlone(t *testing.T) {
	cfg, err := labyaml.Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cell, err := cfg.CellByName("kea")
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]*fakeHost{hostPart(cell.Source.MgmtAddress): {}}
	env, err := cellEnv(context.Background(), cell, "kea", "/repo", t.TempDir(), dialFakes(hosts))
	if err != nil {
		t.Fatal(err)
	}
	want := hostPart(cell.Source.SegAddress)
	if env.SegGateway != want || env.SourceAddr != want {
		t.Errorf("SegGateway %q SourceAddr %q, want both %s", env.SegGateway, env.SourceAddr, want)
	}
	if slices.Contains(env.Source.Capabilities(), sourceadapter.CapRelay) || env.ServerCapture != nil || env.ServerPCAP != "" || env.RelayClientMAC != "" {
		t.Errorf("plain cell carries relay wiring: %+v", env)
	}
	if len(hosts) != 1 {
		t.Errorf("plain cell dialled %d hosts, want only the source", len(hosts))
	}
}
