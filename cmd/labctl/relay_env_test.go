package main

import (
	"crypto/md5"
	"fmt"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
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
