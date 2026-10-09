package main

import (
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
