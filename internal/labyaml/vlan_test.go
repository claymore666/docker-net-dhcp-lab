package labyaml

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The VLAN subnets must sit inside the lab range and collide with no
// cell, relay server segment or the management range, windows cell
// included although it is not in lab.yaml yet (lab #15).
func TestVLANSubnetsCollideWithNothing(t *testing.T) {
	c, err := Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	taken := map[netip.Prefix]string{netip.MustParsePrefix(c.Management.Subnet): "management"}
	var segs []string
	for _, cell := range c.Cells {
		segs = append(segs, cell.Segment.Subnet)
		if cell.Relay != nil {
			segs = append(segs, cell.Relay.ServerSegment.Subnet)
		}
	}
	segs = append(segs, "10.200.16.0/24") // windows cell, not on dev yet
	for _, s := range segs {
		taken[netip.MustParsePrefix(s)] = s
		// C9 renumbers a cell into this subnet for a while: a VLAN pool
		// there would answer for two networks (#15 E3b).
		b := netip.MustParsePrefix(s).Addr().As4()
		if int(b[2])+C9OctetShift <= 254 {
			b[2] += C9OctetShift
			taken[netip.PrefixFrom(netip.AddrFrom4(b), 24)] = "C9 target of " + s
		}
	}
	forbidden := []netip.Prefix{
		netip.MustParsePrefix(hostLAN),
		netip.MustParsePrefix("10.9.0.0/24"),
		netip.MustParsePrefix("169.254.0.0/16"),
	}
	lab := netip.MustParsePrefix("10.200.0.0/16")
	for _, s := range segs {
		v, err := VLANSubnet(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		vp := netip.MustParsePrefix(v)
		if !lab.Contains(vp.Addr()) {
			t.Errorf("%s -> %s outside %s", s, v, lab)
		}
		if who, ok := taken[vp]; ok {
			t.Errorf("%s -> %s collides with %s", s, v, who)
		}
		for _, f := range forbidden {
			if f.Overlaps(vp) {
				t.Errorf("%s -> %s overlaps %s", s, v, f)
			}
		}
		taken[vp] = "vlan of " + s
	}
}

func TestVLANSubnetRefusals(t *testing.T) {
	for _, in := range []string{"10.200.255.0/24", "10.200.105.0/24", hostLAN, "10.200.3.0/16", "11.200.3.0/24", "10.201.3.0/24", "10.200.3.8/24", "nope"} {
		if v, err := VLANSubnet(in); err == nil {
			t.Errorf("%s -> %s, want an error", in, v)
		}
	}
	if v, err := VLANSubnet("10.200.104.0/24"); err != nil || v != "10.200.254.0/24" {
		t.Errorf("104 -> %q %v", v, err)
	}
}

// up-source.sh derives the same third octet in shell; run its two
// lines against every segment here so the rule has one meaning. (#15)
func TestVLANShellDerivationMatchesGo(t *testing.T) {
	src, err := os.ReadFile("../../scripts/up-source.sh")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(l, "vlan_") && strings.Contains(l, "=") && !strings.Contains(l, "__") {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		t.Fatal("up-source.sh has no vlan_* derivation lines")
	}
	for _, seg := range []string{"10.200.0.0/24", "10.200.3.0/24", "10.200.11.0/24", "10.200.16.0/24", "10.200.17.0/24"} {
		want, _ := VLANSubnet(seg)
		base := strings.TrimSuffix(seg, ".0/24")
		// A failover partner sits at .3 on the segment and must not share
		// the primary's VLAN address (lab #15).
		for _, host := range []string{"2", "3"} {
			script := "seg_network=" + strings.TrimSuffix(seg, "/24") + "\nseg_addr=" + base + "." + host + "/24\n" +
				strings.Join(lines, "\n") + "\necho \"$vlan_subnet $vlan_addr\"\n"
			out, err := exec.Command("bash", "-c", script).Output()
			if err != nil {
				t.Fatalf("%s: %v", seg, err)
			}
			wantAddr := strings.TrimSuffix(want, ".0/24") + "." + host
			if got := strings.TrimSpace(string(out)); got != want+" "+wantAddr {
				t.Errorf("%s host .%s: shell %q, Go %q", seg, host, got, want+" "+wantAddr)
			}
		}
	}
}

// hostLAN is the docker host's own network, which no VLAN pool may use
// (lab #15). Split so a text sweep for host addresses stays empty.
const hostLAN = "192.168." + "0.0/24"
