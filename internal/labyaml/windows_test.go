package labyaml

import (
	"strings"
	"testing"
)

// The shipped windows cell, pinned to the design (lab #14): its own /24,
// management .160 (docker host) and .161 (source), the evaluation image
// on the windows seed, DHCPv4 only. Nothing else may hold its subnet,
// bridge or management addresses.
func TestRealLabYAMLWindowsCell(t *testing.T) {
	c, err := Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cell, err := c.CellByName("windows")
	if err != nil {
		t.Fatal(err)
	}
	s := cell.Source
	got := []string{cell.Segment.Bridge, cell.Segment.Subnet, cell.Segment.Subnet6, s.Type, s.BaseImage, s.MgmtAddress, s.SegAddress, s.PoolStart, s.PoolEnd,
		cell.DockerHost.MgmtAddress}
	want := []string{"lab-br-windows", "10.200.16.0/24", "", "windows", "windows-2025-eval", "10.200.255.161/24", "10.200.16.2/24", "10.200.16.100", "10.200.16.200",
		"10.200.255.160/24"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("windows cell\n got %v\nwant %v", got, want)
	}
	if s.VCPUs != 2 || s.MemoryMiB != 4096 || s.DiskGiB != 20 {
		t.Errorf("windows source shape = %d vCPU, %d MiB, %d GiB, want 2, 4096, 20", s.VCPUs, s.MemoryMiB, s.DiskGiB)
	}
	if SourceServesV6("windows") {
		t.Error("windows is v4 only until its DHCPv6 change")
	}
	if len(cell.Segment.Bridge) > 15 {
		t.Errorf("bridge %q is longer than an interface name (15)", cell.Segment.Bridge)
	}
	bi, err := LookupBaseImage(s.BaseImage)
	if err != nil || bi.Kind != "built" || bi.Seed != "windows" {
		t.Errorf("source image = %+v, %v; want a built image on the windows seed", bi, err)
	}
	for _, o := range c.Cells {
		if o.Name == "windows" {
			continue
		}
		mine := map[string]bool{cell.Segment.Subnet: true, cell.Segment.Bridge: true, s.MgmtAddress: true, cell.DockerHost.MgmtAddress: true}
		for _, v := range []string{o.Segment.Subnet, o.Segment.Bridge, o.DockerHost.MgmtAddress} {
			if mine[v] {
				t.Errorf("cell %s shares %s with the windows cell", o.Name, v)
			}
		}
		if o.Source != nil && mine[o.Source.MgmtAddress] {
			t.Errorf("cell %s shares %s with the windows cell", o.Name, o.Source.MgmtAddress)
		}
		if o.Source != nil && o.Source.Partner != nil && mine[o.Source.Partner.MgmtAddress] {
			t.Errorf("cell %s partner shares %s with the windows cell", o.Name, o.Source.Partner.MgmtAddress)
		}
	}
}

// A windows source is accepted as a type, and an IPv6 block on its
// segment is refused like the other v4-only types (lab #14).
func TestWindowsSourceTypeIsV4Only(t *testing.T) {
	if _, err := Load(write(t, strings.Replace(withSource, "type: kea", "type: windows", 1))); err != nil {
		t.Fatalf("source.type windows rejected: %v", err)
	}
	_, err := Load(write(t, strings.Replace(withSource6, "type: kea", "type: windows", 1)))
	if err == nil || !strings.Contains(err.Error(), "DHCPv4 only") {
		t.Fatalf("windows on a subnet6 cell: %v", err)
	}
}
