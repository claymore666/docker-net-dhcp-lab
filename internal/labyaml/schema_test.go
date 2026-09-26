package labyaml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lab.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodMin = `
management:
  libvirt_network: net-mgmt
  subnet: 10.200.255.0/24
  gateway: 10.200.255.1
cells:
  - name: ref-only
    segment:
      bridge: lab-br-ref-only
      subnet: 10.200.0.0/24
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.10/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2
`

func TestLoadGood(t *testing.T) {
	c, err := Load(write(t, goodMin))
	if err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	cell, err := c.CellByName("ref-only")
	if err != nil {
		t.Fatal(err)
	}
	if cell.DockerHost.PluginTag == "" {
		t.Fatal("plugin tag lost in parsing")
	}
}

// A private address outside the lab's own /16 must be refused, not
// silently accepted (drive the absence: the guard the whole check exists
// for). The values here are fictional placeholders, not any real
// network's address: the point is that the guard compares against the
// lab's own range, not against a specific forbidden list.
func TestRejectsOtherPrivateSubnet(t *testing.T) {
	bad := strings.Replace(goodMin, "10.200.0.0/24", "172.20.0.0/24", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a 172.20.0.0/24 segment subnet was accepted")
	}
}

func TestRejectsOtherPrivateManagementSubnet(t *testing.T) {
	bad := strings.Replace(goodMin, "10.200.255.0/24", "172.20.1.0/24", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a 172.20.1.0/24 management subnet was accepted")
	}
}

func TestRejectsSubnetOutsideLabRangeButPrivate(t *testing.T) {
	// Still a 10.x/24, still private, but outside the lab's declared
	// 10.200.0.0/16: a check that only compares first octets would wrongly
	// accept this.
	bad := strings.Replace(goodMin, "10.200.0.0/24", "10.55.0.0/24", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("10.55.0.0/24 (outside 10.200.0.0/16) was accepted")
	}
}

func TestRejectsDuplicateBridge(t *testing.T) {
	two := strings.Replace(goodMin, "cells:", `cells:
  - name: second
    segment:
      bridge: lab-br-ref-only
      subnet: 10.200.1.0/24
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.11/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2`, 1)
	if _, err := Load(write(t, two)); err == nil {
		t.Fatal("two cells sharing a bridge name were accepted")
	}
}

func TestRejectsOverlapWithManagement(t *testing.T) {
	bad := strings.Replace(goodMin, "10.200.0.0/24", "10.200.255.0/25", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a segment overlapping the management subnet was accepted")
	}
}

func TestRejectsMgmtAddressOutsideManagementSubnet(t *testing.T) {
	bad := strings.Replace(goodMin, "10.200.255.10/24", "10.200.0.10/24", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a docker_host.mgmt_address outside management.subnet was accepted")
	}
}

func TestRejectsMissingPluginTag(t *testing.T) {
	bad := strings.Replace(goodMin, "plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2", "plugin_tag: \"\"", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("an empty plugin_tag was accepted")
	}
}

func TestRejectsUnknownField(t *testing.T) {
	bad := strings.Replace(goodMin, "gateway: 10.200.255.1", "gateway: 10.200.255.1\n  typo_field: x", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("an unknown top-level field under management was accepted")
	}
}

// Preservation control: the file this repository actually ships must load.
func TestRealLabYAMLLoads(t *testing.T) {
	if _, err := Load("../../lab.yaml"); err != nil {
		t.Fatalf("the shipped lab.yaml does not validate: %v", err)
	}
}

const withSource = goodMin + `
  - name: kea
    segment:
      bridge: lab-br-kea
      subnet: 10.200.1.0/24
    source:
      type: kea
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.21/24
      seg_address: 10.200.1.2/24
      pool_start: 10.200.1.100
      pool_end: 10.200.1.200
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.20/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2
`

func TestLoadWithSource(t *testing.T) {
	c, err := Load(write(t, withSource))
	if err != nil {
		t.Fatalf("valid source cell rejected: %v", err)
	}
	cell, err := c.CellByName("kea")
	if err != nil {
		t.Fatal(err)
	}
	if cell.Source == nil || cell.Source.Type != "kea" {
		t.Fatal("source block lost in parsing")
	}
}

func TestRejectsUnknownSourceType(t *testing.T) {
	bad := strings.Replace(withSource, "type: kea", "type: bind9", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("an unknown source.type was accepted")
	}
}

// Drive the absence: a source on the management subnet instead of its own
// segment must be refused (issue #2, "never on net-mgmt").
func TestRejectsSourceOnManagementSubnet(t *testing.T) {
	bad := strings.Replace(withSource, "seg_address: 10.200.1.2/24", "seg_address: 10.200.255.99/24", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a source.seg_address on the management subnet was accepted")
	}
}

func TestRejectsSourcePoolOutsideSegment(t *testing.T) {
	bad := strings.Replace(withSource, "pool_end: 10.200.1.200", "pool_end: 10.200.2.200", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a source pool reaching outside its own segment was accepted")
	}
}

func TestRejectsInvertedSourcePool(t *testing.T) {
	bad := strings.Replace(withSource, "pool_start: 10.200.1.100", "pool_start: 10.200.1.250", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a pool_start above pool_end was accepted")
	}
}

func TestRejectsSourceMgmtAddressCollision(t *testing.T) {
	bad := strings.Replace(withSource, "mgmt_address: 10.200.255.21/24", "mgmt_address: 10.200.255.10/24", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a source.mgmt_address reused from another host was accepted")
	}
}

// Preservation: a cell with no source (ref-only's own shape) still loads
// once a sibling cell in the same file does carry one.
func TestSourceCellSitsBesideSourcelessCell(t *testing.T) {
	c, err := Load(write(t, withSource))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := c.CellByName("ref-only")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Source != nil {
		t.Fatal("ref-only cell gained a source it never declared")
	}
}
