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

func TestRejectsUnregisteredDockerHostBaseImage(t *testing.T) {
	bad := strings.Replace(goodMin, "base_image: debian-13-generic-amd64", "base_image: not-a-registered-image", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("an unregistered docker_host.base_image was accepted")
	}
}

func TestRejectsUnregisteredSourceBaseImage(t *testing.T) {
	bad := strings.Replace(withSource, "base_image: debian-13-generic-amd64\n      mgmt_address: 10.200.255.21/24", "base_image: not-a-registered-image\n      mgmt_address: 10.200.255.21/24", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("an unregistered source.base_image was accepted")
	}
}

// A bridge name over IFNAMSIZ-1 (15 characters) is accepted by the YAML
// parser but rejected by the kernel only once up-cell.sh is already
// mid-bring-up (issue #8, measured live: virsh's own "not a valid
// ifname"). Validate must catch it first.
func TestRejectsBridgeNameLongerThanIfnameLimit(t *testing.T) {
	bad := strings.Replace(goodMin, "bridge: lab-br-ref-only", "bridge: lab-br-a-name-that-is-too-long", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a 39-character bridge name was accepted")
	}
}

// lab-seg-firewall.sh forwards bridged traffic only on lab-br+ (#11): a
// bridge outside that prefix would bring up a cell whose DHCP is dropped.
func TestRejectsBridgeOutsideTheFirewallPrefix(t *testing.T) {
	bad := strings.Replace(goodMin, "bridge: lab-br-ref-only", "bridge: br-ref-only", 1)
	if _, err := Load(write(t, bad)); err == nil || !strings.Contains(err.Error(), "does not start with lab-br-") {
		t.Fatalf("a bridge outside lab-br- was accepted: %v", err)
	}
}

// One character over the limit is the boundary the kernel actually
// draws (IFNAMSIZ-1 = 15): the 39-character case above only proves
// "too long" is caught, not that the limit itself is 15 and not 16.
func TestRejectsBridgeNameAtSixteenCharacters(t *testing.T) {
	sixteen := "lab-br-ref-onlyx"
	if len(sixteen) != 16 {
		t.Fatalf("test fixture drifted: %q is %d characters, not 16", sixteen, len(sixteen))
	}
	bad := strings.Replace(goodMin, "bridge: lab-br-ref-only", "bridge: "+sixteen, 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("a 16-character bridge name was accepted")
	}
}

func TestAcceptsBridgeNameAtIfnameLimit(t *testing.T) {
	fifteen := "lab-br-ref-only" // exactly 15 characters, the existing convention
	if len(fifteen) != 15 {
		t.Fatalf("test fixture drifted: %q is %d characters, not 15", fifteen, len(fifteen))
	}
	if _, err := Load(write(t, goodMin)); err != nil {
		t.Fatalf("a 15-character bridge name was rejected: %v", err)
	}
}

// engine_version is optional (issue #8): a cell that never sets it must
// still load, same as before this field existed.
func TestEngineVersionOptional(t *testing.T) {
	c, err := Load(write(t, goodMin))
	if err != nil {
		t.Fatal(err)
	}
	cell, err := c.CellByName("ref-only")
	if err != nil {
		t.Fatal(err)
	}
	if cell.DockerHost.EngineVersion != "" {
		t.Fatalf("engine_version = %q, want empty when never set", cell.DockerHost.EngineVersion)
	}
}

func TestEngineVersionParses(t *testing.T) {
	pinned := strings.Replace(goodMin,
		"plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2",
		"plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2\n      engine_version: 5:20.10.24~3-0~debian-bullseye",
		1)
	c, err := Load(write(t, pinned))
	if err != nil {
		t.Fatalf("valid engine_version rejected: %v", err)
	}
	cell, err := c.CellByName("ref-only")
	if err != nil {
		t.Fatal(err)
	}
	if cell.DockerHost.EngineVersion != "5:20.10.24~3-0~debian-bullseye" {
		t.Fatalf("engine_version = %q, want the pinned value", cell.DockerHost.EngineVersion)
	}
}

const withSource6 = `
management:
  libvirt_network: net-mgmt
  subnet: 10.200.255.0/24
  gateway: 10.200.255.1
ula_prefix: "fd42:200::/48"
cells:
  - name: kea
    segment:
      bridge: lab-br-kea
      subnet: 10.200.1.0/24
      subnet6: "fd42:200:0:100::/64"
    source:
      type: kea
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.21/24
      seg_address: 10.200.1.2/24
      pool_start: 10.200.1.100
      pool_end: 10.200.1.200
      seg_address6: "fd42:200:0:100::2/64"
      pool6_start: "fd42:200:0:100::100"
      pool6_end: "fd42:200:0:100::1ff"
      temp6_pool: "fd42:200:0:100::200/120"
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.20/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2
  - name: isc-dhcp
    segment:
      bridge: lab-br-isc-dhcp
      subnet: 10.200.2.0/24
      subnet6: "fd42:200:0:200::/64"
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.30/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2
`

func TestLoadWithSource6(t *testing.T) {
	c, err := Load(write(t, withSource6))
	if err != nil {
		t.Fatalf("valid v6 cell rejected: %v", err)
	}
	cell, _ := c.CellByName("kea")
	if cell.Segment.Subnet6 != "fd42:200:0:100::/64" || cell.Source.Temp6Pool == "" {
		t.Fatal("v6 fields lost in parsing")
	}
}

// Defeat 17 (#23 group D): every v6 value outside the lab's /48, a v4 value
// in a v6 field, an overlap and a missing field are refused.
func TestRejectsBadV6Values(t *testing.T) {
	cases := []struct{ name, from, to string }{
		{"v4 value in subnet6", `subnet6: "fd42:200:0:100::/64"`, `subnet6: "10.200.9.0/24"`},
		{"global prefix", `subnet6: "fd42:200:0:100::/64"`, `subnet6: "2001:db8:0:100::/64"`},
		{"other /48", `subnet6: "fd42:200:0:100::/64"`, `subnet6: "fd42:201:0:100::/64"`},
		{"overlap across cells", `subnet6: "fd42:200:0:200::/64"`, `subnet6: "fd42:200:0:100::/64"`},
		{"wider prefix covering a sibling", `subnet6: "fd42:200:0:200::/64"`, `subnet6: "fd42:200:0:100::/56"`},
		{"host bits set", `subnet6: "fd42:200:0:200::/64"`, `subnet6: "fd42:200:0:200::1/64"`},
		{"ula outside fd00::/8", `ula_prefix: "fd42:200::/48"`, `ula_prefix: "fc00:200::/48"`},
		{"ula global", `ula_prefix: "fd42:200::/48"`, `ula_prefix: "2001:db8::/48"`},
		{"ula missing", `ula_prefix: "fd42:200::/48"`, ``},
		{"seg_address6 missing", `seg_address6: "fd42:200:0:100::2/64"`, ``},
		{"pool6_end missing", `pool6_end: "fd42:200:0:100::1ff"`, ``},
		{"temp6_pool missing", `temp6_pool: "fd42:200:0:100::200/120"`, ``},
		{"seg_address6 outside subnet6", `seg_address6: "fd42:200:0:100::2/64"`, `seg_address6: "fd42:200:0:200::2/64"`},
		{"seg_address6 wrong length", `seg_address6: "fd42:200:0:100::2/64"`, `seg_address6: "fd42:200:0:100::2/128"`},
		{"pool6 outside subnet6", `pool6_end: "fd42:200:0:100::1ff"`, `pool6_end: "fd42:200:0:101::1ff"`},
		{"pool6 inverted", `pool6_start: "fd42:200:0:100::100"`, `pool6_start: "fd42:200:0:100::1ff0"`},
		{"pool6 holds seg_address6", `pool6_start: "fd42:200:0:100::100"`, `pool6_start: "fd42:200:0:100::1"`},
		{"temp6_pool overlaps pool6", `temp6_pool: "fd42:200:0:100::200/120"`, `temp6_pool: "fd42:200:0:100::100/120"`},
		{"temp6_pool outside subnet6", `temp6_pool: "fd42:200:0:100::200/120"`, `temp6_pool: "fd42:200:0:101::200/120"`},
		{"temp6_pool host bits", `temp6_pool: "fd42:200:0:100::200/120"`, `temp6_pool: "fd42:200:0:100::201/120"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(withSource6, tc.from) {
				t.Fatalf("fixture lacks %q", tc.from)
			}
			bad := strings.Replace(withSource6, tc.from, tc.to, 1)
			if _, err := Load(write(t, bad)); err == nil {
				t.Fatalf("accepted: %s", tc.name)
			}
		})
	}
}

const withRelay = goodMin + `
  - name: kea-relay
    segment:
      bridge: lab-br-kea-rly
      subnet: 10.200.10.0/24
    relay:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.112/24
      client_address: 10.200.10.1/24
      server_address: 10.200.11.1/24
      server_segment:
        bridge: lab-br-kea-rsv
        subnet: 10.200.11.0/24
      agent_options: true
      vcpus: 1
      memory_mib: 1024
      disk_gib: 6
    source:
      type: kea
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.111/24
      seg_address: 10.200.11.2/24
      pool_start: 10.200.10.100
      pool_end: 10.200.10.200
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.110/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2
`

func TestLoadWithRelay(t *testing.T) {
	c, err := Load(write(t, withRelay))
	if err != nil {
		t.Fatalf("valid relay cell rejected: %v", err)
	}
	cell, err := c.CellByName("kea-relay")
	if err != nil {
		t.Fatal(err)
	}
	if cell.Relay == nil || cell.Relay.ServerSegment.Bridge != "lab-br-kea-rsv" || !cell.Relay.AgentOptions {
		t.Fatalf("relay block lost in parsing: %+v", cell.Relay)
	}
	ref, _ := c.CellByName("ref-only")
	if ref.Relay != nil {
		t.Fatal("a cell without a relay block parsed with one")
	}
}

// One row per validator rule (defeat 9 of the relay design, #11): each
// edit breaks exactly one rule of an otherwise valid relay file.
func TestRelayValidatorRules(t *testing.T) {
	cases := []struct {
		name, old, new, want string
	}{
		{"relay without a source", "    source:\n      type: kea\n      base_image: debian-13-generic-amd64\n      mgmt_address: 10.200.255.111/24\n      seg_address: 10.200.11.2/24\n      pool_start: 10.200.10.100\n      pool_end: 10.200.10.200\n", "", "needs a source"},
		{"non-kea source", "      type: kea\n      base_image: debian-13-generic-amd64\n      mgmt_address: 10.200.255.111", "      type: dnsmasq\n      base_image: debian-13-generic-amd64\n      mgmt_address: 10.200.255.111", "only built for a kea source"},
		{"missing base image", "    relay:\n      base_image: debian-13-generic-amd64\n", "    relay:\n", "relay.base_image is required"},
		{"unregistered base image", "    relay:\n      base_image: debian-13-generic-amd64\n", "    relay:\n      base_image: no-such-image\n", "relay.base_image:"},
		{"missing server bridge", "        bridge: lab-br-kea-rsv\n", "", "server_segment.bridge is required"},
		{"server bridge over 15", "lab-br-kea-rsv", "lab-br-kea-rsv-xx", "interface name limit"},
		{"server bridge equals client bridge", "lab-br-kea-rsv", "lab-br-kea-rly", "reused by another segment"},
		{"server bridge outside lab-br-", "lab-br-kea-rsv", "br-kea-rsv", "server_segment.bridge \"br-kea-rsv\" does not start with lab-br-"},
		{"server bridge equals another cell's", "lab-br-kea-rsv", "lab-br-ref-only", "reused by another segment"},
		{"server subnet outside lab range", "        subnet: 10.200.11.0/24", "        subnet: 10.55.11.0/24", "outside the lab's published range"},
		{"server subnet overlaps management", "        subnet: 10.200.11.0/24", "        subnet: 10.200.254.0/23", "overlaps the management subnet"},
		{"server subnet overlaps client segment", "        subnet: 10.200.11.0/24", "        subnet: 10.200.10.0/23", "overlaps segment subnet 10.200.10.0/24"},
		{"server subnet overlaps another cell", "        subnet: 10.200.11.0/24", "        subnet: 10.200.0.128/25", "overlaps segment subnet 10.200.0.0/24"},
		{"mgmt address outside management", "mgmt_address: 10.200.255.112/24", "mgmt_address: 10.200.12.112/24", "relay.mgmt_address is not inside"},
		{"mgmt address reused", "mgmt_address: 10.200.255.112/24", "mgmt_address: 10.200.255.10/24", "relay.mgmt_address 10.200.255.10 reused"},
		{"client address outside client segment", "client_address: 10.200.10.1/24", "client_address: 10.200.11.9/24", "client_address: 10.200.11.9 is not inside"},
		{"client address in pool", "client_address: 10.200.10.1/24", "client_address: 10.200.10.150/24", "inside the source pool"},
		{"client address at the DNS option octet", "client_address: 10.200.10.1/24", "client_address: 10.200.10.253/24", "group B or F reserves"},
		{"client address at the user-class octet", "client_address: 10.200.10.1/24", "client_address: 10.200.10.203/24", "group B or F reserves"},
		{"client address prefix length", "client_address: 10.200.10.1/24", "client_address: 10.200.10.1/25", "prefix length /25"},
		{"client address is the network address", "client_address: 10.200.10.1/24", "client_address: 10.200.10.0/24", "client_address: 10.200.10.0 is the network or broadcast address of 10.200.10.0/24"},
		{"server address is the broadcast address", "server_address: 10.200.11.1/24", "server_address: 10.200.11.255/24", "server_address: 10.200.11.255 is the network or broadcast address of 10.200.11.0/24"},
		{"server address outside server segment", "server_address: 10.200.11.1/24", "server_address: 10.200.10.2/24", "server_address: 10.200.10.2 is not inside"},
		{"server address equals source seg_address", "server_address: 10.200.11.1/24", "server_address: 10.200.11.2/24", "is also source.seg_address"},
		{"seg_address on the client segment", "seg_address: 10.200.11.2/24", "seg_address: 10.200.10.2/24", "source.seg_address is not inside relay.server_segment.subnet"},
		{"pool on the server segment", "pool_start: 10.200.10.100\n      pool_end: 10.200.10.200", "pool_start: 10.200.11.100\n      pool_end: 10.200.11.200", "source pool is not inside segment.subnet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(withRelay, tc.old) {
				t.Fatalf("fixture lacks %q", tc.old)
			}
			_, err := Load(write(t, strings.Replace(withRelay, tc.old, tc.new, 1)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// A source with v6 fields on a cell without segment.subnet6 is refused,
// and a cell without any v6 field still loads (goodMin, withSource).
func TestRejectsV6SourceFieldsWithoutSubnet6(t *testing.T) {
	bad := strings.Replace(withSource6, "      subnet6: \"fd42:200:0:100::/64\"\n", "", 1)
	if _, err := Load(write(t, bad)); err == nil {
		t.Fatal("seg_address6 accepted on a cell with no subnet6")
	}
}

// Every source cell this repository ships carries the IPv6 segment that
// declares sourceadapter.CapV6 for it (#23 group D).
func TestRealLabYAMLSourcesHaveV6(t *testing.T) {
	c, err := Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, cell := range c.Cells {
		if cell.Segment.Subnet6 == "" {
			t.Errorf("cell %s has no segment.subnet6", cell.Name)
		}
	}
}

// The exact-match subnet check let a wider prefix swallow a sibling cell's
// /24 (#11); a duplicate subnet must stay refused too.
func TestRejectsOverlappingCellSubnets(t *testing.T) {
	cases := []struct{ subnet, seg, start, end string }{
		{"10.200.0.0/24", "10.200.0.2/24", "10.200.0.100", "10.200.0.200"},
		{"10.200.0.0/23", "10.200.0.2/23", "10.200.0.100", "10.200.0.200"},
		{"10.200.0.64/26", "10.200.0.66/26", "10.200.0.70", "10.200.0.80"},
	}
	for _, tc := range cases {
		r := strings.NewReplacer("      subnet: 10.200.1.0/24", "      subnet: "+tc.subnet,
			"10.200.1.2/24", tc.seg, "10.200.1.100", tc.start, "10.200.1.200", tc.end)
		_, err := Load(write(t, r.Replace(withSource)))
		if err == nil || !strings.Contains(err.Error(), "overlaps segment subnet 10.200.0.0/24") {
			t.Fatalf("%s beside 10.200.0.0/24: want an overlap error, got %v", tc.subnet, err)
		}
	}
}
