// Package labyaml parses and validates lab.yaml (issue #1). It is the one
// place that knows the file's shape; scripts/up-cell.sh calls `labctl
// resolve` instead of parsing YAML themselves.
package labyaml

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"

	"gopkg.in/yaml.v3"
)

// Every field also carries a json tag, matching the yaml name: `labctl
// resolve` emits JSON and the provisioning shell scripts read it with jq
// against these lowercase, snake_case paths (never the Go field names).
type Management struct {
	LibvirtNetwork string `yaml:"libvirt_network" json:"libvirt_network"`
	Subnet         string `yaml:"subnet" json:"subnet"`
	Gateway        string `yaml:"gateway" json:"gateway"`
}

type Segment struct {
	Bridge string `yaml:"bridge" json:"bridge"`
	Subnet string `yaml:"subnet" json:"subnet"`
}

type DockerHost struct {
	BaseImage   string `yaml:"base_image" json:"base_image"`
	MgmtAddress string `yaml:"mgmt_address" json:"mgmt_address"`
	PluginTag   string `yaml:"plugin_tag" json:"plugin_tag"`
	// PreviousPluginTag is the release A6 upgrades FROM, named explicitly
	// rather than derived by decrementing PluginTag's patch number: the
	// real previous release is not always PluginTag's patch predecessor
	// (e.g. under test v2.3.0-rc1, previous v2.2.3 -- a minor rollback, not
	// a patch one), and deriving it anyway silently tests the wrong pair
	// (issue #3). Optional: a cell that leaves
	// it empty gets A6 as N/A, never a guess.
	PreviousPluginTag string `yaml:"previous_plugin_tag" json:"previous_plugin_tag"`
	VCPUs             int    `yaml:"vcpus" json:"vcpus"`
	MemoryMiB         int    `yaml:"memory_mib" json:"memory_mib"`
	DiskGiB           int    `yaml:"disk_gib" json:"disk_gib"`
}

// Source is one IP source VM: a DHCP server on its cell's own segment,
// never on the management network (issue #2). ReservePoolStart/End are
// the pool this source hands to ordinary clients; the adapter's
// ReserveMAC keeps a separate per-MAC reservation outside that range.
type Source struct {
	Type        string `yaml:"type" json:"type"` // kea | isc-dhcp | dnsmasq
	BaseImage   string `yaml:"base_image" json:"base_image"`
	MgmtAddress string `yaml:"mgmt_address" json:"mgmt_address"`
	SegAddress  string `yaml:"seg_address" json:"seg_address"`
	PoolStart   string `yaml:"pool_start" json:"pool_start"`
	PoolEnd     string `yaml:"pool_end" json:"pool_end"`
	VCPUs       int    `yaml:"vcpus" json:"vcpus"`
	MemoryMiB   int    `yaml:"memory_mib" json:"memory_mib"`
	DiskGiB     int    `yaml:"disk_gib" json:"disk_gib"`
}

var sourceTypes = map[string]bool{"kea": true, "isc-dhcp": true, "dnsmasq": true}

type Cell struct {
	Name        string     `yaml:"name" json:"name"`
	Description string     `yaml:"description" json:"description"`
	Segment     Segment    `yaml:"segment" json:"segment"`
	Source      *Source    `yaml:"source" json:"source"` // null when the cell has no IP source (issue #1)
	DockerHost  DockerHost `yaml:"docker_host" json:"docker_host"`
}

type Config struct {
	Management Management `yaml:"management" json:"management"`
	ULAPrefix  string     `yaml:"ula_prefix" json:"ula_prefix"`
	Cells      []Cell     `yaml:"cells"`
}

// Load reads and validates path. Every error names the field that failed.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate enforces the lab's own safety rule: nothing here may name an
// address outside the lab's declared ranges. It does not check the rest of
// the repo; that is scripts/hygiene-check.sh's job.
func (c *Config) Validate() error {
	if c.Management.LibvirtNetwork == "" {
		return fmt.Errorf("management.libvirt_network is required")
	}
	mgmtPrefix, err := netip.ParsePrefix(c.Management.Subnet)
	if err != nil {
		return fmt.Errorf("management.subnet: %w", err)
	}
	if err := mustBeLabRange(mgmtPrefix); err != nil {
		return fmt.Errorf("management.subnet: %w", err)
	}
	if len(c.Cells) == 0 {
		return fmt.Errorf("at least one cell is required")
	}
	seenBridge := map[string]bool{}
	seenSubnet := map[string]bool{}
	seenMgmt := map[string]bool{}
	for i, cell := range c.Cells {
		if cell.Name == "" {
			return fmt.Errorf("cells[%d]: name is required", i)
		}
		if cell.Segment.Bridge == "" {
			return fmt.Errorf("cell %s: segment.bridge is required", cell.Name)
		}
		if seenBridge[cell.Segment.Bridge] {
			return fmt.Errorf("cell %s: bridge %s reused by another cell", cell.Name, cell.Segment.Bridge)
		}
		seenBridge[cell.Segment.Bridge] = true
		segPrefix, err := netip.ParsePrefix(cell.Segment.Subnet)
		if err != nil {
			return fmt.Errorf("cell %s: segment.subnet: %w", cell.Name, err)
		}
		if err := mustBeLabRange(segPrefix); err != nil {
			return fmt.Errorf("cell %s: segment.subnet: %w", cell.Name, err)
		}
		if seenSubnet[segPrefix.String()] {
			return fmt.Errorf("cell %s: subnet %s reused by another cell", cell.Name, segPrefix)
		}
		seenSubnet[segPrefix.String()] = true
		if overlaps(segPrefix, mgmtPrefix) {
			return fmt.Errorf("cell %s: segment.subnet overlaps the management subnet", cell.Name)
		}
		if cell.DockerHost.BaseImage == "" {
			return fmt.Errorf("cell %s: docker_host.base_image is required", cell.Name)
		}
		if cell.DockerHost.PluginTag == "" {
			return fmt.Errorf("cell %s: docker_host.plugin_tag is required", cell.Name)
		}
		mgmtAddr, err := netip.ParsePrefix(cell.DockerHost.MgmtAddress)
		if err != nil {
			return fmt.Errorf("cell %s: docker_host.mgmt_address: %w", cell.Name, err)
		}
		if !mgmtPrefix.Contains(mgmtAddr.Addr()) {
			return fmt.Errorf("cell %s: docker_host.mgmt_address is not inside management.subnet", cell.Name)
		}
		if seenMgmt[mgmtAddr.Addr().String()] {
			return fmt.Errorf("cell %s: docker_host.mgmt_address %s reused by another host in lab.yaml", cell.Name, mgmtAddr.Addr())
		}
		seenMgmt[mgmtAddr.Addr().String()] = true

		if cell.Source != nil {
			if err := validateSource(cell.Name, cell.Source, mgmtPrefix, segPrefix, seenMgmt); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateSource checks one cell's IP source: it must sit inside the
// cell's own segment (never management.subnet, issue #2), and its pool
// must be a real range inside that same segment.
func validateSource(cellName string, s *Source, mgmtPrefix, segPrefix netip.Prefix, seenMgmt map[string]bool) error {
	if !sourceTypes[s.Type] {
		return fmt.Errorf("cell %s: source.type %q is not one of kea, isc-dhcp, dnsmasq", cellName, s.Type)
	}
	if s.BaseImage == "" {
		return fmt.Errorf("cell %s: source.base_image is required", cellName)
	}
	mgmtAddr, err := netip.ParsePrefix(s.MgmtAddress)
	if err != nil {
		return fmt.Errorf("cell %s: source.mgmt_address: %w", cellName, err)
	}
	if !mgmtPrefix.Contains(mgmtAddr.Addr()) {
		return fmt.Errorf("cell %s: source.mgmt_address is not inside management.subnet", cellName)
	}
	if seenMgmt[mgmtAddr.Addr().String()] {
		return fmt.Errorf("cell %s: source.mgmt_address %s reused by another host in lab.yaml", cellName, mgmtAddr.Addr())
	}
	seenMgmt[mgmtAddr.Addr().String()] = true

	segAddr, err := netip.ParsePrefix(s.SegAddress)
	if err != nil {
		return fmt.Errorf("cell %s: source.seg_address: %w", cellName, err)
	}
	if !segPrefix.Contains(segAddr.Addr()) {
		return fmt.Errorf("cell %s: source.seg_address is not inside segment.subnet", cellName)
	}

	start, err := netip.ParseAddr(s.PoolStart)
	if err != nil {
		return fmt.Errorf("cell %s: source.pool_start: %w", cellName, err)
	}
	end, err := netip.ParseAddr(s.PoolEnd)
	if err != nil {
		return fmt.Errorf("cell %s: source.pool_end: %w", cellName, err)
	}
	if !segPrefix.Contains(start) || !segPrefix.Contains(end) {
		return fmt.Errorf("cell %s: source pool is not inside segment.subnet", cellName)
	}
	if start.Compare(end) >= 0 {
		return fmt.Errorf("cell %s: source.pool_start must be lower than source.pool_end", cellName)
	}
	if start == segAddr.Addr() || end == segAddr.Addr() {
		return fmt.Errorf("cell %s: source pool overlaps the source's own seg_address", cellName)
	}
	return nil
}

// mustBeLabRange refuses any subnet that is not inside 10.200.0.0/16: the
// one range this repository is allowed to publish.
func mustBeLabRange(p netip.Prefix) error {
	lab := netip.MustParsePrefix("10.200.0.0/16")
	if !p.Addr().Is4() {
		return fmt.Errorf("%s is not IPv4", p)
	}
	// Checks the prefix's own network address against the lab range. A
	// prefix wider than the lab's /16 (e.g. a /8) still gets refused: its
	// caller also runs overlaps() against sibling subnets, and a /8
	// containing 10.200.0.0/16 fails that check instead.
	if !lab.Contains(p.Addr()) {
		return fmt.Errorf("%s is outside the lab's published range 10.200.0.0/16", p)
	}
	return nil
}

func overlaps(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

// CellByName finds a cell or returns an error naming what was searched.
func (c *Config) CellByName(name string) (*Cell, error) {
	for i := range c.Cells {
		if c.Cells[i].Name == name {
			return &c.Cells[i], nil
		}
	}
	return nil, fmt.Errorf("no cell named %q in lab.yaml", name)
}
