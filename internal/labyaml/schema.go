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

// maxIfnameLen is IFNAMSIZ-1: the kernel's Linux network interface name
// limit (16 bytes including a terminating NUL).
const maxIfnameLen = 15

// Every field also carries a json tag, matching the yaml name: `labctl
// resolve` emits JSON and the provisioning shell scripts read it with jq
// against these lowercase, snake_case paths (never the Go field names).
type Management struct {
	LibvirtNetwork string `yaml:"libvirt_network" json:"libvirt_network"`
	Subnet         string `yaml:"subnet" json:"subnet"`
	Gateway        string `yaml:"gateway" json:"gateway"`
}

// Subnet6 is the cell's IPv6 /64 inside ula_prefix; a cell without it has
// no IPv6 segment (#23 group D).
type Segment struct {
	Bridge  string `yaml:"bridge" json:"bridge"`
	Subnet  string `yaml:"subnet" json:"subnet"`
	Subnet6 string `yaml:"subnet6,omitempty" json:"subnet6,omitempty"`
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
	// EngineVersion optionally pins docker-ce to one version, e.g.
	// "5:20.10.24~3-0~debian-bullseye" (apt's own version string) for the
	// plugin's oldest supported engine (issue #8). Empty installs
	// whatever the base image's distro/suite repo currently serves.
	EngineVersion string `yaml:"engine_version" json:"engine_version"`
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
	// The IPv6 side, required exactly when the cell has segment.subnet6:
	// eth1's static address, the DHCPv6 IA_NA range, and the prefix the
	// isc-dhcp template serves IA_TA from (#23 group D).
	SegAddress6 string `yaml:"seg_address6,omitempty" json:"seg_address6,omitempty"`
	Pool6Start  string `yaml:"pool6_start,omitempty" json:"pool6_start,omitempty"`
	Pool6End    string `yaml:"pool6_end,omitempty" json:"pool6_end,omitempty"`
	Temp6Pool   string `yaml:"temp6_pool,omitempty" json:"temp6_pool,omitempty"`
	VCPUs       int    `yaml:"vcpus" json:"vcpus"`
	MemoryMiB   int    `yaml:"memory_mib" json:"memory_mib"`
	DiskGiB     int    `yaml:"disk_gib" json:"disk_gib"`
	// Partner, when set, makes the source a failover pair (lab #12).
	Partner *Peer `yaml:"partner" json:"partner,omitempty"`
}

// Peer is the second server of a failover pair: same type, image and
// pool as its primary, its own management and segment address.
type Peer struct {
	MgmtAddress string `yaml:"mgmt_address" json:"mgmt_address"`
	SegAddress  string `yaml:"seg_address" json:"seg_address"`
}

// pairTypes are the source types with a failover mode (lab #12).
var pairTypes = map[string]bool{"kea": true, "isc-dhcp": true}

// Host octets the group B scenarios (#23) hand out on every segment: the
// per-MAC reservations from 211, the class pool up to 230, the DNS option
// value at 253. internal/scenario pins them to its own constants.
const (
	GroupBBandFirstHost = 211
	GroupBBandLastHost  = 230
	DNSOptionHost       = 253
)

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
	var ula netip.Prefix
	if c.ULAPrefix != "" {
		if ula, err = parseULA(c.ULAPrefix); err != nil {
			return fmt.Errorf("ula_prefix: %w", err)
		}
	}
	var seen6 []netip.Prefix
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
		// IFNAMSIZ is 16 bytes including the terminating NUL, so the
		// kernel accepts at most 15 characters; virsh's own rejection of
		// a longer name ("not a valid ifname") only surfaces once
		// up-cell.sh is already mid-bring-up (issue #8, measured live).
		if len(cell.Segment.Bridge) > maxIfnameLen {
			return fmt.Errorf("cell %s: segment.bridge %q is %d characters, longer than the kernel's %d-character interface name limit", cell.Name, cell.Segment.Bridge, len(cell.Segment.Bridge), maxIfnameLen)
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
		var seg6 netip.Prefix
		if cell.Segment.Subnet6 != "" {
			if !ula.IsValid() {
				return fmt.Errorf("cell %s: segment.subnet6 needs ula_prefix", cell.Name)
			}
			if seg6, err = netip.ParsePrefix(cell.Segment.Subnet6); err != nil {
				return fmt.Errorf("cell %s: segment.subnet6: %w", cell.Name, err)
			}
			if err := mustBeLabRange6(seg6, ula); err != nil {
				return fmt.Errorf("cell %s: segment.subnet6: %w", cell.Name, err)
			}
			for _, o := range seen6 {
				if overlaps(seg6, o) {
					return fmt.Errorf("cell %s: segment.subnet6 %s overlaps %s of another cell", cell.Name, seg6, o)
				}
			}
			seen6 = append(seen6, seg6)
		}
		if cell.DockerHost.BaseImage == "" {
			return fmt.Errorf("cell %s: docker_host.base_image is required", cell.Name)
		}
		if _, err := LookupBaseImage(cell.DockerHost.BaseImage); err != nil {
			return fmt.Errorf("cell %s: docker_host.base_image: %w", cell.Name, err)
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
			if err := validateSource6(cell.Name, cell.Source, seg6); err != nil {
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
	if _, err := LookupBaseImage(s.BaseImage); err != nil {
		return fmt.Errorf("cell %s: source.base_image: %w", cellName, err)
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
	if s.Partner != nil {
		return validatePartner(cellName, s, segAddr.Addr(), start, end, mgmtPrefix, segPrefix, seenMgmt)
	}
	return nil
}

// validatePartner checks a failover pair's second server: an address of
// its own on the segment that no client lease can ever take.
func validatePartner(cellName string, s *Source, primarySeg, start, end netip.Addr, mgmtPrefix, segPrefix netip.Prefix, seenMgmt map[string]bool) error {
	p := s.Partner
	if !pairTypes[s.Type] {
		return fmt.Errorf("cell %s: source.partner needs source.type kea or isc-dhcp, not %q", cellName, s.Type)
	}
	mgmtAddr, err := netip.ParsePrefix(p.MgmtAddress)
	if err != nil {
		return fmt.Errorf("cell %s: source.partner.mgmt_address: %w", cellName, err)
	}
	if !mgmtPrefix.Contains(mgmtAddr.Addr()) {
		return fmt.Errorf("cell %s: source.partner.mgmt_address is not inside management.subnet", cellName)
	}
	if seenMgmt[mgmtAddr.Addr().String()] {
		return fmt.Errorf("cell %s: source.partner.mgmt_address %s reused by another host in lab.yaml", cellName, mgmtAddr.Addr())
	}
	seenMgmt[mgmtAddr.Addr().String()] = true
	segAddr, err := netip.ParsePrefix(p.SegAddress)
	if err != nil {
		return fmt.Errorf("cell %s: source.partner.seg_address: %w", cellName, err)
	}
	a := segAddr.Addr()
	if !segPrefix.Contains(a) {
		return fmt.Errorf("cell %s: source.partner.seg_address is not inside segment.subnet", cellName)
	}
	if a == primarySeg {
		return fmt.Errorf("cell %s: source.partner.seg_address equals source.seg_address", cellName)
	}
	if a.Compare(start) >= 0 && a.Compare(end) <= 0 {
		return fmt.Errorf("cell %s: source.partner.seg_address %s is inside the source pool", cellName, a)
	}
	host := int(a.As4()[3])
	if (host >= GroupBBandFirstHost && host <= GroupBBandLastHost) || host == DNSOptionHost {
		return fmt.Errorf("cell %s: source.partner.seg_address %s is in the group B host band (.%d-.%d, .%d)",
			cellName, a, GroupBBandFirstHost, GroupBBandLastHost, DNSOptionHost)
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

// validateSource6 checks the source's IPv6 fields against the cell's
// segment.subnet6 (invalid when the cell has none, and then every v6 field
// must be empty).
func validateSource6(cellName string, s *Source, seg6 netip.Prefix) error {
	fields := []struct{ name, v string }{
		{"seg_address6", s.SegAddress6}, {"pool6_start", s.Pool6Start},
		{"pool6_end", s.Pool6End}, {"temp6_pool", s.Temp6Pool},
	}
	for _, f := range fields {
		if !seg6.IsValid() && f.v != "" {
			return fmt.Errorf("cell %s: source.%s set on a cell with no segment.subnet6", cellName, f.name)
		}
		if seg6.IsValid() && f.v == "" {
			return fmt.Errorf("cell %s: source.%s is required with segment.subnet6", cellName, f.name)
		}
	}
	if !seg6.IsValid() {
		return nil
	}
	segAddr, err := netip.ParsePrefix(s.SegAddress6)
	if err != nil {
		return fmt.Errorf("cell %s: source.seg_address6: %w", cellName, err)
	}
	if segAddr.Bits() != seg6.Bits() || !seg6.Contains(segAddr.Addr()) {
		return fmt.Errorf("cell %s: source.seg_address6 is not an address of segment.subnet6 with its prefix length", cellName)
	}
	start, err := netip.ParseAddr(s.Pool6Start)
	if err != nil {
		return fmt.Errorf("cell %s: source.pool6_start: %w", cellName, err)
	}
	end, err := netip.ParseAddr(s.Pool6End)
	if err != nil {
		return fmt.Errorf("cell %s: source.pool6_end: %w", cellName, err)
	}
	if !seg6.Contains(start) || !seg6.Contains(end) {
		return fmt.Errorf("cell %s: source IPv6 pool is not inside segment.subnet6", cellName)
	}
	if start.Compare(end) >= 0 {
		return fmt.Errorf("cell %s: source.pool6_start must be lower than source.pool6_end", cellName)
	}
	own := segAddr.Addr()
	if start.Compare(own) <= 0 && own.Compare(end) <= 0 {
		return fmt.Errorf("cell %s: source IPv6 pool contains the source's own seg_address6", cellName)
	}
	temp, err := netip.ParsePrefix(s.Temp6Pool)
	if err != nil {
		return fmt.Errorf("cell %s: source.temp6_pool: %w", cellName, err)
	}
	if temp != temp.Masked() || temp.Bits() <= seg6.Bits() || !seg6.Contains(temp.Addr()) {
		return fmt.Errorf("cell %s: source.temp6_pool is not a network prefix inside segment.subnet6", cellName)
	}
	last := lastAddr(temp)
	if temp.Contains(own) || !(end.Less(temp.Addr()) || last.Less(start)) {
		return fmt.Errorf("cell %s: source.temp6_pool overlaps the IPv6 pool or seg_address6", cellName)
	}
	return nil
}

// parseULA accepts a prefix inside fd00::/8, the locally assigned half of
// the unique local range (RFC 4193 section 3.1).
func parseULA(v string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(v)
	if err != nil {
		return p, err
	}
	local := netip.MustParsePrefix("fd00::/8")
	if !p.Addr().Is6() || p.Addr().Is4In6() || p != p.Masked() || p.Bits() < local.Bits() || !local.Contains(p.Addr()) {
		return p, fmt.Errorf("%s is not a network prefix inside fd00::/8", v)
	}
	return p, nil
}

// mustBeLabRange6 refuses any IPv6 subnet that is not a network prefix
// inside the lab's ula_prefix.
func mustBeLabRange6(p, ula netip.Prefix) error {
	if !p.Addr().Is6() || p.Addr().Is4In6() {
		return fmt.Errorf("%s is not IPv6", p)
	}
	if p != p.Masked() {
		return fmt.Errorf("%s has host bits set", p)
	}
	if p.Bits() < ula.Bits() || !ula.Contains(p.Addr()) {
		return fmt.Errorf("%s is outside the lab's ula_prefix %s", p, ula)
	}
	return nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom16(b)
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
