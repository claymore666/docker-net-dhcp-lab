package labyaml

import (
	"fmt"
	"net/netip"
)

// VLANID is the 802.1Q id E3b asks the plugin for (lab #15).
const VLANID = 100

// VLANThirdOctetOffset moves a cell segment 10.200.N.0/24 to the VLAN
// subnet 10.200.(N+offset).0/24 (lab #15). scripts/up-source.sh derives
// the same number in shell; vlan_test.go pins the two together.
const VLANThirdOctetOffset = 150

// VLANSubnet returns the VLAN 100 pool subnet for a cell segment subnet.
// It refuses anything that is not a 10.200.N.0/24 or whose result would
// leave 10.200.0.0/16 below 255 (255 is the management range). (#15)
func VLANSubnet(segSubnet string) (string, error) {
	p, err := netip.ParsePrefix(segSubnet)
	if err != nil {
		return "", fmt.Errorf("vlan subnet: %w", err)
	}
	a := p.Addr().As4()
	if p.Bits() != 24 || a[0] != 10 || a[1] != 200 || a[3] != 0 {
		return "", fmt.Errorf("vlan subnet: %s is not a 10.200.N.0/24", segSubnet)
	}
	n := int(a[2]) + VLANThirdOctetOffset
	if n > 254 {
		return "", fmt.Errorf("vlan subnet: %s maps to third octet %d, past 254", segSubnet, n)
	}
	return fmt.Sprintf("10.200.%d.0/24", n), nil
}
