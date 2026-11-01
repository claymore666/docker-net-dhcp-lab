package sourceadapter

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func capIn(cs []Capability, c Capability) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}

// Which sources can carry the VLAN 100 pool is declared, and every one
// that cannot says why (lab #15 E3b): a source that silently lacks it
// would read as an E3b FAIL instead of N/A.
func TestVLANPoolIsDeclaredOrExplained(t *testing.T) {
	carries := map[string]Adapter{"kea": &KeaAdapter{}, "isc-dhcp": &ISCDHCPAdapter{}, "dnsmasq": &DnsmasqAdapter{}}
	for name, a := range carries {
		if !capIn(a.Capabilities(), CapVLANPool) {
			t.Errorf("%s does not declare %s", name, CapVLANPool)
		}
	}
	without := map[string]Adapter{"udhcpd": &UdhcpdAdapter{}, "pihole": &PiholeAdapter{}, "openwrt": &OpenwrtAdapter{}, "routeros": &RouterOSAdapter{}, "fritzbox": &FritzboxAdapter{}, "windows": &WindowsAdapter{}}
	for name, a := range without {
		if capIn(a.Capabilities(), CapVLANPool) {
			t.Errorf("%s declares %s, but it has no template that carries a VLAN pool", name, CapVLANPool)
		}
		x, ok := a.(NAExplainer)
		if name == "fritzbox" {
			continue // the router: no capabilities, the generic reason covers it
		}
		if !ok {
			t.Errorf("%s cannot explain its missing capabilities", name)
			continue
		}
		if why, ok := x.NAReason(CapVLANPool); !ok || !strings.Contains(why, "VLAN 100 pool") {
			t.Errorf("%s: reason for %s is %q %v", name, CapVLANPool, why, ok)
		}
	}
}

// A failover or HA pair has two sources serving the VLAN pool with no
// peering for it, so the pair withholds it with a reason (lab #15 E3b).
func TestPairWithholdsTheVLANPool(t *testing.T) {
	fp := newFakePair()
	fp.a.caps = append(append([]Capability{}, fp.a.caps...), CapVLANPool)
	fp.b.caps = append(append([]Capability{}, fp.b.caps...), CapVLANPool)
	if capIn(fp.pair.Capabilities(), CapVLANPool) {
		t.Fatal("the pair declares the VLAN pool")
	}
	if why, ok := fp.pair.NAReason(CapVLANPool); !ok || !strings.Contains(why, "eth1.100") {
		t.Fatalf("pair reason %q %v", why, ok)
	}
}

// The two failover peers must not both take the same address on eth1.100;
// the rendered seeds say which (lab #15 E3b).
func TestFailoverPeersGetDifferentVLANAddresses(t *testing.T) {
	re := regexp.MustCompile(`addresses: \[(10\.200\.\d+\.\d+)/24\]\s*\n\s*NETEOF`)
	var got []string
	for _, peer := range []string{"primary", "partner"} {
		b, err := os.ReadFile("../../scripts/testdata/up-source-golden/isc-failover-" + peer + ".golden")
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no eth1.100 address in the rendered seed", peer)
		}
		got = append(got, string(m[1]))
	}
	if got[0] == got[1] {
		t.Errorf("both peers take %s on eth1.100", got[0])
	}
}
