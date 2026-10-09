package labyaml

import (
	"encoding/json"
	"strings"
	"testing"
)

const withPair = goodMin + `
  - name: kea-ha
    segment:
      bridge: lab-br-kea-ha
      subnet: 10.200.8.0/24
    source:
      type: kea
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.91/24
      seg_address: 10.200.8.2/24
      pool_start: 10.200.8.100
      pool_end: 10.200.8.200
      partner:
        mgmt_address: 10.200.255.92/24
        seg_address: 10.200.8.3/24
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.90/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.2.2
`

func TestLoadWithPartner(t *testing.T) {
	c, err := Load(write(t, withPair))
	if err != nil {
		t.Fatalf("valid failover pair rejected: %v", err)
	}
	cell, err := c.CellByName("kea-ha")
	if err != nil {
		t.Fatal(err)
	}
	p := cell.Source.Partner
	if p == nil || p.MgmtAddress != "10.200.255.92/24" || p.SegAddress != "10.200.8.3/24" {
		t.Fatalf("partner lost in parsing: %+v", p)
	}
}

// One case per partner rule (lab #12, defeat 11): each mutation of the
// valid pair must fail with its own rule's message, never another's.
func TestPartnerRules(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"type dnsmasq", "type: kea", "type: dnsmasq", "needs source.type kea or isc-dhcp"},
		{"mgmt unparsable", "mgmt_address: 10.200.255.92/24", "mgmt_address: nope", "source.partner.mgmt_address:"},
		{"mgmt outside management", "mgmt_address: 10.200.255.92/24", "mgmt_address: 10.200.254.92/24", "partner.mgmt_address is not inside management.subnet"},
		{"mgmt equals primary", "mgmt_address: 10.200.255.92/24", "mgmt_address: 10.200.255.91/24", "partner.mgmt_address 10.200.255.91 reused"},
		{"mgmt equals docker host", "mgmt_address: 10.200.255.92/24", "mgmt_address: 10.200.255.10/24", "partner.mgmt_address 10.200.255.10 reused"},
		{"seg unparsable", "seg_address: 10.200.8.3/24", "seg_address: nope", "source.partner.seg_address:"},
		{"seg outside segment", "seg_address: 10.200.8.3/24", "seg_address: 10.200.9.3/24", "partner.seg_address is not inside segment.subnet"},
		{"seg equals primary", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.2/24", "equals source.seg_address"},
		{"seg at pool start", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.100/24", "inside the source pool"},
		{"seg inside pool", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.150/24", "inside the source pool"},
		{"seg at pool end", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.200/24", "inside the source pool"},
		{"seg at band start", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.211/24", "group B host band"},
		{"seg at band end", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.230/24", "group B host band"},
		{"seg at dns host", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.253/24", "group B host band"},
		{"seg at narrowed pool", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.201/24", "above the source pool"},
		{"seg at group F pool", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.205/24", "above the source pool"},
		{"seg at squat target", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.231/24", "above the source pool"},
		{"seg at rogue server", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.240/24", "above the source pool"},
		{"seg at last host", "seg_address: 10.200.8.3/24", "seg_address: 10.200.8.254/24", "above the source pool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(withPair, tc.from) {
				t.Fatalf("fixture lost %q", tc.from)
			}
			bad := withPair
			if strings.HasPrefix(tc.from, "type:") {
				bad = strings.Replace(withPair, "type: kea", tc.to, 1)
			} else {
				i := strings.Index(withPair, "partner:")
				bad = withPair[:i] + strings.Replace(withPair[i:], tc.from, tc.to, 1)
			}
			_, err := Load(write(t, bad))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// Below the pool stays legal up to its edge; .201 up is refused above.
func TestPartnerBandEdgesAccepted(t *testing.T) {
	i := strings.Index(withPair, "partner:")
	for _, host := range []string{"1", "4", "99"} {
		ok := withPair[:i] + strings.Replace(withPair[i:], "seg_address: 10.200.8.3/24", "seg_address: 10.200.8."+host+"/24", 1)
		if _, err := Load(write(t, ok)); err != nil {
			t.Fatalf(".%s rejected: %v", host, err)
		}
	}
}

func TestPartnerOmittedFromJSONWhenUnset(t *testing.T) {
	c, err := Load(write(t, withSource))
	if err != nil {
		t.Fatal(err)
	}
	cell, _ := c.CellByName("kea")
	b, err := json.Marshal(cell.Source)
	if err != nil {
		t.Fatal(err)
	}
	if cell.Source.Partner != nil || strings.Contains(string(b), "partner") {
		t.Fatalf("a source with no partner block grew one: %s", b)
	}
}
