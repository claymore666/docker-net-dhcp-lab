package scenario

import (
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
)

// labyaml refuses a relay client address on any host octet group B or F
// claims (#11); it cannot import this package, so this keeps both lists
// equal: every octet here must be refused there, and nothing else in
// 1..254 outside these bands may be.
func TestRelayReservedHostsMatchGroupB(t *testing.T) {
	want := map[int]bool{dnsOptionHost: true}
	for h := userClassFirstHost; h <= userClassLastHost; h++ {
		want[h] = true
	}
	for h := classPoolFirstHost; h <= classPoolLastHost; h++ {
		want[h] = true
	}
	for i := range Shapes {
		want[reserveBaseHost+i] = true
		want[reserveBaseHost+len(Shapes)+i] = true
	}
	for h := 1; h <= 254; h++ {
		if got := labyaml.ReservedGroupHost(h); got != want[h] {
			t.Errorf("host octet %d: labyaml.ReservedGroupHost = %v, group B/F claims it: %v", h, got, want[h])
		}
	}
}
