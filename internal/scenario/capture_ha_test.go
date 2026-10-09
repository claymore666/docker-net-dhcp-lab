package scenario

import (
	"context"
	"testing"
	"time"
)

// Defeat 13 (lab #12): the locally captured Kea HA rebind goes through
// the shell decoder and parseMessageLog with secs and option 51 intact.
func TestDecodeCaptureKeaHARebind(t *testing.T) {
	msgs, err := decodeCapture(context.Background(), "../..", "../../scripts/testdata/dhcp-c5-kea-ha-rebind.pcap", "ce:26:ae:11:40:98")
	if err != nil || len(msgs) != 9 {
		t.Fatalf("got %d messages, %v", len(msgs), err)
	}
	ack, renew, rebind, rebindACK := msgs[3], msgs[4], msgs[5], msgs[6]
	if ack.Type != "ACK" || ack.Server != "10.200.8.2" || ack.LeaseTime != 40*time.Second {
		t.Errorf("bound ACK %+v", ack)
	}
	if renew.Type != "REQUEST" || renew.Dst != "10.200.8.2" || renew.Secs != 0 || renew.LeaseTime != 0 {
		t.Errorf("T1 renewal %+v", renew)
	}
	if rebind.Type != "REQUEST" || rebind.Dst != "255.255.255.255" || rebind.Secs != 3 {
		t.Errorf("rebind %+v", rebind)
	}
	if rebindACK.Type != "ACK" || rebindACK.Server != "10.200.8.3" || rebindACK.YIAddr != "10.200.8.100" || rebindACK.LeaseTime != 40*time.Second {
		t.Errorf("rebind ACK %+v", rebindACK)
	}
}
