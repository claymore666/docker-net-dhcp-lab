package scenario

import (
	"fmt"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// E5 judge tests (lab #15 soak); "row N" is the defeat list's row.

const (
	e5MAC2 = "02:aa:bb:cc:dd:02"
	e5IP2  = "10.200.1.151"
)

func e5Srv(typ, mac, ip string, sec float64) sourceadapter.ServerEvent {
	return sourceadapter.ServerEvent{At: eAt(sec).Truncate(time.Second), Type: typ, MAC: mac, IP: ip}
}

func withLease(msgs []DHCPMsg, l time.Duration) []DHCPMsg {
	out := append([]DHCPMsg(nil), msgs...)
	for i := range out {
		if out[i].Type == "ACK" {
			out[i].LeaseTime = l
		}
	}
	return out
}

// e5Run is one container bound at 0 and renewed every step seconds up
// to last: its source lines and its wire.
func e5Run(mac, ip string, step, last float64, lease time.Duration) ([]sourceadapter.ServerEvent, []DHCPMsg) {
	srv := []sourceadapter.ServerEvent{e5Srv("ACK", mac, ip, 0)}
	wire := boundWire("b0", ip, 0)
	for n, s := 1, step; s <= last; n, s = n+1, s+step {
		srv = append(srv, e5Srv("ACK", mac, ip, s))
		wire = append(wire, renewWire(fmt.Sprintf("r%d", n), ip, s)...)
	}
	return srv, withLease(wire, lease)
}

func happyE5() e5Obs {
	a, wa := e5Run(eMAC, eIP, 20, 180, 40*time.Second)
	b, wb := e5Run(e5MAC2, e5IP2, 20, 180, 40*time.Second)
	return e5Obs{Lease: 40, Window: 3 * time.Minute, Fresh: append(a, b...), Members: []e5Member{
		{Name: "c1", MAC: eMAC, Addr: eIP, Wire: wa, Held: 180 * time.Second},
		{Name: "c2", MAC: e5MAC2, Addr: e5IP2, Wire: wb, Held: 180 * time.Second},
	}}
}

func TestJudgeE5HappyPath(t *testing.T) {
	o := judgeE5(happyE5())
	wantOutcome(t, o, PASS, "accelerated soak (40s lease, 3m0s window)")
	wantOutcome(t, o, PASS, "c2 kept 10.200.1.151: 9 renewals in the source's log (lease 40s granted, floor 4, ceiling 22")
}

func TestE5Bounds(t *testing.T) {
	for _, c := range []struct {
		held, lease    time.Duration
		floor, ceiling int
	}{{180 * time.Second, 40 * time.Second, 4, 22}, {80 * time.Second, 40 * time.Second, 1, 10}, {120 * time.Second, 40 * time.Second, 2, 14}, {time.Hour, 60 * time.Second, 59, 242}} {
		f, c2 := e5Bounds(c.held, c.lease)
		if f != c.floor || c2 != c.ceiling {
			t.Errorf("e5Bounds(%s, %s) = %d, %d, want %d, %d", c.held, c.lease, f, c2, c.floor, c.ceiling)
		}
	}
}

// Row 1: a member that never renewed fails on the floor.
func TestJudgeE5NoRenewalFails(t *testing.T) {
	o := happyE5()
	a, wa := e5Run(eMAC, eIP, 20, 0, 40*time.Second)
	_, wb := e5Run(e5MAC2, e5IP2, 20, 180, 40*time.Second)
	o.Fresh = append(a, o.Fresh[len(a)+9:]...)
	o.Members[0].Wire, o.Members[1].Wire = wa, wb
	wantOutcome(t, judgeE5(o), FAIL, "c1: 0 renewals in 3m0s with a 40s lease, RFC 2131 section 4.4.5 needs at least 4")
}

// Row 1: within one lease nothing proves a renewal was needed.
func TestJudgeE5ShortHoldBlocks(t *testing.T) {
	o := happyE5()
	o.Members[0].Held, o.Members[1].Held = 40*time.Second, 40*time.Second
	wantOutcome(t, judgeE5(o), BLOCKED, "held 40s, no longer than one 40s lease")
}

// The lease the wire shows wins over the one asked for; without option
// 51 the asked one counts.
func TestJudgeE5UsesTheGrantedLease(t *testing.T) {
	a, wa := e5Run(eMAC, eIP, 60, 180, 120*time.Second)
	o := e5Obs{Lease: 40, Window: 3 * time.Minute, Fresh: a, Members: []e5Member{{Name: "c1", MAC: eMAC, Addr: eIP, Wire: wa, Held: 180 * time.Second}}}
	wantOutcome(t, judgeE5(o), PASS, "3 renewals in the source's log (lease 2m0s granted, floor 1")
	o.Members[0].Wire = withLease(wa, 0)
	wantOutcome(t, judgeE5(o), FAIL, "1m0s between two ACKs")
	wantOutcome(t, judgeE5(o), FAIL, "needs at least 4")
}

// Row 2: an ACK of another address, on the source or on the wire.
func TestJudgeE5AddressChangeFails(t *testing.T) {
	o := happyE5()
	o.Fresh[3].IP = "10.200.1.199"
	wantOutcome(t, judgeE5(o), FAIL, "the source ACKed 10.200.1.199 to 02:aa:bb:cc:dd:01")
	o = happyE5()
	o.Members[1].Wire[5].YIAddr = "10.200.1.198"
	wantOutcome(t, judgeE5(o), FAIL, "c2: the wire shows ACK xid r1 of 10.200.1.198")
}

// Row 3: a lease lost and bound again, even to the same address.
func TestJudgeE5SecondDiscoverFails(t *testing.T) {
	o := happyE5()
	w := o.Members[0].Wire
	for i := range w {
		if w[i].XID == "r4" {
			w[i].CIAddr, w[i].Dst = "", "255.255.255.255"
			if w[i].Type == "REQUEST" {
				w[i].Type = "DISCOVER"
			}
		}
	}
	wantOutcome(t, judgeE5(o), FAIL, "c1: 2 DISCOVER-started exchanges")
}

// Row 3: a gap of a full lease between two ACKs on the source's clock.
func TestJudgeE5LapseFails(t *testing.T) {
	srv := []sourceadapter.ServerEvent{e5Srv("ACK", eMAC, eIP, 0), e5Srv("ACK", eMAC, eIP, 20), e5Srv("ACK", eMAC, eIP, 60), e5Srv("ACK", eMAC, eIP, 80)}
	wire := withLease(cat(boundWire("b0", eIP, 0), renewWire("r1", eIP, 20), renewWire("r2", eIP, 60), renewWire("r3", eIP, 80)), 40*time.Second)
	o := e5Obs{Lease: 40, Window: 100 * time.Second, Fresh: srv, Members: []e5Member{{Name: "c1", MAC: eMAC, Addr: eIP, Wire: wire, Held: 100 * time.Second}}}
	wantOutcome(t, judgeE5(o), FAIL, "c1: 40s between two ACKs on the source's clock, at or past the 40s lease")
	o.Fresh[2] = e5Srv("ACK", eMAC, eIP, 59)
	wantOutcome(t, judgeE5(o), PASS, "3 renewals")
}

// Row 8: a refusal, decline or release for a fleet address.
func TestJudgeE5RefusalsFail(t *testing.T) {
	for _, typ := range []string{"NAK", "DECLINE", "RELEASE"} {
		o := happyE5()
		o.Fresh = append(o.Fresh, e5Srv(typ, e5MAC2, "", 90))
		wantOutcome(t, judgeE5(o), FAIL, "the source logged "+typ+" for 02:aa:bb:cc:dd:02")
	}
}

// Row 7: renewing far above the T1 rate.
func TestJudgeE5RenewalStormFails(t *testing.T) {
	a, wa := e5Run(eMAC, eIP, 4, 180, 40*time.Second)
	o := e5Obs{Lease: 40, Window: 3 * time.Minute, Fresh: a, Members: []e5Member{{Name: "c1", MAC: eMAC, Addr: eIP, Wire: wa, Held: 180 * time.Second}}}
	wantOutcome(t, judgeE5(o), FAIL, "45 renewals in 3m0s with a 40s lease, more than 22: a renewal storm")
}

// Row 9: the two witnesses disagree, or the capture lost a request.
func TestJudgeE5WitnessGapsBlock(t *testing.T) {
	o := happyE5()
	o.Fresh = append(o.Fresh, e5Srv("ACK", eMAC, eIP, 190))
	wantOutcome(t, judgeE5(o), BLOCKED, "c1: the witnesses disagree")
	o = happyE5()
	o.Members[0].Wire = o.Members[0].Wire[4:]
	o.Members[0].Wire = append(o.Members[0].Wire[1:2:2], o.Members[0].Wire[2:]...)
	wantOutcome(t, judgeE5(o), BLOCKED, "c1: the capture holds no ACK or an ACK (xid r1) without its request")
	o = happyE5()
	o.Fresh = o.Fresh[10:]
	wantOutcome(t, judgeE5(o), BLOCKED, "c1: the source logged no ACK for 10.200.1.150")
}

// The source's journal is read after the capture: a renewal it logged
// past the cut is dropped, one inside the cut still disagrees.
func TestJudgeE5CutsTheSourceAtTheCapture(t *testing.T) {
	o := happyE5()
	o.Fresh = append(o.Fresh, e5Srv("ACK", eMAC, eIP, 200))
	wantOutcome(t, judgeE5(o), BLOCKED, "c1: the witnesses disagree")
	o.Cut = eAt(185)
	wantOutcome(t, judgeE5(o), PASS, "c1 kept 10.200.1.150: 9 renewals")
	o.Members[0].Wire = append(o.Members[0].Wire, renewWire("r10", eIP, 200)...)
	wantOutcome(t, judgeE5(o), PASS, "c1 kept 10.200.1.150: 9 renewals")
	o = happyE5()
	o.Cut = eAt(185)
	o.Fresh = append(o.Fresh[:9:9], append([]sourceadapter.ServerEvent{e5Srv("ACK", eMAC, eIP, 170)}, o.Fresh[9:]...)...)
	wantOutcome(t, judgeE5(o), BLOCKED, "c1: the witnesses disagree")
	// past the last wire ACK by more than eWindow, though inside the cut
	o = happyE5()
	o.Cut = eAt(185)
	o.Fresh = append(o.Fresh, e5Srv("ACK", eMAC, eIP, 184))
	wantOutcome(t, judgeE5(o), PASS, "c1 kept 10.200.1.150: 9 renewals")
	// the source's clock a second ahead of the observer's
	o = happyE5()
	o.Cut = eAt(185)
	o.Fresh[9] = e5Srv("ACK", eMAC, eIP, 181.5)
	wantOutcome(t, judgeE5(o), PASS, "c1 kept 10.200.1.150: 9 renewals")
	o = happyE5()
	o.Cut = eAt(185)
	o.Fresh = append(o.Fresh, e5Srv("NAK", eMAC, "", 200))
	wantOutcome(t, judgeE5(o), FAIL, "the source logged NAK for 02:aa:bb:cc:dd:01")
}

// A definite failure on one member is not hidden by another's block.
func TestJudgeE5FailOutranksBlock(t *testing.T) {
	o := happyE5()
	o.Fresh = append(o.Fresh, e5Srv("ACK", eMAC, eIP, 190), e5Srv("NAK", e5MAC2, "", 100))
	wantOutcome(t, judgeE5(o), FAIL, "NAK")
}

// Row 6: ipvlan's members share one hardware address and are told apart
// by address; a third address under it is a change.
func TestJudgeE5SharedMACSplitsByAddress(t *testing.T) {
	a, wa := e5Run(eMAC, eIP, 20, 180, 40*time.Second)
	b, wb := e5Run(eMAC, e5IP2, 15, 180, 40*time.Second)
	o := e5Obs{Lease: 40, Window: 3 * time.Minute, Fresh: append(a, b...), Members: []e5Member{
		{Name: "c1", MAC: eMAC, Addr: eIP, Wire: wa, Held: 180 * time.Second},
		{Name: "c2", MAC: eMAC, Addr: e5IP2, Wire: wb, Held: 180 * time.Second},
	}}
	wantOutcome(t, judgeE5(o), PASS, "c1 kept 10.200.1.150: 9 renewals")
	wantOutcome(t, judgeE5(o), PASS, "c2 kept 10.200.1.151: 12 renewals")
	o.Fresh = append(o.Fresh, e5Srv("ACK", eMAC, "10.200.1.160", 100))
	wantOutcome(t, judgeE5(o), FAIL, "the source ACKed 10.200.1.160")
}

// Preservation: another client's lines change nothing.
func TestJudgeE5IgnoresOtherClients(t *testing.T) {
	o := happyE5()
	o.Fresh = append(o.Fresh, e5Srv("NAK", "02:ff:ff:ff:ff:ff", "", 50), e5Srv("ACK", "02:ff:ff:ff:ff:ff", "10.200.1.170", 60))
	wantOutcome(t, judgeE5(o), PASS, "accelerated")
}
