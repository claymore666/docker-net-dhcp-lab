package scenario

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// e5Member is one soak container: the hardware address the source logs
// it under, the address it started with, its own capture and how long
// it was held.
type e5Member struct {
	Name, MAC, Addr string
	Wire            []DHCPMsg
	Held            time.Duration
}

// e5Obs is everything judgeE5 reads. Fresh holds the source's lines for
// the fleet's hardware addresses logged after the baseline; Cut is the
// moment up to which the capture is complete (zero: no cut).
type e5Obs struct {
	Lease   int
	Window  time.Duration
	Cut     time.Time
	Fresh   []sourceadapter.ServerEvent
	Members []e5Member
}

// grantedLease is the longest option 51 the wire shows for addr; zero
// when no ACK carried one (the relay capture does not decode it).
func grantedLease(wire []DHCPMsg, addr string) time.Duration {
	var l time.Duration
	for _, m := range wire {
		if m.Type == "ACK" && m.YIAddr == addr && m.LeaseTime > l {
			l = m.LeaseTime
		}
	}
	return l
}

// e5Trim keeps a member's wire up to its last ACK at or before cut, and
// the source's ACKs up to that ACK plus eWindow: the journal is read
// after the capture, so a renewal between the two reads is not a
// disagreement (live 1 h run on kea, 2026-10-31, lab #15).
func e5Trim(wire []DHCPMsg, acks []sourceadapter.ServerEvent, cut time.Time) ([]DHCPMsg, []sourceadapter.ServerEvent) {
	var last time.Time
	for _, m := range wire {
		if m.Type == "ACK" && !m.At.After(cut) && m.At.After(last) {
			last = m.At
		}
	}
	if cut.IsZero() || last.IsZero() {
		return wire, acks
	}
	var w []DHCPMsg
	for _, m := range wire {
		if !m.At.After(last) {
			w = append(w, m)
		}
	}
	var a []sourceadapter.ServerEvent
	for _, ev := range acks {
		if !ev.At.After(last.Add(eWindow)) {
			a = append(a, ev)
		}
	}
	return w, a
}

func firstUnseen(ex []wireExchange) string {
	for _, x := range ex {
		if x.Unseen {
			return x.XID
		}
	}
	return ""
}

// e5Bounds are the renewals a client holding a lease for held must have
// made: RFC 2131 section 4.4.5 lets the lease run out at every lease
// time, so at least ceil(held/lease)-1. The ceiling is twice the T1
// default rate (0.5 x lease) plus the bind-adjacent renew (#961).
func e5Bounds(held, lease time.Duration) (floor, ceiling int) {
	n := int(math.Ceil(float64(held) / float64(lease)))
	return n - 1, 4*n + 2
}

// judgeE5 -- every container keeps the address it started with for the
// whole window, the source logs no NAK, DECLINE or RELEASE for it, and
// the source's own log counts at least the renewals the lease required
// and never a lapse or a second DISCOVER (#15 soak). Renewals and
// DISCOVERs are counted up to the capture's last ACK; lapses over every
// ACK the source logged.
func judgeE5(o e5Obs) fOutcome {
	label := fmt.Sprintf("accelerated soak (%ds lease, %s window)", o.Lease, o.Window)
	var fails, blocks, parts []string
	acks := make([][]sourceadapter.ServerEvent, len(o.Members))
	for _, ev := range o.Fresh {
		own, owners := -1, 0
		for i, m := range o.Members {
			if strings.EqualFold(m.MAC, ev.MAC) {
				owners++
				if m.Addr == ev.IP {
					own = i
				}
			}
		}
		switch {
		case owners == 0:
		case ev.Type == "NAK" || ev.Type == "DECLINE" || ev.Type == "RELEASE":
			fails = append(fails, fmt.Sprintf("the source logged %s for %s at %s", ev.Type, ev.MAC, ev.At.UTC().Format(time.RFC3339)))
		case ev.Type == "ACK" && own < 0:
			fails = append(fails, fmt.Sprintf("the source ACKed %s to %s at %s, an address no soak container started with", ev.IP, ev.MAC, ev.At.UTC().Format(time.RFC3339)))
		case ev.Type == "ACK":
			acks[own] = append(acks[own], ev)
		}
	}
	for i, m := range o.Members {
		for _, w := range m.Wire {
			if w.Type == "ACK" && w.YIAddr != m.Addr {
				fails = append(fails, fmt.Sprintf("%s: the wire shows ACK xid %s of %s, it started with %s", m.Name, w.XID, w.YIAddr, m.Addr))
			}
		}
		wire, mine := e5Trim(m.Wire, acks[i], o.Cut)
		if len(mine) == 0 {
			blocks = append(blocks, fmt.Sprintf("%s: the source logged no ACK for %s, so no renewal can be counted", m.Name, m.Addr))
			continue
		}
		ex := wireExchanges(wire)
		if x := firstUnseen(ex); len(ex) == 0 || x != "" {
			blocks = append(blocks, fmt.Sprintf("%s: the capture holds no ACK or an ACK (xid %s) without its request, so the exchanges cannot be classified", m.Name, x))
			continue
		}
		sg := serverGroups(mine)
		if err := alignGroups(sg, exchangeGroups(ex)); err != nil {
			blocks = append(blocks, fmt.Sprintf("%s: the witnesses disagree: %v", m.Name, err))
			continue
		}
		lease, from := grantedLease(wire, m.Addr), "granted"
		if lease == 0 {
			lease, from = time.Duration(o.Lease)*time.Second, "requested, no option 51 on the wire"
		}
		floor, ceiling := e5Bounds(m.Held, lease)
		if floor < 1 {
			blocks = append(blocks, fmt.Sprintf("%s: held %s, no longer than one %s lease, so no renewal was required", m.Name, m.Held.Round(time.Second), lease))
			continue
		}
		if b := eCount(ex, eBound); b != 1 {
			fails = append(fails, fmt.Sprintf("%s: %d DISCOVER-started exchanges, want the one bind: the lease was lost and acquired again", m.Name, b))
		}
		// the gap check reads every ACK the source logged, past the cut too (#15):
		// a capture that stopped early must not hide a lapse after it
		all := serverGroups(acks[i])
		for j := 1; j < len(all); j++ {
			if gap := all[j].First.Sub(all[j-1].First); gap >= lease {
				fails = append(fails, fmt.Sprintf("%s: %s between two ACKs on the source's clock, at or past the %s lease: the lease lapsed", m.Name, gap, lease))
			}
		}
		renewals := len(sg) - 1
		switch {
		case renewals < floor:
			fails = append(fails, fmt.Sprintf("%s: %d renewals in %s with a %s lease, RFC 2131 section 4.4.5 needs at least %d", m.Name, renewals, m.Held.Round(time.Second), lease, floor))
		case renewals > ceiling:
			fails = append(fails, fmt.Sprintf("%s: %d renewals in %s with a %s lease, more than %d: a renewal storm", m.Name, renewals, m.Held.Round(time.Second), lease, ceiling))
		}
		parts = append(parts, fmt.Sprintf("%s kept %s: %d renewals in the source's log (lease %s %s, floor %d, ceiling %d; wire %d unicast renew, %d other)",
			m.Name, m.Addr, renewals, lease, from, floor, ceiling, eCount(ex, eRenew), eCount(ex, eOther)+eCount(ex, eResume)))
	}
	switch {
	case len(fails) > 0:
		return fFail("%s: %s", label, strings.Join(fails, "; "))
	case len(blocks) > 0:
		return fBlocked("%s: %s", label, strings.Join(blocks, "; "))
	}
	return fOK("%s: %s; no NAK, DECLINE or RELEASE", label, strings.Join(parts, "; "))
}
