package scenario

import (
	"os"
	"strings"
	"testing"
	"time"
)

// c5cRun5 is the capture C5c judged on the kea-ha bridge shape in host
// run 5: the dhcp_message_log decode of its last capture read, message
// for message the verdict's capture evidence (#142).
func c5cRun5(t *testing.T) []DHCPMsg {
	t.Helper()
	b, err := os.ReadFile("testdata/c5c-run5-kea-ha-bridge.log")
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := parseMessageLog(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return msgs
}

func run5At(t *testing.T, hms string) time.Time {
	t.Helper()
	at, err := time.Parse("2006-01-02 15:04:05.000", "2026-10-30 "+hms)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// The pair returned between the last ACK before it (08:29:20.855) and
// the returning table's read (08:29:32.981). The primary's first ACK of
// the address came at 08:33:41.812, after the lease's expiry: the run
// judged the later SELECTING exchange of 08:34:41.610 instead.
func TestC5cJudgesTheRun5CaptureByItsFirstACK(t *testing.T) {
	msgs := c5cRun5(t)
	const addr = "10.200.8.82"
	for _, normal := range []string{"08:29:20.856", "08:29:32.981"} {
		normalAt := run5At(t, normal)
		last, ok := lastACKOf(messagesBetween(msgs, time.Time{}, normalAt), addr)
		if !ok {
			t.Fatal("no ACK before the return")
		}
		in := c5cIn{addr: addr, ident: "2e:ec:1c:a0:c7:4b", primaryID: "10.200.8.2", partnerID: "10.200.8.3", standbySilent: true, normalAt: normalAt, deadline: last.At.Add(last.LeaseTime)}
		j := c5cJudge(msgs, in)
		if j.Result != FAIL {
			t.Fatalf("normal at %s: result %q (%s), want FAIL", normal, j.Result, j.Reason)
		}
		for _, want := range []string{"by the lease's expiry (08:31:20.855)", "at 08:33:41.812", "xid 58b8725e"} {
			if !strings.Contains(j.Reason, want) {
				t.Errorf("normal at %s: reason %q lacks %q", normal, j.Reason, want)
			}
		}
		if strings.Contains(j.Reason, "f958be9f") || strings.Contains(j.Reason, "08:34:41") {
			t.Errorf("normal at %s: judged the later exchange: %s", normal, j.Reason)
		}
	}
}

// The same capture with the lease long enough: the primary's ACK pairs
// with the broadcast rebind of its own xid (08:31:24.660) and the
// unicast renewal to the standby before it counts.
func TestC5cPairsTheRun5RebindByXID(t *testing.T) {
	msgs := c5cRun5(t)
	normalAt := run5At(t, "08:29:32.981")
	in := c5cIn{addr: "10.200.8.82", ident: "x", primaryID: "10.200.8.2", partnerID: "10.200.8.3", standbySilent: true, normalAt: normalAt, deadline: normalAt.Add(time.Hour)}
	j := c5cJudge(msgs, in)
	if j.Result != PASS || j.Renewed.XID != "58b8725e" || j.Renewals != 1 {
		t.Fatalf("got %q %q renewed %s renewals %d", j.Result, j.Reason, j.Renewed.XID, j.Renewals)
	}
}

func TestC5cJudgeInterleaved(t *testing.T) {
	t0 := time.Unix(5000, 0)
	const a, p, s, bc = "10.0.0.5", "10.0.0.2", "10.0.0.3", "255.255.255.255"
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }
	in := c5cIn{addr: a, ident: "c", primaryID: p, partnerID: s, standbySilent: true, normalAt: t0, deadline: at(100)}
	withCH := func(m DHCPMsg, ch string) DHCPMsg { m.CHAddr = ch; return m }
	selecting := req(at(20), "s", "", bc)
	selecting.Requested, selecting.Server = a, p
	for _, tc := range []struct {
		name   string
		msgs   []DHCPMsg
		result Result
		reason string
		xid    string
	}{
		// One stalled read holds the rebind's ACK and the next renewal's:
		// the renewal unicast to the primary comes after the rebind.
		{"rebind ack then the next renew in one read", []DHCPMsg{
			req(at(10), "t", a, s), req(at(20), "r", a, bc), ack(at(21), "r", a, p, time.Minute),
			req(at(50), "u", a, p), ack(at(51), "u", a, p, time.Minute),
		}, PASS, "", "r"},
		{"two rebinds interleaved with their acks", []DHCPMsg{
			req(at(10), "t", a, s), req(at(20), "r1", a, bc), req(at(21), "r2", a, bc),
			ack(at(22), "r2", a, p, time.Minute), ack(at(23), "r1", a, p, time.Minute),
		}, PASS, "", "r2"},
		{"the ack's xid matches no broadcast request", []DHCPMsg{
			req(at(10), "t", a, s), req(at(20), "r", a, bc), ack(at(21), "q", a, p, time.Minute),
		}, FAIL, "answers no broadcast REQUEST of that xid", "q"},
		{"the ack of another client's request", []DHCPMsg{
			req(at(10), "t", a, s), withCH(req(at(20), "r", a, bc), "aa"), withCH(ack(at(21), "r", a, p, time.Minute), "bb"),
		}, FAIL, "answers no broadcast REQUEST", "r"},
		{"a selecting request is no rebind", []DHCPMsg{
			req(at(10), "t", a, s), selecting, ack(at(21), "s", a, p, time.Minute),
		}, FAIL, "answers no broadcast REQUEST", "s"},
		{"the first ack after the expiry", []DHCPMsg{
			req(at(10), "t", a, s), req(at(20), "r", a, bc), ack(at(100), "r", a, p, time.Minute),
		}, FAIL, "by the lease's expiry", ""},
		// A stray DHCP server on the segment answers the address in time but
		// is neither peer: only the primary's ACK, after the expiry, counts.
		{"an unknown server's ack in time", []DHCPMsg{
			req(at(10), "t", a, s), req(at(20), "r", a, bc),
			ack(at(30), "r", a, "10.0.0.9", time.Minute), ack(at(100), "r", a, p, time.Minute),
		}, FAIL, "by the lease's expiry", ""},
		{"captured out of order", []DHCPMsg{
			req(at(10), "t", a, s), req(at(20), "r", a, bc), req(at(50), "u", a, bc),
			ack(at(51), "u", a, p, time.Minute), ack(at(21), "r", a, p, time.Minute),
		}, PASS, "", "r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := c5cJudge(tc.msgs, in)
			if j.Result != tc.result || !strings.Contains(j.Reason, tc.reason) {
				t.Fatalf("got %q %q, want %q %q", j.Result, j.Reason, tc.result, tc.reason)
			}
			if tc.xid != "" && j.Renewed.XID != tc.xid && !strings.Contains(j.Reason, "xid "+tc.xid) {
				t.Errorf("judged xid %q (%s), want %q", j.Renewed.XID, j.Reason, tc.xid)
			}
		})
	}
}

func TestC5RebindPairsByClient(t *testing.T) {
	t0 := time.Unix(1000, 0)
	r := req(t0.Add(110*time.Second), "x", "10.0.0.5", "255.255.255.255")
	a := ack(t0.Add(111*time.Second), "x", "10.0.0.5", "S", time.Minute)
	r.CHAddr, a.CHAddr = "aa", "bb"
	if _, _, ok := c5Rebind([]DHCPMsg{r, a}, "10.0.0.5", "S", t0, t0.Add(time.Hour)); ok {
		t.Error("paired an ACK of another client")
	}
	if _, _, ok := c5SurvivorAnswer([]DHCPMsg{r, a}, []DHCPMsg{r}, "10.0.0.5", "S", t0.Add(time.Hour)); ok {
		t.Error("the survivor answer paired an ACK of another client")
	}
	a.CHAddr = "aa"
	if _, _, ok := c5Rebind([]DHCPMsg{r, a}, "10.0.0.5", "S", t0, t0.Add(time.Hour)); !ok {
		t.Error("the same client's ACK was not paired")
	}
	r.Server = "S"
	if _, _, ok := c5Rebind([]DHCPMsg{r, a}, "10.0.0.5", "S", t0, t0.Add(time.Hour)); ok {
		t.Error("a SELECTING request was judged a rebind")
	}
}
