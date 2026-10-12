package scenario

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// The group F wire judges (#20) take the decoded option bytes of one
// identity and return PASS with a short reason, FAIL when the client or
// the server broke the documented behaviour, or BLOCKED when the lab's
// own setup contradicts the wire (nothing to judge). They never read the
// plugin's own log.

type fOutcome struct {
	Result Result
	Reason string
}

func fOK(format string, a ...any) fOutcome {
	return fOutcome{PASS, fmt.Sprintf(format, a...)}
}
func fFail(format string, a ...any) fOutcome {
	return fOutcome{FAIL, fmt.Sprintf(format, a...)}
}
func fBlocked(format string, a ...any) fOutcome {
	return fOutcome{BLOCKED, fmt.Sprintf(format, a...)}
}

func clientMsgs(msgs []OptMsg) []OptMsg {
	var out []OptMsg
	for _, m := range msgs {
		if m.Type == "DISCOVER" || m.Type == "REQUEST" {
			out = append(out, m)
		}
	}
	return out
}

func ofType(msgs []OptMsg, typ string) []OptMsg {
	var out []OptMsg
	for _, m := range msgs {
		if m.Type == typ {
			out = append(out, m)
		}
	}
	return out
}

// userClassBytes is option 77 as RFC 3004 sends one instance: a length
// byte, then the class text.
func userClassBytes(class string) []byte { return append([]byte{byte(len(class))}, class...) }

// judgeF1Wire: with user_class the client sends option 77 in every
// DISCOVER and REQUEST (plugin docs/reference.md, user_class); without
// the feature it sends none.
func judgeF1Wire(present bool, class string, msgs []OptMsg) fOutcome {
	cm := clientMsgs(msgs)
	if len(ofType(cm, "DISCOVER")) == 0 || len(ofType(cm, "REQUEST")) == 0 {
		return fBlocked("the capture holds %d DISCOVER and %d REQUEST of this identity, so option 77 cannot be judged", len(ofType(cm, "DISCOVER")), len(ofType(cm, "REQUEST")))
	}
	want := userClassBytes(class)
	if !present {
		for _, m := range cm {
			if m.Has(77) {
				return fBlocked("%s %s carries option 77 (0x%x) although the lab's version table says this plugin predates user_class", m.Type, m.XID, m.Opts[77])
			}
		}
		return fOK("no option 77 in %d client messages, as expected before user_class", len(cm))
	}
	for _, m := range cm {
		got, ok := m.Opts[77]
		switch {
		case !ok:
			return fFail("%s %s carries no option 77; user_class promises it in every DISCOVER and REQUEST", m.Type, m.XID)
		case !bytes.Equal(got, want):
			return fFail("%s %s carries option 77 0x%x, want 0x%x (length byte %d, then %q)", m.Type, m.XID, got, want, len(class), class)
		}
	}
	return fOK("option 77 = 0x%x (length byte %d, then %q) in all %d DISCOVER and REQUEST", want, len(class), class, len(cm))
}

// prlAsks reports whether a parameter request list (option 55) names code.
func prlAsks(prl []byte, code int) bool {
	for _, b := range prl {
		if int(b) == code {
			return true
		}
	}
	return false
}

// judgeF2aWire: a client that never asks for option 108 must not ask in
// any PRL (plugin docs/reference.md: "never asks for IPv6-Only Preferred
// ... and there is no option to turn it on"). A server that sends 108
// unasked breaks RFC 8925 3.3; that is a server finding, returned in
// note, not a plugin failure.
func judgeF2aWire(msgs []OptMsg) (out fOutcome, note string) {
	cm := clientMsgs(msgs)
	withPRL := 0
	for _, m := range cm {
		if !m.Has(55) {
			continue
		}
		withPRL++
		if prlAsks(m.Opts[55], 108) {
			return fFail("%s %s asks for option 108 in its parameter request list (0x%x); the client is documented to never ask", m.Type, m.XID, m.Opts[55]), ""
		}
	}
	if withPRL == 0 {
		return fBlocked("no DISCOVER or REQUEST with a parameter request list in the capture, so what the client asked for is unknown"), ""
	}
	if len(ofType(msgs, "ACK")) == 0 {
		return fBlocked("no ACK in the capture for this identity"), ""
	}
	var sent []string
	for _, m := range msgs {
		if (m.Type == "OFFER" || m.Type == "ACK") && m.Has(108) {
			sent = append(sent, m.Type+" "+m.XID)
		}
	}
	if len(sent) > 0 {
		note = fmt.Sprintf("server finding: option 108 was sent unasked in %s (RFC 8925 3.3: a server MUST NOT)", strings.Join(sent, ", "))
	}
	return fOK("no option 108 in the parameter request list of %d client messages", withPRL), note
}

// judgeF2bWire: the source forces option 108 into the OFFER of one
// identity; a client that did not ask must ignore it (RFC 8925 3.2) and
// finish the exchange. all holds every message that carried 108 in the
// run's window, to prove the forcing stayed on this identity.
func judgeF2bWire(msgs, all []OptMsg, want []byte) fOutcome {
	for _, m := range clientMsgs(msgs) {
		if m.Has(55) && prlAsks(m.Opts[55], 108) {
			return fFail("%s %s asks for option 108 (PRL 0x%x); the client is documented to never ask", m.Type, m.XID, m.Opts[55])
		}
	}
	xids := map[string]bool{}
	for _, m := range msgs {
		xids[m.XID] = true
	}
	for _, m := range all {
		if m.Has(108) && !xids[m.XID] {
			return fBlocked("%s %s to another client carries option 108: the forcing is not scoped to this identity (lab error)", m.Type, m.XID)
		}
	}
	var offered *OptMsg
	for i, m := range msgs {
		if m.Type == "OFFER" && m.Has(108) {
			offered = &msgs[i]
			break
		}
	}
	if offered == nil {
		return fBlocked("no OFFER to this identity carries option 108, so there is nothing for the client to ignore")
	}
	if !bytes.Equal(offered.Opts[108], want) {
		return fBlocked("OFFER %s carries option 108 0x%x, the lab set 0x%x", offered.XID, offered.Opts[108], want)
	}
	var req, ack bool
	for _, m := range msgs {
		if m.XID != offered.XID {
			continue
		}
		req = req || m.Type == "REQUEST"
		ack = ack || m.Type == "ACK"
	}
	switch {
	case !req:
		return fFail("the client sent no REQUEST after OFFER %s carrying option 108 (RFC 8925 3.2: it must ignore the option)", offered.XID)
	case !ack:
		return fFail("REQUEST followed OFFER %s but no ACK did", offered.XID)
	}
	return fOK("OFFER %s carried option 108 = 0x%x; the client never asked, sent its REQUEST and got the ACK", offered.XID, want)
}

// judgeF2bControl: a second client, with no forced client id, got a lease
// inside the forcing window. If the capture shows it and its messages
// carry no option 108, the forcing is scoped to the one identity; with
// no ACK for it the scoping was never exercised, which is a lab error.
func judgeF2bControl(control []OptMsg) fOutcome {
	if len(ofType(control, "ACK")) == 0 {
		return fBlocked("no ACK for the control client in the capture, so the forcing's scope was not exercised")
	}
	for _, m := range control {
		if m.Has(108) {
			return fBlocked("%s %s to the control client carries option 108: the forcing is not scoped to the one client id (lab error)", m.Type, m.XID)
		}
	}
	return fOK("the control client got its lease with no option 108")
}

// collapse drops immediate repeats of a message type, so a retransmitted
// DISCOVER does not read as a second exchange step.
func collapse(types []string) []string {
	var out []string
	for _, t := range types {
		if len(out) == 0 || out[len(out)-1] != t {
			out = append(out, t)
		}
	}
	return out
}

// judgeF3Wire: with rapid_commit the client puts option 80 in its
// DISCOVER. A server with rapid commit answers the ACK (option 80 echoed)
// and the exchange takes two messages; one without it answers OFFER and
// the exchange continues unchanged (RFC 4039 section 3; plugin
// docs/reference.md, rapid_commit). Without the feature the client sends
// no option 80 and the exchange takes four messages.
func judgeF3Wire(present, serverRapid bool, msgs []OptMsg) fOutcome {
	var ackXID string
	for _, m := range msgs {
		if m.Type == "ACK" {
			ackXID = m.XID
			break
		}
	}
	if ackXID == "" {
		return fBlocked("no ACK in the capture for this identity")
	}
	var seq []string
	var disc, offer, ack *OptMsg
	for i, m := range msgs {
		if m.XID != ackXID {
			continue
		}
		seq = append(seq, m.Type)
		switch m.Type {
		case "DISCOVER":
			if disc == nil {
				disc = &msgs[i]
			}
		case "OFFER":
			if offer == nil {
				offer = &msgs[i]
			}
		case "ACK":
			if ack == nil {
				ack = &msgs[i]
			}
		}
	}
	seq = collapse(seq)
	four := "DISCOVER OFFER REQUEST ACK"
	if disc == nil {
		return fBlocked("the capture has no DISCOVER for xid %s (messages: %s)", ackXID, strings.Join(seq, " "))
	}
	if !present {
		for _, m := range msgs {
			if m.XID == ackXID && m.Has(80) {
				return fBlocked("%s %s carries option 80 although the lab's version table says this plugin predates rapid_commit", m.Type, m.XID)
			}
		}
		if got := strings.Join(seq, " "); got != four {
			return fFail("without rapid_commit the exchange on xid %s was %q, want %q", ackXID, got, four)
		}
		return fOK("no option 80 sent; four messages on xid %s", ackXID)
	}
	if !disc.Has(80) {
		return fFail("DISCOVER %s carries no option 80 although rapid_commit is set", ackXID)
	}
	if serverRapid {
		if got := strings.Join(seq, " "); got != "DISCOVER ACK" {
			return fFail("the source supports rapid commit but the exchange on xid %s was %q, want \"DISCOVER ACK\"", ackXID, got)
		}
		if !ack.Has(80) {
			return fFail("ACK %s answers the rapid-commit DISCOVER without echoing option 80 (RFC 4039 section 3)", ackXID)
		}
		return fOK("DISCOVER with option 80 was answered by an ACK carrying option 80; two messages on xid %s", ackXID)
	}
	if got := strings.Join(seq, " "); got != four {
		return fFail("the source has no rapid commit, so the exchange on xid %s should continue unchanged as %q, was %q", ackXID, four, got)
	}
	if offer != nil && offer.Has(80) {
		return fBlocked("OFFER %s carries option 80: this source does answer rapid commit, but the lab expected it not to", ackXID)
	}
	return fOK("DISCOVER carried option 80, the source answered OFFER without it and the exchange ran as four messages on xid %s", ackXID)
}

// f8Send is one FORCERENEW the sender put on the wire: its mode, when
// labctl started it (before the sender's ssh calls, so only named in a
// reason; the windows use the frame's capture time), and its xid.
type f8Send struct {
	Mode string
	At   time.Time
	XID  string
}

// f8Obs is what F8-forcerenew judges after the three sends: the identity's messages
// and option bytes (54, 90, 145) since its ACK, the source table's lease
// expiry read after the ACK and after each wait, the lease address before
// and after, and the addresses inside the container after the signed wait.
type f8Obs struct {
	present     bool
	lease, addr string
	server      string // option 54 of the ACK (RFC 2132 9.7)
	own         []string
	bind        time.Time
	sends       [3]f8Send // unsigned, badkey, signed
	msgs        []DHCPMsg
	opts        []OptMsg
	expires     [4]time.Time
	addrAfter   string
	signedWait  time.Duration
	// relayMAC and relayMsgs are set on a relay cell only: the client
	// leg's FORCERENEWs with their Ethernet addresses (DESIGN-11 section 6,
	// #11). Empty relayMAC leaves the judge as it is on every other cell.
	relayMAC  string
	relayMsgs []RelayMsg
}

// judgeF8Ack (defeat 9): the identity's last ACK must carry option 90 as
// the lab wrote it, else the nonce never reached the client and nothing
// can be judged. The client's DISCOVER/REQUEST carry 145 iff present.
func judgeF8Ack(present bool, opts []OptMsg, want []byte) (OptMsg, fOutcome) {
	acks := ofType(opts, "ACK")
	if len(acks) == 0 {
		return OptMsg{}, fBlocked("no ACK of this identity in the capture, so the nonce cannot be read")
	}
	ack := acks[len(acks)-1]
	if !ack.Has(90) {
		return ack, fBlocked("ACK %s carries no option 90: the source did not hand out the FORCERENEW nonce (lab error)", ack.XID)
	}
	if !bytes.Equal(ack.Opts[90], want) {
		return ack, fBlocked("ACK %s option 90 is %x, the lab wrote %x (lab error)", ack.XID, ack.Opts[90], want)
	}
	if len(ack.Opts[54]) != 4 {
		return ack, fBlocked("ACK %s carries no server identifier (option 54) to send the FORCERENEW from", ack.XID)
	}
	cm := clientMsgs(opts)
	if len(cm) == 0 {
		return ack, fBlocked("no DISCOVER or REQUEST of this identity in the capture, so option 145 cannot be judged")
	}
	for _, m := range cm {
		has := m.Has(145) && bytes.Equal(m.Opts[145], []byte{1})
		if present && !has {
			return ack, fFail("%s %s carries no option 145 = 01, which the plugin documents on every DISCOVER and REQUEST (RFC 6704 3.1.1, 3.1.4)", m.Type, m.XID)
		}
		if !present && m.Has(145) {
			return ack, fBlocked("%s %s carries option 145 although the plugin tag predates FORCERENEW support: the lab's version table is wrong", m.Type, m.XID)
		}
	}
	return ack, fOK("option 145 as documented; the ACK carried the nonce")
}

func f8Find(msgs []DHCPMsg, typ, xid string) (DHCPMsg, bool) {
	for _, m := range msgs {
		if m.Type == typ && m.XID == xid {
			return m, true
		}
	}
	return DHCPMsg{}, false
}

func f8FindRelay(msgs []RelayMsg, xid string) (RelayMsg, bool) {
	for _, m := range msgs {
		if m.Type == "FORCERENEW" && m.XID == xid {
			return m, true
		}
	}
	return RelayMsg{}, false
}

func f8Opt(opts []OptMsg, typ, xid string) (OptMsg, bool) {
	for _, m := range opts {
		if m.Type == typ && m.XID == xid {
			return m, true
		}
	}
	return OptMsg{}, false
}

// f8Requests is the identity's REQUESTs in [from, to).
func f8Requests(msgs []DHCPMsg, from, to time.Time) []DHCPMsg {
	var out []DHCPMsg
	for _, m := range msgs {
		if m.Type == "REQUEST" && !m.At.Before(from) && m.At.Before(to) {
			out = append(out, m)
		}
	}
	return out
}

// judgeF8: RFC 6704 section 3 and 3.1.4 -- a client drops a FORCERENEW
// without option 90 and one whose HMAC fails, and answers a valid one by
// entering RENEWING (a REQUEST unicast to the server, ciaddr set, RFC 2131
// 4.4.5). The drops count only next to an obeyed signed send (defeat 12);
// a send past T1 could be a natural renewal (defeat 11). Windows open at
// each frame's capture time, the capture's own clock.
func judgeF8(o f8Obs) fOutcome {
	names := [3]string{"unsigned", "wrongly signed", "signed"}
	if o.expires[0].IsZero() {
		return fBlocked("the source's table gives no expiry for %s, so a renewal cannot be shown in it", o.lease)
	}
	var at [3]time.Time
	for i, s := range o.sends {
		m, ok := f8Find(o.msgs, "FORCERENEW", s.XID)
		if !ok {
			return fBlocked("the observer did not see the %s FORCERENEW (xid %s, started %s), so the client's answer to it cannot be judged", names[i], s.XID, s.At.UTC().Format("15:04:05"))
		}
		at[i] = m.At
		if m.Dst != o.lease || m.CIAddr != o.lease {
			return fBlocked("the %s FORCERENEW (xid %s) went to %s with ciaddr %s, not to the lease %s (lab error)", names[i], s.XID, m.Dst, m.CIAddr, o.lease)
		}
		if o.relayMAC != "" {
			rm, ok := f8FindRelay(o.relayMsgs, s.XID)
			if !ok {
				return fBlocked("the relay-decoded client capture has no %s FORCERENEW (xid %s), so its layer 2 source cannot be read", names[i], s.XID)
			}
			if !sameMAC(rm.EthSrc, o.relayMAC) {
				return fBlocked("the %s FORCERENEW (xid %s) reached the client with layer 2 source %s, want the relay's client leg %s: the relay did not route it (lab error)", names[i], s.XID, rm.EthSrc, o.relayMAC)
			}
		}
		om, ok := f8Opt(o.opts, "FORCERENEW", s.XID)
		if !ok || om.Has(90) != (s.Mode != "unsigned") {
			return fBlocked("the %s FORCERENEW (xid %s) does not carry option 90 as its mode says (lab error)", names[i], s.XID)
		}
	}
	half := o.bind.Add(o.expires[0].Sub(o.bind) / 2)
	if at[2].After(half) {
		return fBlocked("the last FORCERENEW went out at %s, after half the lease (%s), where a natural renewal could answer it", at[2].UTC().Format("15:04:05"), half.UTC().Format("15:04:05"))
	}
	judged := 1
	if o.present {
		judged = 2
	}
	for i := 0; i < judged; i++ {
		if r := f8Requests(o.msgs, at[i], at[i+1]); len(r) > 0 {
			return fFail("the client sent REQUEST %s after the %s FORCERENEW (xid %s), which RFC 6704 section 3 says it must not act on", r[0].XID, names[i], o.sends[i].XID)
		}
		if !o.expires[i+1].Equal(o.expires[0]) {
			return fFail("the lease expiry moved from %s to %s after the %s FORCERENEW, which must be discarded", o.expires[0].UTC().Format(time.RFC3339), o.expires[i+1].UTC().Format(time.RFC3339), names[i])
		}
	}
	s := o.sends[2]
	reqs := f8Requests(o.msgs, at[2], at[2].Add(o.signedWait))
	if !o.present {
		return fOK("the plugin predates FORCERENEW support: no renewal after the unsigned FORCERENEW; the signed one drew %d REQUEST(s), recorded, not judged", len(reqs))
	}
	if len(reqs) == 0 {
		return fBlocked("no REQUEST within %s of the signed FORCERENEW (xid %s) the observer saw reach %s, so the two drops cannot count (design defeat 12): a plugin that ignores it and a frame the client cannot verify look the same here", o.signedWait, s.XID, o.lease)
	}
	r := reqs[0]
	if r.CIAddr != o.lease || r.Dst != o.server {
		return fFail("REQUEST %s after the signed FORCERENEW went to %q with ciaddr %q, not the RENEWING request to the server %s that RFC 2131 4.4.5 describes", r.XID, r.Dst, r.CIAddr, o.server)
	}
	acked := false
	for _, m := range o.msgs {
		if m.Type == "ACK" && m.XID == r.XID && !m.At.Before(r.At) {
			acked = true
		}
	}
	if !acked {
		return fFail("REQUEST %s after the signed FORCERENEW drew no ACK in the capture", r.XID)
	}
	if am, ok := f8Opt(o.opts, "ACK", r.XID); ok && am.Has(90) {
		return fBlocked("the renewal's ACK %s carries option 90 again, which RFC 6704 3.1.3 says a server should not send: the snippet is not scoped to the first ACK (lab error)", r.XID)
	}
	if !o.expires[3].After(o.expires[0]) {
		return fFail("the client renewed (REQUEST/ACK %s) but the source's table still shows the expiry %s", r.XID, o.expires[0].UTC().Format(time.RFC3339))
	}
	if o.addrAfter != o.addr {
		return fFail("the source's table moved the lease from %s to %s across the forced renewal", o.addr, o.addrAfter)
	}
	if !containsAddr(o.own, o.addr) {
		return fFail("after the forced renewal the container carries %v, not its address %s", o.own, o.addr)
	}
	return fOK("the unsigned and the wrongly signed FORCERENEW were dropped (no REQUEST, expiry unchanged); the signed one drew the unicast REQUEST %s within %s, an ACK, and moved the expiry to %s; the container kept its address", r.XID, r.At.Sub(at[2]).Round(time.Second), o.expires[3].UTC().Format(time.RFC3339))
}

// judgeF8Control (defeat 16): a client outside F8-forcerenew's client id gets its
// lease with neither 145 nor 90, else the snippet is not scoped.
func judgeF8Control(control []OptMsg) fOutcome {
	if len(ofType(control, "ACK")) == 0 {
		return fBlocked("no ACK for the control client in the capture, so the nonce's scope was not exercised")
	}
	for _, m := range control {
		if m.Type != "OFFER" && m.Type != "ACK" {
			continue
		}
		if m.Has(145) || m.Has(90) {
			return fBlocked("%s %s to the control client carries option 145 or 90: the FORCERENEW snippet is not scoped to the one client id (lab error)", m.Type, m.XID)
		}
	}
	return fOK("the control client got its lease with no option 145 or 90")
}
