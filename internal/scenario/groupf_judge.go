package scenario

import (
	"bytes"
	"fmt"
	"strings"
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
