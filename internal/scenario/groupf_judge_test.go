package scenario

import (
	"strings"
	"testing"
)

func om(typ, xid string, opts map[int][]byte) OptMsg {
	if opts == nil {
		opts = map[int][]byte{}
	}
	return OptMsg{Type: typ, XID: xid, Opts: opts}
}

func TestClientHasFeature(t *testing.T) {
	cases := []struct {
		tag     string
		want    bool
		wantErr bool
	}{
		{"v2.4.0-rc1", true, false},
		{"v2.4.0", true, false},
		{"v2.5.0", true, false},
		{"v3.0.0", true, false},
		{"v2.3.0-rc1", false, false},
		{"v2.2.3", false, false},
		{"ghcr.io/claymore666/docker-net-dhcp:v2.4.0", true, false},
		{"ghcr.io/claymore666/docker-net-dhcp:v2.2.3", false, false},
		{"", false, true},
		{"latest", false, true},
		{"v2.4", false, true},
		{"dev", false, true},
	}
	for _, c := range cases {
		got, err := clientHasFeature(c.tag, fSince4)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("clientHasFeature(%q) = %v, %v; want %v, err=%v", c.tag, got, err, c.want, c.wantErr)
		}
	}
}

func TestParseOptionBytes(t *testing.T) {
	out := "1700000000.250000 DISCOVER 0f100001 0x0a6c61622d636c617373 -\n" +
		"1700000000.500000 OFFER 0f100001 - 0x\n"
	msgs, err := parseOptionBytes(out, []int{77, 80})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].Type != "DISCOVER" || msgs[0].XID != "0f100001" {
		t.Fatalf("got %+v", msgs)
	}
	if string(msgs[0].Opts[77][1:]) != "lab-class" || msgs[0].Has(80) {
		t.Errorf("discover opts = %v", msgs[0].Opts)
	}
	if !msgs[1].Has(80) || len(msgs[1].Opts[80]) != 0 || msgs[1].Has(77) {
		t.Errorf("a zero-length option must be present and empty: %v", msgs[1].Opts)
	}
	for _, bad := range []string{"1.0 ACK x -\n", "abc ACK x - -\n", "1.0 ACK x zz -\n", "1.0 ACK x 0xzz -\n"} {
		if _, err := parseOptionBytes(bad, []int{77, 80}); err == nil {
			t.Errorf("%q must be an error", bad)
		}
	}
}

func TestJudgeF1Wire(t *testing.T) {
	cls := "lab-class"
	with := map[int][]byte{77: userClassBytes(cls)}
	good := []OptMsg{om("DISCOVER", "1", with), om("OFFER", "1", nil), om("REQUEST", "1", with), om("ACK", "1", nil)}
	if o := judgeF1Wire(true, cls, good); o.Result != PASS {
		t.Errorf("good = %+v", o)
	}
	noReq := []OptMsg{om("DISCOVER", "1", with)}
	if o := judgeF1Wire(true, cls, noReq); o.Result != BLOCKED {
		t.Errorf("no REQUEST = %+v", o)
	}
	missing := []OptMsg{om("DISCOVER", "1", with), om("REQUEST", "1", nil)}
	if o := judgeF1Wire(true, cls, missing); o.Result != FAIL || !strings.Contains(o.Reason, "carries no option 77") {
		t.Errorf("present, REQUEST without 77 must FAIL: %+v", o)
	}
	wrong := map[int][]byte{77: []byte(cls)} // text without the RFC 3004 length byte
	bad := []OptMsg{om("DISCOVER", "1", wrong), om("REQUEST", "1", wrong)}
	if o := judgeF1Wire(true, cls, bad); o.Result != FAIL {
		t.Errorf("77 without a length byte must FAIL: %+v", o)
	}
	plain := []OptMsg{om("DISCOVER", "1", nil), om("REQUEST", "1", nil)}
	if o := judgeF1Wire(false, cls, plain); o.Result != PASS {
		t.Errorf("absent and no 77 = %+v", o)
	}
	if o := judgeF1Wire(false, cls, good); o.Result != BLOCKED {
		t.Errorf("absent but 77 on the wire must BLOCK: %+v", o)
	}
}

func TestJudgeF2aWire(t *testing.T) {
	prl := func(b ...byte) map[int][]byte { return map[int][]byte{55: b} }
	ok := []OptMsg{om("DISCOVER", "1", prl(1, 3, 6)), om("OFFER", "1", nil), om("REQUEST", "1", prl(1, 3, 6)), om("ACK", "1", nil)}
	if o, note := judgeF2aWire(ok); o.Result != PASS || note != "" {
		t.Errorf("ok = %+v %q", o, note)
	}
	asks := []OptMsg{om("DISCOVER", "1", prl(1, 108)), om("ACK", "1", nil)}
	if o, _ := judgeF2aWire(asks); o.Result != FAIL {
		t.Errorf("a PRL naming 108 must FAIL: %+v", o)
	}
	noPRL := []OptMsg{om("DISCOVER", "1", nil), om("ACK", "1", nil)}
	if o, _ := judgeF2aWire(noPRL); o.Result != BLOCKED {
		t.Errorf("no PRL must BLOCK: %+v", o)
	}
	noACK := []OptMsg{om("DISCOVER", "1", prl(1))}
	if o, _ := judgeF2aWire(noACK); o.Result != BLOCKED {
		t.Errorf("no ACK must BLOCK: %+v", o)
	}
	unasked := []OptMsg{om("DISCOVER", "1", prl(1)), om("OFFER", "1", map[int][]byte{108: {0, 0, 7, 8}}), om("ACK", "1", nil)}
	o, note := judgeF2aWire(unasked)
	if o.Result != PASS || !strings.Contains(note, "RFC 8925 3.3") {
		t.Errorf("a server sending 108 unasked is a note, not a plugin FAIL: %+v %q", o, note)
	}
}

func TestJudgeF2bWire(t *testing.T) {
	want := f108Bytes()
	prl := map[int][]byte{55: {1, 3}}
	ex := func() []OptMsg {
		return []OptMsg{om("DISCOVER", "1", prl), om("OFFER", "1", map[int][]byte{108: want}), om("REQUEST", "1", prl), om("ACK", "1", nil)}
	}
	if o := judgeF2bWire(ex(), ex(), want); o.Result != PASS {
		t.Errorf("good = %+v", o)
	}
	stopped := ex()[:2]
	if o := judgeF2bWire(stopped, stopped, want); o.Result != FAIL || !strings.Contains(o.Reason, "no REQUEST") {
		t.Errorf("client stopping after the forced OFFER must FAIL: %+v", o)
	}
	noReq := []OptMsg{ex()[0], ex()[1], ex()[3]}
	if o := judgeF2bWire(noReq, noReq, want); o.Result != FAIL || !strings.Contains(o.Reason, "no REQUEST") {
		t.Errorf("an ACK without a REQUEST must FAIL: %+v", o)
	}
	noAck := ex()[:3]
	if o := judgeF2bWire(noAck, noAck, want); o.Result != FAIL || !strings.Contains(o.Reason, "no ACK did") {
		t.Errorf("no ACK must FAIL: %+v", o)
	}
	leak := append(ex(), om("OFFER", "9", map[int][]byte{108: want}))
	if o := judgeF2bWire(ex(), leak, want); o.Result != BLOCKED {
		t.Errorf("forcing leaked to another xid must BLOCK: %+v", o)
	}
	none := []OptMsg{om("DISCOVER", "1", prl), om("OFFER", "1", nil), om("REQUEST", "1", prl), om("ACK", "1", nil)}
	if o := judgeF2bWire(none, none, want); o.Result != BLOCKED {
		t.Errorf("no 108 offered must BLOCK: %+v", o)
	}
	wrongVal := []OptMsg{om("DISCOVER", "1", prl), om("OFFER", "1", map[int][]byte{108: {0, 0, 0, 1}}), om("REQUEST", "1", prl), om("ACK", "1", nil)}
	if o := judgeF2bWire(wrongVal, wrongVal, want); o.Result != BLOCKED {
		t.Errorf("a different 108 value must BLOCK: %+v", o)
	}
	asked := ex()
	asked[0] = om("DISCOVER", "1", map[int][]byte{55: {1, 108}})
	if o := judgeF2bWire(asked, asked, want); o.Result != FAIL {
		t.Errorf("a client asking for 108 must FAIL: %+v", o)
	}
}

func TestJudgeF3Wire(t *testing.T) {
	rc := map[int][]byte{80: {}}
	four := []OptMsg{om("DISCOVER", "1", rc), om("OFFER", "1", nil), om("REQUEST", "1", nil), om("ACK", "1", nil)}
	two := []OptMsg{om("DISCOVER", "1", rc), om("ACK", "1", rc)}
	plainFour := []OptMsg{om("DISCOVER", "1", nil), om("OFFER", "1", nil), om("REQUEST", "1", nil), om("ACK", "1", nil)}
	cases := []struct {
		name        string
		present     bool
		serverRapid bool
		msgs        []OptMsg
		want        Result
	}{
		{"dnsmasq two messages", true, true, two, PASS},
		{"Kea/ISC four messages", true, false, four, PASS},
		{"retransmitted DISCOVER still four", true, false, append([]OptMsg{om("DISCOVER", "1", rc)}, four...), PASS},
		{"present, DISCOVER without 80", true, false, plainFour, FAIL},
		{"rapid server but four messages", true, true, four, FAIL},
		{"rapid server, four messages, ACK echoes 80", true, true, []OptMsg{om("DISCOVER", "1", rc), om("OFFER", "1", nil), om("REQUEST", "1", nil), om("ACK", "1", rc)}, FAIL},
		{"rapid server, ACK without 80", true, true, []OptMsg{om("DISCOVER", "1", rc), om("ACK", "1", nil)}, FAIL},
		{"no rapid server but two messages", true, false, two, FAIL},
		{"no rapid server but OFFER carries 80", true, false, []OptMsg{om("DISCOVER", "1", rc), om("OFFER", "1", rc), om("REQUEST", "1", nil), om("ACK", "1", nil)}, BLOCKED},
		{"absent, plain four", false, false, plainFour, PASS},
		{"absent but 80 on the wire", false, false, four, BLOCKED},
		{"absent, only two messages", false, false, []OptMsg{om("DISCOVER", "1", nil), om("ACK", "1", nil)}, FAIL},
		{"no ACK", true, true, []OptMsg{om("DISCOVER", "1", rc)}, BLOCKED},
		{"ACK without DISCOVER", true, true, []OptMsg{om("ACK", "1", rc)}, BLOCKED},
	}
	for _, c := range cases {
		if o := judgeF3Wire(c.present, c.serverRapid, c.msgs); o.Result != c.want {
			t.Errorf("%s: %+v, want %v", c.name, o, c.want)
		}
	}
}
