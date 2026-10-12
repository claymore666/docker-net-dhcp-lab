package scenario

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// The relay cell as the rig builds it (lab.yaml kea-relay, #11): client
// segment 10.200.10.0/24 behind the relay's .1, source on 10.200.11.2.
const (
	rCliMAC = "02:11:00:00:00:01"
	rSrvMAC = "02:11:00:00:00:02"
	rSrcMAC = "02:11:00:00:00:20"
	rGW     = "10.200.10.1"
	rSrvLeg = "10.200.11.1"
	rSrc    = "10.200.11.2"
	rO82    = "0x0104657468310203726c79" // circuit-id "eth1", remote-id "rly"
)

func relayEnvOf(e Env) Env {
	e.SegSubnet, e.PoolStart, e.PoolEnd = "10.200.10.0/24", "10.200.10.100", "10.200.10.200"
	e.SegGateway, e.SourceAddr = rGW, rSrc
	e.RelayClientMAC, e.RelayServerMAC = rCliMAC, rSrvMAC
	return e
}

func rm(at time.Time, typ, xid, ident, src, dst, ethSrc, ethDst, giaddr, o82 string) RelayMsg {
	return RelayMsg{
		DHCPMsg: DHCPMsg{At: at, Type: typ, XID: xid, CHAddr: ident, Src: src, Dst: dst},
		GIAddr:  giaddr, Flags: "0x0000", EthSrc: ethSrc, EthDst: ethDst, Opt82: o82,
	}
}

// edit returns msgs with f applied to a copy of every message of type typ.
func edit(msgs []RelayMsg, typ string, f func(*RelayMsg)) []RelayMsg {
	out := append([]RelayMsg(nil), msgs...)
	for i := range out {
		if out[i].Type == typ {
			f(&out[i])
		}
	}
	return out
}

// goodWire is a clean relayed acquisition of addr: the client segment as
// the client hears it, the server segment as the source sees it.
func goodWire(ident, addr string, t0 time.Time) (client, server []RelayMsg) {
	at := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Millisecond) }
	const bc = "255.255.255.255"
	for i, p := range [][2]string{{"DISCOVER", "OFFER"}, {"REQUEST", "ACK"}} {
		xid := "x" + string(rune('1'+i))
		creq := rm(at(2*i*2), p[0], xid, ident, "0.0.0.0", bc, ident, "ff:ff:ff:ff:ff:ff", "", "")
		crep := rm(at(2*i*2+1), p[1], xid, ident, rGW, bc, rCliMAC, "ff:ff:ff:ff:ff:ff", rGW, "")
		crep.Server, crep.YIAddr = rSrc, addr
		sreq := rm(at(2*i*2), p[0], xid, ident, rSrvLeg, rSrc, rSrvMAC, rSrcMAC, rGW, rO82)
		srep := rm(at(2*i*2+1), p[1], xid, ident, rSrc, rGW, rSrcMAC, rSrvMAC, rGW, rO82)
		srep.Server, srep.YIAddr = rSrc, addr
		client = append(client, creq, crep)
		server = append(server, sreq, srep)
	}
	return client, server
}

func TestJudgeC12Wire(t *testing.T) {
	const id, addr = "aa:bb:cc:00:00:01", "10.200.10.101"
	t0 := time.Now()
	upTo := t0.Add(10 * time.Millisecond)
	type tc struct {
		name   string
		client func([]RelayMsg) []RelayMsg
		server func([]RelayMsg) []RelayMsg
		env    func(*Env)
		want   relayKind
		sub    string
	}
	same := func(m []RelayMsg) []RelayMsg { return m }
	set := func(typ string, f func(*RelayMsg)) func([]RelayMsg) []RelayMsg {
		return func(m []RelayMsg) []RelayMsg { return edit(m, typ, f) }
	}
	drop := func(typ string) func([]RelayMsg) []RelayMsg {
		return func(m []RelayMsg) []RelayMsg {
			var out []RelayMsg
			for _, x := range m {
				if x.Type != typ {
					out = append(out, x)
				}
			}
			return out
		}
	}
	cases := []tc{
		{"clean relayed acquisition", same, same, nil, relayOK, ""},
		// RFC 3046 section 2.2: the server copies option 82 unchanged.
		{"option 82 reordered in the reply", same, set("OFFER", func(m *RelayMsg) { m.Opt82 = "0x0203726c79010465746831" }), nil, relayBlocked, "does not echo"},
		{"option 82 changed in the reply", same, set("ACK", func(m *RelayMsg) { m.Opt82 = "0x0104657468390203726c79" }), nil, relayBlocked, "does not echo"},
		{"option 82 with an extra sub-option", same, set("OFFER", func(m *RelayMsg) { m.Opt82 += "0301ff" }), nil, relayBlocked, "does not echo"},
		{"option 82 dropped from the reply", same, set("OFFER", func(m *RelayMsg) { m.Opt82 = "" }), nil, relayBlocked, "option 82"},
		{"option 82 malformed in the reply", same, set("ACK", func(m *RelayMsg) { m.Opt82 = "0x01ff00" }), nil, relayBlocked, "runs past the end"},
		{"relayed DISCOVER without option 82", same, set("DISCOVER", func(m *RelayMsg) { m.Opt82 = "" }), nil, relayBlocked, "without -a"},
		{"giaddr missing on the relayed request", same, set("REQUEST", func(m *RelayMsg) { m.GIAddr = "" }), nil, relayBlocked, "giaddr"},
		{"giaddr is another address", same, set("DISCOVER", func(m *RelayMsg) { m.GIAddr = "10.200.10.9" }), nil, relayBlocked, "giaddr"},
		{"request not from the relay's server leg", same, set("DISCOVER", func(m *RelayMsg) { m.EthSrc = id }), nil, relayBlocked, "server leg"},
		{"request not to the source", same, set("REQUEST", func(m *RelayMsg) { m.Dst = "10.200.11.9" }), nil, relayBlocked, "REQUEST"},
		{"no reply on the server leg", same, drop("OFFER"), nil, relayBlocked, "no OFFER"},
		{"reply not addressed to giaddr", same, set("ACK", func(m *RelayMsg) { m.Dst = "255.255.255.255" }), nil, relayBlocked, "no ACK"},
		{"reply names another server in option 54", same, set("ACK", func(m *RelayMsg) { m.Server = rGW }), nil, relayBlocked, "option 54"},
		{"another client's traffic only", same, func(m []RelayMsg) []RelayMsg {
			return edit(m, "DISCOVER", func(x *RelayMsg) { x.CHAddr = "aa:bb:cc:00:00:99" })
		}, nil, relayBlocked, "no DISCOVER"},
		{"empty relay server MAC is not a pass", same, same, func(e *Env) { e.RelayServerMAC = "" }, relayBlocked, "server leg"},
		// The source answers the client directly: the relay was bypassed.
		{"client frame from the source's IP", func(m []RelayMsg) []RelayMsg {
			return append(m, rm(t0.Add(5*time.Millisecond), "OFFER", "x1", id, rSrc, "255.255.255.255", rCliMAC, "ff:ff:ff:ff:ff:ff", "", ""))
		}, same, nil, relayBlocked, "from the source itself"},
		{"client frame from the source's MAC under another IP", func(m []RelayMsg) []RelayMsg {
			return append(m, rm(t0.Add(5*time.Millisecond), "ACK", "x2", id, rGW, "255.255.255.255", rSrcMAC, "ff:ff:ff:ff:ff:ff", "", ""))
		}, same, nil, relayBlocked, "from the source itself"},
		{"a routed ACK from the source after the bind is not the acquisition", func(m []RelayMsg) []RelayMsg {
			return append(m, rm(upTo.Add(time.Second), "ACK", "x9", id, rSrc, addr, rCliMAC, id, "", ""))
		}, same, nil, relayOK, ""},
		// The plugin's rules: FAIL, not BLOCKED.
		{"client OFFER from the wrong MAC", set("OFFER", func(m *RelayMsg) { m.EthSrc = "02:11:00:00:00:77" }), same, nil, relayFail, "OFFER came from"},
		{"client ACK from the wrong IP", set("ACK", func(m *RelayMsg) { m.Src = "10.200.10.77" }), same, nil, relayFail, "ACK came from"},
		{"client OFFER names the relay in option 54", set("OFFER", func(m *RelayMsg) { m.Server = rGW }), same, nil, relayFail, "option 54"},
		{"client ACK still carries option 82", set("ACK", func(m *RelayMsg) { m.Opt82 = rO82 }), same, nil, relayFail, "strip"},
		{"client heard no OFFER", drop("OFFER"), same, nil, relayFail, "no OFFER"},
		{"client heard no ACK", drop("ACK"), same, nil, relayFail, "no ACK"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := relayEnvOf(Env{})
			if c.env != nil {
				c.env(&e)
			}
			cm, sm := goodWire(id, addr, t0)
			o := judgeC12Wire(e, id, c.client(cm), c.server(sm), upTo)
			if o.kind != c.want || (c.sub != "" && !strings.Contains(o.reason, c.sub)) {
				t.Fatalf("kind %d reason %q, want kind %d containing %q", o.kind, o.reason, c.want, c.sub)
			}
			if c.want == relayOK && !strings.Contains(o.note, "option 82 echoed in OFFER, ACK") {
				t.Errorf("note %q", o.note)
			}
		})
	}
}

func TestJudgeC12WireRecordsTheDeliveryAndTheFlags(t *testing.T) {
	const id, addr = "aa:bb:cc:00:00:01", "10.200.10.101"
	t0 := time.Now()
	cm, sm := goodWire(id, addr, t0)
	cm = edit(cm, "DISCOVER", func(m *RelayMsg) { m.Flags = "0x8000" })
	cm = edit(cm, "ACK", func(m *RelayMsg) { m.Dst = addr })
	o := judgeC12Wire(relayEnvOf(Env{}), id, cm, sm, t0.Add(10*time.Millisecond))
	if o.kind != relayOK || !strings.Contains(o.note, "1 reply(ies) by broadcast, 1 unicast") || !strings.Contains(o.note, "DISCOVER=0x8000") || !strings.Contains(o.note, "REQUEST=0x0000") {
		t.Fatalf("%+v", o)
	}
}

func TestOpt82Echoed(t *testing.T) {
	for _, c := range []struct {
		name, req, rep string
		want, bad      bool
	}{
		{"equal", rO82, rO82, true, false},
		{"reordered", rO82, "0x0203726c79010465746831", false, false},
		{"changed byte", rO82, "0x0104657468390203726c79", false, false},
		{"extra sub-option", rO82, rO82 + "0301ff", false, false},
		{"missing sub-option", rO82, "0x010465746831", false, false},
		{"empty request", "", rO82, false, true},
		{"empty reply", rO82, "", false, true},
		{"non-hex", rO82, "0xzz", false, true},
		{"overrun", rO82, "0x01ff00", false, true},
		{"truncated header", "0x01", rO82, false, true},
	} {
		got, err := opt82Echoed(c.req, c.rep)
		if got != c.want || (err != nil) != c.bad {
			t.Errorf("%s: %v %v, want %v bad=%v", c.name, got, err, c.want, c.bad)
		}
	}
}

func TestParseRelayLog(t *testing.T) {
	line := "1791571282.274322 REQUEST c67f9f51 02:11:00:00:00:10 01:02:11:00:00:00:10 - - 10.200.10.100 - 10.200.10.100 10.200.11.2 3 - 0x8000 02:11:00:00:00:10 02:11:00:00:00:01 " + rO82 + "\n"
	got, err := parseRelayLog(line + "\n")
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	m := got[0]
	if m.Type != "REQUEST" || m.XID != "c67f9f51" || m.CIAddr != "10.200.10.100" || m.Src != "10.200.10.100" || m.Dst != "10.200.11.2" ||
		m.Secs != 3 || m.GIAddr != "" || m.Flags != "0x8000" || m.EthSrc != "02:11:00:00:00:10" || m.EthDst != "02:11:00:00:00:01" || m.Opt82 != rO82 || m.Server != "" || m.At.Unix() != 1791571282 {
		t.Errorf("%+v", m)
	}
	for name, bad := range map[string]string{
		"sixteen fields":  "1.0 REQUEST x a b - - - - 1.1.1.1 2.2.2.2 0 - 0x0000 e1 e2\n",
		"bad timestamp":   strings.Replace(line, "1791571282.274322", "soon", 1),
		"bad secs":        strings.Replace(line, " 3 - 0x8000", " 70000 - 0x8000", 1),
		"flags not hex":   strings.Replace(line, "0x8000", "-", 1),
		"seventeen words": strings.TrimSuffix(line, "\n") + " extra\n",
	} {
		if _, err := parseRelayLog(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The shell decoder over the real dhcrelay, Kea and udhcpc captures of the
// rig (testdata/relay), through the same path ObserverCapture uses.
func TestRealRelayCapturesPassTheJudges(t *testing.T) {
	ctx := context.Background()
	dir := "../../scripts/testdata/relay/"
	const ident = "02:11:00:00:00:10"
	read := func(f string) []RelayMsg {
		m, err := decodeRelayCapture(ctx, "../..", dir+f, ident)
		if err != nil || len(m) == 0 {
			t.Fatalf("%s: %d messages, %v", f, len(m), err)
		}
		return m
	}
	cm, sm := read("real-bc-kea-renew.pcap"), read("real-bs-kea-renew.pcap")
	e := relayEnvOf(Env{})
	var bind time.Time
	for _, m := range cm {
		if m.Type == "ACK" && m.YIAddr == "10.200.10.100" && (bind.IsZero() || m.At.Before(bind)) {
			bind = m.At
		}
	}
	if o := judgeC12Wire(e, ident, cm, sm, bind); o.kind != relayOK {
		t.Errorf("real acquisition: %+v", o)
	}
	if o := judgeC12b(e, ident, "10.200.10.100", bind, cm, sm); o.kind != relayOK || !strings.Contains(o.note, "relayed copies (giaddr set) on the server leg: 1") {
		t.Errorf("real renewal: %+v", o)
	}
	// The same judge refuses the real capture once the rules differ.
	e2 := e
	e2.RelayClientMAC = "02:11:00:00:00:99"
	if o := judgeC12b(e2, ident, "10.200.10.100", bind, cm, sm); o.kind != relayFail || !strings.Contains(o.reason, "layer 2") {
		t.Errorf("wrong relay MAC: %+v", o)
	}
	e3 := e
	e3.SegGateway = "10.200.10.9"
	if o := judgeC12Wire(e3, ident, cm, sm, bind); o.kind != relayBlocked {
		t.Errorf("wrong giaddr on the real capture: %+v", o)
	}
	// Broadcast flag set and clear: both are accepted, both are recorded.
	for f, flag := range map[string]string{"real-bc-kea-b.pcap": "0x8000", "real-bc-kea-nob.pcap": "0x0000"} {
		for _, m := range read(f) {
			if m.Type == "DISCOVER" && m.Flags != flag {
				t.Errorf("%s: DISCOVER flags %s, want %s", f, m.Flags, flag)
			}
		}
	}
}

// ---- C12b ------------------------------------------------------------

func renewalWire(ident, addr string, bind time.Time) (client, server []RelayMsg) {
	at := func(ms int) time.Time { return bind.Add(time.Duration(ms) * time.Millisecond) }
	client = []RelayMsg{
		rm(bind, "ACK", "b", ident, rGW, "255.255.255.255", rCliMAC, "ff:ff:ff:ff:ff:ff", rGW, ""),
		rm(at(20), "REQUEST", "r1", ident, addr, rSrc, ident, rCliMAC, "", ""),
		rm(at(21), "ACK", "r1", ident, rGW, addr, rCliMAC, ident, rGW, ""),
	}
	client[0].YIAddr, client[1].CIAddr, client[2].YIAddr = addr, addr, addr
	server = []RelayMsg{
		rm(at(20), "REQUEST", "r1", ident, addr, rSrc, rSrvMAC, rSrcMAC, "", ""),
		rm(at(20), "REQUEST", "r1", ident, rSrvLeg, rSrc, rSrvMAC, rSrcMAC, rGW, rO82),
		rm(at(21), "ACK", "r1", ident, rSrc, addr, rSrcMAC, rSrvMAC, "", ""),
	}
	server[0].CIAddr, server[1].CIAddr = addr, addr
	return client, server
}

func TestJudgeC12b(t *testing.T) {
	const id, addr = "aa:bb:cc:00:00:01", "10.200.10.101"
	bind := time.Now()
	type tc struct {
		name   string
		client func([]RelayMsg) []RelayMsg
		server func([]RelayMsg) []RelayMsg
		want   relayKind
		sub    string
	}
	same := func(m []RelayMsg) []RelayMsg { return m }
	only := func(m []RelayMsg, keep func(RelayMsg) bool) []RelayMsg {
		var out []RelayMsg
		for _, x := range m {
			if keep(x) {
				out = append(out, x)
			}
		}
		return out
	}
	req := func(f func(*RelayMsg)) func([]RelayMsg) []RelayMsg {
		return func(m []RelayMsg) []RelayMsg { return edit(m, "REQUEST", f) }
	}
	cases := []tc{
		{"unicast renewal, routed, answered", same, same, relayOK, ""},
		{"rebind only: a broadcast REQUEST", req(func(m *RelayMsg) { m.Dst = "255.255.255.255" }), same, relayFail, "T2 rebind"},
		{"ciaddr is not the container address", req(func(m *RelayMsg) { m.CIAddr = "10.200.10.150" }), same, relayFail, "ciaddr"},
		{"ciaddr empty", req(func(m *RelayMsg) { m.CIAddr = "" }), same, relayFail, "ciaddr"},
		{"IP source is not the container address", req(func(m *RelayMsg) { m.Src = "10.200.10.150" }), same, relayFail, "ciaddr"},
		{"layer 2 destination is the source's MAC", req(func(m *RelayMsg) { m.EthDst = rSrcMAC }), same, relayFail, "layer 2"},
		{"layer 2 destination is broadcast", req(func(m *RelayMsg) { m.EthDst = "ff:ff:ff:ff:ff:ff" }), same, relayFail, "layer 2"},
		{"giaddr set by the client", req(func(m *RelayMsg) { m.GIAddr = rGW }), same, relayFail, "giaddr"},
		{"no REQUEST after the bind", func(m []RelayMsg) []RelayMsg {
			return only(m, func(x RelayMsg) bool { return x.Type != "REQUEST" })
		}, same, relayFail, "no REQUEST"},
		{"the renewal never reaches the server segment", same, func(m []RelayMsg) []RelayMsg {
			return only(m, func(x RelayMsg) bool { return x.Type != "REQUEST" })
		}, relayBlocked, "never shows"},
		{"another client's renewal with the same xid is no evidence", same, func(m []RelayMsg) []RelayMsg {
			return edit(m, "REQUEST", func(x *RelayMsg) { x.CHAddr = "aa:bb:cc:00:00:99" })
		}, relayBlocked, "never shows"},
		{"only the relayed copy reaches the server", same, func(m []RelayMsg) []RelayMsg {
			return only(m, func(x RelayMsg) bool { return x.Type != "REQUEST" || x.GIAddr != "" })
		}, relayBlocked, "forwarded copy"},
		{"the routed copy carries option 82", same, req(func(m *RelayMsg) {
			if m.GIAddr == "" {
				m.Opt82 = rO82
			}
		}), relayBlocked, "relay side added it"},
		{"the client's own renewal carries option 82", req(func(m *RelayMsg) { m.Opt82 = rO82 }), same, relayFail, "client's renewal REQUEST"},
		{"the client's renewal carries option 82 and so does the routed copy: the plugin is charged", req(func(m *RelayMsg) { m.Opt82 = rO82 }), req(func(m *RelayMsg) {
			if m.GIAddr == "" {
				m.Opt82 = rO82
			}
		}), relayFail, "client's renewal REQUEST"},
		{"the ACK never reaches the client", func(m []RelayMsg) []RelayMsg {
			return only(m, func(x RelayMsg) bool { return x.XID != "r1" || x.Type != "ACK" })
		}, same, relayFail, "no ACK"},
		{"an ACK of another xid does not count", func(m []RelayMsg) []RelayMsg {
			return edit(m, "ACK", func(x *RelayMsg) {
				if x.XID == "r1" {
					x.XID = "zz"
				}
			})
		}, same, relayFail, "no ACK"},
		{"a broadcast REQUEST follows the unicast one", func(m []RelayMsg) []RelayMsg {
			return append(m, rm(bind.Add(40*time.Millisecond), "REQUEST", "r2", id, addr, "255.255.255.255", id, "ff:ff:ff:ff:ff:ff", "", ""))
		}, same, relayFail, "broadcast a REQUEST"},
		{"a REQUEST from before the bind is not the renewal", func(m []RelayMsg) []RelayMsg {
			return append(m, rm(bind.Add(-time.Second), "REQUEST", "r0", id, "0.0.0.0", "255.255.255.255", id, "ff:ff:ff:ff:ff:ff", "", ""))
		}, same, relayOK, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := relayEnvOf(Env{})
			cm, sm := renewalWire(id, addr, bind)
			o := judgeC12b(e, id, addr, bind, c.client(cm), c.server(sm))
			if o.kind != c.want || (c.sub != "" && !strings.Contains(o.reason, c.sub)) {
				t.Fatalf("kind %d reason %q, want kind %d containing %q", o.kind, o.reason, c.want, c.sub)
			}
			if c.want == relayOK && !strings.Contains(o.note, "relayed copies (giaddr set) on the server leg: 1") {
				t.Errorf("note %q", o.note)
			}
		})
	}
	// An empty RelayClientMAC would make the layer 2 rule vacuous.
	e := relayEnvOf(Env{})
	e.RelayClientMAC = ""
	cm, sm := renewalWire(id, addr, bind)
	if o := judgeC12b(e, id, addr, bind, cm, sm); o.kind != relayFail {
		t.Errorf("empty RelayClientMAC passed: %+v", o)
	}
}

// ---- the run bodies, against fakes -------------------------------------

// relayCap serves both observers of a relay cell from a function of the
// identity; Messages returns the plain view the bind wait reads.
type relayCap struct {
	mu  sync.Mutex
	fn  func(ident string) []RelayMsg
	err error
	// plainUntil, when set, cuts the plain view at the bind: the bind wait
	// runs before a renewal exists, as on the real capture.
	plainUntil func() time.Time
}

func (c *relayCap) msgs(ident string) []RelayMsg {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fn == nil {
		return nil
	}
	return c.fn(ident)
}

func (c *relayCap) Messages(_ context.Context, ident, snap string) ([]DHCPMsg, error) {
	if c.err != nil {
		return nil, c.err
	}
	if err := os.WriteFile(snap, []byte("pcap"), 0o644); err != nil {
		return nil, err
	}
	var out []DHCPMsg
	for _, m := range c.msgs(ident) {
		if c.plainUntil != nil && m.At.After(c.plainUntil()) {
			continue
		}
		out = append(out, m.DHCPMsg)
	}
	return out, nil
}

func (c *relayCap) RelayMessages(_ context.Context, ident, snap string) ([]RelayMsg, error) {
	if c.err != nil {
		return nil, c.err
	}
	if err := os.WriteFile(snap, []byte("pcap"), 0o644); err != nil {
		return nil, err
	}
	return c.msgs(ident), nil
}

// needRemoved: the container went, whatever networks the run also made.
func needRemoved(t *testing.T, h *bRunner, container string) {
	t.Helper()
	for _, c := range h.cmds {
		if strings.HasSuffix(c, "docker rm -f "+container) {
			return
		}
	}
	t.Errorf("container %s was never removed", container)
}

// routeHost answers the container's route table like a relay cell does:
// default via the relay's client address (10.200.10.1 = 010AC80A).
type routeHost struct {
	*cRunner
	gw string
}

func (r *routeHost) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "cat /proc/net/route") {
		return "Iface\tDestination\tGateway\tFlags\neth0\t00000000\t" + r.gw + "\t0003\n", nil
	}
	return r.cRunner.Run(ctx, cmd)
}

const routeViaRelay = "010AC80A"

type relayRig struct {
	*cRig
	client, server *relayCap
	host           *routeHost
	bind           time.Time
	wire           func(ident, addr string, bind time.Time) (c, s []RelayMsg)
	mutate         func(side, ident string, m []RelayMsg) []RelayMsg
}

func relayRigOf(t *testing.T, scenario string, wire func(ident, addr string, bind time.Time) (c, s []RelayMsg)) *relayRig {
	t.Helper()
	r := &relayRig{cRig: cSetup(t, ShapeMacvlan), client: &relayCap{}, server: &relayCap{}, wire: wire}
	r.host = &routeHost{cRunner: r.h, gw: routeViaRelay}
	r.h.addrFn = func(name, mac string) string {
		if strings.HasSuffix(name, "-c12s") {
			return "10.200.10.102"
		}
		return "10.200.10.101"
	}
	r.e = relayEnvOf(r.e)
	r.e.Host, r.e.Capture, r.e.ServerCapture = r.host, r.client, r.server
	addrOf := func(ident string) string {
		r.h.mu.Lock()
		defer r.h.mu.Unlock()
		for _, c := range r.h.containers {
			if c.mac == ident {
				return c.addr
			}
		}
		return "10.200.10.250"
	}
	serve := func(side string) func(string) []RelayMsg {
		return func(ident string) []RelayMsg {
			if r.bind.IsZero() {
				r.bind = time.Now()
			}
			c, s := r.wire(ident, addrOf(ident), r.bind)
			m := c
			if side == "server" {
				m = s
			}
			if r.mutate != nil {
				m = r.mutate(side, ident, m)
			}
			return m
		}
	}
	r.client.fn, r.server.fn = serve("client"), serve("server")
	r.src.fn = func(int) []sourceadapter.Lease {
		var ls []sourceadapter.Lease
		r.h.mu.Lock()
		defer r.h.mu.Unlock()
		for _, c := range r.h.containers {
			ls = append(ls, sourceadapter.Lease{MAC: c.mac, Address: c.addr, Expires: time.Now().Add(time.Hour)})
		}
		return ls
	}
	return r
}

func acquisition(ident, addr string, bind time.Time) ([]RelayMsg, []RelayMsg) {
	return goodWire(ident, addr, bind)
}

func TestRunC12PassesThroughTheRelayOnBothNetworks(t *testing.T) {
	r := relayRigOf(t, NameC12, acquisition)
	v := runC12Tuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, r.e, v)
	for _, want := range []string{"main leased 10.200.10.101", "c12s leased 10.200.10.102"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("reason %q lacks %q", v.Reason, want)
		}
	}
	// Each container keeps its own bind snapshot and evidence entry (#11).
	m, c := v.Evidence["capture-bind-main"], v.Evidence["capture-bind-c12s"]
	if m == "" || c == "" || m == c {
		t.Fatalf("bind evidence entries: main %q, c12s %q", m, c)
	}
	for _, p := range []string{m, c} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("bind evidence %s: %v", p, err)
		}
	}
	// The second network allows the source and denies the relay.
	if !r.h.has("dhcp_servers=10.200.11.2") || !r.h.has("dhcp_deny_servers=10.200.10.1") {
		t.Errorf("the -c12s network lacks its server options: %v", r.h.cmds)
	}
	needCleanup(t, r.h.bRunner, "c12s", containerName(r.e, NameC12)+"-c12s")
	needRemoved(t, r.h.bRunner, containerName(r.e, NameC12))
}

func TestRunC12Judges(t *testing.T) {
	for _, c := range []struct {
		name    string
		mutate  func(side, ident string, m []RelayMsg) []RelayMsg
		gw      string
		res     Result
		sub     string
		second  bool // the break is on the -c12s container only
		noLease bool
	}{
		{"bypassed relay", func(side, id string, m []RelayMsg) []RelayMsg {
			if side == "client" {
				return append(m, rm(time.Now().Add(-time.Hour), "OFFER", "x1", id, rSrc, "255.255.255.255", rSrcMAC, "ff:ff:ff:ff:ff:ff", "", ""))
			}
			return m
		}, routeViaRelay, BLOCKED, "from the source itself", false, false},
		{"option 82 not echoed on the second network", func(side, id string, m []RelayMsg) []RelayMsg {
			if side == "server" && id == "aa:bb:cc:00:00:02" {
				return edit(m, "ACK", func(x *RelayMsg) { x.Opt82 = "0x0203726c79010465746831" })
			}
			return m
		}, routeViaRelay, BLOCKED, "c12s: ", true, false},
		{"default route is the source, not the relay", nil, "0200C80A", FAIL, "default route", false, false},
		{"client OFFER keeps option 82", func(side, id string, m []RelayMsg) []RelayMsg {
			if side == "client" {
				return edit(m, "OFFER", func(x *RelayMsg) { x.Opt82 = rO82 })
			}
			return m
		}, routeViaRelay, FAIL, "strip", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := relayRigOf(t, NameC12, acquisition)
			r.mutate, r.host.gw = c.mutate, c.gw
			v := runC12Tuned(context.Background(), r.e, cFast)
			needResult(t, v, c.res)
			needReason(t, v, c.sub)
			needWritten(t, r.e, v)
			// A failed run leaves neither network nor container behind.
			needRemoved(t, r.h.bRunner, containerName(r.e, NameC12))
			if c.second {
				needCleanup(t, r.h.bRunner, "c12s", containerName(r.e, NameC12)+"-c12s")
			}
		})
	}
}

func TestRunC12BlocksWithoutTheRelayFacts(t *testing.T) {
	for name, mut := range map[string]func(*Env){
		"no client MAC":          func(e *Env) { e.RelayClientMAC = "" },
		"no server MAC":          func(e *Env) { e.RelayServerMAC = "" },
		"no server observer":     func(e *Env) { e.ServerCapture = nil },
		"router is the source":   func(e *Env) { e.SegGateway = e.SourceAddr },
		"plain capture client":   func(e *Env) { e.Capture = &cCapture{} },
		"no router in the env":   func(e *Env) { e.SegGateway = "" },
		"no source in the env":   func(e *Env) { e.SourceAddr = "" },
		"server reader is plain": func(e *Env) { e.ServerCapture = &cCapture{} },
	} {
		t.Run(name, func(t *testing.T) {
			for _, run := range []func(context.Context, Env, cTiming) Verdict{runC12Tuned, runC12bTuned} {
				r := relayRigOf(t, NameC12, acquisition)
				mut(&r.e)
				v := run(context.Background(), r.e, cFast)
				needResult(t, v, BLOCKED)
				if r.h.has("docker run") || r.h.has("docker network create") {
					t.Errorf("a container or network was created before the cell was checked: %v", r.h.cmds)
				}
			}
		})
	}
}

func TestC12IsNotApplicableOnTheIPAMShapesAndC12bRuns(t *testing.T) {
	for _, shape := range []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} {
		r := relayRigOf(t, NameC12, acquisition)
		r.e.Shape = shape
		needResult(t, runC12Tuned(context.Background(), r.e, cFast), NA)
		r = c12bRig(t)
		r.e.Shape = shape
		needResult(t, runC12bTuned(context.Background(), r.e, cFast), PASS)
	}
}

func c12bRig(t *testing.T) *relayRig {
	r := relayRigOf(t, NameC12b, renewalWire)
	r.client.plainUntil = func() time.Time { return r.bind }
	call := 0
	var before time.Time
	r.src.fn = func(int) []sourceadapter.Lease {
		call++
		if before.IsZero() {
			before = time.Now().Add(2 * time.Minute)
		}
		exp := before
		if call > 1 {
			exp = before.Add(time.Minute)
		}
		r.h.mu.Lock()
		defer r.h.mu.Unlock()
		var ls []sourceadapter.Lease
		for _, c := range r.h.containers {
			ls = append(ls, sourceadapter.Lease{MAC: c.mac, Address: c.addr, Expires: exp})
		}
		return ls
	}
	return r
}

func TestRunC12bPassesOnAUnicastRenewalThroughTheRelay(t *testing.T) {
	r := c12bRig(t)
	v := runC12bTuned(context.Background(), r.e, cFast)
	needResult(t, v, PASS)
	needWritten(t, r.e, v)
	if !r.src.shortened || !r.src.restored {
		t.Errorf("lease time shortened=%v restored=%v", r.src.shortened, r.src.restored)
	}
	needRemoved(t, r.h.bRunner, containerName(r.e, NameC12b))
}

func TestRunC12bJudges(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(side, ident string, m []RelayMsg) []RelayMsg
		res    Result
		sub    string
	}{
		{"wrong ciaddr", func(side, id string, m []RelayMsg) []RelayMsg {
			if side == "client" {
				return edit(m, "REQUEST", func(x *RelayMsg) { x.CIAddr = "10.200.10.150" })
			}
			return m
		}, FAIL, "ciaddr"},
		{"rebind instead of renewal", func(side, id string, m []RelayMsg) []RelayMsg {
			if side == "client" {
				return edit(m, "REQUEST", func(x *RelayMsg) { x.Dst = "255.255.255.255" })
			}
			return m
		}, FAIL, "rebind"},
		{"renewal lost between the segments", func(side, id string, m []RelayMsg) []RelayMsg {
			if side == "server" {
				return nil
			}
			return m
		}, BLOCKED, "never shows"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := c12bRig(t)
			r.mutate = c.mutate
			v := runC12bTuned(context.Background(), r.e, cFast)
			needResult(t, v, c.res)
			needReason(t, v, c.sub)
			needWritten(t, r.e, v)
			if !r.src.restored {
				t.Error("the lease time was not restored")
			}
			needRemoved(t, r.h.bRunner, containerName(r.e, NameC12b))
		})
	}
}

func TestRunC12bFailsWhenTheLeaseDidNotMove(t *testing.T) {
	r := c12bRig(t)
	r.src.fn = func(int) []sourceadapter.Lease {
		r.h.mu.Lock()
		defer r.h.mu.Unlock()
		var ls []sourceadapter.Lease
		for _, c := range r.h.containers {
			ls = append(ls, sourceadapter.Lease{MAC: c.mac, Address: c.addr, Expires: time.Now().Add(time.Hour).Truncate(time.Hour)})
		}
		return ls
	}
	v := runC12bTuned(context.Background(), r.e, cFast)
	needResult(t, v, FAIL)
	needReason(t, v, "expiry did not move")
}

// The wait is bind + c12bWait, taken from the capture's own bind time.
func TestC12bWaitsForTheRenewalWindow(t *testing.T) {
	if cDefault.c12bWait != 75*time.Second || cDefault.lease != 120 {
		t.Fatalf("C12b waits %s on a %d s lease, want 75 s on 120 s (T1 = 60 s, T2 = 105 s)", cDefault.c12bWait, cDefault.lease)
	}
}

// ---- catalog and demand ------------------------------------------------

func TestRelayScenariosAreRegisteredWithTheirPoolDemand(t *testing.T) {
	var got = map[string][]sourceadapter.Capability{}
	for _, s := range Catalog {
		if s.Name == NameC12 || s.Name == NameC12b {
			got[s.Name] = s.Needs
		}
	}
	for _, n := range []string{NameC12, NameC12b} {
		if len(got[n]) != 1 || got[n][0] != sourceadapter.CapRelay {
			t.Errorf("%s needs %v, want exactly relay", n, got[n])
		}
	}
	if NameC12b != "C12b-relay-renewal" {
		t.Errorf("NameC12b = %q", NameC12b)
	}
	if poolDemand[NameC12] != 2 || poolDemand[NameC12b] != 1 {
		t.Errorf("pool demand C12 %d C12b %d, want 2 and 1", poolDemand[NameC12], poolDemand[NameC12b])
	}
	relay := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4, sourceadapter.CapRelay}}
	plain := &fakeAdapter{caps: []sourceadapter.Capability{sourceadapter.CapV4}}
	if d := PoolDemand([]Scenario{{Name: NameC12, Needs: []sourceadapter.Capability{sourceadapter.CapRelay}}, {Name: NameC12b, Needs: []sourceadapter.Capability{sourceadapter.CapRelay}}}, relay); d != 3 {
		t.Errorf("relay cell demand for C12+C12b = %d, want 3", d)
	}
	if d := PoolDemand(Catalog, relay) - PoolDemand(Catalog, plain); d != 3 {
		t.Errorf("the relay capability adds %d addresses, want 3", d)
	}
}

// A13 follows the relay (#11): behind it the router is the relay's client
// leg (SegGateway), never the source's own address.
func TestRunA13OnARelayCellComparesTheRouteToTheRelayLeg(t *testing.T) {
	cell, shape := "kea-relay", ShapeMacvlan
	for _, c := range []struct {
		name, route string
		res         Result
	}{
		{"default via the relay leg 10.200.10.1", a13Route("010AC80A"), PASS},
		{"default via the source 10.200.11.2", a13Route("020BC80A"), FAIL},
	} {
		t.Run(c.name, func(t *testing.T) {
			internalNet := NetworkName(cell, shape) + "-a13-internal"
			host := &a13Runner{
				internalNet: internalNet,
				mac:         "aa:bb:cc:dd:ee:05", addr: "10.200.10.105", endpointID: "97ce0dfd016fae55",
				internalMac: "aa:bb:cc:dd:ee:06", internalAddr: "172.20.0.2", internalEP: "ep-13b",
				route: c.route,
			}
			source := &fakeAdapter{leases: []sourceadapter.Lease{{MAC: host.mac, Address: host.addr}}}
			e := relayEnvOf(Env{
				Host: host, Source: source, Cell: cell, Shape: shape, Network: "net1",
				EvidenceDir: t.TempDir(), GitSHA: "sha",
			})
			v := runA13(context.Background(), e)
			needResult(t, v, c.res)
			if c.res == FAIL {
				needReason(t, v, "default route")
			}
		})
	}
}

// The FORCERENEW scenario on a relay cell reads the frame's Ethernet source on the client
// leg (DESIGN-11 section 6, #11); a plain cell never asks for it.
func TestJudgeF8ReadsTheLayer2SourceOnARelayCell(t *testing.T) {
	relayed := func(ethSrc string) f8Obs {
		o := f8Base()
		o.relayMAC = rCliMAC
		for _, s := range o.sends {
			o.relayMsgs = append(o.relayMsgs, RelayMsg{DHCPMsg: DHCPMsg{Type: "FORCERENEW", XID: s.XID}, EthSrc: ethSrc})
		}
		return o
	}
	if o := judgeF8(relayed(rCliMAC)); o.Result != PASS {
		t.Fatalf("relay MAC: %s: %s", o.Result, o.Reason)
	}
	if o := judgeF8(relayed(rSrcMAC)); o.Result != BLOCKED || !strings.Contains(o.Reason, "did not route it") {
		t.Errorf("source MAC: %+v", o)
	}
	o := relayed(rCliMAC)
	o.relayMsgs = o.relayMsgs[:2]
	if got := judgeF8(o); got.Result != BLOCKED || !strings.Contains(got.Reason, "no signed FORCERENEW") {
		t.Errorf("a FORCERENEW missing from the relay view: %+v", got)
	}
	plain := relayed(rSrcMAC)
	plain.relayMAC = ""
	if got := judgeF8(plain); got.Result != PASS {
		t.Errorf("plain cell with relay data present: %+v", got)
	}
}

func TestRunF8ReadsTheRelayClientLegOnlyOnARelayCell(t *testing.T) {
	for _, c := range []struct {
		name   string
		relay  bool
		ethSrc string
		want   Result
		reads  int
	}{
		{"relay cell, routed by the relay", true, rCliMAC, PASS, 1},
		{"relay cell, eth source is the source itself", true, rSrcMAC, BLOCKED, 1},
		{"plain cell, the same eth source", false, rSrcMAC, PASS, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newF8Fix(t, tagNew)
			f.cap.ethSrc = c.ethSrc
			if c.relay {
				f.e = relayEnvOf(f.e)
				f.e.ServerCapture = f.cap
			}
			needResult(t, runF8(context.Background(), f.e), c.want)
			if f.cap.relayCalls != c.reads {
				t.Errorf("relay reads = %d, want %d", f.cap.relayCalls, c.reads)
			}
		})
	}
}

// On ipvlan chaddr is the parent MAC and the identity is the client id;
// a reply that does not echo option 61 belongs to the request with its xid.
func TestOwnedByLinksRepliesToTheirRequestsByXID(t *testing.T) {
	const id, parent = "01:aa:bb:cc:00:00:07", "02:11:00:00:00:99"
	req := rm(time.Now(), "REQUEST", "x1", parent, "0.0.0.0", "255.255.255.255", parent, "ff:ff:ff:ff:ff:ff", "", "")
	req.ClientID = id
	ack := rm(time.Now(), "ACK", "x1", parent, rSrc, rGW, rSrcMAC, rSrvMAC, rGW, rO82)
	other := rm(time.Now(), "ACK", "x2", parent, rSrc, rGW, rSrcMAC, rSrvMAC, rGW, rO82)
	otherReq := rm(time.Now(), "REQUEST", "x2", parent, "0.0.0.0", "255.255.255.255", parent, "ff:ff:ff:ff:ff:ff", "", "")
	otherReq.ClientID = "01:aa:bb:cc:00:00:08"
	got := ownedBy([]RelayMsg{req, ack, other, otherReq}, id)
	if len(got) != 2 || got[0].Type != "REQUEST" || got[1].XID != "x1" || got[1].Type != "ACK" {
		t.Fatalf("kept %+v, want the REQUEST and the ACK of xid x1", got)
	}
	if got := ownedBy([]RelayMsg{ack}, id); len(got) != 0 {
		t.Errorf("a reply with no request of this identity was kept: %+v", got)
	}
}
