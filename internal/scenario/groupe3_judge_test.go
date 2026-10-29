package scenario

import (
	"strings"
	"testing"
)

const e3ID = "0123456789abcdef0123456789abcdef"

func link(name, master string, alt ...string) ipLink {
	return ipLink{Name: name, Master: master, Kind: "veth", Altnames: alt}
}

// A real `ip -d -o link show` line of each kind the judges read. (#15)
func TestParseIPLinks(t *testing.T) {
	out := strings.Join([]string{
		`2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:aa:bb:cc brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 68 maxmtu 65535 addrgenmode eui64 numtxqueues 1`,
		`9: dh-0123456789ab@if8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-lab state UP mode DEFAULT group default qlen 1000\    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff link-netnsid 1 promiscuity 1 minmtu 68 maxmtu 65535 \    veth \    bridge_slave state forwarding\    altname dh-aaaaaaaaaaaa`,
		`10: eth1.100@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000 alias docker-net-dhcp\    link/ether 52:54:00:aa:bb:cc brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 65535 \    vlan protocol 802.1Q id 100 <REORDER_HDR> addrgenmode eui64`,
		`11: eth1.100: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000\    link/ether 02:00:00:00:00:02 brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 0 maxmtu 0 \    dummy addrgenmode eui64 numtxqueues 1`,
	}, "\n")
	ls := parseIPLinks(out)
	if len(ls) != 4 {
		t.Fatalf("%d links: %+v", len(ls), ls)
	}
	if ls[1].Name != "dh-0123456789ab" || ls[1].Master != "br-lab" || ls[1].Kind != "veth" || len(ls[1].Altnames) != 1 || ls[1].Altnames[0] != "dh-aaaaaaaaaaaa" {
		t.Errorf("veth: %+v", ls[1])
	}
	v := ls[2]
	if v.Kind != "vlan" || v.VlanProto != "802.1Q" || v.VlanID != 100 || v.Parent != "eth1" || v.Alias != "docker-net-dhcp" {
		t.Errorf("vlan: %+v", v)
	}
	if ls[3].Kind != "dummy" || ls[3].Parent != "" {
		t.Errorf("dummy: %+v", ls[3])
	}
}

func TestKernelAtLeast(t *testing.T) {
	for in, want := range map[string]bool{"6.1.0-13-amd64": false, "6.2.0": true, "6.12.113+deb13": true, "5.15.0-91-generic": false, "7.0.1": true} {
		if got, ok := kernelAtLeast(in, 6, 2); !ok || got != want {
			t.Errorf("%s: %v %v", in, got, ok)
		}
	}
	if _, ok := kernelAtLeast("garbage", 6, 2); ok {
		t.Error("garbage parsed")
	}
}

func e3aBridgeBase() e3aBridgeObs {
	id2 := "fedcba9876543210fedcba9876543210"
	return e3aBridgeObs{
		Kernel: "6.12.1", Bridge: "br-lab", EndpointID: e3ID, RenameName: "e3a-hn", RenameEndpoint: id2,
		Before:        []ipLink{link("eth1", "")},
		During:        []ipLink{link("eth1", ""), link("dh-0123456789ab", "br-lab")},
		After:         []ipLink{link("eth1", "")},
		RenameDuring:  []ipLink{link("eth1", ""), link("e3a-hn", "br-lab", "dh-fedcba987654")},
		RenameAfter:   []ipLink{link("eth1", "")},
		AppliedDelta:  1,
		FailuresDelta: 0,
	}
}

func TestJudgeE3aBridge(t *testing.T) {
	old := func(o *e3aBridgeObs) {
		o.Kernel = "6.1.0-13-amd64"
		o.RenameDuring = []ipLink{link("eth1", ""), link("dh-fedcba987654", "br-lab")}
		o.AppliedDelta, o.FailuresDelta = 0, 1
	}
	cases := []struct {
		name string
		mod  func(*e3aBridgeObs)
		want Result
		frag string
	}{
		{"new kernel renames", func(o *e3aBridgeObs) {}, PASS, "altname"},
		// row 8: old kernel, rename fails, counted PASS from dh- name plus failures +1 (#15)
		{"old kernel rename failure is a pass", old, PASS, "below 6.2"},
		{"old kernel but the link was renamed", func(o *e3aBridgeObs) {
			old(o)
			o.RenameDuring = []ipLink{link("e3a-hn", "br-lab")}
		}, FAIL, "must fail there"},
		{"old kernel without the failure counter", func(o *e3aBridgeObs) { old(o); o.FailuresDelta = 0 }, FAIL, "host_ifname_failures"},
		{"new kernel kept the dh- name", func(o *e3aBridgeObs) {
			o.RenameDuring = []ipLink{link("dh-fedcba987654", "br-lab")}
		}, FAIL, "no link named e3a-hn"},
		{"new kernel failure counter moved", func(o *e3aBridgeObs) { o.FailuresDelta = 1 }, FAIL, "want +1 and +0"},
		{"new kernel lost the altname", func(o *e3aBridgeObs) { o.RenameDuring = []ipLink{link("e3a-hn", "br-lab")} }, FAIL, "altname"},
		{"unreadable kernel", func(o *e3aBridgeObs) { o.Kernel = "?" }, BLOCKED, "kernel"},
		// defeat a: a leftover of ANOTHER endpoint's ID, and an altname-only leftover (#15)
		{"leftover of another endpoint", func(o *e3aBridgeObs) {
			o.After = append(o.After, link("dh-ffffffffffff", "br-lab"))
		}, FAIL, "dh-ffffffffffff"},
		{"leftover by altname only", func(o *e3aBridgeObs) {
			o.RenameAfter = append(o.RenameAfter, link("e3a-hn", "", "dh-fedcba987654"))
		}, FAIL, "e3a-hn"},
		{"leftover by bridge master only", func(o *e3aBridgeObs) {
			o.After = append(o.After, link("veth9", "br-lab"))
		}, FAIL, "veth9"},
		// preservation control: a dh- link that was already there (another
		// container on the host) is not a leftover of this run (#15)
		{"older dh- link stays", func(o *e3aBridgeObs) {
			pre := link("dh-ffffffffffff", "br-lab")
			o.Before = append(o.Before, pre)
			o.During = append(o.During, pre)
			o.After = append(o.After, pre)
			o.RenameAfter = append(o.RenameAfter, pre)
		}, PASS, "altname"},
		{"default name wrong", func(o *e3aBridgeObs) { o.During = []ipLink{link("dh-ffffffffffff", "br-lab")} }, FAIL, "no host-side link dh-0123456789ab"},
		{"default link on the wrong master", func(o *e3aBridgeObs) { o.During = []ipLink{link("dh-0123456789ab", "docker0")} }, FAIL, "master"},
	}
	for _, c := range cases {
		o := e3aBridgeBase()
		c.mod(&o)
		got := judgeE3aBridge(o)
		if got.Result != c.want || !strings.Contains(got.Reason, c.frag) {
			t.Errorf("%s: %s %q, want %s containing %q", c.name, got.Result, got.Reason, c.want, c.frag)
		}
	}
}

func TestJudgeE3aParent(t *testing.T) {
	base := func() e3aParentObs {
		return e3aParentObs{Mode: "macvlan", Before: []ipLink{link("eth1", "")}, During: []ipLink{link("eth1", "")},
			RefusalErr: "ssh: err: Error response from daemon: host_ifname cannot be set in mode=macvlan: the host-side link"}
	}
	cases := []struct {
		name string
		mod  func(*e3aParentObs)
		want Result
		frag string
	}{
		{"clean", func(o *e3aParentObs) {}, PASS, "refused"},
		{"a dh- link appeared", func(o *e3aParentObs) { o.During = append(o.During, link("dh-0123456789ab", "")) }, FAIL, "moves the link"},
		// defeat d: any error is not the documented one; success is not a refusal (#15)
		{"another error", func(o *e3aParentObs) { o.RefusalErr = "ssh: err: network already exists" }, FAIL, "another error"},
		{"empty error", func(o *e3aParentObs) { o.RefusalErr = "" }, FAIL, "another error"},
		{"wrong mode in the text", func(o *e3aParentObs) { o.RefusalErr = "host_ifname cannot be set in mode=bridge" }, FAIL, "another error"},
		{"created", func(o *e3aParentObs) { o.RefusalCreated = true }, FAIL, "was created"},
		{"child left on the parent", func(o *e3aParentObs) { o.Left = []string{"mac0"} }, FAIL, "mac0"},
	}
	for _, c := range cases {
		o := base()
		c.mod(&o)
		got := judgeE3aParent(o)
		if got.Result != c.want || !strings.Contains(got.Reason, c.frag) {
			t.Errorf("%s: %s %q, want %s containing %q", c.name, got.Result, got.Reason, c.want, c.frag)
		}
	}
}

const e3bTagged = `10:00:01.000000 52:54:00:11:22:33 > 52:54:00:44:55:66, ethertype 802.1Q (0x8100), length 346: vlan 100, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 328)
    10.200.153.2.67 > 10.200.153.150.68: BOOTP/DHCP, Reply, length 300, xid 0x1, Flags [none]
	  Your-IP 10.200.153.150
	  Client-Ethernet-Address 02:42:0a:00:00:09
	  Vendor-rfc1048 Extensions
	    DHCP-Message (53), length 1: ACK
10:00:00.500000 02:42:0a:00:00:09 > ff:ff:ff:ff:ff:ff, ethertype 802.1Q (0x8100), length 346: vlan 100, p 0, ethertype IPv4 (0x0800), (tos 0x10, ttl 128, id 1, offset 0, flags [none], proto UDP (17), length 328)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request, length 300, xid 0x1, Flags [none]
	  Client-Ethernet-Address 02:42:0a:00:00:09
`

func TestParseTaggedReplies(t *testing.T) {
	got := parseTaggedReplies(e3bTagged)
	up := parseTaggedReplies(strings.ReplaceAll(e3bTagged, "02:42:0a:00:00:09", "02:42:0A:00:00:09"))
	if len(up) != 1 || up[0].MAC != "02:42:0a:00:00:09" {
		t.Errorf("an upper-case MAC is not folded: %+v", up)
	}
	if len(got) != 1 || got[0].VLAN != 100 || got[0].YourIP != "10.200.153.150" || got[0].MAC != "02:42:0a:00:00:09" || got[0].Type != "ACK" {
		t.Fatalf("%+v", got)
	}
}

func e3bBase() e3bObs {
	vl := ipLink{Name: "eth1.100", Kind: "vlan", VlanProto: "802.1Q", VlanID: 100, Parent: "eth1", Alias: "docker-net-dhcp"}
	return e3bObs{
		Parent: "eth1", VLANName: "eth1.100", VLANSubnet: "10.200.153.0/24",
		During: []ipLink{vl}, After: []ipLink{link("eth1", "")},
		Addr: "10.200.153.150", MAC: "02:42:0a:00:00:09", LeaseFound: true, LeaseAddr: "10.200.153.150",
		Tagged:  []taggedReply{{VLAN: 100, Type: "ACK", YourIP: "10.200.153.150", MAC: "02:42:0a:00:00:09"}},
		R1Err:   "Error: vlan 100 already exists on eth1 as vlan100, and the kernel takes one per parent and ID",
		R2Err:   "Error: eth1.100 exists and is a dummy link, not a vlan; remove it",
		R2After: []ipLink{{Name: "eth1.100", Kind: "dummy"}},
	}
}

func TestJudgeE3b(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*e3bObs)
		want Result
		frag string
	}{
		{"clean", func(o *e3bObs) {}, PASS, "documented"},
		{"no vlan link", func(o *e3bObs) { o.During = nil }, FAIL, "made no eth1.100"},
		{"link is not 802.1Q", func(o *e3bObs) { o.During[0].VlanProto = "802.1ad" }, FAIL, "802.1ad"},
		{"parent is another NIC", func(o *e3bObs) { o.During[0].Parent = "eth0" }, FAIL, "parent"},
		{"no plugin alias", func(o *e3bObs) { o.During[0].Alias = "" }, FAIL, "alias"},
		// defeat b: untagged-pool lease, tagged frames also present (#15)
		{"untagged pool address", func(o *e3bObs) {
			o.Addr, o.LeaseAddr = "10.200.3.150", "10.200.3.150"
			o.Tagged[0].YourIP = "10.200.3.150"
		}, FAIL, "untagged pool"},
		{"lease missing at the source", func(o *e3bObs) { o.LeaseFound = false }, FAIL, "lease table"},
		// defeat f: nothing tagged was seen (#15)
		{"no tagged reply", func(o *e3bObs) { o.Tagged = nil }, FAIL, "tagged observer leg"},
		{"tagged reply for another client", func(o *e3bObs) { o.Tagged[0].MAC = "02:42:ff:ff:ff:ff" }, FAIL, "tagged observer leg"},
		{"tagged reply granting another address", func(o *e3bObs) { o.Tagged[0].YourIP = "10.200.153.151" }, FAIL, "tagged observer leg"},
		{"tagged reply on another VLAN", func(o *e3bObs) { o.Tagged[0].VLAN = 200 }, FAIL, "tagged observer leg"},
		{"link left behind", func(o *e3bObs) { o.After = append(o.After, o.During[0]) }, FAIL, "left on the host"},
		// defeat d (#15)
		{"refusal 1 another error", func(o *e3bObs) { o.R1Err = "boom" }, FAIL, "not the documented one"},
		{"refusal 1 created", func(o *e3bObs) { o.R1Created = true }, FAIL, "was created"},
		{"refusal 2 another error", func(o *e3bObs) { o.R2Err = "some error" }, FAIL, "not the documented one"},
		{"refusal 2 created", func(o *e3bObs) { o.R2Created = true }, FAIL, "was created"},
		// defeat c: the user-made link disappears or is replaced (#15)
		{"dummy gone", func(o *e3bObs) { o.R2After = nil }, FAIL, "removed a link it does not own"},
		{"dummy replaced by a vlan", func(o *e3bObs) { o.R2After = []ipLink{{Name: "eth1.100", Kind: "vlan"}} }, FAIL, "not the dummy"},
	}
	for _, c := range cases {
		o := e3bBase()
		c.mod(&o)
		got := judgeE3b(o)
		if got.Result != c.want || !strings.Contains(got.Reason, c.frag) {
			t.Errorf("%s: %s %q, want %s containing %q", c.name, got.Result, got.Reason, c.want, c.frag)
		}
	}
}
