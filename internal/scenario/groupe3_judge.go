package scenario

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Pure judges for E3a (host link names) and E3b (VLAN parent), lab #15.
// They read observations only; the runners in scenarios_group_e3.go
// collect them.

// ipLink is one line of `ip -d -o link show`. (#15)
type ipLink struct {
	Name, Master, Kind, Alias, VlanProto, Parent string
	Altnames                                     []string
	VlanID                                       int
}

var (
	linkHeadRE   = regexp.MustCompile(`^\d+:\s+([^:@\s]+)(?:@([^:\s]+))?:`)
	linkMasterRE = regexp.MustCompile(`\bmaster (\S+)`)
	linkAliasRE  = regexp.MustCompile(`\balias ([^\s\\]+)`)
	linkAltRE    = regexp.MustCompile(`\baltname (\S+)`)
	linkVlanRE   = regexp.MustCompile(`\bvlan protocol (\S+) id (\d+)`)
	linkKindRE   = regexp.MustCompile(`maxmtu \d+\s*\\?\s*(\w+)`)
)

func parseIPLinks(out string) []ipLink {
	var links []ipLink
	for _, line := range strings.Split(out, "\n") {
		h := linkHeadRE.FindStringSubmatch(line)
		if h == nil {
			continue
		}
		l := ipLink{Name: h[1], Parent: h[2]}
		if m := linkMasterRE.FindStringSubmatch(line); m != nil {
			l.Master = m[1]
		}
		if m := linkAliasRE.FindStringSubmatch(line); m != nil {
			l.Alias = m[1]
		}
		for _, m := range linkAltRE.FindAllStringSubmatch(line, -1) {
			l.Altnames = append(l.Altnames, m[1])
		}
		if m := linkVlanRE.FindStringSubmatch(line); m != nil {
			l.VlanProto = m[1]
			l.VlanID, _ = strconv.Atoi(m[2])
			l.Kind = "vlan"
		} else if m := linkKindRE.FindStringSubmatch(line); m != nil {
			l.Kind = m[1]
		}
		links = append(links, l)
	}
	return links
}

func findLink(links []ipLink, name string) (ipLink, bool) {
	for _, l := range links {
		if l.Name == name {
			return l, true
		}
	}
	return ipLink{}, false
}

func hasAltPrefix(l ipLink, prefix string) bool {
	for _, a := range l.Altnames {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

// hostLinkLeftovers is every link in after that the plugin may have left
// behind: new against before, and a dh- name, a dh- altname or the
// network's bridge as master. It never matches on one endpoint's ID, so a
// link of another endpoint is found too (defeat a). (#15)
func hostLinkLeftovers(before, after []ipLink, bridge string) []string {
	known := map[string]bool{}
	for _, l := range before {
		known[l.Name] = true
	}
	var left []string
	for _, l := range after {
		if known[l.Name] {
			continue
		}
		if strings.HasPrefix(l.Name, "dh-") || hasAltPrefix(l, "dh-") || (bridge != "" && l.Master == bridge) {
			left = append(left, l.Name)
		}
	}
	return left
}

// kernelAtLeast reports whether release ("6.1.0-13-amd64") is at least
// major.minor; ok is false when release has no number to read. (#15)
func kernelAtLeast(release string, major, minor int) (atLeast, ok bool) {
	m := regexp.MustCompile(`^(\d+)\.(\d+)`).FindStringSubmatch(strings.TrimSpace(release))
	if m == nil {
		return false, false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	return a > major || (a == major && b >= minor), true
}

// e3aBridgeObs is E3a on the bridge shapes: leg 1 keeps the default
// host-side name, leg 2 asks for host_ifname=container_name. (#15)
type e3aBridgeObs struct {
	Kernel, Bridge                          string
	EndpointID                              string
	Before, During, After                   []ipLink
	RenameName, RenameEndpoint              string
	RenameDuring, RenameAfter               []ipLink
	AppliedDelta, FailuresDelta, ConflDelta int64
}

func judgeE3aBridge(o e3aBridgeObs) fOutcome {
	newKernel, ok := kernelAtLeast(o.Kernel, 6, 2)
	if !ok {
		return fBlocked("cannot read the docker host's kernel version from %q", o.Kernel)
	}
	if len(o.EndpointID) < 12 || len(o.RenameEndpoint) < 12 {
		return fBlocked("the endpoint ID is shorter than 12 characters")
	}
	def := "dh-" + o.EndpointID[:12]
	l, found := findLink(o.During, def)
	switch {
	case !found:
		return fFail("default leg: no host-side link %s while the container ran", def)
	case l.Master != o.Bridge:
		return fFail("default leg: %s has master %q, want the network's bridge %s", def, l.Master, o.Bridge)
	}
	if left := hostLinkLeftovers(o.Before, o.After, o.Bridge); len(left) > 0 {
		return fFail("default leg: links left on the host after the container stopped: %s", strings.Join(left, ", "))
	}
	rdef := "dh-" + o.RenameEndpoint[:12]
	if newKernel {
		r, found := findLink(o.RenameDuring, o.RenameName)
		switch {
		case !found:
			return fFail("kernel %s: no link named %s while the container ran (host_ifname=container_name)", o.Kernel, o.RenameName)
		case r.Master != o.Bridge:
			return fFail("renamed link %s has master %q, want %s", o.RenameName, r.Master, o.Bridge)
		case !slicesHas(r.Altnames, rdef):
			return fFail("renamed link %s lacks the old name %s as altname (altnames %v)", o.RenameName, rdef, r.Altnames)
		case o.AppliedDelta != 1 || o.FailuresDelta != 0:
			return fFail("kernel %s: host_ifnames_applied +%d, host_ifname_failures +%d, want +1 and +0", o.Kernel, o.AppliedDelta, o.FailuresDelta)
		}
	} else {
		if _, renamed := findLink(o.RenameDuring, o.RenameName); renamed {
			return fFail("kernel %s is below 6.2 and a link named %s exists: the rename must fail there", o.Kernel, o.RenameName)
		}
		r, found := findLink(o.RenameDuring, rdef)
		switch {
		case !found:
			return fFail("kernel %s: the link kept no dh- name %s after the failed rename", o.Kernel, rdef)
		case r.Master != o.Bridge:
			return fFail("link %s has master %q, want %s", rdef, r.Master, o.Bridge)
		case o.FailuresDelta != 1 || o.AppliedDelta != 0:
			return fFail("kernel %s: host_ifname_failures +%d, host_ifnames_applied +%d, want +1 and +0", o.Kernel, o.FailuresDelta, o.AppliedDelta)
		}
	}
	if left := hostLinkLeftovers(o.Before, o.RenameAfter, o.Bridge); len(left) > 0 {
		return fFail("rename leg: links left on the host after the container stopped: %s", strings.Join(left, ", "))
	}
	if newKernel {
		return fOK("kernel %s: default name %s on the bridge, host_ifname=container_name renamed it to %s with altname %s, nothing left", o.Kernel, def, o.RenameName, rdef)
	}
	return fOK("kernel %s is below 6.2: default name %s on the bridge; the rename failed as documented (host_ifname_failures +1) and the link kept %s, nothing left", o.Kernel, def, rdef)
}

func slicesHas(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// e3aParentObs is E3a on macvlan and ipvlan: no host-side link is named,
// and host_ifname is refused with the documented text. (#15)
type e3aParentObs struct {
	Mode           string
	Before, During []ipLink
	RefusalErr     string
	RefusalCreated bool
	Left           []string // parent children after stop and network rm
}

func judgeE3aParent(o e3aParentObs) fOutcome {
	if left := hostLinkLeftovers(o.Before, o.During, ""); len(left) > 0 {
		return fFail("%s: a dh- host-side link appeared: %s; this mode moves the link into the container", o.Mode, strings.Join(left, ", "))
	}
	want := "host_ifname cannot be set in mode=" + o.Mode
	switch {
	case o.RefusalCreated:
		return fFail("%s: the network with host_ifname=container_name was created; the plugin must refuse it with %q", o.Mode, want)
	case !strings.Contains(o.RefusalErr, want):
		return fFail("%s: the create failed with another error, want %q: %s", o.Mode, want, o.RefusalErr)
	}
	if len(o.Left) > 0 {
		return fFail("%s: links left on %s after stop and network rm: %s", o.Mode, SegmentNIC, strings.Join(o.Left, ", "))
	}
	return fOK("%s: no dh- link on the host, host_ifname refused with %q, nothing left on %s", o.Mode, want, SegmentNIC)
}

// taggedReply is one DHCP reply the tagged capture decoded. (#15)
type taggedReply struct {
	VLAN              int
	Type, YourIP, MAC string
}

var (
	tcpStampRE = regexp.MustCompile(`^\d\d:\d\d:\d\d\.\d+ `)
	tcpVlanRE  = regexp.MustCompile(`\bvlan (\d+),`)
	tcpYourRE  = regexp.MustCompile(`Your-IP (\S+)`)
	tcpMACRE   = regexp.MustCompile(`Client-Ethernet-Address (\S+)`)
	tcpTypeRE  = regexp.MustCompile(`DHCP-Message[^:]*?\(53\)[^:]*?: (\w+)`)
)

// parseTaggedReplies reads `tcpdump -n -e -vv -r` text: one record per
// timestamped line, kept when it is a BOOTP Reply under an 802.1Q tag. (#15)
func parseTaggedReplies(text string) []taggedReply {
	var recs [][]string
	for _, line := range strings.Split(text, "\n") {
		if tcpStampRE.MatchString(line) {
			recs = append(recs, nil)
		}
		if len(recs) > 0 {
			recs[len(recs)-1] = append(recs[len(recs)-1], line)
		}
	}
	var out []taggedReply
	for _, r := range recs {
		block := strings.Join(r, "\n")
		v := tcpVlanRE.FindStringSubmatch(block)
		if v == nil || !strings.Contains(block, "BOOTP/DHCP, Reply") {
			continue
		}
		t := taggedReply{}
		t.VLAN, _ = strconv.Atoi(v[1])
		if m := tcpYourRE.FindStringSubmatch(block); m != nil {
			t.YourIP = m[1]
		}
		if m := tcpMACRE.FindStringSubmatch(block); m != nil {
			t.MAC = strings.ToLower(m[1])
		}
		if m := tcpTypeRE.FindStringSubmatch(block); m != nil {
			t.Type = m[1]
		}
		out = append(out, t)
	}
	return out
}

// e3bObs is everything E3b collected. (#15)
type e3bObs struct {
	Parent, VLANName, VLANSubnet string
	During, After                []ipLink
	Addr, MAC                    string
	LeaseFound                   bool
	LeaseAddr                    string
	Tagged                       []taggedReply
	// Refusal 1: the same ID under another name (vlan100). (#15)
	R1Err     string
	R1Created bool
	// Refusal 2: a user-made dummy named eth1.100. (#15)
	R2Err     string
	R2Created bool
	R2After   []ipLink
}

const (
	e3bR1Text = "vlan 100 already exists on eth1 as vlan100"
	e3bR2Text = "eth1.100 exists and is a dummy link, not a vlan"
)

func judgeE3b(o e3bObs) fOutcome {
	l, found := findLink(o.During, o.VLANName)
	switch {
	case !found:
		return fFail("-o vlan=100 made no %s while the container ran", o.VLANName)
	case l.Kind != "vlan" || l.VlanProto != "802.1Q" || l.VlanID != 100:
		return fFail("%s is %s protocol %q id %d, want vlan 802.1Q id 100", o.VLANName, l.Kind, l.VlanProto, l.VlanID)
	case l.Parent != o.Parent:
		return fFail("%s has parent %q, want %s", o.VLANName, l.Parent, o.Parent)
	case l.Alias != "docker-net-dhcp":
		return fFail("%s carries alias %q, want docker-net-dhcp (the plugin's mark)", o.VLANName, l.Alias)
	}
	pfx, perr := netip.ParsePrefix(o.VLANSubnet)
	ip, aerr := netip.ParseAddr(o.Addr)
	if perr != nil || aerr != nil {
		return fBlocked("cannot compare the lease %q with the VLAN subnet %q", o.Addr, o.VLANSubnet)
	}
	if !pfx.Contains(ip) {
		return fFail("the container's address %s is outside the VLAN 100 subnet %s: it came from the untagged pool", o.Addr, o.VLANSubnet)
	}
	if !o.LeaseFound || o.LeaseAddr != o.Addr {
		return fFail("the source's lease table has no lease for %s (found %v, address %q)", o.Addr, o.LeaseFound, o.LeaseAddr)
	}
	tagged := false
	for _, t := range o.Tagged {
		if t.VLAN == 100 && t.YourIP == o.Addr && (o.MAC == "" || t.MAC == strings.ToLower(o.MAC)) && (t.Type == "ACK" || t.Type == "") {
			tagged = true
		}
	}
	if !tagged {
		return fFail("the tagged observer leg saw no VLAN 100 reply granting %s to %s (%d tagged replies)", o.Addr, o.MAC, len(o.Tagged))
	}
	if _, still := findLink(o.After, o.VLANName); still {
		return fFail("%s was left on the host after the last network was removed", o.VLANName)
	}
	switch {
	case o.R1Created:
		return fFail("a second network for VLAN 100 under another name (vlan100) was created; it must be refused with %q", e3bR1Text)
	case !strings.Contains(o.R1Err, e3bR1Text):
		return fFail("the vlan100 refusal is not the documented one, want %q: %s", e3bR1Text, o.R1Err)
	case o.R2Created:
		return fFail("a network over a user-made dummy %s was created; it must be refused with %q", o.VLANName, e3bR2Text)
	case !strings.Contains(o.R2Err, e3bR2Text):
		return fFail("the dummy refusal is not the documented one, want %q: %s", e3bR2Text, o.R2Err)
	}
	d, ok := findLink(o.R2After, o.VLANName)
	if !ok {
		return fFail("the user-made %s is gone after the refused create: the plugin removed a link it does not own", o.VLANName)
	}
	if d.Kind != "dummy" {
		return fFail("the user-made %s is now a %s, not the dummy the test made", o.VLANName, d.Kind)
	}
	return fOK("%s is vlan 802.1Q id 100 on %s with the plugin's alias; %s came from %s and a tagged reply granted it to %s; the link went with the network; both refusals matched the documented text and the user-made dummy survived",
		o.VLANName, o.Parent, o.Addr, o.VLANSubnet, o.MAC)
}
