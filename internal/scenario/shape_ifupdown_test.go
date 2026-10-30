package scenario

import (
	"context"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
)

const ifupdownTestCell = "host-debian11-docker2010"

var allShapes = []Shape{ShapeBridge, ShapeMacvlan, ShapeIpvlan, ShapeBridgeIPAM, ShapeMacvlanIPAM}

// cloudInitENI is what cloud-init 20.4.1's eni renderer writes for
// cloud-init/network-config.tmpl.yaml: eth1 has no `auto` line (lab #70).
const cloudInitENI = "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\n    address 10.200.255.60/24\n    dns-nameservers 10.200.255.1\n    gateway 10.200.255.1\n\niface eth1 inet manual\n"

type fakeLink struct {
	up, bridge, noV6 bool
	master           string
}

type fakeStanza struct {
	method string
	opts   []string
}

// fakeIfupdownHost is the Debian 11 docker host of lab #70: no
// /etc/netplan, ifupdown 0.8.36, bridge-utils not installed, eth1 up
// after first boot. A reboot raises only `auto` stanzas from
// interfaces.d names source-directory reads, then runs the image's
// bootcmd line. Docker refuses a macvlan/ipvlan parent that is down.
type fakeIfupdownHost struct {
	t        *testing.T
	setup    string
	files    map[string]string
	links    map[string]*fakeLink
	pkgs     map[string]bool
	ifstate  map[string]bool
	rules    map[string]int
	networks map[string]bool
	calls    []string
}

func newFakeIfupdownHost(t *testing.T, img labyaml.BaseImage) *fakeIfupdownHost {
	h := &fakeIfupdownHost{
		t:        t,
		setup:    img.SegmentNICSetup(),
		files:    map[string]string{"/etc/network/interfaces.d/50-cloud-init": cloudInitENI},
		links:    map[string]*fakeLink{"eth0": {up: true}, "eth1": {up: true}},
		pkgs:     map[string]bool{},
		ifstate:  map[string]bool{"lo": true, "eth0": true},
		rules:    map[string]int{},
		networks: map[string]bool{},
	}
	h.bootcmd()
	return h
}

// bootcmd executes the image's real setup line under sh, with the
// stanza path moved into a temp dir and ifup recorded, then applies
// what it did to the model.
func (h *fakeIfupdownHost) bootcmd() {
	if h.setup == "" {
		return
	}
	dir := h.t.TempDir()
	if body, ok := h.files[labyaml.SegmentNICStanzaPath]; ok {
		if err := os.WriteFile(filepath.Join(dir, "stanza"), []byte(body), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
	line := strings.ReplaceAll(h.setup, labyaml.SegmentNICStanzaPath, filepath.Join(dir, "stanza"))
	script := "ifup() { echo \"$*\" >>" + filepath.Join(dir, "ifup.log") + "; }\n" + line + "\n"
	if out, err := exec.Command("sh", "-c", script).CombinedOutput(); err != nil {
		h.t.Fatalf("bootcmd setup line under sh: %v: %s", err, out)
	}
	body, err := os.ReadFile(filepath.Join(dir, "stanza"))
	if err != nil {
		h.t.Fatalf("bootcmd setup line wrote no stanza: %v", err)
	}
	h.files[labyaml.SegmentNICStanzaPath] = string(body)
	log, _ := os.ReadFile(filepath.Join(dir, "ifup.log"))
	for _, l := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		if l != "" {
			_ = h.ifup(l, false)
		}
	}
}

// reboot: links reset, bridges gone, networking.service runs `ifup -a`
// (auto stanzas only), then cloud-init's per-boot bootcmd.
func (h *fakeIfupdownHost) reboot() {
	for name, l := range h.links {
		if l.bridge {
			delete(h.links, name)
			continue
		}
		*l = fakeLink{}
	}
	h.ifstate = map[string]bool{}
	_, autos := h.stanzas()
	for _, name := range autos {
		_ = h.ifup(name, false)
	}
	h.bootcmd()
}

var sourceDirectoryName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func (h *fakeIfupdownHost) stanzas() (map[string]*fakeStanza, []string) {
	ifaces := map[string]*fakeStanza{}
	var autos []string
	for _, path := range slices.Sorted(maps.Keys(h.files)) {
		if filepath.Dir(path) != "/etc/network/interfaces.d" || !sourceDirectoryName.MatchString(filepath.Base(path)) {
			continue
		}
		var cur *fakeStanza
		for _, line := range strings.Split(h.files[path], "\n") {
			f := strings.Fields(line)
			switch {
			case len(f) == 0:
			case f[0] == "auto":
				autos = append(autos, f[1:]...)
				cur = nil
			case f[0] == "iface" && len(f) == 4:
				if ifaces[f[1]] == nil {
					ifaces[f[1]] = &fakeStanza{}
				}
				cur = ifaces[f[1]]
				cur.method = f[3]
			case cur != nil && line[0] == ' ':
				cur.opts = append(cur.opts, strings.Join(f, " "))
			}
		}
	}
	return ifaces, autos
}

func (s *fakeStanza) opt(key string) string {
	for _, o := range s.opts {
		if v, ok := strings.CutPrefix(o, key+" "); ok {
			return v
		}
	}
	return ""
}

func (h *fakeIfupdownHost) ifup(name string, force bool) error {
	ifaces, _ := h.stanzas()
	s := ifaces[name]
	if s == nil {
		return fmt.Errorf("ifup: unknown interface %s", name)
	}
	if h.ifstate[name] && !force {
		return nil
	}
	if port := s.opt("bridge_ports"); port != "" && h.pkgs["bridge-utils"] {
		if h.links[name] == nil {
			h.links[name] = &fakeLink{bridge: true}
		}
		if p := h.links[port]; p != nil && p.master != name {
			p.noV6, p.master, p.up = true, name, true
		}
	}
	l := h.links[name]
	if l == nil {
		return fmt.Errorf("ifup: Cannot find device %q", name)
	}
	switch {
	case s.method == "dhcp":
		l.up = true
	case s.opt("up") == "ip link set "+name+" up":
		l.up = true
	}
	h.ifstate[name] = true
	return nil
}

func (h *fakeIfupdownHost) ifdown(name string) error {
	if !h.ifstate[name] {
		return nil
	}
	ifaces, _ := h.stanzas()
	s := ifaces[name]
	if s == nil {
		return fmt.Errorf("ifdown: unknown interface %s", name)
	}
	if l := h.links[name]; l != nil {
		l.up = false
	}
	if port := s.opt("bridge_ports"); port != "" && h.pkgs["bridge-utils"] {
		if p := h.links[port]; p != nil && p.master == name {
			p.up, p.master, p.noV6 = false, "", false
		}
		delete(h.links, name)
	}
	h.ifstate[name] = false
	return nil
}

var (
	teeRE       = regexp.MustCompile(`(?s)^sudo tee (\S+) >/dev/null <<'LABEOF'\n(.*)LABEOF\n$`)
	masterRE    = regexp.MustCompile(`^readlink -f /sys/class/net/(\S+)/master \| grep -q '/(\S+)\$'$`)
	forwardRE   = regexp.MustCompile(`^sudo (ip6?tables) (-[ACD]) FORWARD -i (\S+) -j ACCEPT$`)
	optParentRE = regexp.MustCompile(` -o parent=(\S+)`)
	optBridgeRE = regexp.MustCompile(` -o bridge=(\S+)`)
)

func (h *fakeIfupdownHost) Run(_ context.Context, cmd string) (string, error) {
	h.calls = append(h.calls, cmd)
	f := strings.Fields(cmd)
	switch {
	case teeRE.MatchString(cmd):
		m := teeRE.FindStringSubmatch(cmd)
		if filepath.Dir(m[1]) != "/etc/network/interfaces.d" {
			return "", fmt.Errorf("tee: %s: No such file or directory", m[1])
		}
		h.files[m[1]] = m[2]
	case strings.Contains(cmd, "netplan"):
		return "", fmt.Errorf("sudo: netplan: command not found")
	case strings.HasPrefix(cmd, "dpkg -s "):
		if !h.pkgs[f[2]] {
			return "", fmt.Errorf("package %s is not installed", f[2])
		}
	case strings.Contains(cmd, "apt-get install -y "):
		h.pkgs[f[len(f)-1]] = true
	case len(f) == 4 && f[1] == "ifup" && f[2] == "--force":
		return "", h.ifup(f[3], true)
	case len(f) == 3 && f[1] == "ifup":
		return "", h.ifup(f[2], false)
	case len(f) == 3 && f[1] == "ifdown":
		return "", h.ifdown(f[2])
	case strings.HasPrefix(cmd, "ip -o link show "):
		l := h.links[f[4]]
		if l == nil {
			return "", fmt.Errorf("Device %q does not exist", f[4])
		}
		line := "2: " + f[4] + ": <BROADCAST,MULTICAST> mtu 1500 qdisc fq_codel"
		if l.master != "" {
			line += " master " + l.master
		}
		return line + " state UP mode DEFAULT\n", nil
	case strings.HasPrefix(cmd, "ip link show "):
		if h.links[f[3]] == nil {
			return "", fmt.Errorf("Device %q does not exist", f[3])
		}
	case masterRE.MatchString(cmd):
		m := masterRE.FindStringSubmatch(cmd)
		if l := h.links[m[1]]; l == nil || l.master != m[2] {
			return "", fmt.Errorf("exit 1")
		}
	case forwardRE.MatchString(cmd):
		m := forwardRE.FindStringSubmatch(cmd)
		key := m[1] + " " + m[3]
		switch {
		case m[2] == "-A":
			h.rules[key]++
		case h.rules[key] == 0:
			return "", fmt.Errorf("Bad rule")
		case m[2] == "-D":
			h.rules[key]--
		}
	case strings.HasPrefix(cmd, "sudo ip link set ") && strings.HasSuffix(cmd, " nomaster"):
		if l := h.links[f[4]]; l != nil {
			l.master = ""
		}
	case strings.HasPrefix(cmd, "sudo ip link del "):
		if h.links[f[4]] == nil {
			return "", fmt.Errorf("Cannot find device %q", f[4])
		}
		for _, l := range h.links {
			if l.master == f[4] {
				l.master = ""
			}
		}
		delete(h.links, f[4])
	case strings.HasPrefix(cmd, "sudo rm -f "):
		for _, p := range f[3:] {
			delete(h.files, p)
		}
	case cmd == "sudo netfilter-persistent save":
		if !h.pkgs["iptables-persistent"] {
			return "", fmt.Errorf("netfilter-persistent: command not found")
		}
	case strings.HasPrefix(cmd, "sudo docker network rm "):
		delete(h.networks, f[4])
	case strings.HasPrefix(cmd, "sudo docker network create "):
		if m := optParentRE.FindStringSubmatch(cmd); m != nil {
			if l := h.links[m[1]]; l == nil || !l.up {
				return "", fmt.Errorf("parent interface is down: %s", m[1])
			}
		}
		if m := optBridgeRE.FindStringSubmatch(cmd); m != nil && h.links[m[1]] == nil {
			return "", fmt.Errorf("bridge %s does not exist", m[1])
		}
		h.networks[f[len(f)-1]] = true
	default:
		h.t.Errorf("fakeIfupdownHost: unmodelled command %q", cmd)
		return "", fmt.Errorf("unmodelled")
	}
	return "", nil
}

func debian11Image(t *testing.T) labyaml.BaseImage {
	t.Helper()
	img, err := labyaml.LookupBaseImage("debian-11-generic-amd64")
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// The cell's own failure, replayed: the netplan recipe on this host dies
// at the tee, which is why the stack must come from the catalogue.
func TestFakeIfupdownHostRefusesTheNetplanRecipe(t *testing.T) {
	h := newFakeIfupdownHost(t, debian11Image(t))
	_, err := NetworkUp(context.Background(), h, labyaml.NetStackNetplan, ifupdownTestCell, ShapeBridge)
	if err == nil || !strings.Contains(err.Error(), "write /etc/netplan/60-dhcp-bridge.yaml: tee: ") {
		t.Fatalf("NetworkUp with the netplan recipe on the Debian 11 host: err = %v", err)
	}
}

// Defeat row 3a: the docs' ifupdown recipe, where ifupdown reads it,
// applied by ifup, with bridge-utils installed first.
func TestIfupdownBridgeNetworkUp(t *testing.T) {
	img := debian11Image(t)
	for _, shape := range []Shape{ShapeBridge, ShapeBridgeIPAM} {
		h := newFakeIfupdownHost(t, img)
		net, err := NetworkUp(context.Background(), h, img.NetStack, ifupdownTestCell, shape)
		if err != nil {
			t.Fatalf("%s: NetworkUp: %v", shape, err)
		}
		br := hostBridgeName(net)
		want := "iface eth1 inet manual\n\nauto " + br + "\niface " + br + " inet dhcp\n    bridge_ports eth1\n    bridge_stp off\n    bridge_fd 0\n"
		if got := h.files["/etc/network/interfaces.d/60-dhcp-bridge"]; got != want {
			t.Errorf("%s: bridge stanza = %q, want %q", shape, got, want)
		}
		for _, c := range h.calls {
			if strings.Contains(c, "netplan") {
				t.Errorf("%s: a netplan command ran on the ifupdown host: %q", shape, c)
			}
		}
		install := slices.IndexFunc(h.calls, func(c string) bool { return strings.HasSuffix(c, "apt-get install -y bridge-utils") })
		apply := slices.Index(h.calls, "sudo ifup "+br)
		if install < 0 || apply < 0 || install > apply {
			t.Errorf("%s: bridge-utils install at %d, ifup %s at %d; calls: %v", shape, install, br, apply, h.calls)
		}
		if !bridgeReady(context.Background(), h, br) {
			t.Errorf("%s: bridgeReady false after NetworkUp", shape)
		}
	}
}

// Defeat row 3b: after a reboot eth1 is up on every shape because the
// host's own stack raises it, and the cell's A5b create succeeds.
func TestIfupdownSegmentNICUpAfterReboot(t *testing.T) {
	img := debian11Image(t)
	for _, shape := range allShapes {
		h := newFakeIfupdownHost(t, img)
		net, err := NetworkUp(context.Background(), h, img.NetStack, ifupdownTestCell, shape)
		if err != nil {
			t.Errorf("%s: NetworkUp: %v", shape, err)
			continue
		}
		h.reboot()
		if !h.links["eth1"].up {
			t.Errorf("%s: eth1 is down after the reboot", shape)
		}
		if usesHostBridge(shape) && !bridgeReady(context.Background(), h, hostBridgeName(net)) {
			t.Errorf("%s: bridge %s did not come back after the reboot", shape, hostBridgeName(net))
		}
		if _, err := NetworkUp(context.Background(), h, img.NetStack, ifupdownTestCell, shape); err != nil {
			t.Errorf("%s: NetworkUp after the reboot: %v", shape, err)
		}
		NetworkDown(context.Background(), h, img.NetStack, ifupdownTestCell, shape)
		h.reboot()
		if l := h.links["eth1"]; !l.up || l.master != "" {
			t.Errorf("%s: eth1 after teardown and reboot = %+v", shape, *l)
		}
	}
}

// Defeat row 3d: teardown removes exactly what NetworkUp wrote and leaves
// eth1 as it found it, after a plain NetworkUp, a repeated one, and one
// a reboot re-raised.
func TestIfupdownNetworkDownRestoresTheHost(t *testing.T) {
	img := debian11Image(t)
	for _, shape := range []Shape{ShapeBridge, ShapeBridgeIPAM} {
		for _, path := range []string{"once", "twice", "reboot"} {
			h := newFakeIfupdownHost(t, img)
			files := maps.Clone(h.files)
			eth1 := *h.links["eth1"]
			for range map[bool]int{true: 1, false: 2}[path == "twice"] {
				if _, err := NetworkUp(context.Background(), h, img.NetStack, ifupdownTestCell, shape); err != nil {
					t.Fatalf("%s/%s: NetworkUp: %v", shape, path, err)
				}
			}
			if path == "reboot" {
				h.reboot()
			}
			NetworkDown(context.Background(), h, img.NetStack, ifupdownTestCell, shape)
			if !maps.Equal(h.files, files) {
				t.Errorf("%s/%s: files after teardown %v, before %v", shape, path, slices.Sorted(maps.Keys(h.files)), slices.Sorted(maps.Keys(files)))
			}
			if *h.links["eth1"] != eth1 {
				t.Errorf("%s/%s: eth1 after teardown = %+v, before %+v", shape, path, *h.links["eth1"], eth1)
			}
			br := hostBridgeName(NetworkName(ifupdownTestCell, shape))
			if h.links[br] != nil || h.ifstate[br] {
				t.Errorf("%s/%s: bridge %s left behind (ifstate %v)", shape, path, br, h.ifstate[br])
			}
		}
	}
}

// Defeat row 3e: a bridge shape on a stack the catalogue does not name
// runs nothing; macvlan and ipvlan never read the stack.
func TestBridgeShapeRefusesAnUnknownStack(t *testing.T) {
	for _, shape := range []Shape{ShapeBridge, ShapeBridgeIPAM} {
		r := &fakeShapeRunner{}
		if _, err := NetworkUp(context.Background(), r, "", "kea", shape); err == nil || len(r.calls) != 0 {
			t.Errorf("%s with no stack: err = %v, calls %v", shape, err, r.calls)
		}
	}
	r := &fakeShapeRunner{}
	if _, err := NetworkUp(context.Background(), r, "", "kea", ShapeMacvlan); err != nil {
		t.Errorf("macvlan with no stack: %v", err)
	}
}

// Defeat row 3c: every command NetworkUp and NetworkDown send to a netplan
// host, for every shape with and without the iptables-persistent install,
// is byte-identical to the transcript recorded on lab dev 85e9dda.
func TestNetplanShapeTranscriptUnchanged(t *testing.T) {
	var out []string
	for _, shape := range allShapes {
		for _, fresh := range []bool{false, true} {
			r := &fakeShapeRunner{fail: func(cmd string) bool { return fresh && strings.HasPrefix(cmd, "dpkg -s ") }}
			if _, err := NetworkUp(context.Background(), r, labyaml.NetStackNetplan, "kea", shape); err != nil {
				t.Fatal(err)
			}
			NetworkDown(context.Background(), r, labyaml.NetStackNetplan, "kea", shape)
			out = append(out, "## "+string(shape))
			out = append(out, r.calls...)
		}
	}
	want, err := os.ReadFile("testdata/netplan-shape-transcript.golden")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(out, "\n") + "\n"; got != string(want) {
		t.Errorf("netplan transcript changed:\n%s", got)
	}
}
