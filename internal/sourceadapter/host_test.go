package sourceadapter

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// initdHost is a stand-in for a source without systemd or iproute2
// netns (OpenWrt's procd, #9): init.d command sets, not portable.
var initdHost = host{
	unit: func(name string) service {
		d := "sudo /etc/init.d/" + name
		return service{name: name, isActive: d + " running", stop: d + " stop", start: d + " start", restart: d + " restart",
			signal: "sudo kill -s %s $(pidof " + name + ")"}
	},
	main: "dnsmasq",
	nic:  "eth1",
}

// initdUnits is a dnsmasq source with a v6 config and a radvd unit.
var initdUnits = sourceUnits{service: "dnsmasq", cfgPath: "/etc/dnsmasq.conf",
	extra: []extraConf{{dnsmasqLabV6Conf, "dnsmasq"}, {radvdConf, "radvd"}}}

// initdRunner is a source whose config files and eth1 addresses the
// stub reads and writes.
type initdRunner struct {
	files map[string]string
	addrs string
	calls []string
}

func (r *initdRunner) Run(_ context.Context, cmd string) (string, error) {
	r.calls = append(r.calls, cmd)
	const flush = "sudo ip -4 addr flush dev eth1 && sudo ip addr add "
	switch {
	case cmd == initdHost.stateCmd(initdUnits):
		out := "addr:" + r.addrs + " \naddr6:fd42:200:0:100::2/64 \n"
		for _, e := range initdUnits.extra {
			out += "cfg6:" + e.path + ":" + base64.StdEncoding.EncodeToString([]byte(r.files[e.path])) + "\n"
		}
		return out + "cfg:\n" + r.files[initdUnits.cfgPath], nil
	case cmd == initdHost.segAddrCmd():
		return r.addrs + "\n", nil
	case strings.HasPrefix(cmd, flush):
		r.addrs = strings.Fields(strings.TrimPrefix(cmd, flush))[0]
	case strings.HasPrefix(cmd, "sudo tee "):
		path, body, _ := strings.Cut(strings.TrimPrefix(cmd, "sudo tee "), " >/dev/null <<'LABEOF'\n")
		r.files[path] = strings.TrimSuffix(body, "LABEOF\n")
	}
	return "", nil
}

func noLeases(context.Context) ([]Lease, error) { return nil, nil }

func initdFiles() map[string]string {
	return map[string]string{"/etc/dnsmasq.conf": "dhcp-range=10.200.1.100,10.200.1.200\n",
		dnsmasqLabV6Conf: "enable-ra\n", radvdConf: "interface eth1 {};\n"}
}

// Every shared helper a non-systemd source reaches sends its own unit
// strings and nothing that needs systemd, iproute2 netns, pgrep or tc;
// Ready still holds eth1, which Renumber moves on any host, and Recover
// puts it back (#9).
func TestNonSystemdHostSendsNoSystemctlAndNoNetns(t *testing.T) {
	ctx := context.Background()
	r := &initdRunner{files: initdFiles(), addrs: "10.200.1.2/24"}
	h, u, b := initdHost, initdUnits, &baseline{}
	if err := h.sourceReady(ctx, r, u, noLeases, b); err != nil {
		t.Fatal(err)
	}
	r.addrs = "10.200.2.2/24"
	if err := h.sourceReady(ctx, r, u, noLeases, b); err == nil || !strings.Contains(err.Error(), "eth1 carries") {
		t.Fatalf("Ready accepted eth1 renumbered away from its baseline: %v", err)
	}
	r.files["/etc/dnsmasq.conf"] += "dhcp-option=6,10.200.1.53\n"
	r.files[radvdConf] = "drifted\n"
	if err := h.sourceRecover(ctx, r, u, b); err != nil {
		t.Fatal(err)
	}
	if want := initdFiles(); r.addrs != "10.200.1.2/24" || r.files["/etc/dnsmasq.conf"] != want["/etc/dnsmasq.conf"] || r.files[radvdConf] != want[radvdConf] {
		t.Fatalf("Recover left eth1 at %q and the configs at %q", r.addrs, r.files)
	}
	if err := resetLeasesViaTruncate(ctx, r, "/tmp/dhcp.leases", nil, h.svc(), "stub"); err != nil {
		t.Fatal(err)
	}
	for _, act := range []string{"stop", "start", "restart"} {
		if err := h.svc().do(ctx, r, act, "stub"); err != nil {
			t.Fatal(err)
		}
	}
	restore, err := h.setRAViaRadvd(ctx, r, RAParams{Off: true}, "stub")
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(ctx); err != nil {
		t.Fatal(err)
	}
	st, addr := h.stateCmd(u), h.segAddrCmd()
	want := []string{
		"sudo /etc/init.d/dnsmasq running", "sudo /etc/init.d/radvd running", st,
		"sudo /etc/init.d/dnsmasq running", "sudo /etc/init.d/radvd running", st,
		st, "sudo ip -4 addr flush dev eth1 && sudo ip addr add 10.200.1.2/24 brd + dev eth1", addr,
		"sudo tee /etc/dnsmasq.conf >/dev/null <<'LABEOF'\ndhcp-range=10.200.1.100,10.200.1.200\nLABEOF\n",
		"sudo tee /etc/radvd.conf >/dev/null <<'LABEOF'\ninterface eth1 {};\nLABEOF\n",
		"sudo /etc/init.d/dnsmasq restart", "sudo /etc/init.d/radvd restart",
		"sudo /etc/init.d/dnsmasq stop && sudo truncate -s 0 /tmp/dhcp.leases && sudo /etc/init.d/dnsmasq start",
		"sudo /etc/init.d/dnsmasq stop", "sudo /etc/init.d/dnsmasq start", "sudo /etc/init.d/dnsmasq restart",
		"sudo /etc/init.d/radvd stop", "sudo /etc/init.d/radvd start",
	}
	if strings.Join(r.calls, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("calls:\n%q\nwant:\n%q", r.calls, want)
	}
	for _, c := range r.calls {
		for _, bad := range []string{"systemctl", "ip netns", "pgrep", "tc qdisc", tcBin} {
			if strings.Contains(c, bad) {
				t.Fatalf("a non-systemd, non-portable host sent %q: %q", bad, c)
			}
		}
	}
}

// The netns, tc and python3 actors refuse on a non-portable host (#9)
// before any command reaches it.
func TestNonPortableHostRefusesTheActorsBeforeAnySSH(t *testing.T) {
	ctx := context.Background()
	r := &initdRunner{}
	h := initdHost
	if _, err := h.squat(ctx, r, "10.200.1.231", true); err == nil {
		t.Error("Squat ran on a non-portable host")
	}
	if _, err := h.startRogue(ctx, r, "10.200.1.240", "10.200.1.241", "10.200.1.250"); err == nil {
		t.Error("StartRogue ran on a non-portable host")
	}
	if _, err := h.rogueLeases(ctx, r); err == nil {
		t.Error("RogueLeases ran on a non-portable host")
	}
	if _, err := h.impair(ctx, r, 100*time.Millisecond, 0); err == nil {
		t.Error("Impair ran on a non-portable host")
	}
	if _, err := h.sendForceRenew(ctx, r, []byte("print()\n"), ForceRenewParams{Mode: "unsigned", Addr: "10.200.1.150", CHAddr: "02:00:00:00:00:01", Server: "10.200.1.1"}); err == nil {
		t.Error("SendForceRenew ran on a non-portable host")
	}
	if len(r.calls) != 0 {
		t.Fatalf("a refused actor still sent %q", r.calls)
	}
}

// The refusal names the action and the source, so a cell log says which
// actor a non-portable source turned away (#9).
func TestNeedPortableNamesTheActionAndTheSource(t *testing.T) {
	err := initdHost.needPortable("squatter")
	if err == nil || err.Error() != "squatter: the dnsmasq source has no iproute2 netns, pgrep, tc or python3" {
		t.Fatalf("needPortable = %v", err)
	}
	if err := debianHost("kea-dhcp4-server").needPortable("squatter"); err != nil {
		t.Fatalf("a portable host refused: %v", err)
	}
}

// A non-portable host's state read is the address and config lines
// only, byte for byte: the stub above answers whatever stateCmd builds,
// so only this literal sees a line go missing (#9).
func TestNonPortableStateCmdIsPinned(t *testing.T) {
	want := `printf 'addr:'; ip -4 -o addr show dev eth1 | awk '{printf "%s ", $4}'; echo; ` +
		`printf 'addr6:'; ip -6 -o addr show dev eth1 scope global permanent | awk '{printf "%s ", $4}'; echo; ` +
		`printf 'cfg6:/etc/dnsmasq.d/lab-v6.conf:'; sudo base64 -w0 /etc/dnsmasq.d/lab-v6.conf 2>/dev/null || printf '!'; echo; ` +
		`printf 'cfg6:/etc/radvd.conf:'; sudo base64 -w0 /etc/radvd.conf 2>/dev/null || printf '!'; echo; ` +
		`echo 'cfg:'; sudo cat /etc/dnsmasq.conf`
	if got := initdHost.stateCmd(initdUnits); got != want {
		t.Fatalf("stateCmd:\n%q\nwant:\n%q", got, want)
	}
}

// The Debian default is systemd on eth1 with the absolute tc path, the
// strings every cell sent before #9, for the main unit and any other.
func TestDebianHostIsTheSystemdDefault(t *testing.T) {
	h := debianHost("kea-dhcp4-server")
	want := service{"kea-dhcp4-server", "sudo systemctl is-active --quiet kea-dhcp4-server",
		"sudo systemctl stop kea-dhcp4-server", "sudo systemctl start kea-dhcp4-server", "sudo systemctl restart kea-dhcp4-server",
		"sudo systemctl kill -s %s kea-dhcp4-server"}
	if h.svc() != want || h.nic != "eth1" || h.tc != "/usr/sbin/tc" || !h.portable {
		t.Fatalf("debianHost = %+v", h)
	}
	if got := h.unit("radvd").stop; got != "sudo systemctl stop radvd" {
		t.Fatalf("radvd stop = %q", got)
	}
	if got, err := h.svc().kill("HUP"); err != nil || got != "sudo systemctl kill -s HUP kea-dhcp4-server" {
		t.Fatalf("kill HUP = %q, %v", got, err)
	}
}

// A service with no signal format refuses kill, as do refuses a missing
// verb, instead of sending a malformed command (#9).
func TestKillRefusesAMissingSignalFormat(t *testing.T) {
	got, err := service{name: "udhcpd"}.kill("USR1")
	if err == nil || got != "" || err.Error() != "no signal command for udhcpd" {
		t.Fatalf("kill without a signal format = %q, %v", got, err)
	}
}
