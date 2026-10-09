package sourceadapter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	katNonce  = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	katScript = filepath.Join("..", "..", "scripts", "forcerenew-send.py")
)

// dryRun runs the repo's sender with --dry-run and returns the frame.
func dryRun(t *testing.T, mode string, extra ...string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), mode+".bin")
	args := append([]string{"-I", katScript, "--dst-mac", "02:00:00:00:00:08", "--dst-ip", "10.200.1.100",
		"--src-ip", "10.200.1.2", "--src-mac", "02:00:00:00:00:01", "--chaddr", "02:00:00:00:00:08",
		"--client-id", "01020304", "--mode", mode, "--nonce", hex.EncodeToString(katNonce),
		"--ack-replay", "1", "--xid", "0x01020304", "--dry-run", out}, extra...)
	if b, err := exec.Command("python3", args...).CombinedOutput(); err != nil {
		t.Fatalf("forcerenew-send.py %s: %v\n%s", mode, err, b)
	}
	fr, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return fr
}

func csum16(b []byte) uint16 {
	if len(b)%2 == 1 {
		b = append(b, 0)
	}
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

type katFrame struct {
	payload []byte
	opts    map[byte][]byte
	auth    int // offset of option 90's value in payload, -1 if absent
}

// parseFrame checks the Ethernet, IPv4 and UDP layers and the BOOTP
// header the client tests before it looks at option 90 (defeats 8a, 8c).
func parseFrame(t *testing.T, fr []byte) katFrame {
	t.Helper()
	if !bytes.Equal(fr[0:6], []byte{2, 0, 0, 0, 0, 8}) || !bytes.Equal(fr[6:12], []byte{2, 0, 0, 0, 0, 1}) || !bytes.Equal(fr[12:14], []byte{8, 0}) {
		t.Fatalf("ethernet header % x", fr[:14])
	}
	ip := fr[14:34]
	if ip[0] != 0x45 || ip[9] != 17 || csum16(ip) != 0 {
		t.Fatalf("IPv4 header % x (checksum over it %#x)", ip, csum16(ip))
	}
	if !net.IP(ip[12:16]).Equal(net.IPv4(10, 200, 1, 2)) || !net.IP(ip[16:20]).Equal(net.IPv4(10, 200, 1, 100)) {
		t.Fatalf("IPv4 %v -> %v, want the server -> the lease, unicast", net.IP(ip[12:16]), net.IP(ip[16:20]))
	}
	if int(binary.BigEndian.Uint16(ip[2:])) != len(fr)-14 {
		t.Fatalf("IPv4 total length %d, frame carries %d", binary.BigEndian.Uint16(ip[2:]), len(fr)-14)
	}
	udp := fr[34:]
	if binary.BigEndian.Uint16(udp[0:]) != 67 || binary.BigEndian.Uint16(udp[2:]) != 68 || int(binary.BigEndian.Uint16(udp[4:])) != len(udp) {
		t.Fatalf("UDP header % x", udp[:8])
	}
	pseudo := append(append(append([]byte{}, ip[12:20]...), 0, 17), udp[4:6]...)
	if csum16(append(pseudo, udp...)) != 0 {
		t.Fatal("UDP checksum does not verify")
	}
	p := udp[8:]
	if p[0] != 2 || p[1] != 1 || p[2] != 6 || p[3] != 0 {
		t.Fatalf("op/htype/hlen/hops = % x, want 02 01 06 00", p[:4])
	}
	if !net.IP(p[12:16]).Equal(net.IPv4(10, 200, 1, 100)) || !bytes.Equal(p[24:28], make([]byte, 4)) || !bytes.Equal(p[28:34], []byte{2, 0, 0, 0, 0, 8}) {
		t.Fatalf("ciaddr %v giaddr % x chaddr % x, want the lease, zero, the lease MAC", net.IP(p[12:16]), p[24:28], p[28:34])
	}
	if !bytes.Equal(p[236:240], []byte{0x63, 0x82, 0x53, 0x63}) {
		t.Fatal("no magic cookie")
	}
	k := katFrame{payload: p, opts: map[byte][]byte{}, auth: -1}
	for i := 240; i < len(p) && p[i] != 255; {
		if p[i] == 0 {
			i++
			continue
		}
		code, n := p[i], int(p[i+1])
		k.opts[code] = p[i+2 : i+2+n]
		if code == 90 {
			k.auth = i + 2
		}
		i += 2 + n
	}
	if !bytes.Equal(k.opts[53], []byte{9}) || !bytes.Equal(k.opts[54], []byte{10, 200, 1, 2}) || !bytes.Equal(k.opts[61], []byte{1, 2, 3, 4}) {
		t.Fatalf("options 53/54/61 = % x / % x / % x", k.opts[53], k.opts[54], k.opts[61])
	}
	return k
}

// hmacOver is RFC 6704 3.1.4's check: HMAC-MD5 keyed with key over the
// DHCP message with the 16 digest octets zeroed.
func hmacOver(k katFrame, key []byte) []byte {
	z := append([]byte{}, k.payload...)
	copy(z[k.auth+12:k.auth+28], make([]byte, 16))
	m := hmac.New(md5.New, key)
	m.Write(z)
	return m.Sum(nil)
}

// The known answer (defeat 8): for fixed inputs the signed digest is
// pinned, recomputing it with crypto/hmac agrees, and a one-byte flip of
// the message or of the key changes it. The pinned value was checked
// with dhcp-golib v1.4.4 wire.VerifyForcerenew (measured for lab #21).
func TestForceRenewSenderHMACKnownAnswer(t *testing.T) {
	const want = "e196e3765c80c4a03c4226e852a82f6b"
	k := parseFrame(t, dryRun(t, "signed"))
	a := k.opts[90]
	if len(a) != 28 || a[0] != 3 || a[1] != 1 || a[2] != 0 || a[11] != 2 {
		t.Fatalf("option 90 = % x, want 28 octets: 03 01 00 <replay> 02 <digest>", a)
	}
	if r := binary.BigEndian.Uint64(a[3:11]); r != 3 {
		t.Fatalf("signed replay %d, want the ACK's 1 + 2 (defeat 8b)", r)
	}
	got := a[12:28]
	if hex.EncodeToString(got) != want {
		t.Errorf("signed digest %x, pinned %s", got, want)
	}
	if !hmac.Equal(got, hmacOver(k, katNonce)) {
		t.Fatal("signed digest is not HMAC-MD5(nonce, message with digest zeroed)")
	}
	flipped := k
	flipped.payload = append([]byte{}, k.payload...)
	flipped.payload[4] ^= 1 // one bit of the xid
	if hmac.Equal(got, hmacOver(flipped, katNonce)) {
		t.Error("a one-byte flip of the message left the digest valid")
	}
	key := append([]byte{}, katNonce...)
	key[15] ^= 1
	if hmac.Equal(got, hmacOver(k, key)) {
		t.Error("a one-byte flip of the key left the digest valid")
	}
}

// badkey carries a digest the nonce does not verify, one replay step
// above the ACK so the client reaches the digest check; unsigned carries
// no option 90 at all (defeats 8, 8b).
func TestForceRenewSenderBadkeyAndUnsigned(t *testing.T) {
	k := parseFrame(t, dryRun(t, "badkey"))
	a := k.opts[90]
	if len(a) != 28 || a[11] != 2 {
		t.Fatalf("badkey option 90 = % x", a)
	}
	if r := binary.BigEndian.Uint64(a[3:11]); r != 2 {
		t.Fatalf("badkey replay %d, want the ACK's 1 + 1", r)
	}
	if hmac.Equal(a[12:28], hmacOver(k, katNonce)) {
		t.Fatal("badkey digest verifies with the nonce")
	}
	u := parseFrame(t, dryRun(t, "unsigned"))
	if _, ok := u.opts[90]; ok {
		t.Fatal("unsigned frame carries option 90")
	}
}

type neighRunner struct {
	neigh string
	calls []string
}

func (n *neighRunner) Run(_ context.Context, cmd string) (string, error) {
	n.calls = append(n.calls, cmd)
	if strings.HasPrefix(cmd, "ip neigh show") {
		return n.neigh, nil
	}
	return "forcerenew mode=signed\n", nil
}

func goodFR() ForceRenewParams {
	return ForceRenewParams{Mode: "signed", Addr: "10.200.1.100", CHAddr: "02:00:00:00:00:08", ClientID: "01:02:03:04",
		Server: "10.200.1.2", Nonce: katNonce, AckReplay: 1}
}

// SendForceRenew pings, reads the neighbour MAC, pushes the script and
// runs it with that MAC; bad input never reaches the runner.
func TestSendForceRenewRunsTheSenderWithTheNeighbourMAC(t *testing.T) {
	script := []byte("print('x')\n")
	for name := range baselines {
		r := &neighRunner{neigh: "10.200.1.100 lladdr 02:42:0a:c8:01:64 REACHABLE\n"}
		a := featureAdapter(name, r)
		if !hasCap(a, CapForceRenewNonce) {
			t.Errorf("%s does not declare CapForceRenewNonce", name)
		}
		out, err := a.SendForceRenew(context.Background(), script, goodFR())
		if err != nil || out != "forcerenew mode=signed" {
			t.Fatalf("%s: %q %v", name, out, err)
		}
		if len(r.calls) != 4 || r.calls[0] != "ping -c1 -W2 10.200.1.100" || !strings.Contains(r.calls[2], "<<'LABEOF'\nprint('x')\nLABEOF\n") {
			t.Fatalf("%s: calls %q", name, r.calls)
		}
		want := "sudo python3 /run/lab/forcerenew-send.py --dst-mac 02:42:0a:c8:01:64 --iface eth1 --dst-ip 10.200.1.100 --src-ip 10.200.1.2 --chaddr 02:00:00:00:00:08 --mode signed --client-id 01020304 --nonce 00112233445566778899aabbccddeeff --ack-replay 1"
		if r.calls[3] != want {
			t.Fatalf("%s: run\n%q\nwant\n%q", name, r.calls[3], want)
		}
	}
	bad := []func(*ForceRenewParams){
		func(p *ForceRenewParams) { p.Mode = "signed; id" },
		func(p *ForceRenewParams) { p.Addr = "10.200.1.100; id" },
		func(p *ForceRenewParams) { p.Server = "" },
		func(p *ForceRenewParams) { p.CHAddr = "02:00:00:00:00:08 --mode unsigned" },
		func(p *ForceRenewParams) { p.ClientID = "01:02'; id" },
		func(p *ForceRenewParams) { p.Nonce = katNonce[:15] },
	}
	for i, mut := range bad {
		p := goodFR()
		mut(&p)
		r := &neighRunner{neigh: "x lladdr 02:42:0a:c8:01:64"}
		if _, err := featureAdapter("kea", r).SendForceRenew(context.Background(), script, p); err == nil || len(r.calls) != 0 {
			t.Errorf("bad case %d: err=%v calls=%q", i, err, r.calls)
		}
	}
	for _, s := range []string{"", "no newline", "a\nLABEOF\nb\n"} {
		r := &neighRunner{neigh: "x lladdr 02:42:0a:c8:01:64"}
		if _, err := featureAdapter("kea", r).SendForceRenew(context.Background(), []byte(s), goodFR()); err == nil || len(r.calls) != 0 {
			t.Errorf("script %q: err=%v calls=%q", s, err, r.calls)
		}
	}
	r := &neighRunner{neigh: "10.200.1.100 FAILED\n"}
	if _, err := featureAdapter("kea", r).SendForceRenew(context.Background(), script, goodFR()); err == nil || !strings.Contains(err.Error(), "no neighbour MAC") {
		t.Errorf("no neighbour entry: %v", err)
	}
}
