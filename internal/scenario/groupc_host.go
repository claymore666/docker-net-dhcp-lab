package scenario

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// timedResult is one docker host command, timed on the docker host
// itself so the SSH round trip is not part of the wall time (#23
// defeat 3).
type timedResult struct {
	RC   int
	Wall time.Duration
	Out  string
}

// timedRun runs cmd on the docker host and reports its exit code and
// wall time; a nonzero exit is a result here, not an error.
func timedRun(ctx context.Context, r sourceadapter.Runner, cmd string) (timedResult, error) {
	wrapped := fmt.Sprintf(`s=$(date +%%s%%N); out=$(%s 2>&1); rc=$?; e=$(date +%%s%%N); printf 'lab-wall %%s %%s %%s\n' "$rc" "$s" "$e"; printf '%%s' "$out"`, cmd)
	out, err := r.Run(ctx, wrapped)
	if err != nil {
		return timedResult{}, fmt.Errorf("timed run: %w", err)
	}
	first, rest, _ := strings.Cut(strings.TrimLeft(out, " \t\r\n"), "\n")
	f := strings.Fields(first)
	if len(f) != 4 || f[0] != "lab-wall" {
		return timedResult{}, fmt.Errorf("timed run printed no lab-wall line: %q", first)
	}
	rc, err1 := strconv.Atoi(f[1])
	s, err2 := strconv.ParseInt(f[2], 10, 64)
	e, err3 := strconv.ParseInt(f[3], 10, 64)
	if err := errors.Join(err1, err2, err3); err != nil || e < s {
		return timedResult{}, fmt.Errorf("timed run: unreadable lab-wall line %q", first)
	}
	return timedResult{RC: rc, Wall: time.Duration(e - s), Out: rest}, nil
}

// timedDockerRun is runContainer's docker run, timed (C1, C10).
func timedDockerRun(ctx context.Context, r sourceadapter.Runner, net, name string) (timedResult, error) {
	removeContainer(ctx, r, name)
	return timedRun(ctx, r, fmt.Sprintf("sudo docker run -d --name %s --network %s alpine:3.20 sleep 600", name, net))
}

// timedNetworkCreate is NetworkUpExtra's create, timed (C11). down is
// never nil and removes the network whatever happened.
func timedNetworkCreate(ctx context.Context, e Env, suffix string, opts []string) (net string, res timedResult, down func(), err error) {
	net = e.Network + "-" + suffix
	down = func() { NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, suffix) }
	NetworkDownExtra(ctx, e.Host, e.Network, suffix)
	br := ""
	if usesHostBridge(e.Shape) {
		br = hostBridgeName(e.Network)
		opts = append(append([]string{}, opts...), "ignore_conflicts=true")
	}
	create, err := networkCreateCmd(e.Shape, net, br, opts)
	if err != nil {
		return net, timedResult{}, down, err
	}
	res, err = timedRun(ctx, e.Host, create)
	return net, res, down, err
}

// cNetwork is bNetwork for group C's suffixes (c1, c1b, c11, ...).
func cNetwork(ctx context.Context, e Env, suffix string, opts []string) (net string, down func(), err error) {
	down = func() { NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, suffix) }
	net, err = NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, suffix, opts)
	return net, down, err
}

// endpointCount is how many containers docker lists on net.
func endpointCount(ctx context.Context, r sourceadapter.Runner, net string) (int, error) {
	out, err := r.Run(ctx, fmt.Sprintf("sudo docker network inspect -f '{{len .Containers}}' %s", net))
	if err != nil {
		return 0, fmt.Errorf("docker network inspect %s: %w", net, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("docker network inspect %s: %q is not a count", net, out)
	}
	return n, nil
}

// containerAddrs reads the IPv4 addresses inside the container's own
// namespace, loopback excluded: what the container really carries,
// not what docker inspect recorded at attach (#23 defeat 5).
func containerAddrs(ctx context.Context, r sourceadapter.Runner, name string) ([]string, error) {
	out, err := r.Run(ctx, fmt.Sprintf("sudo docker exec %s ip -4 -o addr show", name))
	if err != nil {
		return nil, fmt.Errorf("docker exec %s ip addr: %w", name, err)
	}
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] != "inet" {
			continue
		}
		a, _, _ := strings.Cut(f[3], "/")
		if !strings.HasPrefix(a, "127.") {
			addrs = append(addrs, a)
		}
	}
	return addrs, nil
}

func containsAddr(addrs []string, want string) bool {
	for _, a := range addrs {
		if a == want {
			return true
		}
	}
	return false
}

// cIdent is the identity the plugin puts on the wire for a container on
// the cell's main network: its MAC, or under ipvlan the endpoint
// derived client id (docs/parent-attached-modes.md).
func cIdent(shape Shape, mac, endpointID string) (string, error) {
	if shape == ShapeIpvlan {
		return ipvlanClientID(endpointID)
	}
	return strings.ToLower(mac), nil
}

// leasesForIdent are the table's rows for ident, matched as a MAC and as
// a client id, so one helper serves every shape.
func leasesForIdent(leases []sourceadapter.Lease, ident string) []sourceadapter.Lease {
	var out []sourceadapter.Lease
	for _, l := range leases {
		if strings.EqualFold(l.MAC, ident) || strings.EqualFold(l.ClientID, ident) {
			out = append(out, l)
		}
	}
	return out
}

// active keeps the rows that have not expired at now; a zero Expires is
// a lease without an end.
func active(leases []sourceadapter.Lease, now time.Time) []sourceadapter.Lease {
	var out []sourceadapter.Lease
	for _, l := range leases {
		if l.Expires.IsZero() || l.Expires.After(now) {
			out = append(out, l)
		}
	}
	return out
}

// readCapture snapshots the capture for ident and writes the decoded
// log beside it; ev gains the log, the .pcap stays next to it. A nil
// reader is an error: a group C rule is never judged without the wire.
func readCapture(ctx context.Context, e Env, scenario, label, ident string, ev map[string]string) ([]DHCPMsg, error) {
	if e.Capture == nil {
		return nil, errors.New("no capture reader for this run")
	}
	snap := strings.TrimSuffix(evidencePath(e, scenario, label), ".txt") + ".pcap"
	msgs, err := e.Capture.Messages(ctx, ident, snap)
	if err != nil {
		return nil, err
	}
	logPath := evidencePath(e, scenario, label)
	if err := writeMessageLog(logPath, msgs); err != nil {
		return nil, err
	}
	ev[label] = logPath
	return msgs, nil
}

// bindAnchor is the time of the last ACK to ident for addr in the
// capture, waited for up to bound: the lease clock starts at the bind
// the wire shows, never at the source's own clock (#23 defeat A5).
func bindAnchor(ctx context.Context, e Env, scenario, ident, addr string, bound, poll time.Duration, ev map[string]string) (time.Time, error) {
	m, err := bindACK(ctx, e, scenario, ident, addr, bound, poll, ev)
	return m.At, err
}

// bindACK is bindAnchor's ACK itself: its server-id and option 51 time
// the C5 family (lab #12).
func bindACK(ctx context.Context, e Env, scenario, ident, addr string, bound, poll time.Duration, ev map[string]string) (DHCPMsg, error) {
	return bindACKLabeled(ctx, e, scenario, "capture-bind", ident, addr, bound, poll, ev)
}

// bindACKLabeled is bindACK with its own evidence label, for a scenario
// that binds more than one container (C12, #11).
func bindACKLabeled(ctx context.Context, e Env, scenario, label, ident, addr string, bound, poll time.Duration, ev map[string]string) (DHCPMsg, error) {
	deadline := time.Now().Add(bound)
	for {
		msgs, err := readCapture(ctx, e, scenario, label, ident, ev)
		if err != nil {
			return DHCPMsg{}, err
		}
		if m, ok := lastACKOf(msgs, addr); ok {
			return m, nil
		}
		if time.Now().After(deadline) {
			return DHCPMsg{}, fmt.Errorf("the capture shows no ACK of %s to %s within %s", addr, ident, bound)
		}
		if err := sleepCtx(ctx, poll); err != nil {
			return DHCPMsg{}, err
		}
	}
}

// lastACKOf is the latest ACK of addr in msgs.
func lastACKOf(msgs []DHCPMsg, addr string) (DHCPMsg, bool) {
	var last DHCPMsg
	for _, m := range messagesOfType(msgs, "ACK") {
		if m.YIAddr == addr && m.At.After(last.At) {
			last = m
		}
	}
	return last, !last.At.IsZero()
}

// sleepUntil waits until t or until ctx ends.
func sleepUntil(ctx context.Context, t time.Time) error {
	if d := time.Until(t); d > 0 {
		return sleepCtx(ctx, d)
	}
	return nil
}
