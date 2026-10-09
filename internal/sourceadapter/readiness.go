package sourceadapter

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// segmentNIC is the source VM's leg on the cell segment (cloud-init's
// eth1); netem and the address check apply there only (#23).
const segmentNIC = "eth1"

// tcBin is spelled absolute: the ssh user's non-login shell has no
// /usr/sbin in PATH, so a bare "tc" is not found and the read-back that
// guards C10 failed with "command not found" on the first kea run (#23).
const tcBin = "/usr/sbin/tc"

// baseline is the state the first Ready of an adapter saw: the segment
// addresses and the main config bytes. Reservations live in include
// files, so B1/B2 never move it (group C defeat A8, #23).
type baseline struct {
	mu    sync.Mutex
	taken bool
	addrs string
	cfg   string
}

type sourceState struct {
	netns []string
	links []string
	procs int
	netem bool
	addrs string
	cfg   string
}

// actorRE matches the group C actors' names (adapter.go) in netns,
// link and process lists. The bracket keeps the text "labc-" out of
// every command that searches for it, so pgrep and pkill never match
// the shell running the search itself (pgrep(1) -f reads full argv).
const actorRE = `[l]abc-`

// stateCmd reads every Ready input in one remote command; the config
// comes last, after a "cfg:" line, so its bytes stay exact.
func stateCmd(cfgPath string) string {
	return fmt.Sprintf(`printf 'netns:'; ip netns list 2>/dev/null | awk '$1 ~ /^%[4]s/ {printf "%%s ", $1}'; echo; `+
		`printf 'links:'; ip -o link show | awk -F': ' '$2 ~ /^%[4]s/ {split($2, n, "@"); printf "%%s ", n[1]}'; echo; `+
		`printf 'procs:'; pgrep -f '%[4]s' | wc -l; `+
		`printf 'netem:'; %[3]s qdisc show dev %[2]s root 2>/dev/null | grep -c netem; `+
		`printf 'addr:'; ip -4 -o addr show dev %[2]s | awk '{printf "%%s ", $4}'; echo; `+
		`echo 'cfg:'; sudo cat %[1]s`, cfgPath, segmentNIC, tcBin, actorRE)
}

func parseState(out string) (sourceState, error) {
	head, cfg, ok := strings.Cut(out, "cfg:\n")
	if !ok {
		return sourceState{}, fmt.Errorf("state read carries no cfg: marker")
	}
	st := sourceState{cfg: cfg}
	seen := 0
	for _, line := range strings.Split(head, "\n") {
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "netns":
			st.netns = strings.Fields(val)
			seen++
		case "links":
			st.links = strings.Fields(val)
			seen++
		case "procs":
			n, err := strconv.Atoi(val)
			if err != nil {
				return sourceState{}, fmt.Errorf("state read: process count %q", val)
			}
			st.procs = n
			seen++
		case "netem":
			st.netem = val != "" && val != "0"
			seen++
		case "addr":
			st.addrs = val
			seen++
		}
	}
	if seen != 5 {
		return sourceState{}, fmt.Errorf("state read is incomplete: %q", head)
	}
	return st, nil
}

func readState(ctx context.Context, r Runner, cfgPath string) (sourceState, error) {
	out, err := r.Run(ctx, stateCmd(cfgPath))
	if err != nil {
		return sourceState{}, fmt.Errorf("read source state: %w", err)
	}
	return parseState(out)
}

// sourceReady is every adapter's Ready body (#23).
func sourceReady(ctx context.Context, r Runner, service, cfgPath string, leases func(context.Context) ([]Lease, error), b *baseline) error {
	if _, err := r.Run(ctx, "sudo systemctl is-active --quiet "+service); err != nil {
		return fmt.Errorf("%s is not active: %w", service, err)
	}
	if _, err := leases(ctx); err != nil {
		return fmt.Errorf("lease table not readable: %w", err)
	}
	st, err := readState(ctx, r, cfgPath)
	if err != nil {
		return err
	}
	if len(st.netns) > 0 {
		return fmt.Errorf("leftover network namespaces: %s", strings.Join(st.netns, " "))
	}
	if len(st.links) > 0 {
		return fmt.Errorf("leftover links: %s", strings.Join(st.links, " "))
	}
	if st.procs > 0 {
		return fmt.Errorf("%d leftover group C actor processes", st.procs)
	}
	if st.netem {
		return fmt.Errorf("a netem qdisc is still on %s", segmentNIC)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.taken {
		b.taken, b.addrs, b.cfg = true, st.addrs, st.cfg
		return nil
	}
	if st.addrs != b.addrs {
		return fmt.Errorf("%s carries %q, the first readiness check saw %q", segmentNIC, st.addrs, b.addrs)
	}
	if st.cfg != b.cfg {
		return fmt.Errorf("%s differs from the copy taken at the first readiness check", cfgPath)
	}
	return nil
}

// sourceRecover is every adapter's Recover body (#23): kill the actor
// processes, delete their netns and links and the netem qdisc, put the
// baseline segment addresses and config back when they differ, and
// restart the service.
func sourceRecover(ctx context.Context, r Runner, service, cfgPath string, b *baseline) error {
	clean := fmt.Sprintf(`sudo pkill -f '%[3]s'; for n in $(ip netns list 2>/dev/null | awk '$1 ~ /^%[3]s/ {print $1}'); do p=$(sudo ip netns pids "$n"); [ -z "$p" ] || sudo kill -9 $p; sudo ip netns del "$n"; done; `+
		`for l in $(ip -o link show | awk -F': ' '$2 ~ /^%[3]s/ {split($2, n, "@"); print n[1]}'); do sudo ip link del "$l"; done; `+
		`sudo %[1]s qdisc del dev %[2]s root 2>/dev/null; true`, tcBin, segmentNIC, actorRE)
	if _, err := r.Run(ctx, clean); err != nil {
		return fmt.Errorf("recover: clear actors and qdisc: %w", err)
	}
	b.mu.Lock()
	taken, addrs, cfg := b.taken, b.addrs, b.cfg
	b.mu.Unlock()
	if taken {
		st, err := readState(ctx, r, cfgPath)
		if err != nil {
			return fmt.Errorf("recover: %w", err)
		}
		if st.addrs != addrs {
			var want []netip.Prefix
			for _, f := range strings.Fields(addrs) {
				p, err := netip.ParsePrefix(f)
				if err != nil {
					return fmt.Errorf("recover: baseline %s address %q: %w", segmentNIC, f, err)
				}
				want = append(want, p)
			}
			if len(want) == 0 {
				return fmt.Errorf("recover: baseline holds no %s address to put back", segmentNIC)
			}
			if err := setSegmentAddrs(ctx, r, want); err != nil {
				return fmt.Errorf("recover: %w", err)
			}
		}
		if st.cfg != cfg {
			if !strings.HasSuffix(cfg, "\n") {
				return fmt.Errorf("recover: baseline %s does not end in a newline, cannot write it back byte for byte", cfgPath)
			}
			if err := writeRemoteConfig(ctx, r, cfgPath, cfg); err != nil {
				return fmt.Errorf("recover: write %s back: %w", cfgPath, err)
			}
		}
	}
	if _, err := r.Run(ctx, "sudo systemctl restart "+service); err != nil {
		return fmt.Errorf("recover: restart %s: %w", service, err)
	}
	return nil
}

// impairMaxDelay bounds a delay so a typo cannot hold a source for minutes.
const impairMaxDelay = 10 * time.Second

// impair is every adapter's Impair body (C10, #23). The qdisc is read
// back after the replace, so a kernel without sch_netem fails here and
// never as a silent no-op (defeat 9).
func impair(ctx context.Context, r Runner, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	if delay < 0 || delay > impairMaxDelay || delay%time.Millisecond != 0 {
		return nil, fmt.Errorf("impair: delay %s outside 0..%s in whole milliseconds", delay, impairMaxDelay)
	}
	if lossPct < 0 || lossPct > 100 {
		return nil, fmt.Errorf("impair: loss %d%% outside 0..100", lossPct)
	}
	if delay == 0 && lossPct == 0 {
		return nil, fmt.Errorf("impair: neither a delay nor a loss given")
	}
	del := func(ctx context.Context) error {
		if _, err := r.Run(ctx, fmt.Sprintf("sudo %s qdisc del dev %s root", tcBin, segmentNIC)); err != nil {
			return fmt.Errorf("impair: remove netem from %s: %w", segmentNIC, err)
		}
		return nil
	}
	cmd := fmt.Sprintf("sudo modprobe sch_netem 2>/dev/null; sudo %[4]s qdisc replace dev %[1]s root netem delay %[2]dms loss %[3]d%% && %[4]s qdisc show dev %[1]s root | grep -q netem",
		segmentNIC, delay.Milliseconds(), lossPct, tcBin)
	if _, err := r.Run(ctx, cmd); err != nil {
		_ = del(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("impair: netem on %s not in place: %w", segmentNIC, err)
	}
	return del, nil
}
