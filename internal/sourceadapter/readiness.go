package sourceadapter

import (
	"context"
	"fmt"
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
	netem bool
	addrs string
	cfg   string
}

// stateCmd reads every Ready input in one remote command; the config
// comes last, after a "cfg:" line, so its bytes stay exact.
func stateCmd(cfgPath string) string {
	return fmt.Sprintf(`printf 'netns:'; ip netns list 2>/dev/null | awk '$1 ~ /^labc-/ {printf "%%s ", $1}'; echo; `+
		`printf 'netem:'; %[3]s qdisc show dev %[2]s root 2>/dev/null | grep -c netem; `+
		`printf 'addr:'; ip -4 -o addr show dev %[2]s | awk '{printf "%%s ", $4}'; echo; `+
		`echo 'cfg:'; sudo cat %[1]s`, cfgPath, segmentNIC, tcBin)
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
		case "netem":
			st.netem = val != "" && val != "0"
			seen++
		case "addr":
			st.addrs = val
			seen++
		}
	}
	if seen != 3 {
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

// sourceRecover is every adapter's Recover body (#23): delete labc-*
// netns and the netem qdisc, write the baseline config back when it
// differs, and restart the service. Segment addresses are PR 2's
// Renumber restore and are not rewritten here.
func sourceRecover(ctx context.Context, r Runner, service, cfgPath string, b *baseline) error {
	clean := fmt.Sprintf(`for n in $(ip netns list 2>/dev/null | awk '$1 ~ /^labc-/ {print $1}'); do sudo ip netns del "$n"; done; sudo %s qdisc del dev %s root 2>/dev/null; true`, tcBin, segmentNIC)
	if _, err := r.Run(ctx, clean); err != nil {
		return fmt.Errorf("recover: clear netns and qdisc: %w", err)
	}
	b.mu.Lock()
	taken, cfg := b.taken, b.cfg
	b.mu.Unlock()
	if taken {
		st, err := readState(ctx, r, cfgPath)
		if err != nil {
			return fmt.Errorf("recover: %w", err)
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
