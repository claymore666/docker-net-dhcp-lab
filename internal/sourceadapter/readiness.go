package sourceadapter

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"slices"
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
// addresses and the config bytes. Reservations live in include files,
// so B1/B2 never move it (group C defeat A8, #23).
type baseline struct {
	mu     sync.Mutex
	taken  bool
	addrs  string
	addrs6 string
	cfg    string
	extra  map[string]string
}

// extraConf is a v6 config file and the unit that serves it; Ready holds
// both to the baseline, so a lost SetRA or feature restore fails the
// next scenario's Ready and not its verdict (group D defeat 4, #23).
type extraConf struct{ path, service string }

// sourceUnits names one adapter's Ready and Recover inputs.
type sourceUnits struct {
	service string
	cfgPath string
	extra   []extraConf
	leases6 func(context.Context) ([]Lease6, error)
}

// services is the main unit, then every extra unit once, in order.
func (u sourceUnits) services() []string {
	out := []string{u.service}
	for _, e := range u.extra {
		if !slices.Contains(out, e.service) {
			out = append(out, e.service)
		}
	}
	return out
}

type sourceState struct {
	netns  []string
	links  []string
	procs  int
	netem  bool
	addrs  string
	addrs6 string
	cfg    string
	extra  map[string]string
}

// actorRE matches the group C actors' names (adapter.go) in netns,
// link and process lists. The bracket keeps the text "labc-" out of
// every command that searches for it, so pgrep and pkill never match
// the shell running the search itself (pgrep(1) -f reads full argv).
const actorRE = `[l]abc-`

// stateCmd reads every Ready input in one remote command; a host
// without the actor tools skips their four lines (#9). Each v6 config
// comes base64 on one line ("!" when unreadable, outside the alphabet);
// the main config comes last, after a "cfg:" line, so its bytes stay
// exact. addr6 lists permanent addresses only, so an RA-formed address
// on the source never moves the baseline.
func (h host) stateCmd(u sourceUnits) string {
	var b strings.Builder
	if h.portable {
		fmt.Fprintf(&b, `printf 'netns:'; ip netns list 2>/dev/null | awk '$1 ~ /^%[3]s/ {printf "%%s ", $1}'; echo; `+
			`printf 'links:'; ip -o link show | awk -F': ' '$2 ~ /^%[3]s/ {split($2, n, "@"); printf "%%s ", n[1]}'; echo; `+
			`printf 'procs:'; pgrep -f '%[3]s' | wc -l; `+
			`printf 'netem:'; %[2]s qdisc show dev %[1]s root 2>/dev/null | grep -c netem; `, h.nic, h.tc, actorRE)
	}
	fmt.Fprintf(&b, `printf 'addr:'; ip -4 -o addr show dev %[1]s | awk '{printf "%%s ", $4}'; echo; `+
		`printf 'addr6:'; ip -6 -o addr show dev %[1]s scope global permanent | awk '{printf "%%s ", $4}'; echo; `, h.nic)
	for _, e := range u.extra {
		fmt.Fprintf(&b, `printf 'cfg6:%[1]s:'; sudo base64 -w0 %[1]s 2>/dev/null || printf '!'; echo; `, e.path)
	}
	fmt.Fprintf(&b, `echo 'cfg:'; sudo cat %s`, u.cfgPath)
	return b.String()
}

func parseState(out string, u sourceUnits, portable bool) (sourceState, error) {
	head, cfg, ok := strings.Cut(out, "cfg:\n")
	if !ok {
		return sourceState{}, fmt.Errorf("state read carries no cfg: marker")
	}
	st := sourceState{cfg: cfg, extra: map[string]string{}}
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
		case "addr6":
			st.addrs6 = val
			seen++
		case "cfg6":
			path, enc, ok := strings.Cut(val, ":")
			if !ok || !slices.ContainsFunc(u.extra, func(e extraConf) bool { return e.path == path }) {
				return sourceState{}, fmt.Errorf("state read names an unexpected v6 config: %q", line)
			}
			if _, dup := st.extra[path]; dup {
				return sourceState{}, fmt.Errorf("state read names %s twice", path)
			}
			body, err := base64.StdEncoding.DecodeString(enc)
			if err != nil {
				return sourceState{}, fmt.Errorf("%s is not readable on the source", path)
			}
			st.extra[path] = string(body)
		}
	}
	want := 2
	if portable {
		want = 6
	}
	if seen != want || len(st.extra) != len(u.extra) {
		return sourceState{}, fmt.Errorf("state read is incomplete: %q", head)
	}
	return st, nil
}

func (h host) readState(ctx context.Context, r Runner, u sourceUnits) (sourceState, error) {
	out, err := r.Run(ctx, h.stateCmd(u))
	if err != nil {
		return sourceState{}, fmt.Errorf("read source state: %w", err)
	}
	return parseState(out, u, h.portable)
}

// sourceReady is every adapter's Ready body (#23).
func (h host) sourceReady(ctx context.Context, r Runner, u sourceUnits, leases func(context.Context) ([]Lease, error), b *baseline) error {
	for _, name := range u.services() {
		if _, err := r.Run(ctx, h.unit(name).isActive); err != nil {
			return fmt.Errorf("%s is not active: %w", name, err)
		}
	}
	if _, err := leases(ctx); err != nil {
		return fmt.Errorf("lease table not readable: %w", err)
	}
	if u.leases6 != nil {
		if _, err := u.leases6(ctx); err != nil {
			return fmt.Errorf("v6 lease table not readable: %w", err)
		}
	}
	st, err := h.readState(ctx, r, u)
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
		return fmt.Errorf("a netem qdisc is still on %s", h.nic)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.taken {
		b.taken, b.addrs, b.addrs6, b.cfg, b.extra = true, st.addrs, st.addrs6, st.cfg, st.extra
		return nil
	}
	if st.addrs != b.addrs {
		return fmt.Errorf("%s carries %q, the first readiness check saw %q", h.nic, st.addrs, b.addrs)
	}
	if st.addrs6 != b.addrs6 {
		return fmt.Errorf("%s carries v6 %q, the first readiness check saw %q", h.nic, st.addrs6, b.addrs6)
	}
	if st.cfg != b.cfg {
		return fmt.Errorf("%s differs from the copy taken at the first readiness check", u.cfgPath)
	}
	for _, e := range u.extra {
		if st.extra[e.path] != b.extra[e.path] {
			return fmt.Errorf("%s differs from the copy taken at the first readiness check", e.path)
		}
	}
	return nil
}

// sourceRecover is every adapter's Recover body (#23): kill the actor
// processes, delete their netns and links and the netem qdisc (a
// portable host only, #9), put the baseline v4 segment addresses and
// every baseline config back when they differ, and restart every unit
// (a stopped radvd starts again).
func (h host) sourceRecover(ctx context.Context, r Runner, u sourceUnits, b *baseline) error {
	if h.portable {
		if err := h.sweepActors(ctx, r); err != nil {
			return err
		}
	}
	b.mu.Lock()
	taken, addrs, cfg, extra := b.taken, b.addrs, b.cfg, b.extra
	b.mu.Unlock()
	if taken {
		if err := h.restoreBaseline(ctx, r, u, addrs, cfg, extra); err != nil {
			return err
		}
	}
	for _, name := range u.services() {
		if _, err := r.Run(ctx, h.unit(name).restart); err != nil {
			return fmt.Errorf("recover: restart %s: %w", name, err)
		}
	}
	return nil
}

// sweepActors kills the group C actors, deletes their netns and links
// and the netem qdisc (#23).
func (h host) sweepActors(ctx context.Context, r Runner) error {
	clean := fmt.Sprintf(`sudo pkill -f '%[3]s'; for n in $(ip netns list 2>/dev/null | awk '$1 ~ /^%[3]s/ {print $1}'); do p=$(sudo ip netns pids "$n"); [ -z "$p" ] || sudo kill -9 $p; sudo ip netns del "$n"; done; `+
		`for l in $(ip -o link show | awk -F': ' '$2 ~ /^%[3]s/ {split($2, n, "@"); print n[1]}'); do sudo ip link del "$l"; done; `+
		`sudo %[1]s qdisc del dev %[2]s root 2>/dev/null; true`, h.tc, h.nic, actorRE)
	if _, err := r.Run(ctx, clean); err != nil {
		return fmt.Errorf("recover: clear actors and qdisc: %w", err)
	}
	return nil
}

// restoreBaseline puts the baseline v4 segment addresses and every
// baseline config back where they differ from what the source holds.
func (h host) restoreBaseline(ctx context.Context, r Runner, u sourceUnits, addrs, cfg string, extra map[string]string) error {
	st, err := h.readState(ctx, r, u)
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	if st.addrs != addrs {
		var want []netip.Prefix
		for _, f := range strings.Fields(addrs) {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return fmt.Errorf("recover: baseline %s address %q: %w", h.nic, f, err)
			}
			want = append(want, p)
		}
		if len(want) == 0 {
			return fmt.Errorf("recover: baseline holds no %s address to put back", h.nic)
		}
		if err := h.setSegmentAddrs(ctx, r, want); err != nil {
			return fmt.Errorf("recover: %w", err)
		}
	}
	want := map[string]string{u.cfgPath: cfg}
	got := map[string]string{u.cfgPath: st.cfg}
	paths := []string{u.cfgPath}
	for _, e := range u.extra {
		want[e.path], got[e.path] = extra[e.path], st.extra[e.path]
		paths = append(paths, e.path)
	}
	for _, p := range paths {
		if got[p] == want[p] {
			continue
		}
		if !strings.HasSuffix(want[p], "\n") {
			return fmt.Errorf("recover: baseline %s does not end in a newline, cannot write it back byte for byte", p)
		}
		if err := writeRemoteConfig(ctx, r, p, want[p]); err != nil {
			return fmt.Errorf("recover: write %s back: %w", p, err)
		}
	}
	return nil
}

// impairMaxDelay bounds a delay so a typo cannot hold a source for minutes.
const impairMaxDelay = 10 * time.Second

// impair is every adapter's Impair body (C10, #23). The qdisc is read
// back after the replace, so a kernel without sch_netem fails here and
// never as a silent no-op (defeat 9).
func (h host) impair(ctx context.Context, r Runner, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	if err := h.needPortable("impair"); err != nil {
		return nil, err
	}
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
		if _, err := r.Run(ctx, fmt.Sprintf("sudo %s qdisc del dev %s root", h.tc, h.nic)); err != nil {
			return fmt.Errorf("impair: remove netem from %s: %w", h.nic, err)
		}
		return nil
	}
	cmd := fmt.Sprintf("sudo modprobe sch_netem 2>/dev/null; sudo %[4]s qdisc replace dev %[1]s root netem delay %[2]dms loss %[3]d%% && %[4]s qdisc show dev %[1]s root | grep -q netem",
		h.nic, delay.Milliseconds(), lossPct, h.tc)
	if _, err := r.Run(ctx, cmd); err != nil {
		_ = del(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("impair: netem on %s not in place: %w", h.nic, err)
	}
	return del, nil
}
