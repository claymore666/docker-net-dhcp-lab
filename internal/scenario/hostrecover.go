package scenario

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// HostRecovery power-cycles the cell's own docker host VM when a gate
// finds it not answering ssh: four cells in runs 1-6 lost every later
// scenario to a host that never came back from a reboot (#158).
type HostRecovery struct {
	Cell        string
	Shape       Shape
	EvidenceDir string
	// Virsh runs one virsh command on the lab host; nil means sudo -n virsh.
	Virsh func(ctx context.Context, args ...string) (string, error)
	Max   int           // resets allowed per labctl run
	Wait  time.Duration // bound for ssh and docker to answer after a reset
	Poll  time.Duration
	used  int
	note  string // the last reset, until a verdict takes it
}

// TakeNote returns the reset not yet named in a verdict, once.
func (h *HostRecovery) TakeNote() string {
	if h == nil {
		return ""
	}
	n := h.note
	h.note = ""
	return n
}

// HostDomain is the docker host's libvirt domain, named as up-cell.sh names it.
func HostDomain(cell string) string { return "lab-" + cell + "-dockerhost" }

func virshLocal(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "sudo", append([]string{"-n", "virsh"}, args...)...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Try power-cycles the host when gateErr is an ssh connect error and the
// budget allows, then waits for ssh and docker. tried is false when no
// reset was attempted; note names the reset for the next verdict.
func (h *HostRecovery) Try(ctx context.Context, r sourceadapter.Runner, gateErr error) (note string, tried bool, err error) {
	if h == nil || !sourceadapter.IsConnectError(gateErr) || h.used >= h.Max {
		return "", false, nil
	}
	h.used++
	virsh := h.Virsh
	if virsh == nil {
		virsh = virshLocal
	}
	dom := HostDomain(h.Cell)
	start := time.Now().UTC()
	var log strings.Builder
	fmt.Fprintf(&log, "cell=%s shape=%s domain=%s reset=%d/%d started=%s\ngate error: %s\n",
		h.Cell, h.Shape, dom, h.used, h.Max, start.Format(time.RFC3339), strings.Join(strings.Fields(gateErr.Error()), " "))
	state, _ := virsh(ctx, "domstate", dom)
	fmt.Fprintf(&log, "domstate before: %s\n", state)
	action := "reset"
	out, rerr := virsh(ctx, "reset", dom)
	if rerr != nil {
		action = "start"
		fmt.Fprintf(&log, "virsh reset: %v: %s\n", rerr, out)
		out, rerr = virsh(ctx, "start", dom)
	}
	fmt.Fprintf(&log, "virsh %s: err=%v out=%s\n", action, rerr, out)
	if rerr == nil {
		rerr = h.waitBack(ctx, r)
	}
	took := time.Since(start).Round(time.Second)
	if rerr != nil {
		fmt.Fprintf(&log, "outcome: still not back after %s: %v\n", took, rerr)
	} else {
		fmt.Fprintf(&log, "outcome: ssh and docker answered %s after the %s\n", took, action)
	}
	path := filepath.Join(h.EvidenceDir, fmt.Sprintf("%s-%s-host-reset-%d-%s.txt", h.Cell, h.Shape, h.used, start.Format("20060102T150405Z")))
	if werr := os.WriteFile(path, []byte(log.String()), 0o644); werr != nil {
		rerr = errors.Join(rerr, fmt.Errorf("host reset evidence: %w", werr))
	}
	fmt.Fprintf(os.Stderr, "labctl run: docker host %s %s after an ssh connect error; evidence %s\n", dom, action, path)
	if rerr != nil {
		return "", true, fmt.Errorf("docker host %s %s did not bring it back: %w", dom, action, rerr)
	}
	h.note = fmt.Sprintf("the docker host stopped answering ssh and was power-cycled (virsh %s, back after %s, %s)", action, took, path)
	return h.note, true, nil
}

// Gate runs gate, and once more after a reset when it failed on an ssh
// connect error; a failed reset joins the gate's error.
func (h *HostRecovery) Gate(ctx context.Context, r sourceadapter.Runner, gate func() error) error {
	err := gate()
	if _, tried, rerr := h.Try(ctx, r, err); tried {
		if rerr != nil {
			return fmt.Errorf("%w; %v", err, rerr)
		}
		return gate()
	}
	return err
}

// waitBack polls the boot id until ssh answers, then docker info, all
// inside Wait: the retrying runner is one-shot once a host is down.
func (h *HostRecovery) waitBack(ctx context.Context, r sourceadapter.Runner) error {
	wctx, cancel := context.WithTimeout(ctx, h.Wait)
	defer cancel()
	var err error
	for {
		if _, err = bootID(wctx, r); err == nil {
			if _, err = r.Run(wctx, "sudo docker info >/dev/null"); err == nil {
				return nil
			}
		}
		select {
		case <-wctx.Done():
			return fmt.Errorf("not answering within %s: %w", h.Wait, err)
		case <-time.After(h.Poll):
		}
	}
}
