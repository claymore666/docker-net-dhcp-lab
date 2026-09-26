package scenario

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// runContainer starts one throwaway container on net and returns the
// MAC/address the plugin reported to docker: an identifier to look up
// in the source's own table, never evidence on its own (same discipline
// scripts/run-source-lease-test.sh already established for issue #2).
// It carries no restart policy, matching Docker's own default.
func runContainer(ctx context.Context, r sourceadapter.Runner, net, name string) (mac, addr string, err error) {
	return runContainerPolicy(ctx, r, net, name, "")
}

// runContainerPolicy is runContainer with an explicit Docker restart
// policy. A4 (daemon restart) and A5 (host reboot) need it set to
// "unless-stopped": a container started with no restart policy is never
// supposed to come back on its own after either event -- that is Docker's
// own documented default, not a plugin defect, and a scenario that leaves
// it unset is testing something no real user configured (issue #3, lead
// directive 2026-09-26).
func runContainerPolicy(ctx context.Context, r sourceadapter.Runner, net, name, restart string) (mac, addr string, err error) {
	_, _ = r.Run(ctx, fmt.Sprintf("sudo docker rm -f %s", name))
	restartFlag := ""
	if restart != "" {
		restartFlag = fmt.Sprintf(" --restart %s", restart)
	}
	if _, err = r.Run(ctx, fmt.Sprintf("sudo docker run -d --name %s --network %s%s alpine:3.20 sleep 600", name, net, restartFlag)); err != nil {
		return "", "", fmt.Errorf("docker run: %w", err)
	}
	if mac, err = inspectField(ctx, r, name, "MacAddress"); err != nil {
		return "", "", err
	}
	if addr, err = inspectField(ctx, r, name, "IPAddress"); err != nil {
		return "", "", err
	}
	if mac == "" || addr == "" {
		return "", "", fmt.Errorf("container %s has no mac/address reported", name)
	}
	return mac, addr, nil
}

func inspectField(ctx context.Context, r sourceadapter.Runner, name, field string) (string, error) {
	out, err := r.Run(ctx, fmt.Sprintf(
		`sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.%s}}{{end}}' %s`, field, name))
	if err != nil {
		return "", fmt.Errorf("docker inspect %s %s: %w", name, field, err)
	}
	return strings.TrimSpace(out), nil
}

func removeContainer(ctx context.Context, r sourceadapter.Runner, name string) {
	_, _ = r.Run(ctx, fmt.Sprintf("sudo docker rm -f %s", name))
}

func waitContainerRunning(ctx context.Context, r sourceadapter.Runner, name string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := r.Run(ctx, fmt.Sprintf("sudo docker inspect -f '{{.State.Running}}' %s", name))
		if err == nil && strings.TrimSpace(out) == "true" {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("container %s did not report Running within 30s", name)
}

func waitDockerBack(ctx context.Context, r sourceadapter.Runner, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := r.Run(ctx, "sudo docker version >/dev/null"); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("dockerd did not come back within %s: %v", timeout, lastErr)
}

// bootID reads the kernel's own boot id, the one identifier that
// actually distinguishes "the old boot, still shutting down" from "the
// new boot, up for real" -- unlike a bare SSH poll, which sshd keeps
// answering on for a beat after `systemctl reboot` is issued.
func bootID(ctx context.Context, r sourceadapter.Runner) (string, error) {
	out, err := r.Run(ctx, "cat /proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(out)
	if id == "" {
		return "", fmt.Errorf("empty boot id")
	}
	return id, nil
}

// waitHostRebooted replaces the old first-poll-wins waitSSHBack after a
// live diagnostic against a real cell (issue #3, A5, 2026-09-26): a bare
// successful SSH poll right after `systemctl reboot` is not evidence the
// reboot happened. Measured directly: two polls landed successfully at
// +1.05s and +2.4s after the reboot command returned, both still against
// the OLD boot id (sshd keeps answering while the box is mid-shutdown);
// the connection only actually dropped on the third poll, ~4.1s in. A
// scenario that trusted the first of those polls would report the host
// "back" while it was still going down for the real reboot over the
// next ~59s -- exactly the shape of the cascade this fix addresses (A6
// onward failing with connection-refused right after an A5 PASS).
//
// So this checks three things, in order, all bounded by wall clock:
//  1. the kernel's own boot id changes from the one recorded before the
//     reboot was issued (not just "SSH answers again" -- that answered a
//     survived response, twice, from the boot that was already dying);
//  2. a second poll against that SAME new boot id lands at least 10s
//     after the first sighting, so a lucky single ping (or a second,
//     unplanned reboot mid-settle) cannot pass on its own;
//  3. `docker info` answers on the confirmed new boot.
func waitHostRebooted(ctx context.Context, r sourceadapter.Runner, beforeBootID string, timeout time.Duration) error {
	return waitHostRebootedTuned(ctx, r, beforeBootID, timeout, 10*time.Second, 2*time.Second)
}

// waitHostRebootedTuned is waitHostRebooted with the settle window and
// poll interval broken out so a test can shrink both (a real 10s settle
// window is the point of the fix, not something to skip -- shrinking it
// is a test-speed concern only, never a way to weaken the check itself).
func waitHostRebootedTuned(ctx context.Context, r sourceadapter.Runner, beforeBootID string, timeout, settle, poll time.Duration) error {
	deadline := time.Now().Add(timeout)

	var newID string
	for time.Now().Before(deadline) {
		if id, err := bootID(ctx, r); err == nil && id != beforeBootID {
			newID = id
			break
		}
		time.Sleep(poll)
	}
	if newID == "" {
		return fmt.Errorf("boot id never changed from %s within %s: host did not come back on a new boot", beforeBootID, timeout)
	}
	firstSeen := time.Now()

	settled := false
	for time.Now().Before(deadline) {
		if time.Since(firstSeen) >= settle {
			id, err := bootID(ctx, r)
			if err == nil && id == newID {
				settled = true
				break
			}
			if err == nil && id != newID {
				return fmt.Errorf("boot id changed again mid-settle (%s -> %s): a second reboot happened while waiting for %s to settle", newID, id, newID)
			}
		}
		time.Sleep(poll)
	}
	if !settled {
		return fmt.Errorf("boot id %s never got a second confirmation >=%s later within %s", newID, settle, timeout)
	}

	if _, err := r.Run(ctx, "sudo docker info >/dev/null"); err != nil {
		return fmt.Errorf("boot id %s confirmed twice, but docker info did not answer: %w", newID, err)
	}
	return nil
}

// pluginPID finds the plugin's own process by exact name. The plugin
// manifest asks for the host PID namespace (docs/index.md in the plugin
// repo), so its process is visible here directly; -x matches the exact
// name only, the same rule every process check in this repo already
// follows -- never -f, which would match this very command's own argv.
func pluginPID(ctx context.Context, r sourceadapter.Runner) (string, error) {
	out, err := r.Run(ctx, "sudo pgrep -x net-dhcp")
	if err != nil {
		return "", fmt.Errorf("pgrep -x net-dhcp: %w", err)
	}
	pid := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if pid == "" {
		return "", fmt.Errorf("no net-dhcp process found")
	}
	return pid, nil
}

// waitPluginBack polls for the plugin's process by exact name, first on
// its own and then, only if that never happens, after one explicit
// re-enable -- and says in its return value which one actually worked,
// so a scenario that had to intervene reports that honestly rather than
// reading identically to a self-heal (issue #3: never tune a scenario
// to pass; report what happened).
func waitPluginBack(ctx context.Context, r sourceadapter.Runner) (recoveredBy string, err error) {
	if pollPluginPID(ctx, r, 30*time.Second) {
		return "self", nil
	}
	if _, enableErr := r.Run(ctx, "sudo docker plugin enable "+pluginAlias); enableErr != nil {
		return "", fmt.Errorf("did not come back on its own in 30s, and a manual re-enable failed: %w", enableErr)
	}
	if pollPluginPID(ctx, r, 30*time.Second) {
		return "manual", nil
	}
	return "", fmt.Errorf("did not come back within 30s on its own or 30s after a manual re-enable")
}

func pollPluginPID(ctx context.Context, r sourceadapter.Runner, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := pluginPID(ctx, r); err == nil {
			return true
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func installedPluginTag(ctx context.Context, r sourceadapter.Runner) (string, error) {
	out, err := r.Run(ctx, "sudo docker plugin inspect -f '{{.PluginReference}}' "+pluginAlias)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// dhcpExchangeReason reuses the repo's own checker (issue #2's
// dhcp-exchange-check.sh) so there is exactly one place that defines a
// complete DHCP exchange, tied to one MAC via option 53 -- never a
// second, drifting copy of that logic in Go.
func dhcpExchangeReason(ctx context.Context, repoRoot, pcapPath, mac string) (string, error) {
	script := repoRoot + "/scripts/dhcp-exchange-check.sh"
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("dhcp-exchange-check.sh not found at %s: %w", script, err)
	}
	cmd := exec.CommandContext(ctx, "bash", "-c",
		`. "$1"; dhcp_exchange_reason "$2" "$3"`,
		"dhcp-exchange-check-wrapper", script, pcapPath, mac)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("dhcp_exchange_reason: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
