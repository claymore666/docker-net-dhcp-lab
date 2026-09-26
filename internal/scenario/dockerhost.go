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
func runContainer(ctx context.Context, r sourceadapter.Runner, net, name string) (mac, addr string, err error) {
	_, _ = r.Run(ctx, fmt.Sprintf("sudo docker rm -f %s", name))
	if _, err = r.Run(ctx, fmt.Sprintf("sudo docker run -d --name %s --network %s alpine:3.20 sleep 600", name, net)); err != nil {
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

// waitSSHBack retries a harmless remote command, bounded by wall clock
// rather than the caller's context: a host reboot (issue #3's A5) drops
// the connection this Run is issued over, and that is expected, not an
// error to surface -- only never coming back inside the bound is.
func waitSSHBack(ctx context.Context, r sourceadapter.Runner, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if _, err := r.Run(ctx, "true"); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("ssh did not come back within %s: %v", timeout, lastErr)
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
