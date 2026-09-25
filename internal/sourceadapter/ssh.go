package sourceadapter

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// SSHRunner reaches a source VM's own mgmt address the same way this
// repo's shell scripts do: a per-cell known_hosts file, no connection
// multiplexing, accept-new on a first, expected host key.
type SSHRunner struct {
	Host       string
	User       string
	KeyPath    string
	KnownHosts string
}

func (r SSHRunner) Run(ctx context.Context, remoteCmd string) (string, error) {
	args := []string{
		"-o", "UserKnownHostsFile=" + r.KnownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "ConnectTimeout=5",
		"-i", r.KeyPath,
		r.User + "@" + r.Host,
		remoteCmd,
	}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh %s@%s: %w: %s", r.User, r.Host, err, errOut.String())
	}
	return out.String(), nil
}
