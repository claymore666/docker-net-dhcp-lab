package sourceadapter

import (
	"context"
	"fmt"
)

// service is the command set that controls one source daemon; name
// labels errors and signal is a format taking the signal name. Ready,
// Recover, ResetLeases and SetRA run these strings only, so a source
// without systemd brings its own set (#9).
type service struct {
	name                           string
	isActive, stop, start, restart string
	signal                         string
}

// systemdService is the default set, the Debian cells' systemd units.
func systemdService(unit string) service {
	return service{
		name:     unit,
		isActive: "sudo systemctl is-active --quiet " + unit,
		stop:     "sudo systemctl stop " + unit,
		start:    "sudo systemctl start " + unit,
		restart:  "sudo systemctl restart " + unit,
		signal:   "sudo systemctl kill -s %s " + unit,
	}
}

// kill is the command that sends sig to the daemon; no signal format is
// refused like do's missing verb (#9).
func (s service) kill(sig string) (string, error) {
	if s.signal == "" {
		return "", fmt.Errorf("no signal command for %s", s.name)
	}
	return fmt.Sprintf(s.signal, sig), nil
}

// do sends the stop, start or restart command.
func (s service) do(ctx context.Context, r Runner, action, label string) error {
	cmd := map[string]string{"stop": s.stop, "start": s.start, "restart": s.restart}[action]
	if cmd == "" {
		return fmt.Errorf("%s: no %s command for %s", label, action, s.name)
	}
	if _, err := r.Run(ctx, cmd); err != nil {
		return fmt.Errorf("%s: %s %s: %w", label, action, s.name, err)
	}
	return nil
}

// host is what the shared helpers know about a source VM's userland:
// the command set of each named unit, the main one, the segment NIC and
// tc path, and whether iproute2 netns, pgrep, tc and python3 are there
// (portable). The actor lines of the state read, Recover's actor sweep,
// Impair, ForceRenew and the group C actors need a portable host (#9).
type host struct {
	unit     func(name string) service
	main     string
	label    string // names the source in a refusal when main does not (lab #9)
	nic      string
	tc       string
	portable bool
}

// debianHost is the cloud-init Debian source VM every cell ran on before
// #9: systemd, eth1 and /usr/sbin/tc.
func debianHost(main string) host {
	return host{unit: systemdService, main: main, nic: segmentNIC, tc: tcBin, portable: true}
}

// svc is the main unit's command set.
func (h host) svc() service { return h.unit(h.main) }

// needPortable refuses what before any command reaches the source.
func (h host) needPortable(what string) error {
	if !h.portable {
		name := h.main
		if h.label != "" {
			name = h.label
		}
		return fmt.Errorf("%s: the %s source has no iproute2 netns, pgrep, tc or python3", what, name)
	}
	return nil
}
