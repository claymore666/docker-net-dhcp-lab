package scenario

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// VLANWitness is what E3b reads off the lab host: the segment bridge's
// VLAN filtering flag and the tagged capture leg (lab #15 E3b).
type VLANWitness interface {
	// Filtering is the bridge's vlan_filtering value, "0" or "1". (#15)
	Filtering(ctx context.Context) (string, error)
	// Tagged decodes the observer's VLAN-100 capture into path and
	// returns the text. (#15)
	Tagged(ctx context.Context, path string) (string, error)
}

// ObserverVLAN reads the segment bridge in the lab host's sysfs and the
// second tcpdump scripts/capture-start.sh runs in the observer. (#15)
type ObserverVLAN struct {
	Cell   string
	Bridge string
}

func (o ObserverVLAN) Filtering(ctx context.Context) (string, error) {
	b, err := os.ReadFile("/sys/class/net/" + o.Bridge + "/bridge/vlan_filtering")
	if err != nil {
		return "", fmt.Errorf("read vlan_filtering of %s: %w", o.Bridge, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func (o ObserverVLAN) Tagged(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, "sudo", "-n", "docker", "exec", "lab-observer-"+o.Cell,
		"tcpdump", "-n", "-e", "-vv", "-r", "/tmp/obs-vlan.pcap").Output()
	if err != nil {
		return "", fmt.Errorf("read the tagged capture of lab-observer-%s: %w", o.Cell, err)
	}
	return string(out), os.WriteFile(path, out, 0o644)
}
