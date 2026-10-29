package scenario

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// NamespaceLinks is one network namespace's `ip -d -o link show`, headed
// by the name or pid that identifies the namespace in the evidence (#97).
type NamespaceLinks struct {
	Name  string
	Links string
	Err   error
}

var (
	safeNetnsName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	containerIDRE = regexp.MustCompile(`^[0-9a-f]+$`)
	pidDigitsRE   = regexp.MustCompile(`^[0-9]+$`)
)

const linkListCmd = "ip -d -o link show"

// listOtherNamespaces reads the links of every network namespace except the
// docker host's own: each `ip netns` entry, each running container through
// nsenter on its pid, and the plugin's process (#97). A namespace that
// cannot be read is a section with Err, since a container can stop between
// the listing and the read; only a failure to enumerate is an error.
func listOtherNamespaces(ctx context.Context, r sourceadapter.Runner) ([]NamespaceLinks, error) {
	var res []NamespaceLinks
	names, err := r.Run(ctx, "ip netns list")
	if err != nil {
		return nil, fmt.Errorf("ip netns list: %w", err)
	}
	for _, line := range strings.Split(names, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if !safeNetnsName.MatchString(f[0]) {
			res = append(res, NamespaceLinks{Name: fmt.Sprintf("netns %q", f[0]), Err: fmt.Errorf("name not safe to pass to a command")})
			continue
		}
		out, rerr := r.Run(ctx, fmt.Sprintf("sudo ip netns exec %s %s", f[0], linkListCmd))
		res = append(res, NamespaceLinks{Name: "netns " + f[0], Links: out, Err: rerr})
	}
	ids, err := r.Run(ctx, "sudo docker ps -q")
	if err != nil {
		return nil, fmt.Errorf("docker ps -q: %w", err)
	}
	for _, id := range strings.Fields(ids) {
		if !containerIDRE.MatchString(id) {
			res = append(res, NamespaceLinks{Name: fmt.Sprintf("container %q", id), Err: fmt.Errorf("id not safe to pass to a command")})
			continue
		}
		res = append(res, containerLinks(ctx, r, id))
	}
	res = append(res, pluginLinks(ctx, r))
	return res, nil
}

func nsenterLinks(ctx context.Context, r sourceadapter.Runner, label, pid string) NamespaceLinks {
	if !pidDigitsRE.MatchString(pid) || pid == "0" {
		return NamespaceLinks{Name: label, Err: fmt.Errorf("no usable pid %q", pid)}
	}
	label = fmt.Sprintf("%s (pid %s)", label, pid)
	out, err := r.Run(ctx, fmt.Sprintf("sudo nsenter -t %s -n %s", pid, linkListCmd))
	return NamespaceLinks{Name: label, Links: out, Err: err}
}

func containerLinks(ctx context.Context, r sourceadapter.Runner, id string) NamespaceLinks {
	out, err := r.Run(ctx, fmt.Sprintf("sudo docker inspect -f '{{.Name}} {{.State.Pid}}' %s", id))
	f := strings.Fields(out)
	if err != nil || len(f) != 2 {
		if err == nil {
			err = fmt.Errorf("unexpected inspect output %q", strings.TrimSpace(out))
		}
		return NamespaceLinks{Name: "container " + id, Err: err}
	}
	return nsenterLinks(ctx, r, "container "+strings.TrimPrefix(f[0], "/"), f[1])
}

func pluginLinks(ctx context.Context, r sourceadapter.Runner) NamespaceLinks {
	pid, err := pluginPID(ctx, r)
	if err != nil {
		return NamespaceLinks{Name: "plugin", Err: err}
	}
	return nsenterLinks(ctx, r, "plugin", pid)
}

// FormatNamespaceLinks is the text of <cell>-parent-busy-links.txt: one
// section per namespace, headed by its name or pid.
func FormatNamespaceLinks(nss []NamespaceLinks) string {
	var b strings.Builder
	for _, ns := range nss {
		fmt.Fprintf(&b, "== %s ==\n", ns.Name)
		if ns.Err != nil {
			fmt.Fprintf(&b, "unreadable: %s\n", strings.Join(strings.Fields(ns.Err.Error()), " "))
			continue
		}
		b.WriteString(strings.TrimRight(ns.Links, "\n"))
		b.WriteString("\n")
	}
	return b.String()
}

// parentBusyText says whether err is the plugin's refusal to create a
// macvlan or ipvlan link on the parent (#97, run of 2026-10-13: `failed
// to create macvlan link on "eth1": device or resource busy`).
func parentBusyText(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "device or resource busy") && (strings.Contains(s, "macvlan") || strings.Contains(s, "ipvlan"))
}

// BusyCapture wraps the docker host runner. At the first parent EBUSY of a
// cell it writes every namespace's links to <cell>-parent-busy-links.txt;
// later ones append a marker line. The caller sees Inner's result as is (#97).
type BusyCapture struct {
	Inner       sourceadapter.Runner
	Cell        string
	EvidenceDir string
	Log         io.Writer
	mu          sync.Mutex
}

func (c *BusyCapture) Run(ctx context.Context, remoteCmd string) (string, error) {
	out, err := c.Inner.Run(ctx, remoteCmd)
	if parentBusyText(err) {
		c.capture(ctx, remoteCmd, err)
	}
	return out, err
}

func (c *BusyCapture) capture(ctx context.Context, remoteCmd string, cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	path := filepath.Join(c.EvidenceDir, c.Cell+"-parent-busy-links.txt")
	at := time.Now().UTC().Format(time.RFC3339)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if os.IsExist(err) {
		f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			_, err = fmt.Fprintf(f, "later parent EBUSY at %s from: %s\n", at, remoteCmd)
		}
	} else if err == nil {
		host, herr := c.Inner.Run(ctx, linkListCmd)
		nss := []NamespaceLinks{{Name: "host", Links: host, Err: herr}}
		others, lerr := listOtherNamespaces(ctx, c.Inner)
		if lerr != nil {
			nss = append(nss, NamespaceLinks{Name: "other namespaces", Err: lerr})
		}
		nss = append(nss, others...)
		_, err = fmt.Fprintf(f, "first parent EBUSY of cell %s at %s from: %s\nerror: %s\n%s",
			c.Cell, at, remoteCmd, strings.Join(strings.Fields(cause.Error()), " "), FormatNamespaceLinks(nss))
	}
	if f != nil {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil && c.Log != nil {
		fmt.Fprintf(c.Log, "parent-busy capture: %v\n", err)
	}
}
