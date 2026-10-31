package scenario

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// ParentCleanWindow bounds the wait for the segment NIC to lose the
// children of the previous shape's network (lab#38): a macvlan or ipvlan
// network removed a moment earlier can still hold the parent, and the
// plugin then refuses the next container with "would not accept another
// child". The lab waits for a clean parent and records the wait; it never
// retries a scenario.
const (
	ParentCleanWindow = 30 * time.Second
	ParentCleanPoll   = 2 * time.Second
)

// ParentChild is one macvlan or ipvlan link still attached to the parent.
type ParentChild struct {
	Name  string
	Kind  string
	Owner string
}

func (c ParentChild) String() string {
	return fmt.Sprintf("%s (%s, owner %s)", c.Name, c.Kind, c.Owner)
}

var (
	childKindRE  = regexp.MustCompile(`\s(macvlan|ipvlan|macvtap)\s`)
	childOwnerRE = regexp.MustCompile(`link-netns(?:id)?\s+(\S+)`)
)

// parentChildren reads `ip -d -o link show` output and returns the
// macvlan, ipvlan and macvtap links whose parent is the named NIC.
func parentChildren(out, parent string) []ParentChild {
	return childrenWithPrefix(out, "@"+parent+":")
}

// parentIndex is the ifindex of the named link in the host's listing.
func parentIndex(out, parent string) string {
	m := regexp.MustCompile(`(?m)^(\d+):\s+` + regexp.QuoteMeta(parent) + `[@:]`).FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1]
}

// childrenInNamespace returns the links of another namespace whose lower
// device is the parent: there ip prints the lower device as @if<ifindex>,
// the name not being visible (#97).
func childrenInNamespace(ns NamespaceLinks, idx string) []ParentChild {
	if idx == "" || ns.Err != nil {
		return nil
	}
	kids := childrenWithPrefix(ns.Links, "@if"+idx+":")
	for i := range kids {
		kids[i].Owner = "namespace " + ns.Name
	}
	return kids
}

func childrenWithPrefix(out, prefix string) []ParentChild {
	var kids []ParentChild
	for _, line := range strings.Split(out, "\n") {
		head, _, ok := strings.Cut(line, prefix)
		if !ok {
			continue
		}
		fields := strings.Fields(head)
		if len(fields) < 2 {
			continue
		}
		kind := childKindRE.FindStringSubmatch(line)
		if kind == nil {
			continue
		}
		owner := "not shown by ip -d"
		if m := childOwnerRE.FindStringSubmatch(line); m != nil {
			owner = "netns " + m[1]
		}
		kids = append(kids, ParentChild{Name: fields[len(fields)-1], Kind: kind[1], Owner: owner})
	}
	return kids
}

// WaitParentClean polls the docker host until the parent has no
// macvlan/ipvlan child or the window ends. report is the evidence text:
// one line per poll with what was still attached; left is what remained
// at the end (empty when clean).
func WaitParentClean(ctx context.Context, r sourceadapter.Runner, parent string, window, poll time.Duration) (report string, left []ParentChild, err error) {
	var b strings.Builder
	start := time.Now()
	fmt.Fprintf(&b, "waiting up to %s for %s to have no macvlan/ipvlan child, polling every %s\n", window, parent, poll)
	for n := 1; ; n++ {
		out, rerr := r.Run(ctx, "ip -d -o link show")
		if rerr != nil {
			return b.String(), nil, fmt.Errorf("parent-clean wait: ip -d -o link show: %w", rerr)
		}
		left = parentChildren(out, parent)
		// A child in a container or named namespace is not in the host's
		// listing (#97); only a host view with no child needs the rest.
		unreadable := ""
		if len(left) == 0 {
			others, lerr := listOtherNamespaces(ctx, r)
			if lerr != nil {
				return b.String(), nil, fmt.Errorf("parent-clean wait: %w", lerr)
			}
			idx := parentIndex(out, parent)
			var bad []string
			for _, ns := range others {
				if ns.Err != nil {
					bad = append(bad, ns.Name)
				}
				left = append(left, childrenInNamespace(ns, idx)...)
			}
			if len(bad) > 0 {
				unreadable = fmt.Sprintf(" (%d namespaces unreadable: %s)", len(bad), strings.Join(bad, ", "))
			}
		}
		elapsed := time.Since(start).Round(10 * time.Millisecond)
		if len(left) == 0 {
			fmt.Fprintf(&b, "poll %d at %s: clean%s\nwaited %s\n", n, elapsed, unreadable, elapsed)
			return b.String(), nil, nil
		}
		names := make([]string, len(left))
		for i, c := range left {
			names[i] = c.String()
		}
		fmt.Fprintf(&b, "poll %d at %s: still attached: %s\n", n, elapsed, strings.Join(names, "; "))
		if elapsed >= window {
			fmt.Fprintf(&b, "gave up after %s\n", elapsed)
			return b.String(), left, nil
		}
		if serr := sleepCtx(ctx, poll); serr != nil {
			return b.String(), left, serr
		}
	}
}

// ParentBusyReason is the BLOCKED reason when the parent never cleared.
func ParentBusyReason(parent string, window time.Duration, left []ParentChild) string {
	names := make([]string, len(left))
	for i, c := range left {
		names[i] = c.String()
	}
	return fmt.Sprintf("parent %s still had child link %s after waiting %s; the plugin or Docker left it there after the previous network was removed, so no scenario of this shape was run",
		parent, strings.Join(names, " and "), window)
}

// ParentReady is the between-shapes step, run before every shape: it waits
// for a clean SegmentNIC after removing the cell's leftover containers
// (#139), writes the wait to <cell>-<shape>-parent-ready.txt
// in evidenceDir and returns a non-empty blocked reason when the parent
// never cleared.
func ParentReady(ctx context.Context, r sourceadapter.Runner, cell string, shape Shape, evidenceDir string, window, poll time.Duration) (blocked string, err error) {
	// The bridge shapes too: the kernel will not make a NIC with a macvlan
	// or ipvlan child a bridge port, and bridge-ipam ended as an
	// infrastructure error behind such a child in the 2026-10-09 run (lab#38).
	if err := RemoveLeftoverContainers(ctx, r, cell, shape, evidenceDir); err != nil {
		return "", err
	}
	report, left, werr := WaitParentClean(ctx, r, SegmentNIC, window, poll)
	name := fmt.Sprintf("%s-%s-parent-ready.txt", cell, shape)
	if err := os.WriteFile(filepath.Join(evidenceDir, name), []byte(report), 0o644); err != nil {
		return "", fmt.Errorf("parent-ready evidence: %w", err)
	}
	if werr != nil {
		return "", werr
	}
	if len(left) > 0 {
		return ParentBusyReason(SegmentNIC, window, left) + " (wait record: " + name + ")", nil
	}
	return "", nil
}
