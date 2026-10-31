package scenario

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// The saturation windows of host run 5 lasted up to 5.5 min and reset the
// ssh connection under a teardown that then discarded its errors, leaving
// the segment NIC enslaved to the previous shape's bridge (#137).
var (
	teardownRetryBound = 6 * time.Minute
	teardownRetryPoll  = 5 * time.Second
)

// runRetrying runs an idempotent command and repeats it while ssh itself
// fails (exit 255) within teardownRetryBound; any other error is the
// command's own answer and comes back at once.
func runRetrying(ctx context.Context, r sourceadapter.Runner, cmd string) (string, error) {
	deadline := time.Now().Add(teardownRetryBound)
	for {
		out, err := r.Run(ctx, cmd)
		if err == nil || !isTransport(err) {
			return out, err
		}
		if !time.Now().Before(deadline) {
			return out, fmt.Errorf("%w (ssh still failing after %s of retries)", err, teardownRetryBound)
		}
		if serr := sleepCtx(ctx, teardownRetryPoll); serr != nil {
			return out, err
		}
	}
}

func isTransport(err error) bool { return err != nil && sshTransportRE.MatchString(err.Error()) }

var heldByMasterRE = regexp.MustCompile(`\smaster\s+(\S+)`)

// linkMaster is the bridge or bond the named link is enslaved to, empty
// when it has none. The read is retried over ssh; a link that cannot be
// read is an error, never "no master".
func linkMaster(ctx context.Context, r sourceadapter.Runner, link string) (string, error) {
	out, err := runRetrying(ctx, r, "ip -o link show "+link)
	if err != nil {
		return "", fmt.Errorf("ip -o link show %s: %w", link, err)
	}
	if m := heldByMasterRE.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", nil
}

// linkExists reports whether the named link is on the host. A failed read
// that is not ssh's own means the link does not exist (`ip` exits 1).
func linkExists(ctx context.Context, r sourceadapter.Runner, link string) (bool, error) {
	out, err := runRetrying(ctx, r, "ip -o link show "+link)
	if err != nil {
		if isTransport(err) {
			return false, fmt.Errorf("ip -o link show %s: %w", link, err)
		}
		return false, nil
	}
	return strings.Contains(out, link+":"), nil
}

// parentHeldReason is NetworkUp's refusal for a macvlan or ipvlan shape
// whose parent is still enslaved by an earlier shape (#137); the reason
// reaches the BLOCKED rows through the wrapper.
func parentHeldReason(shape Shape, master string) string {
	return fmt.Sprintf("networkup(%s): lab: parent %s is still enslaved to %s, left there by an earlier shape's teardown; no scenario of this shape was run", shape, SegmentNIC, master)
}
