package sourceadapter

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

// IsConnectError reports an ssh failure that happened before the remote command could run.
func IsConnectError(err error) bool {
	if err == nil {
		return false
	}
	// ssh exits 255 and names the connect or banner step (OpenSSH
	// ssh.c/sshconnect.c messages); a session dropped after the command
	// started reads "closed by remote host" and must not be re-run (#38).
	s := err.Error()
	if !strings.Contains(s, "exit status 255") {
		return false
	}
	return strings.Contains(s, "connect to host ") ||
		strings.Contains(s, "during banner exchange") ||
		strings.Contains(s, "kex_exchange_identification")
}

// RetryRunner retries a call whose ssh connection failed before the command ran, within Bound per call and never past ctx.
type RetryRunner struct {
	Inner Runner
	Bound time.Duration
	Poll  time.Duration
	Log   io.Writer
	down  atomic.Bool
}

func (r *RetryRunner) Run(ctx context.Context, remoteCmd string) (string, error) {
	// #38, -j 6 run of 2026-10-09: four guests refused new ssh connections
	// for 1.5 to 4 min at peak load, and one attempt per scenario used up
	// whole shapes. After one exhausted Bound a call makes a single attempt
	// until one succeeds, so a dead guest costs Bound once per process.
	start := time.Now()
	var first, last error
	for attempt := 1; ; attempt++ {
		out, err := r.Inner.Run(ctx, remoteCmd)
		if err == nil {
			r.down.Store(false)
			if first != nil && r.Log != nil {
				fmt.Fprintf(r.Log, "ssh retry: answered after %s and %d attempts, first error: %s\n",
					time.Since(start).Round(time.Second), attempt, strings.Join(strings.Fields(first.Error()), " "))
			}
			return out, nil
		}
		if last != nil && ctx.Err() != nil {
			// The caller's deadline cut this attempt; the connect failure before it is the answer.
			return out, last
		}
		if !IsConnectError(err) || r.down.Load() {
			return out, err
		}
		if first == nil {
			first = err
		}
		last = err
		if time.Since(start) >= r.Bound {
			r.down.Store(true)
			return out, fmt.Errorf("%w (unreachable for %s of retries)", err, r.Bound)
		}
		select {
		case <-ctx.Done():
			return out, err
		case <-time.After(r.Poll):
		}
	}
}
