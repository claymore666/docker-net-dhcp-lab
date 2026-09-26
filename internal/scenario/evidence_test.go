package scenario

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// countingReachAdapter is a minimal sourceadapter.Adapter whose
// Reachable method is scripted by call count and per-call latency, so
// reachableWithRetry's actual retry behaviour -- not just its final
// PASS/FAIL -- can be asserted without a real source VM.
type countingReachAdapter struct {
	unreachableFor int // calls that report unreachable before the first reachable one
	reachDelay     time.Duration
	calls          int
}

func (a *countingReachAdapter) Capabilities() []sourceadapter.Capability { return nil }
func (a *countingReachAdapter) Leases(_ context.Context) ([]sourceadapter.Lease, error) {
	return nil, nil
}
func (a *countingReachAdapter) ReserveMAC(_ context.Context, _, _ string) error { return nil }
func (a *countingReachAdapter) Restart(_ context.Context) error                 { return nil }
func (a *countingReachAdapter) Stop(_ context.Context) error                    { return nil }
func (a *countingReachAdapter) Start(_ context.Context) error                   { return nil }
func (a *countingReachAdapter) Reachable(_ context.Context, _ string) error {
	a.calls++
	if a.reachDelay > 0 {
		time.Sleep(a.reachDelay)
	}
	if a.calls <= a.unreachableFor {
		return fmt.Errorf("no route to host (call %d)", a.calls)
	}
	return nil
}

// TestReachableWithRetryPassesOnceTheContainerAnswers is the case
// reachabilityWindow exists for: a container that is not reachable the
// moment its lease is confirmed, but answers a few seconds later, must
// still PASS. A mutant that shrinks the retry window to a single ping
// (reachabilityWindow set to 0) fails this test, since the fake here
// only starts answering on its fourth call.
func TestReachableWithRetryPassesOnceTheContainerAnswers(t *testing.T) {
	a := &countingReachAdapter{unreachableFor: 3}
	secs, err := reachableWithRetry(context.Background(), a, "10.200.1.100")
	if err != nil {
		t.Fatalf("want PASS once the source answers, got error: %v", err)
	}
	if a.calls < 4 {
		t.Fatalf("want at least 4 calls to Reachable (3 failing + 1 succeeding), got %d", a.calls)
	}
	if secs < 3 {
		t.Fatalf("want the reported seconds to reflect the retries actually taken, got %d", secs)
	}
}

// TestReachableWithRetryDoesNotPassAfterTheWindowElapses covers the two
// edges the retry loop must respect: a reply that only arrives once
// reachabilityWindow has already elapsed does not count as reachable,
// and a timeout reports the real elapsed time rather than a value
// clamped to the window.
func TestReachableWithRetryDoesNotPassAfterTheWindowElapses(t *testing.T) {
	a := &countingReachAdapter{reachDelay: reachabilityWindow + 1200*time.Millisecond}
	secs, err := reachableWithRetry(context.Background(), a, "10.200.1.100")
	if err == nil {
		t.Fatalf("want an error when the only reply arrives after the window elapsed, got PASS after %ds", secs)
	}
	if a.calls != 1 {
		t.Fatalf("want exactly one attempt when its own latency already exceeds the window, got %d", a.calls)
	}
	if want := int(reachabilityWindow / time.Second); secs <= want {
		t.Fatalf("want the reported seconds to reflect the real elapsed time (> %ds), got %d", want, secs)
	}
}
