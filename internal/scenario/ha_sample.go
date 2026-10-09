package scenario

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// haSample writes each peer's failover state, its clock and that clock's
// skew from the controller to the scenario's evidence, unjudged (lab
// #12): a verdict on a pair is then read against what the pair was doing.
// It returns "" on a single source or when the file cannot be written.
func haSample(ctx context.Context, e Env, scenario, label string) string {
	pc, ok := e.Source.(sourceadapter.PairControl)
	if !ok {
		return ""
	}
	var b strings.Builder
	for _, n := range pc.PeerNames() {
		now := time.Now()
		st, err := pc.PeerState(ctx, n)
		switch {
		case err != nil:
			fmt.Fprintf(&b, "%s error=%q\n", n, err.Error())
		case st.Clock.IsZero():
			fmt.Fprintf(&b, "%s state=%s clock=unknown\n", n, st.State)
		default:
			fmt.Fprintf(&b, "%s state=%s clock=%s skew=%s\n", n, st.State, st.Clock.UTC().Format(time.RFC3339), st.Clock.Sub(now).Round(time.Second))
		}
	}
	path := evidencePath(e, scenario, label)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return ""
	}
	return path
}

// withHASamples adds the two samples to a PASS or FAIL; a BLOCKED or
// N/A verdict carries no evidence by the verdict rules (#4).
func withHASamples(v Verdict, before, after string) Verdict {
	if v.Result != PASS && v.Result != FAIL {
		return v
	}
	if v.Evidence == nil {
		v.Evidence = map[string]string{}
	}
	for k, p := range map[string]string{"ha-state-before": before, "ha-state-after": after} {
		if p != "" {
			v.Evidence[k] = p
		}
	}
	return v
}
