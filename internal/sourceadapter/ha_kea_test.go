package sourceadapter

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type seqRunner struct {
	replies []string
	errs    []error
	calls   []string
}

func (s *seqRunner) Run(_ context.Context, cmd string) (string, error) {
	i := len(s.calls)
	s.calls = append(s.calls, cmd)
	if i >= len(s.replies) {
		return "", errors.New("seqRunner: no reply left")
	}
	return s.replies[i], s.errs[i]
}

func TestKeaHAStateReadsBothReplies(t *testing.T) {
	sg, hb := readFixture(t, "status-get-hot-standby.json"), readFixture(t, "ha-heartbeat-hot-standby.json")
	r := &seqRunner{replies: []string{sg, hb}, errs: []error{nil, nil}}
	got, err := KeaHAState(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 || !strings.Contains(r.calls[1], `"command":"ha-heartbeat"`) {
		t.Fatalf("calls %q", r.calls)
	}
	if got.State != "hot-standby" || !strings.Contains(got.Raw, sg) || !strings.Contains(got.Raw, hb) {
		t.Fatalf("got %+v", got)
	}
}

func TestKeaHAStateHeartbeatTransportError(t *testing.T) {
	r := &seqRunner{replies: []string{readFixture(t, "status-get-hot-standby.json"), ""}, errs: []error{nil, errors.New("ssh down")}}
	if _, err := KeaHAState(context.Background(), r); err == nil || !strings.Contains(err.Error(), "ha-heartbeat: ssh down") {
		t.Fatalf("err %v", err)
	}
}

// Each rule rejects a reply that only it can catch, so the message names the rule.
func TestParseKeaHAStateNamesEachRule(t *testing.T) {
	const sgOne = `{"result":0,"arguments":{"high-availability":[{"ha-servers":{"local":{"state":"hot-standby"}}}]}}`
	const hbOne = `{"result":0,"arguments":{"state":"hot-standby","date-time":"Fri, 09 Oct 2026 18:38:11 GMT"}}`
	sg, hb := "["+sgOne+"]", "["+hbOne+"]"
	if _, err := parseKeaHAState(sg, hb); err != nil {
		t.Fatalf("minimal replies: %v", err)
	}
	for _, c := range []struct{ name, sg, hb, want string }{
		{"status-get not JSON", "{", hb, "status-get reply"},
		{"two status-get replies", "[" + sgOne + "," + sgOne + "]", hb, "carries no HA state"},
		{"status-get error result", strings.Replace(sg, `"result":0`, `"result":1`, 1), hb, "carries no HA state"},
		{"status-get without a local state", `[{"result":0,"arguments":{"high-availability":[{"ha-servers":{"local":{}}}]}}]`, hb, "carries no HA state"},
		{"heartbeat not JSON", sg, "{", "ha-heartbeat reply"},
		{"two heartbeat replies", sg, "[" + hbOne + "," + hbOne + "]", "carries no state"},
		{"heartbeat error result", sg, strings.Replace(hb, `"result":0`, `"result":1`, 1), "carries no state"},
		{"heartbeat without a state", sg, `[{"result":0,"arguments":{"date-time":"Fri, 09 Oct 2026 18:38:11 GMT"}}]`, "carries no state"},
	} {
		if _, err := parseKeaHAState(c.sg, c.hb); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", c.name, err, c.want)
		}
	}
}
