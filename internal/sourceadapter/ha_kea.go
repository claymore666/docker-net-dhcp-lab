package sourceadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// HAState is one failover peer's own report of its state (lab #12).
// Clock is the peer's clock as its heartbeat states it, so a verdict can
// record the skew between the two VMs.
type HAState struct {
	State string
	Clock time.Time
	Raw   string
}

const keaStatusGetCmd = `curl -sf -X POST -H "Content-Type: application/json" ` +
	`-d '{"command":"status-get","service":["dhcp4"]}' http://127.0.0.1:8000/`

const keaHeartbeatCmd = `curl -sf -X POST -H "Content-Type: application/json" ` +
	`-d '{"command":"ha-heartbeat","service":["dhcp4"]}' http://127.0.0.1:8000/`

// KeaHotStandby is the state both peers of a healthy hot-standby pair
// report (Kea 2.6 ARM, HA states; measured locally, lab #12).
const KeaHotStandby = "hot-standby"

// KeaHAState reads a Kea peer's HA state from status-get and requires
// ha-heartbeat to report the same state; a disagreement is an error, not
// a state, so Ready never passes on a reply caught mid-transition.
func KeaHAState(ctx context.Context, r Runner) (HAState, error) {
	sg, err := r.Run(ctx, keaStatusGetCmd)
	if err != nil {
		return HAState{}, fmt.Errorf("kea: status-get: %w", err)
	}
	hb, err := r.Run(ctx, keaHeartbeatCmd)
	if err != nil {
		return HAState{}, fmt.Errorf("kea: ha-heartbeat: %w", err)
	}
	return parseKeaHAState(sg, hb)
}

func parseKeaHAState(statusGet, heartbeat string) (HAState, error) {
	var sg []struct {
		Result    int `json:"result"`
		Arguments struct {
			HA []struct {
				Servers struct {
					Local struct {
						State string `json:"state"`
					} `json:"local"`
				} `json:"ha-servers"`
			} `json:"high-availability"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal([]byte(statusGet), &sg); err != nil {
		return HAState{}, fmt.Errorf("kea: status-get reply: %w", err)
	}
	if len(sg) != 1 || sg[0].Result != 0 || len(sg[0].Arguments.HA) == 0 || sg[0].Arguments.HA[0].Servers.Local.State == "" {
		return HAState{}, fmt.Errorf("kea: status-get carries no HA state: %.300s", statusGet)
	}
	var hb []struct {
		Result    int `json:"result"`
		Arguments struct {
			State    string `json:"state"`
			DateTime string `json:"date-time"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal([]byte(heartbeat), &hb); err != nil {
		return HAState{}, fmt.Errorf("kea: ha-heartbeat reply: %w", err)
	}
	if len(hb) != 1 || hb[0].Result != 0 || hb[0].Arguments.State == "" {
		return HAState{}, fmt.Errorf("kea: ha-heartbeat carries no state: %.300s", heartbeat)
	}
	st := sg[0].Arguments.HA[0].Servers.Local.State
	if hb[0].Arguments.State != st {
		return HAState{}, fmt.Errorf("kea: status-get says %q, ha-heartbeat says %q", st, hb[0].Arguments.State)
	}
	clock, err := time.Parse(time.RFC1123, hb[0].Arguments.DateTime)
	if err != nil {
		return HAState{}, fmt.Errorf("kea: ha-heartbeat date-time: %w", err)
	}
	return HAState{State: st, Clock: clock, Raw: statusGet + "\n" + heartbeat}, nil
}
