package sourceadapter

import (
	"context"
	"encoding/json"
	"fmt"
)

// KeaAdapter reads leases through the Kea control agent's own HTTP API,
// bound to 127.0.0.1 only (never the segment or mgmt network) and
// reached over the same SSH connection as the service itself -- the
// control channel never opens a port beyond what SSH already reaches.
// ReserveMAC's command construction is unit-tested against a fake
// runner (adapter_test.go); restart/stop/start are implemented but not
// yet exercised against a live Kea instance.
type KeaAdapter struct {
	Runner Runner
}

func (a *KeaAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart}
}

const keaLeaseCmd = `curl -sf -X POST -H "Content-Type: application/json" ` +
	`-d '{"command":"lease4-get-all","service":["dhcp4"]}' http://127.0.0.1:8000/`

// keaResponse mirrors the control agent's own reply shape: a JSON array,
// one element per queried service, `result` 0 for leases present, 3 for
// "no leases" (Kea's own CONTROL_RESULT_EMPTY), anything else an error
// state at the source itself, not a transport failure.
type keaResponse struct {
	Result    int `json:"result"`
	Arguments struct {
		Leases []struct {
			IPAddress string `json:"ip-address"`
			HWAddress string `json:"hw-address"`
			Hostname  string `json:"hostname"`
		} `json:"leases"`
	} `json:"arguments"`
}

func (a *KeaAdapter) Leases(ctx context.Context) ([]Lease, error) {
	out, err := a.Runner.Run(ctx, keaLeaseCmd)
	if err != nil {
		return nil, fmt.Errorf("kea: control agent request: %w", err)
	}
	return parseKeaLeases(out)
}

// parseKeaLeases separates a genuinely empty table (result 3) from a
// truncated or malformed reply, which must fail rather than read as
// zero leases (issue #2).
func parseKeaLeases(raw string) ([]Lease, error) {
	var resp []keaResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, fmt.Errorf("kea: control agent reply did not parse as JSON: %w", err)
	}
	if len(resp) == 0 {
		return nil, fmt.Errorf("kea: control agent reply had no service entries")
	}
	switch resp[0].Result {
	case 0, 3:
	default:
		return nil, fmt.Errorf("kea: control agent returned result=%d", resp[0].Result)
	}
	leases := make([]Lease, 0, len(resp[0].Arguments.Leases))
	for _, l := range resp[0].Arguments.Leases {
		leases = append(leases, Lease{MAC: l.HWAddress, Address: l.IPAddress, Hostname: l.Hostname})
	}
	return leases, nil
}

// ReserveMAC appends to the reservations file Kea's config includes
// (issue #2), then asks the running server to reload -- never a
// restart, so leases already handed out stay live. hw/ip are guaranteed
// clean by validateMAC/validateAddr before they ever reach this string.
func (a *KeaAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf(
		`sudo jq '. + [{"hw-address":"%s","ip-address":"%s"}]' /etc/kea/reservations.json | sudo tee /etc/kea/reservations.json.tmp >/dev/null && sudo mv /etc/kea/reservations.json.tmp /etc/kea/reservations.json && sudo systemctl kill -s HUP kea-dhcp4-server`,
		hw, ip,
	)
	if _, err := a.Runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("kea: reserve %s -> %s: %w", hw, ip, err)
	}
	return nil
}

func (a *KeaAdapter) Restart(ctx context.Context) error { return a.systemctl(ctx, "restart") }
func (a *KeaAdapter) Stop(ctx context.Context) error    { return a.systemctl(ctx, "stop") }
func (a *KeaAdapter) Start(ctx context.Context) error   { return a.systemctl(ctx, "start") }

func (a *KeaAdapter) systemctl(ctx context.Context, action string) error {
	if _, err := a.Runner.Run(ctx, "sudo systemctl "+action+" kea-dhcp4-server"); err != nil {
		return fmt.Errorf("kea: systemctl %s: %w", action, err)
	}
	return nil
}
