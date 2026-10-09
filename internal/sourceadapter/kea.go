package sourceadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// keaValidLifetimeRE matches the config's own "valid-lifetime": N, field
// (ShortenLeaseTime, #3, A14).
var keaValidLifetimeRE = regexp.MustCompile(`"valid-lifetime":\s*[0-9]+,`)

// KeaAdapter reads leases through the Kea control agent's own HTTP API,
// bound to 127.0.0.1 only (never the segment or mgmt network) and
// reached over the same SSH connection as the service itself -- the
// control channel never opens a port beyond what SSH already reaches.
// ReserveMAC's command construction is unit-tested against a fake
// runner (adapter_test.go); restart/stop/start are implemented but not
// yet exercised against a live Kea instance.
type KeaAdapter struct {
	Runner Runner
	base   baseline
}

func (a *KeaAdapter) Capabilities() []Capability {
	return []Capability{CapV4, CapReserveMAC, CapRestart, CapShortLease, CapReserveClientID, CapVendorClassPool, CapOptionChange, CapImpair, CapUserClassPool, CapOption108, CapForceRenewNonce, CapSquatter, CapRogueServer, CapNarrowPool, CapRenumber}
}

const keaLeaseCmd = `curl -sf -X POST -H "Content-Type: application/json" ` +
	`-d '{"command":"lease4-get-all","service":["dhcp4"]}' http://127.0.0.1:8000/`

// keaLeaseFile is the on-disk path the cloud-init template now names
// explicitly in "lease-database".name (issue #3 part 2): without an
// explicit name the package's own default is not something this
// adapter can rely on being the same across a Debian package upgrade,
// and ResetLeases has to truncate the exact file the running config
// actually writes to.
const keaLeaseFile = "/var/lib/kea/kea-leases4.csv"

// keaReloadedLeaseFiles are the memfile lease-file cleanup (LFC) copies
// Kea reads back at start beside keaLeaseFile; leaving one behind refills
// the table after ResetLeases (C4 defeat 2, #23).
var keaReloadedLeaseFiles = []string{keaLeaseFile + ".1", keaLeaseFile + ".2", keaLeaseFile + ".output", keaLeaseFile + ".completed"}

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
			ClientID  string `json:"client-id"`
			State     int    `json:"state"`
			CLTT      int64  `json:"cltt"`
			ValidLft  int64  `json:"valid-lft"`
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
		// State 0 is "default" (active); declined, expired-reclaimed
		// and released rows stay in the memfile until reclaimed and
		// are not leases (B7, #23). A row that carries cltt but a zero
		// valid-lft is a release too.
		if l.State != 0 || (l.CLTT != 0 && l.ValidLft == 0) {
			continue
		}
		lease := Lease{
			MAC: l.HWAddress, Address: l.IPAddress, Hostname: l.Hostname,
			ClientID: strings.ToLower(l.ClientID),
		}
		if l.ValidLft > 0 {
			lease.Expires = time.Unix(l.CLTT+l.ValidLft, 0).UTC()
		}
		leases = append(leases, lease)
	}
	return leases, nil
}

// keaReserve replaces any reservation for the same identifier and adds
// the new one in a single jq pass over the include file, then asks the
// running server to reload -- never a restart, so leases already handed
// out stay live. A rerun after a half-finished run therefore never
// leaves two rows for one identifier (#23). field and value are
// validated by the caller (validateMAC, validateClientID); ip by
// validateAddr.
func (a *KeaAdapter) keaReserve(ctx context.Context, field, value, ip string) error {
	cmd := fmt.Sprintf(
		`sudo jq 'map(select(.["%s"] != "%s")) + [{"%s":"%s","ip-address":"%s"}]' /etc/kea/reservations.json | sudo tee /etc/kea/reservations.json.tmp >/dev/null && sudo mv /etc/kea/reservations.json.tmp /etc/kea/reservations.json && sudo systemctl kill -s HUP kea-dhcp4-server`,
		field, value, field, value, ip,
	)
	if _, err := a.Runner.Run(ctx, cmd); err != nil {
		return fmt.Errorf("kea: reserve %s %s -> %s: %w", field, value, ip, err)
	}
	return nil
}

// ReserveMAC reserves ip for the MAC (issue #2). hw/ip are guaranteed
// clean by validateMAC/validateAddr before they ever reach the command.
func (a *KeaAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	hw, err := validateMAC(mac)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return a.keaReserve(ctx, "hw-address", hw, ip)
}

// ReserveClientID reserves ip for an option 61 value (B2, #23). Kea's
// "client-id" reservation key is on its default host-reservation-
// identifiers list and carries the whole option payload including the
// type byte, the same shape its lease rows report.
func (a *KeaAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	id, err := validateClientID(clientID)
	if err != nil {
		return err
	}
	ip, err := validateAddr(addr)
	if err != nil {
		return err
	}
	return a.keaReserve(ctx, "client-id", id, ip)
}

func (a *KeaAdapter) Restart(ctx context.Context) error { return a.systemctl(ctx, "restart") }
func (a *KeaAdapter) Stop(ctx context.Context) error    { return a.systemctl(ctx, "stop") }
func (a *KeaAdapter) Start(ctx context.Context) error   { return a.systemctl(ctx, "start") }

func (a *KeaAdapter) Reachable(ctx context.Context, addr string) error {
	return reachable(ctx, a.Runner, addr)
}

// ResetLeases stops kea-dhcp4-server, truncates keaLeaseFile, removes its LFC copies, and
// starts it again (issue #3 part 2). kea-ctrl-agent is left alone: it
// serves the control API this adapter's own Leases() reads and carries
// no lease state itself.
func (a *KeaAdapter) ResetLeases(ctx context.Context) error {
	return resetLeasesViaTruncate(ctx, a.Runner, keaLeaseFile, keaReloadedLeaseFiles, "kea-dhcp4-server", "kea")
}

func (a *KeaAdapter) systemctl(ctx context.Context, action string) error {
	if _, err := a.Runner.Run(ctx, "sudo systemctl "+action+" kea-dhcp4-server"); err != nil {
		return fmt.Errorf("kea: systemctl %s: %w", action, err)
	}
	return nil
}

// ShortenLeaseTime rewrites the RUNNING config's valid-lifetime
// (seconds, kea-dhcp4 config reference) and restarts -- a schema value
// like this one needs the full restart, not the plain HUP ReserveMAC's
// own reload uses (issue #3, A14). It captures /etc/kea/kea-dhcp4.conf
// as it stands right now, never /root/lab-stock-config/
// kea-dhcp4.conf.stock: that file is the package's own pre-install
// default, captured before this cell's own subnet/pool/reservations
// include ever got written over it, so restoring from it would drop
// this cell's whole working config, including the reservations.json
// include ReserveMAC depends on. Kea has no renew-timer/rebind-timer of
// its own in this config, so T1/T2 fall back to every RFC 2131 client's
// own default (roughly half of valid-lifetime), the same fallback
// dnsmasq and isc-dhcp both rely on here too.
func (a *KeaAdapter) ShortenLeaseTime(ctx context.Context, seconds int) (func(context.Context) error, error) {
	if seconds <= 0 {
		return nil, fmt.Errorf("kea: lease time must be positive, got %d", seconds)
	}
	repl := fmt.Sprintf(`"valid-lifetime": %d,`, seconds)
	return shortenLeaseTimeViaSubstitution(ctx, a.Runner, "/etc/kea/kea-dhcp4.conf",
		keaValidLifetimeRE, repl,
		func(ctx context.Context) error { return a.Restart(ctx) }, "kea")
}

// keaRoutersOptionRE anchors SetDNSOption on the one option-data entry
// the cloud-init template always writes (cloud-init/kea-user-data).
var keaRoutersOptionRE = regexp.MustCompile(`("option-data": \[ \{ "name": "routers", "data": "[^"]*" \})`)

// SetDNSOption adds a domain-name-servers entry beside the routers
// option in the running config and restarts (B6, #23). Kea reads
// option-data at start, so a HUP is not enough here.
func (a *KeaAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	ip, err := validateAddr(addr)
	if err != nil {
		return nil, err
	}
	repl := fmt.Sprintf(`${1}, { "name": "domain-name-servers", "data": "%s" }`, ip)
	return setDNSOptionViaSubstitution(ctx, a.Runner, "/etc/kea/kea-dhcp4.conf",
		keaRoutersOptionRE, repl, `"domain-name-servers"`,
		func(ctx context.Context) error { return a.Restart(ctx) }, "kea")
}

// Ready, Recover and Impair: the shared group C bodies (readiness.go, #23).
func (a *KeaAdapter) Ready(ctx context.Context) error {
	return sourceReady(ctx, a.Runner, a.units(), a.Leases, &a.base)
}

func (a *KeaAdapter) Recover(ctx context.Context) error {
	return sourceRecover(ctx, a.Runner, a.units(), &a.base)
}

func (a *KeaAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return impair(ctx, a.Runner, delay, lossPct)
}
