package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// ISC failover states as the lease file names them (dhcpd.leases(5);
// measured on 4.4.3-P1, lab #12). The survivor of a stopped peer reports
// communications-interrupted: auto-partner-down is off, so it never
// reaches partner-down by itself.
const (
	ISCNormal                    = "normal"
	ISCCommunicationsInterrupted = "communications-interrupted"
	ISCPartnerDown               = "partner-down"
)

// iscFailoverPeerName is the peer name every pool names in "failover
// peer" in cloud-init/isc-dhcp-failover-user-data.tmpl.yaml; the state
// reader matches only this name (lab #12).
const iscFailoverPeerName = "lab"

var (
	iscStateStartRE = regexp.MustCompile(`(?m)^failover peer "lab" state \{`)
	iscStateBlockRE = regexp.MustCompile(`(?ms)^failover peer "lab" state \{\n(.*?)^\}`)
	iscMyStateRE    = regexp.MustCompile(`(?m)^[ \t]*my state ([a-z-]+) at `)
	// iscOmLocalStateRE reads the failover-state object omshell prints
	// (OMAPI, measured: local-state = 00:00:00:02 is normal).
	iscOmLocalStateRE = regexp.MustCompile(`(?m)^local-state = ((?:[0-9a-f]{2}:){3}[0-9a-f]{2})\s*$`)
)

// iscOmStates maps OMAPI's local-state to the lease file's names. 01
// startup, 02 normal and 03 communications-interrupted were measured;
// the rest follow draft-ietf-dhc-failover-12 section 12.1 (INFERRED).
var iscOmStates = map[string]string{
	"00:00:00:00": "unknown-state",
	"00:00:00:01": "startup",
	"00:00:00:02": "normal",
	"00:00:00:03": "communications-interrupted",
	"00:00:00:04": "partner-down",
	"00:00:00:06": "recover",
	"00:00:00:09": "recover-done",
}

// iscOmshellCmd reads the failover-state object without changing it:
// connect, new, set name, open (omapi-port 7911 in the template).
const iscOmshellCmd = `printf 'server 127.0.0.1\nport 7911\nconnect\nnew failover-state\nset name = "lab"\nopen\n' | omshell`

var errISCNoStateBlock = errors.New("isc-dhcp: dhcpd.leases carries no failover state block")

// ISCHAState reads a peer's failover state from the LAST state block of
// its lease file (dhcpd appends one at every change, so the first block
// is history). Only a file with no block at all falls back to omshell,
// read-only: a fresh block is never overruled by the live query.
func ISCHAState(ctx context.Context, r Runner) (HAState, error) {
	out, err := r.Run(ctx, "sudo cat "+iscLeaseFile)
	if err != nil {
		return HAState{}, fmt.Errorf("isc-dhcp: read dhcpd.leases: %w", err)
	}
	st, err := parseISCHAState(out)
	if err == nil || !errors.Is(err, errISCNoStateBlock) {
		return st, err
	}
	om, oerr := r.Run(ctx, iscOmshellCmd)
	if oerr != nil {
		return HAState{}, fmt.Errorf("%w; omshell: %v", err, oerr)
	}
	return parseISCOmshell(om)
}

// ISCLiveState asks the running dhcpd for its failover state over OMAPI.
// A restarted peer's lease file keeps its pre-stop "normal" block and
// gets no new one (m8-primary-back.txt, lab #12), so only the daemon's
// own answer proves it is normal again; no daemon is an error.
func ISCLiveState(ctx context.Context, r Runner) (HAState, error) {
	om, err := r.Run(ctx, iscOmshellCmd)
	if err != nil {
		return HAState{}, fmt.Errorf("isc-dhcp: omshell: %w", err)
	}
	return parseISCOmshell(om)
}

// parseISCHAState returns the last state block's own state (lab #12). Fewer
// closed blocks than opened means the file was cut mid-write: an error,
// never the previous block's stale state.
func parseISCHAState(raw string) (HAState, error) {
	starts := iscStateStartRE.FindAllStringIndex(raw, -1)
	if len(starts) == 0 {
		return HAState{}, errISCNoStateBlock
	}
	blocks := iscStateBlockRE.FindAllStringSubmatch(raw, -1)
	if len(blocks) != len(starts) {
		return HAState{}, fmt.Errorf("isc-dhcp: %d failover state block(s) opened but only %d closed; dhcpd.leases looks truncated", len(starts), len(blocks))
	}
	last := blocks[len(blocks)-1][0]
	m := iscMyStateRE.FindStringSubmatch(last)
	if m == nil {
		return HAState{}, fmt.Errorf("isc-dhcp: the last failover state block has no \"my state\": %.200s", last)
	}
	return HAState{State: m[1], Raw: last}, nil
}

func parseISCOmshell(raw string) (HAState, error) {
	m := iscOmLocalStateRE.FindStringSubmatch(raw)
	if m == nil {
		return HAState{}, fmt.Errorf("isc-dhcp: omshell reply has no local-state: %.300s", raw)
	}
	name, ok := iscOmStates[m[1]]
	if !ok {
		return HAState{}, fmt.Errorf("isc-dhcp: omshell local-state %s is not a state this lab knows", m[1])
	}
	return HAState{State: name, Raw: raw}, nil
}

// parseISCBackupAddrs lists the addresses whose latest block is
// "backup": on the primary these are the partner's half of the pool
// (split 128), the only ones the survivor may hand out first.
func parseISCBackupAddrs(raw string) ([]string, error) {
	starts := iscLeaseStartRE.FindAllStringIndex(raw, -1)
	blocks := iscLeaseBlockRE.FindAllStringSubmatch(raw, -1)
	if len(blocks) != len(starts) {
		return nil, fmt.Errorf("isc-dhcp: %d lease block(s) opened but only %d parsed cleanly; leases file looks truncated", len(starts), len(blocks))
	}
	last := map[string]string{}
	for _, b := range blocks {
		if m := iscStateRE.FindStringSubmatch(b[2]); len(m) == 2 {
			last[b[1]] = m[1]
		}
	}
	var out []string
	for ip, st := range last {
		if st == "backup" {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out, nil
}

// BackupAddrs reads this peer's lease file for its backup addresses: on
// the primary, the partner's half of the pool under split 128, which
// C5b checks the outage address against (RFC 3074 load balancing, lab #12).
func (a *ISCDHCPAdapter) BackupAddrs(ctx context.Context) ([]string, error) {
	out, err := a.Runner.Run(ctx, "sudo cat "+iscLeaseFile)
	if err != nil {
		return nil, fmt.Errorf("isc-dhcp: read dhcpd.leases: %w", err)
	}
	return parseISCBackupAddrs(out)
}
