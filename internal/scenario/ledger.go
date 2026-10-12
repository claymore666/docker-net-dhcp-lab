package scenario

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// ledgerHostDir is where the docker host carries the plugin's STATE_DIR
// since v1.5.0: a bind mount at this exact path, so a repointed
// STATE_DIR keeps the ledger inside the plugin rootfs, out of reach of
// the host (docs/reference.md "Lease audit ledger", lab #15).
const ledgerHostDir = "/var/lib/net-dhcp"

const ledgerAbsentMarker = "LEDGER-ABSENT"

// ErrLedgerAbsent means the host has no ledger to read: audit_log was
// not set, nothing has been written yet, or STATE_DIR was repointed.
// A caller reports BLOCKED, never an empty ledger (lab #15).
var ErrLedgerAbsent = errors.New("the audit ledger is absent")

// LedgerEntry is one line of the plugin's STATE_DIR/leases.jsonl; the
// field names are the plugin's own (pkg/plugin/ledger.go), TS is its
// RFC 3339 UTC stamp with one-second resolution.
type LedgerEntry struct {
	TS        time.Time
	Kind      string
	Network   string
	Endpoint  string
	Container string
	Hostname  string
	IP        string
	Source    string
	MAC       string
}

type ledgerLine struct {
	TS        string `json:"ts"`
	Kind      string `json:"kind"`
	Network   string `json:"network"`
	Endpoint  string `json:"endpoint"`
	Container string `json:"container"`
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	Source    string `json:"source"`
	MAC       string `json:"mac"`
}

// ledgerStateDir reads STATE_DIR from the installed plugin's settings; a
// plugin that lists none runs on the default.
func ledgerStateDir(ctx context.Context, r sourceadapter.Runner) (string, error) {
	out, err := r.Run(ctx, "sudo docker plugin inspect -f '{{range .Settings.Env}}{{println .}}{{end}}' "+pluginAlias)
	if err != nil {
		return "", fmt.Errorf("read the plugin settings: %w", err)
	}
	dir := ledgerHostDir
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "STATE_DIR="); ok {
			dir = v
		}
	}
	return dir, nil
}

// readLedgerFile returns the file's content, or ok=false when it does not
// exist; any other failure is an error.
func readLedgerFile(ctx context.Context, r sourceadapter.Runner, path string) (string, bool, error) {
	out, err := r.Run(ctx, fmt.Sprintf("if sudo test -f %s; then sudo cat %s; else echo %s; fi", path, path, ledgerAbsentMarker))
	if err != nil {
		return "", false, fmt.Errorf("read %s: %w", path, err)
	}
	if strings.TrimSpace(out) == ledgerAbsentMarker {
		return "", false, nil
	}
	return out, true, nil
}

// ReadLedger returns the docker host's lease ledger entries stamped at or
// after since (one-second resolution), oldest first, for mac (every
// entry when mac is empty). It reads the rotated generation first so a
// rotation inside the window loses nothing. An absent ledger returns
// ErrLedgerAbsent and a line that is not a ledger entry is an error, so
// a count is never taken over a partial read (lab #15).
func ReadLedger(ctx context.Context, r sourceadapter.Runner, since time.Time, mac string) ([]LedgerEntry, error) {
	if since.IsZero() {
		return nil, errors.New("ledger: since is the zero time")
	}
	if mac != "" {
		var err error
		if mac, err = normalizeLedgerMAC(mac); err != nil {
			return nil, err
		}
	}
	dir, err := ledgerStateDir(ctx, r)
	if err != nil {
		return nil, err
	}
	if dir != ledgerHostDir {
		return nil, fmt.Errorf("%w: STATE_DIR is %q, so the ledger is inside the plugin rootfs and not on the host's %s", ErrLedgerAbsent, dir, ledgerHostDir)
	}
	path := ledgerHostDir + "/leases.jsonl"
	rotated, _, err := readLedgerFile(ctx, r, path+".1")
	if err != nil {
		return nil, err
	}
	current, ok, err := readLedgerFile(ctx, r, path)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s does not exist (audit_log not set on the network, or nothing was written)", ErrLedgerAbsent, path)
	}
	floor := since.UTC().Truncate(time.Second)
	var entries []LedgerEntry
	for _, part := range []struct{ name, text string }{{path + ".1", rotated}, {path, current}} {
		for i, line := range strings.Split(part.text, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			e, err := parseLedgerLine(line)
			if err != nil {
				return nil, fmt.Errorf("ledger: %s line %d: %w", part.name, i+1, err)
			}
			if e.TS.Before(floor) || (mac != "" && e.MAC != mac) {
				continue
			}
			entries = append(entries, e)
		}
	}
	return entries, nil
}

func parseLedgerLine(line string) (LedgerEntry, error) {
	var l ledgerLine
	if err := json.Unmarshal([]byte(line), &l); err != nil {
		return LedgerEntry{}, err
	}
	ts, err := time.Parse(time.RFC3339, l.TS)
	if err != nil {
		return LedgerEntry{}, fmt.Errorf("ts %q: %w", l.TS, err)
	}
	if l.Kind == "" {
		return LedgerEntry{}, errors.New("no kind")
	}
	mac := ""
	if l.MAC != "" {
		if mac, err = normalizeLedgerMAC(l.MAC); err != nil {
			return LedgerEntry{}, err
		}
	}
	return LedgerEntry{TS: ts.UTC(), Kind: l.Kind, Network: l.Network, Endpoint: l.Endpoint, Container: l.Container,
		Hostname: l.Hostname, IP: l.IP, Source: l.Source, MAC: mac}, nil
}

func normalizeLedgerMAC(mac string) (string, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return "", fmt.Errorf("ledger: invalid MAC %q: %w", mac, err)
	}
	return hw.String(), nil
}
