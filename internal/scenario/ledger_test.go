package scenario

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ledgerRunner answers the three commands ReadLedger issues: the plugin
// settings, then the rotated and the current file. A nil file is absent.
type ledgerRunner struct {
	settings string
	current  *string
	rotated  *string
	err      error
	calls    []string
}

func (l *ledgerRunner) Run(_ context.Context, cmd string) (string, error) {
	l.calls = append(l.calls, cmd)
	if l.err != nil {
		return "", l.err
	}
	switch {
	case strings.Contains(cmd, "docker plugin inspect"):
		return l.settings, nil
	case strings.Contains(cmd, "leases.jsonl.1"):
		return fileOrMarker(l.rotated), nil
	case strings.Contains(cmd, "leases.jsonl"):
		return fileOrMarker(l.current), nil
	}
	return "", errors.New("unexpected command: " + cmd)
}

func fileOrMarker(s *string) string {
	if s == nil {
		return ledgerAbsentMarker + "\n"
	}
	return *s
}

func sp(s string) *string { return &s }

var ledgerSince = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

const (
	ledgerOld  = `{"ts":"2026-10-11T11:59:59Z","kind":"bound","network":"n","endpoint":"e0","ip":"10.200.1.140","mac":"02:AA:BB:CC:DD:01"}` + "\n"
	ledgerEdge = `{"ts":"2026-10-11T12:00:00Z","kind":"bound","network":"n","endpoint":"e1","container":"c1","hostname":"h1","ip":"10.200.1.150","mac":"02:AA:BB:CC:DD:01"}` + "\n"
	ledgerNext = `{"ts":"2026-10-11T12:30:00Z","kind":"renew","network":"n","endpoint":"e1","ip":"10.200.1.150","mac":"02:aa:bb:cc:dd:01"}` + "\n"
	ledgerOth  = `{"ts":"2026-10-11T12:31:00Z","kind":"bound","network":"n","endpoint":"e2","ip":"10.200.1.151","mac":"02:aa:bb:cc:dd:02"}` + "\n"
	ledgerNoIP = `{"ts":"2026-10-11T12:32:00Z","kind":"stopped","network":"n","endpoint":"e1"}` + "\n"
)

func kinds(es []LedgerEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Kind+"/"+e.Endpoint)
	}
	return out
}

func TestReadLedgerFiltersBySinceAndMAC(t *testing.T) {
	r := &ledgerRunner{current: sp(ledgerOld + ledgerEdge + ledgerNext + ledgerOth + ledgerNoIP)}
	got, err := ReadLedger(context.Background(), r, ledgerSince, "")
	if err != nil {
		t.Fatal(err)
	}
	// since is inclusive at the ledger's one-second resolution; the entry
	// one second before is out.
	if g := strings.Join(kinds(got), " "); g != "bound/e1 renew/e1 bound/e2 stopped/e1" {
		t.Errorf("entries: %s", g)
	}
	if got[0].MAC != "02:aa:bb:cc:dd:01" || got[0].Container != "c1" || got[0].Hostname != "h1" || got[0].IP != "10.200.1.150" || !got[0].TS.Equal(ledgerSince) {
		t.Errorf("entry fields: %+v", got[0])
	}

	// A since inside the second still includes that second's entries.
	got, err = ReadLedger(context.Background(), r, ledgerSince.Add(700*time.Millisecond), "02:AA:BB:CC:DD:01")
	if err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(kinds(got), " "); g != "bound/e1 renew/e1" {
		t.Errorf("mac-filtered entries: %s", g)
	}
}

func TestReadLedgerReadsTheRotatedGenerationFirst(t *testing.T) {
	r := &ledgerRunner{rotated: sp(ledgerEdge), current: sp(ledgerNext)}
	got, err := ReadLedger(context.Background(), r, ledgerSince, "")
	if err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(kinds(got), " "); g != "bound/e1 renew/e1" {
		t.Errorf("entries: %s", g)
	}
}

func TestReadLedgerAbsentIsNotEmpty(t *testing.T) {
	// No current file, even with a rotated one: the writer is gone or the
	// option is off, and an empty list would read as "no events".
	for name, r := range map[string]*ledgerRunner{
		"no files":        {},
		"rotated only":    {rotated: sp(ledgerEdge)},
		"repointed state": {settings: "STATE_DIR=/elsewhere\n", current: sp(ledgerEdge)},
	} {
		got, err := ReadLedger(context.Background(), r, ledgerSince, "")
		if !errors.Is(err, ErrLedgerAbsent) || got != nil {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}

func TestReadLedgerEmptyFileIsEmptyNotAbsent(t *testing.T) {
	r := &ledgerRunner{current: sp("")}
	got, err := ReadLedger(context.Background(), r, ledgerSince, "")
	if err != nil || len(got) != 0 {
		t.Errorf("%v, %v", got, err)
	}
}

func TestReadLedgerDefaultStateDirIsTheHostMount(t *testing.T) {
	r := &ledgerRunner{settings: "AUDIT=1\nSTATE_DIR=/var/lib/net-dhcp\n", current: sp(ledgerEdge)}
	if _, err := ReadLedger(context.Background(), r, ledgerSince, ""); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls[1:] {
		if !strings.Contains(c, "/var/lib/net-dhcp/leases.jsonl") {
			t.Errorf("read outside the host mount: %s", c)
		}
	}
}

func TestReadLedgerBadInputIsAnErrorNotASkip(t *testing.T) {
	for name, text := range map[string]string{
		"not json":  "not json\n",
		"bad ts":    `{"ts":"yesterday","kind":"bound"}` + "\n",
		"no kind":   `{"ts":"2026-10-11T12:00:00Z"}` + "\n",
		"bad mac":   `{"ts":"2026-10-11T12:00:00Z","kind":"bound","mac":"zz"}` + "\n",
		"torn line": ledgerEdge + `{"ts":"2026-10-11T12:01:0`,
	} {
		got, err := ReadLedger(context.Background(), &ledgerRunner{current: sp(text)}, ledgerSince, "")
		if err == nil || got != nil {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}

func TestReadLedgerRefusesZeroSinceAndHostileMAC(t *testing.T) {
	r := &ledgerRunner{current: sp(ledgerEdge)}
	if _, err := ReadLedger(context.Background(), r, time.Time{}, ""); err == nil {
		t.Error("zero since accepted")
	}
	for _, bad := range []string{"02:aa:bb:cc:dd:01'; reboot #", "$(id)", "x"} {
		if _, err := ReadLedger(context.Background(), r, ledgerSince, bad); err == nil {
			t.Errorf("mac %q accepted", bad)
		}
	}
	if len(r.calls) != 0 {
		t.Errorf("a refused call reached the host: %q", r.calls)
	}
}

func TestReadLedgerPropagatesTheHostFailure(t *testing.T) {
	boom := errors.New("ssh: connection refused")
	got, err := ReadLedger(context.Background(), &ledgerRunner{err: boom}, ledgerSince, "")
	if !errors.Is(err, boom) || got != nil || errors.Is(err, ErrLedgerAbsent) {
		t.Errorf("%v, %v", got, err)
	}
}
