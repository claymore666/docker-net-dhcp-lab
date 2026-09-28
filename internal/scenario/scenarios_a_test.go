package scenario

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corroborate must never read e.PCAP before it exists: the whole-cell
// capture is only written once every shape has run (capture-stop.sh,
// issue #8), so a check here would always read an empty or missing
// file and misreport a disagreement no capture ever supported. This
// guards the deferred path added for that: the evidence file carries
// the mac and says "deferred", never "disagreement" and never the
// underlying awk-on-empty-input text.
func TestCorroborateDefersWhenPCAPDoesNotExistYet(t *testing.T) {
	dir := t.TempDir()
	e := Env{
		Shape:       ShapeBridge,
		Cell:        "dnsmasq",
		PCAP:        filepath.Join(dir, "observer.pcap"), // never written in this test
		EvidenceDir: dir,
	}
	ev := map[string]string{}
	corroborate(context.Background(), e, "de:ad:be:ef:00:01", ev, "T1", "capture-check")

	path, ok := ev["capture-check"]
	if !ok {
		t.Fatal("corroborate did not record a capture-check evidence entry")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	text := string(got)
	if !strings.Contains(text, "deferred") || !strings.Contains(text, "de:ad:be:ef:00:01") {
		t.Fatalf("expected a deferred marker carrying the mac, got %q", text)
	}
	if strings.Contains(text, "capture disagreement") || strings.Contains(text, "no single xid") {
		t.Fatalf("a missing pcap read as a disagreement instead of deferred: %q", text)
	}
}

// Preservation: once the capture exists, corroborate still runs the
// real check against it and reports a clean match, the same as before
// the deferred path was added.
func TestCorroborateChecksImmediatelyWhenPCAPAlreadyExists(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	mac := "da:b6:45:5b:ef:fe" // matches scripts/testdata/dhcp-good.pcap
	e := Env{
		Shape:       ShapeBridge,
		Cell:        "dnsmasq",
		PCAP:        filepath.Join(repoRoot, "scripts", "testdata", "dhcp-good.pcap"),
		RepoRoot:    repoRoot,
		EvidenceDir: t.TempDir(),
	}
	ev := map[string]string{}
	corroborate(context.Background(), e, mac, ev, "T1", "capture-check")

	path, ok := ev["capture-check"]
	if !ok {
		t.Fatal("corroborate did not record a capture-check evidence entry")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	text := string(got)
	if !strings.Contains(text, "clean 4-message exchange") || !strings.Contains(text, mac) {
		t.Fatalf("expected a clean match against the good fixture, got %q", text)
	}
}

// When e.PCAP exists (so corroborate takes the immediate-check branch)
// but tcpdump itself cannot read it, the evidence text must say so, not
// "capture disagreement" -- exercised through dhcpExchangeReason's own
// bash -c wrapper (dockerhost.go), which carries no pipefail of its
// own, unlike this repo's shell test harnesses.
func TestCorroborateReportsAnErrorWhenTheCaptureIsUnreadable(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	e := Env{
		Shape:       ShapeBridge,
		Cell:        "dnsmasq",
		PCAP:        t.TempDir(), // exists (os.Stat succeeds), not a pcap tcpdump can read
		RepoRoot:    repoRoot,
		EvidenceDir: t.TempDir(),
	}
	ev := map[string]string{}
	corroborate(context.Background(), e, "de:ad:be:ef:00:01", ev, "T1", "capture-check")

	path, ok := ev["capture-check"]
	if !ok {
		t.Fatal("corroborate did not record a capture-check evidence entry")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	text := string(got)
	if strings.Contains(text, "capture disagreement") {
		t.Fatalf("an unreadable capture read as a disagreement: %q", text)
	}
	if !strings.Contains(text, "error") {
		t.Fatalf("expected an error report for an unreadable capture, got %q", text)
	}
}
