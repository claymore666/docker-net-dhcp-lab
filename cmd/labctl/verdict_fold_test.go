package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oldIsolationVerdict is the rc2 run's file shape (#94): the isolation
// value ends in an ssh error's newline, so the next line begins with ")".
const oldIsolationVerdict = "scenario: A5-host-reboot\ncell: host-ubuntu2404\nshape: macvlan-ipam\nresult: PASS\nreason: ok\ngit_sha: abc123\n" +
	"isolation: network recreated between scenarios (docker network rm failed: ssh lab@10.200.255.40: exit status 255: Connection refused\n" +
	")\ntimestamp: 2026-10-13T12:38:10Z\nevidence.lease: lease.txt\n"

func writeOldTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"host-ubuntu2404-macvlan-ipam-A5-host-reboot.verdict": oldIsolationVerdict,
		"lease.txt":                         "x",
		"host-ubuntu2404-resolved-lab.json": `{"cell":{"name":"host-ubuntu2404","docker_host":{"plugin_tag":"t","previous_plugin_tag":"p"}}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func captureOut(t *testing.T, f func() int) (int, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	code := f()
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return code, <-done
}

func TestRemainingReadsAnOldFileWithAContinuationLine(t *testing.T) {
	dir := writeOldTree(t)
	code, out := captureOut(t, func() int {
		return cmdRemaining([]string{"../../lab.yaml", "host-ubuntu2404", "macvlan-ipam", dir})
	})
	if code != 0 {
		t.Fatalf("labctl remaining exit %d: %s", code, out)
	}
	names := strings.Split(strings.TrimSpace(out), ",")
	for _, n := range names {
		if n == "A5-host-reboot" {
			t.Fatalf("remaining still lists the scenario the old file covers: %s", out)
		}
	}
	if len(names) < 2 || names[0] != "A1-first-lease" {
		t.Fatalf("remaining dropped more than the old file's scenario: %s", out)
	}
}

func TestMatrixReadsAnOldFileWithAContinuationLine(t *testing.T) {
	dir := writeOldTree(t)
	code, out := captureOut(t, func() int {
		return cmdMatrix([]string{"--root", filepath.Dir(dir), dir})
	})
	if code != 0 {
		t.Fatalf("labctl matrix exit %d: %s", code, out)
	}
	if !strings.Contains(out, "A5-host-reboot.verdict") {
		t.Fatalf("the matrix does not list the old file's verdict: %s", out)
	}
}
