#!/bin/bash
# The one command issue #3 part 1 asks for: bring up a cell, run every
# group-A scenario across all three null-IPAM shapes, and leave one
# evidence bundle behind (resolved lab.yaml, versions, a config diff
# from stock, one capture spanning the whole run, and one verdict file
# per scenario x shape). A FAIL is a finding about the plugin; this
# script never retries or tunes a scenario to make one pass.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CELL=${1:?usage: run-group-a.sh <cell-name> [work-dir] [evidence-dir]}
WORK=${2:-/srv/lab/work/$(whoami)/$CELL}
EVIDENCE_DIR=${3:-$WORK/evidence}
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"

mkdir -p "$WORK" "$EVIDENCE_DIR"
GIT_SHA=$(cd "$REPO_ROOT" && git rev-parse HEAD)
TS=$(date -u +%Y%m%dT%H%M%SZ)
echo "run-group-a: repo at $GIT_SHA, started $TS"

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$LAB_YAML" "$CELL")
bridge=$(jq -r '.cell.segment.bridge' <<<"$RESOLVED")
mgmt_addr=$(jq -r '.cell.docker_host.mgmt_address' <<<"$RESOLVED")
mgmt_ip=${mgmt_addr%%/*}
source_type=$(jq -r '.cell.source.type // empty' <<<"$RESOLVED")
source_mgmt_addr=$(jq -r '.cell.source.mgmt_address // empty' <<<"$RESOLVED")
source_mgmt_ip=${source_mgmt_addr%%/*}
plugin_tag=$(jq -r '.cell.docker_host.plugin_tag' <<<"$RESOLVED")
previous_plugin_tag=$(jq -r '.cell.docker_host.previous_plugin_tag // empty' <<<"$RESOLVED")

if [ -z "$source_type" ]; then
	echo "run-group-a: cell $CELL has no source; nothing group A can run against" >&2
	exit 1
fi

echo "== bring up cell $CELL =="
"$REPO_ROOT/scripts/up-cell.sh" "$CELL" "$WORK"

echo "$RESOLVED" >"$EVIDENCE_DIR/${CELL}-resolved-lab.json"

known_hosts="$WORK/known_hosts"
ssh_run() {
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ControlMaster=no -o ControlPath=none \
		-i ~/.ssh/id_ed25519_lab lab@"$1" "$2"
}

echo "== versions =="
{
	echo "# versions for cell $CELL, commit $GIT_SHA, captured $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "plugin_tag: $plugin_tag"
	echo "previous_plugin_tag: ${previous_plugin_tag:-none configured}"
	echo "docker_host engine: $(ssh_run "$mgmt_ip" "sudo docker version --format '{{.Server.Version}}'")"
	echo "docker_host kernel: $(ssh_run "$mgmt_ip" "uname -r")"
	echo "source type: $source_type"
	echo "source kernel: $(ssh_run "$source_mgmt_ip" "uname -r")"
} >"$EVIDENCE_DIR/${CELL}-versions.txt"

echo "== config diff from stock =="
"$REPO_ROOT/scripts/capture-source-config-diff.sh" "$CELL" "$source_type" "$source_mgmt_ip" "$WORK" "$EVIDENCE_DIR"

echo "== capture: start (spans every shape below) =="
"$REPO_ROOT/scripts/capture-start.sh" "$CELL" "$bridge" "$WORK"
READY="$WORK/observer.ready"
waited=0
until [ -f "$READY" ]; do
	waited=$((waited + 1))
	if [ "$waited" -ge 200 ]; then
		echo "run-group-a: FAIL -- observer did not become ready inside the 60s bound" >&2
		exit 1
	fi
	sleep 0.3
done

# One shape at a time, never overlapping: each labctl run tears its own
# network down (deferred inside cmdRun) before returning, so the next
# shape's NetworkUp never races it (issue #3 defeat list).
RUNNER_FAILED=0
for shape in bridge macvlan ipvlan; do
	echo "== scenarios: $shape =="
	if ! go run "$REPO_ROOT/cmd/labctl" run "$LAB_YAML" "$REPO_ROOT" "$CELL" "$shape" "$WORK" "$EVIDENCE_DIR" "$WORK/observer.pcap"; then
		echo "run-group-a: labctl run exited non-zero for $CELL/$shape (an infrastructure error, not a scenario FAIL)" >&2
		RUNNER_FAILED=1
	fi
done

echo "== capture: stop =="
"$REPO_ROOT/scripts/capture-stop.sh" "$CELL" "$WORK"
cp "$WORK/observer.pcap" "$EVIDENCE_DIR/${CELL}.pcap" 2>/dev/null || true

echo "== plugin logs (journalctl copy, survives a plugin upgrade) =="
ssh_run "$mgmt_ip" "sudo journalctl -u docker --since '2 hours ago'" \
	| grep net-dhcp >"$EVIDENCE_DIR/${CELL}-plugin-log.txt" || true

echo "== tear down cell $CELL =="
LAB_EVIDENCE_DIR="$EVIDENCE_DIR" "$REPO_ROOT/scripts/down-cell.sh" "$CELL" "$WORK"

if [ "$RUNNER_FAILED" -ne 0 ]; then
	echo "run-group-a: FAIL -- at least one shape's labctl run hit an infrastructure error; see above" >&2
	exit 1
fi
echo "run-group-a: bundle written to $EVIDENCE_DIR (verdicts, capture, lease snapshots, versions, config diff, plugin log)"
