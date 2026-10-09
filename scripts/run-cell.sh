#!/bin/bash
# The one command issue #3 asks for: bring up a cell, run every scenario
# across all five shapes (the plugin's own null IPAM and its
# own IPAM driver, each in bridge and macvlan, plus ipvlan), and leave
# one evidence bundle behind (resolved lab.yaml, versions, a config
# diff from stock, one capture spanning the whole run, and one verdict
# file per scenario x shape). A FAIL is a finding about the plugin;
# this script never retries or tunes a scenario to make one pass.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CELL=${1:?usage: run-cell.sh <cell-name> [work-dir] [evidence-dir]}
WORK=${2:-/srv/lab/work/$(whoami)/$CELL}
# A sibling of $WORK, never inside it: down-cell.sh's own rm -rf at the
# end of this script removes the whole of $WORK, and now refuses to run
# at all if the evidence dir it was handed is nested inside $WORK
# (measured live 2026-09-26: this default used to nest it there, and
# every evidence bundle from a run that hit that path was destroyed
# along with $WORK).
EVIDENCE_DIR=${3:-$(dirname "$WORK")/evidence}
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"

mkdir -p "$WORK" "$EVIDENCE_DIR"
GIT_SHA=$(cd "$REPO_ROOT" && git rev-parse HEAD)
TS=$(date -u +%Y%m%dT%H%M%SZ)
echo "run-cell: repo at $GIT_SHA, started $TS"

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$LAB_YAML" "$CELL")
bridge=$(jq -r '.cell.segment.bridge' <<<"$RESOLVED")
mgmt_addr=$(jq -r '.cell.docker_host.mgmt_address' <<<"$RESOLVED")
mgmt_ip=${mgmt_addr%%/*}
source_type=$(jq -r '.cell.source.type // empty' <<<"$RESOLVED")
source_mgmt_addr=$(jq -r '.cell.source.mgmt_address // empty' <<<"$RESOLVED")
source_mgmt_ip=${source_mgmt_addr%%/*}
# A failover pair (#12): every per-source step below runs once per peer,
# labelled source and partner.
partner_mgmt_addr=$(jq -r '.cell.source.partner.mgmt_address // empty' <<<"$RESOLVED")
peers="source=$source_mgmt_ip"
[ -z "$partner_mgmt_addr" ] || peers="$peers partner=${partner_mgmt_addr%%/*}"
plugin_tag=$(jq -r '.cell.docker_host.plugin_tag' <<<"$RESOLVED")
previous_plugin_tag=$(jq -r '.cell.docker_host.previous_plugin_tag // empty' <<<"$RESOLVED")
# A relay cell (#11): empty in every other cell.
relay_mgmt_addr=$(jq -r '.cell.relay.mgmt_address // empty' <<<"$RESOLVED")
relay_mgmt_ip=${relay_mgmt_addr%%/*}
server_bridge=$(jq -r '.cell.relay.server_segment.bridge // empty' <<<"$RESOLVED")

if [ -z "$source_type" ]; then
	echo "run-cell: cell $CELL has no source; nothing can run against it" >&2
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
	echo "docker_host distro: $(ssh_run "$mgmt_ip" ". /etc/os-release && echo \$PRETTY_NAME")"
	echo "docker_host engine: $(ssh_run "$mgmt_ip" "sudo docker version --format '{{.Server.Version}}'")"
	echo "docker_host kernel: $(ssh_run "$mgmt_ip" "uname -r")"
	echo "source type: $source_type"
	for peer in $peers; do
		echo "${peer%%=*} kernel: $(ssh_run "${peer#*=}" "uname -r")"
	done
	if [ -n "$relay_mgmt_ip" ]; then
		echo "relay distro: $(ssh_run "$relay_mgmt_ip" ". /etc/os-release && echo \$PRETTY_NAME")"
		echo "relay kernel: $(ssh_run "$relay_mgmt_ip" "uname -r")"
		echo "relay isc-dhcp-relay: $(ssh_run "$relay_mgmt_ip" "dpkg-query -W -f '\${Version}' isc-dhcp-relay")"
	fi
} >"$EVIDENCE_DIR/${CELL}-versions.txt"

echo "== config diff from stock =="
for peer in $peers; do
	label=$CELL
	[ "${peer%%=*}" = source ] || label="${CELL}-${peer%%=*}"
	"$REPO_ROOT/scripts/capture-source-config-diff.sh" "$label" "$source_type" "${peer#*=}" "$WORK" "$EVIDENCE_DIR"
done
if [ -n "$relay_mgmt_ip" ]; then
	# The relay's two files against the package's own (#11); diff exits 1
	# whenever they differ, which they always do.
	ssh_run "$relay_mgmt_ip" "sudo diff -u /root/lab-stock-config/isc-dhcp-relay.stock /etc/default/isc-dhcp-relay; sudo diff -u /root/lab-stock-config/nftables.conf.stock /etc/nftables.conf" \
		>"$EVIDENCE_DIR/${CELL}-relay-config-diff.txt" || true
fi

echo "== capture: start (spans every shape below) =="
wait_observer() {
	local waited=0
	until [ -f "$1/observer.ready" ]; do
		waited=$((waited + 1))
		if [ "$waited" -ge 200 ]; then
			echo "run-cell: FAIL -- observer in $1 did not become ready inside the 60s bound" >&2
			exit 1
		fi
		sleep 0.3
	done
}
"$REPO_ROOT/scripts/capture-start.sh" "$CELL" "$bridge" "$WORK"
wait_observer "$WORK"
# A relay cell's second observer, on the source's server segment (#11).
if [ -n "$server_bridge" ]; then
	mkdir -p "$WORK/srv"
	"$REPO_ROOT/scripts/capture-start.sh" "$CELL-srv" "$server_bridge" "$WORK/srv"
	wait_observer "$WORK/srv"
fi

stop_server_capture() {
	if [ -n "$server_bridge" ]; then
		"$REPO_ROOT/scripts/capture-stop.sh" "$CELL-srv" "$WORK/srv"
		cp "$WORK/srv/observer.pcap" "$EVIDENCE_DIR/${CELL}-server.pcap" 2>/dev/null || true
	fi
}

# The relay's own account of every relayed packet (#11).
relay_journal() {
	if [ -n "$relay_mgmt_ip" ]; then
		ssh_run "$relay_mgmt_ip" "sudo journalctl -u isc-dhcp-relay --no-pager -o short-iso" \
			>"$EVIDENCE_DIR/${CELL}-relay-log.txt" || true
	fi
}

# The relay must carry one lease end to end before any shape runs (#11);
# a shape run through a broken relay would read as plugin FAILs.
if [ -n "$relay_mgmt_ip" ]; then
	echo "== relay probe =="
	if ! "$REPO_ROOT/scripts/relay-probe.sh" "$CELL" "$mgmt_ip" "$relay_mgmt_ip" "$WORK"; then
		"$REPO_ROOT/scripts/capture-stop.sh" "$CELL" "$WORK" || true
		cp "$WORK/observer.pcap" "$EVIDENCE_DIR/${CELL}.pcap" 2>/dev/null || true
		stop_server_capture
		relay_journal
		LAB_EVIDENCE_DIR="$EVIDENCE_DIR" "$REPO_ROOT/scripts/down-cell.sh" "$CELL" "$WORK" || true
		echo "run-cell: FAIL -- the relay probe failed; no shape was run (lab error, not a plugin finding)" >&2
		exit 1
	fi
fi

# One shape at a time, never overlapping: each labctl run tears its own
# network down (deferred inside cmdRun) before returning, so the next
# shape's NetworkUp never races it (issue #3 defeat list).
#
# Exit code 3 is labctl's own sentinel for a lab error, not a scenario
# FAIL: the pre-shape pool check (#3) found the source's pool cannot
# cover even this one shape's worst case. Continuing to the next shape
# would run it against the same undersized pool, so the whole cell
# aborts here instead.
RUNNER_FAILED=0
for shape in bridge macvlan ipvlan bridge-ipam macvlan-ipam; do
	echo "== scenarios: $shape =="
	# Resume support (issue #8): a scenario that already has a verdict for
	# this cell/shape in $EVIDENCE_DIR is never re-run -- `labctl remaining`
	# reads each verdict's own content, never a file name, and this script
	# passes the result straight into `labctl run`'s existing
	# scenario-filter argument, unchanged. A shape whose whole catalog is
	# already covered is skipped outright, without bringing its network up.
	remaining=$(go run "$REPO_ROOT/cmd/labctl" remaining "$LAB_YAML" "$CELL" "$shape" "$EVIDENCE_DIR")
	if [ -z "$remaining" ]; then
		echo "run-cell: $CELL/$shape already has a verdict for every scenario in $EVIDENCE_DIR, skipping"
		continue
	fi
	rc=0
	go run "$REPO_ROOT/cmd/labctl" run "$LAB_YAML" "$REPO_ROOT" "$CELL" "$shape" "$WORK" "$EVIDENCE_DIR" "$WORK/observer.pcap" "$remaining" || rc=$?
	if [ "$rc" -eq 3 ]; then
		echo "run-cell: labctl run reported a lab error (insufficient pool capacity) for $CELL/$shape; aborting the cell, not running the remaining shapes" >&2
		RUNNER_FAILED=1
		break
	elif [ "$rc" -ne 0 ]; then
		echo "run-cell: labctl run exited non-zero for $CELL/$shape (an infrastructure error, not a scenario FAIL)" >&2
		RUNNER_FAILED=1
	fi
done

echo "== capture: stop =="
"$REPO_ROOT/scripts/capture-stop.sh" "$CELL" "$WORK"
cp "$WORK/observer.pcap" "$EVIDENCE_DIR/${CELL}.pcap" 2>/dev/null || true
stop_server_capture

echo "== capture: regenerate the capture-check evidence against the final pcap (issue #8) =="
"$REPO_ROOT/scripts/capture-check-regenerate.sh" "$CELL" "$EVIDENCE_DIR"

echo "== plugin logs (journalctl copy, survives a plugin upgrade) =="
# dockerd tags a managed plugin's own stdout/stderr lines with
# "plugin=<instance id>", never with the literal text "net-dhcp"
# (internal/scenario/dockerhost.go's pluginJournalTagPattern, issue #3):
# a plain `grep net-dhcp` here dropped every one of those lines, in
# every bundle, at any log level. Match both, the same rule
# pluginJournalLines uses, so this whole-cell dump and the per-scenario
# captures agree on what counts as a plugin line, and so a window that
# spans a plugin upgrade keeps the old instance's lines too, not only
# the current one's.
ssh_run "$mgmt_ip" "sudo journalctl -u docker --since '2 hours ago'" \
	| grep -E 'net-dhcp|plugin=[0-9a-f]+' >"$EVIDENCE_DIR/${CELL}-plugin-log.txt" || true

relay_journal

echo "== source state directory (Kea lease-file cleanup copies, #23) =="
# Kea's memfile cleanup (lfc-interval, default 3600 s) leaves
# kea-leases4.csv.1/.2 behind; C4's ResetLeases must remove each one
# (defeat 2), and only this listing after a run of an hour or more shows
# which copies exist.
if [ "$source_type" = kea ]; then
	for peer in $peers; do
		ssh_run "${peer#*=}" "sudo ls -l --time-style=full-iso /var/lib/kea/; date -u +%Y-%m-%dT%H:%M:%SZ" \
			>"$EVIDENCE_DIR/${CELL}-${peer%%=*}-var-lib-kea.txt" || true
	done
fi

echo "== tear down cell $CELL =="
LAB_EVIDENCE_DIR="$EVIDENCE_DIR" "$REPO_ROOT/scripts/down-cell.sh" "$CELL" "$WORK"

if [ "$RUNNER_FAILED" -ne 0 ]; then
	echo "run-cell: FAIL -- at least one shape's labctl run hit an infrastructure error; see above" >&2
	exit 1
fi
echo "run-cell: bundle written to $EVIDENCE_DIR (verdicts, capture, lease snapshots, versions, config diff, plugin log)"
