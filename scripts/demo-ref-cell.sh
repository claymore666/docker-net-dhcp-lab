#!/bin/bash
# The one command issue #1 asks for: from a clean lab host, bring up the
# `ref-only` cell, fire a DHCPDISCOVER from a test container, and prove
# the observer captured it. No source VM, no DHCP server anywhere.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CELL=${1:-ref-only}
WORK=${2:-/srv/lab/work/$(whoami)/$CELL}
PCAP="$WORK/observer.pcap"

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$REPO_ROOT/lab.yaml" "$CELL")
bridge=$(jq -r '.cell.segment.bridge' <<<"$RESOLVED")
mgmt_addr=$(jq -r '.cell.docker_host.mgmt_address' <<<"$RESOLVED")
mgmt_ip=${mgmt_addr%%/*}

"$REPO_ROOT/scripts/up-cell.sh" "$CELL" "$WORK"

"$REPO_ROOT/scripts/observe-segment.sh" "$CELL" "$bridge" "$PCAP" 30 &
observer_pid=$!

# Bounded wait on the observer's own ready marker (issue #1/#3 direction:
# "the observer must be capturing before the network create"), never a
# fixed sleep -- observe-segment.sh's apk/veth setup time is not constant.
READY="$WORK/observer.ready"
waited=0
until [ -f "$READY" ]; do
	if ! kill -0 "$observer_pid" 2>/dev/null; then
		echo "demo-ref-cell: FAIL -- observer exited before it became ready" >&2
		exit 1
	fi
	waited=$((waited + 1))
	if [ "$waited" -ge 200 ]; then
		echo "demo-ref-cell: FAIL -- observer did not become ready inside the 60s bound" >&2
		kill "$observer_pid" 2>/dev/null || true
		exit 1
	fi
	sleep 0.3
done

"$REPO_ROOT/scripts/run-dhcpdiscover-test.sh" "$mgmt_ip" "$WORK"
wait "$observer_pid"

count=$(tcpdump -r "$PCAP" 'udp port 68' 2>/dev/null | grep -c 'BOOTP/DHCP, Request' || true)
if [ "${count:-0}" -lt 1 ]; then
	echo "demo-ref-cell: FAIL -- no DHCPDISCOVER seen in $PCAP" >&2
	exit 1
fi
echo "demo-ref-cell: PASS -- $count DHCP request frame(s) captured in $PCAP"
