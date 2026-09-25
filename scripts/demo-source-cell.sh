#!/bin/bash
# The one command issue #2 asks for, per source: from a clean lab host,
# bring up a source cell (docker host + source VM), fire a real DHCP
# exchange from a test container, and prove the observer captured all
# four message types and the source's own table (through the Go
# adapter) shows the same lease.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CELL=${1:?usage: demo-source-cell.sh <cell-name> [work-dir]}
WORK=${2:-/srv/lab/work/$(whoami)/$CELL}
PCAP="$WORK/observer.pcap"

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$REPO_ROOT/lab.yaml" "$CELL")
bridge=$(jq -r '.cell.segment.bridge' <<<"$RESOLVED")
mgmt_addr=$(jq -r '.cell.docker_host.mgmt_address' <<<"$RESOLVED")
mgmt_ip=${mgmt_addr%%/*}
source_type=$(jq -r '.cell.source.type' <<<"$RESOLVED")
source_mgmt_ip=$(jq -r '.cell.source.mgmt_address' <<<"$RESOLVED")
source_mgmt_ip=${source_mgmt_ip%%/*}

"$REPO_ROOT/scripts/up-cell.sh" "$CELL" "$WORK"

"$REPO_ROOT/scripts/observe-segment.sh" "$CELL" "$bridge" "$PCAP" 30 &
observer_pid=$!

READY="$WORK/observer.ready"
waited=0
until [ -f "$READY" ]; do
	if ! kill -0 "$observer_pid" 2>/dev/null; then
		echo "demo-source-cell: FAIL -- observer exited before it became ready" >&2
		exit 1
	fi
	waited=$((waited + 1))
	if [ "$waited" -ge 200 ]; then
		echo "demo-source-cell: FAIL -- observer did not become ready inside the 60s bound" >&2
		kill "$observer_pid" 2>/dev/null || true
		exit 1
	fi
	sleep 0.3
done

lease_out=$("$REPO_ROOT/scripts/run-source-lease-test.sh" "$mgmt_ip" "$WORK")
echo "$lease_out"
wait "$observer_pid"

mac=$(grep -oE 'mac=[0-9a-f:]+' <<<"$lease_out" | cut -d= -f2)
addr=$(grep -oE 'address=[0-9.]+' <<<"$lease_out" | cut -d= -f2)
if [ -z "$mac" ] || [ -z "$addr" ]; then
	echo "demo-source-cell: FAIL -- could not read the leased mac/address from run-source-lease-test.sh" >&2
	exit 1
fi

echo "== observer: DHCP message types captured (raw) =="
decoded=$(tcpdump -v -r "$PCAP" 'udp port 67 or udp port 68' 2>/dev/null)
echo "$decoded"
missing=""
for kind in Discover Offer Request ACK; do
	grep -qi "$kind" <<<"$decoded" || missing="$missing $kind"
done
if [ -n "$missing" ]; then
	echo "demo-source-cell: FAIL -- missing message type(s) in $PCAP:$missing" >&2
	exit 1
fi

echo "== source's own table, read through the Go adapter =="
lease_table=$(go run "$REPO_ROOT/cmd/labctl" leases "$source_type" "$source_mgmt_ip" "$WORK/known_hosts")
echo "$lease_table"
if ! grep -qi "$mac" <<<"$lease_table" || ! grep -q "$addr" <<<"$lease_table"; then
	echo "demo-source-cell: FAIL -- $mac/$addr not found in the source's own lease table" >&2
	exit 1
fi

echo "demo-source-cell: PASS -- $CELL ($source_type) leased $mac -> $addr, all four DHCP message types captured, lease confirmed in the source's own table"
