#!/bin/bash
# The one command issue #2 asks for, per source: from a clean lab host,
# bring up a source cell (docker host + source VM), fire a real DHCP
# exchange from a test container, and prove the observer captured all
# four message types (tied to the container's own MAC and one xid), the
# source's own table (through the Go adapter) shows the same lease, and
# containment held throughout.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/dhcp-exchange-check.sh
. "$REPO_ROOT/scripts/dhcp-exchange-check.sh"
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

# Containment (issue #2 HOLD finding 5): capture on the management
# bridge for the whole exchange below, so the demo log itself proves no
# DHCP server reply ever reaches it, not just the segment bridge the
# source is meant to answer on. sudo -n, same as every other privileged
# call in this repo; bounded by "timeout" so it always ends even if the
# kill below never reaches it.
MGMT_PCAP="$WORK/mgmt.pcap"
sudo -n rm -f "$MGMT_PCAP"
sudo -n timeout 40 tcpdump -n -i virbr-mgmt -w "$MGMT_PCAP" 'udp port 67 or udp port 68' >/dev/null 2>&1 &
mgmt_pid=$!
mgmt_waited=0
until sudo -n pgrep -f "tcpdump -n -i virbr-mgmt" >/dev/null 2>&1; do
	mgmt_waited=$((mgmt_waited + 1))
	if [ "$mgmt_waited" -ge 50 ]; then
		echo "demo-source-cell: FAIL -- mgmt-bridge capture did not start inside the 5s bound" >&2
		exit 1
	fi
	sleep 0.1
done

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

sudo -n kill -TERM "$mgmt_pid" 2>/dev/null || true
wait "$mgmt_pid" 2>/dev/null || true
sudo -n chown "$(id -u):$(id -g)" "$MGMT_PCAP" 2>/dev/null || true

mac=$(grep -oE 'mac=[0-9a-f:]+' <<<"$lease_out" | cut -d= -f2)
addr=$(grep -oE 'address=[0-9.]+' <<<"$lease_out" | cut -d= -f2)
if [ -z "$mac" ] || [ -z "$addr" ]; then
	echo "demo-source-cell: FAIL -- could not read the leased mac/address from run-source-lease-test.sh" >&2
	exit 1
fi

echo "== containment: virbr-mgmt capture for the whole exchange (raw) =="
tcpdump -n -r "$MGMT_PCAP" 2>/dev/null
mgmt_replies=$(tcpdump -n -r "$MGMT_PCAP" 'udp src port 67' 2>/dev/null | wc -l)
if [ "$mgmt_replies" -ne 0 ]; then
	echo "demo-source-cell: FAIL -- $mgmt_replies DHCP server reply frame(s) on virbr-mgmt (source port 67); a source reply must never reach the management network" >&2
	exit 1
fi
echo "demo-source-cell: containment ok -- 0 DHCP server replies on virbr-mgmt"

echo "== containment: $bridge port list (raw) =="
vnet_count=0
obs_count=0
unexpected=""
for port in /sys/class/net/"$bridge"/brif/*; do
	[ -e "$port" ] || continue
	p=$(basename "$port")
	echo "$p"
	case "$p" in
	vnet*) vnet_count=$((vnet_count + 1)) ;;
	veth-obs-*) obs_count=$((obs_count + 1)) ;;
	*) unexpected="$unexpected $p" ;;
	esac
done
if [ -n "$unexpected" ] || [ "$vnet_count" -ne 2 ] || [ "$obs_count" -ne 1 ]; then
	echo "demo-source-cell: FAIL -- $bridge carries unexpected ports (want 2 VM taps + 1 observer veth; saw vnet=$vnet_count obs=$obs_count unexpected=[$unexpected])" >&2
	exit 1
fi
echo "demo-source-cell: containment ok -- $bridge carries only its 2 VM taps and 1 observer veth"

echo "== observer: DHCP message types captured (raw) =="
tcpdump -n -v -r "$PCAP" 'udp port 67 or udp port 68' 2>/dev/null
exchange_reason=$(dhcp_exchange_reason "$PCAP" "$mac")
if [ -n "$exchange_reason" ]; then
	echo "demo-source-cell: FAIL -- $exchange_reason" >&2
	exit 1
fi

echo "== source's own table, read through the Go adapter =="
lease_table=$(go run "$REPO_ROOT/cmd/labctl" leases "$source_type" "$source_mgmt_ip" "$WORK/known_hosts")
echo "$lease_table"
if ! awk -v mac="$mac" -v addr="$addr" \
	'tolower($1) == tolower(mac) && $2 == addr { found = 1 } END { exit !found }' \
	<<<"$lease_table"; then
	echo "demo-source-cell: FAIL -- no row in the source's own table has both mac=$mac and address=$addr" >&2
	exit 1
fi

echo "demo-source-cell: PASS -- $CELL ($source_type) leased $mac -> $addr, all four DHCP message types captured, lease confirmed in the source's own table, containment held"
