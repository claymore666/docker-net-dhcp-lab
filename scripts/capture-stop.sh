#!/bin/bash
# Stop the capture capture-start.sh began, copy the pcap out, and remove
# the observer's leg on the segment (issue #3). Idempotent: safe to call
# on a cell whose capture was never started, or already stopped.
set -euo pipefail

CELL=${1:?usage: capture-stop.sh <cell-name> <work-dir>}
WORK=${2:?}
PCAP="$WORK/observer.pcap"

cell_hash=$(echo -n "$CELL" | md5sum | cut -c1-5)
VETH_HOST="veth-obs-${cell_hash}h"
CONTAINER="lab-observer-${CELL}"

if sudo -n docker inspect "$CONTAINER" >/dev/null 2>&1; then
	sudo -n docker exec "$CONTAINER" pkill tcpdump || true
	sleep 1
	sudo -n docker cp "$CONTAINER:/tmp/obs.pcap" "$PCAP" 2>/dev/null || true
	sudo -n docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
fi
sudo -n ip link del "$VETH_HOST" 2>/dev/null || true

if [ -s "$PCAP" ]; then
	echo "capture-stop: wrote $PCAP"
else
	echo "capture-stop: WARNING -- $PCAP is missing or empty" >&2
fi
