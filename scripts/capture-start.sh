#!/bin/bash
# Start the observer's leg on one segment and leave tcpdump running in
# the background (issue #3: one pcap per cell, spanning every scenario x
# shape that cell runs, not the fixed duration observe-segment.sh built
# for issue #1's single demo). Setup is identical to observe-segment.sh;
# capture-stop.sh is its other half. Every privileged call runs under
# sudo -n, same reasoning as observe-segment.sh and up-cell.sh: this
# script runs as the unprivileged lab-host operator.
set -euo pipefail

CELL=${1:?usage: capture-start.sh <cell-name> <bridge> <work-dir>}
BRIDGE=${2:?}
WORK=${3:?}
PCAP="$WORK/observer.pcap"

READY="$WORK/observer.ready"
rm -f "$READY" "$PCAP"

# Same 15-character IFNAMSIZ-1 limit and hash-based naming as
# observe-segment.sh and down-cell.sh (issue #1); capture-stop.sh
# recomputes the same names rather than sharing state, matching every
# other paired script here.
cell_hash=$(echo -n "$CELL" | md5sum | cut -c1-5)
VETH_HOST="veth-obs-${cell_hash}h"
VETH_PEER="veth-obs-${cell_hash}c"
CONTAINER="lab-observer-${CELL}"

sudo -n docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
sudo -n ip link del "$VETH_HOST" 2>/dev/null || true

# Started on Docker's own default bridge for outbound internet just long
# enough to install tcpdump, then disconnected before the segment leg
# goes on: the isolated segment bridge has no route out (issue #1).
sudo -n docker run -d --name "$CONTAINER" --cap-add NET_ADMIN --cap-add NET_RAW \
	--entrypoint sleep alpine:3.20 infinity >/dev/null
sudo -n docker exec "$CONTAINER" sh -c "apk add --no-cache tcpdump >/dev/null"
sudo -n docker network disconnect bridge "$CONTAINER"

sudo -n ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
sudo -n "$(dirname "${BASH_SOURCE[0]}")/build-bridge.sh" "$BRIDGE" --add-port "$VETH_HOST"
pid=$(sudo -n docker inspect -f '{{.State.Pid}}' "$CONTAINER")
sudo -n ip link set "$VETH_PEER" netns "$pid"
sudo -n nsenter -t "$pid" -n ip link set lo up
sudo -n nsenter -t "$pid" -n ip link set "$VETH_PEER" name eth-obs up

sudo -n docker exec -d "$CONTAINER" tcpdump -i eth-obs -w /tmp/obs.pcap -U 'udp port 67 or udp port 68'

# Bounded wait for tcpdump to actually be running before telling the
# caller it is safe to generate traffic (issue #1); -x, not -f, for the
# same reason as every other process check in this repo.
waited=0
until sudo -n docker exec "$CONTAINER" sh -c "pgrep -x tcpdump >/dev/null" 2>/dev/null; do
	waited=$((waited + 1))
	if [ "$waited" -ge 100 ]; then
		echo "capture-start: FAIL -- tcpdump did not start inside the 10s bound" >&2
		exit 1
	fi
	sleep 0.1
done
: >"$READY"
echo "capture-start: capturing on $BRIDGE into $PCAP (running; stop with capture-stop.sh)"
