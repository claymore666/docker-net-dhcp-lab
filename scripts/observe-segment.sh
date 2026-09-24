#!/bin/bash
# Give the observer container a leg on one segment and capture on it
# (issue #1, done means: "the observer captures" a DHCPDISCOVER). The
# container itself never touches the segment's IP space; it only listens.
set -euo pipefail

CELL=${1:?usage: observe-segment.sh <cell-name> <bridge> <pcap-path> <seconds>}
BRIDGE=${2:?}
PCAP=${3:?}
SECONDS_TO_CAPTURE=${4:-25}

VETH_HOST="veth-obs-${CELL}"
VETH_PEER="veth-obs-${CELL}-c"
CONTAINER="lab-observer-${CELL}"

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
ip link del "$VETH_HOST" 2>/dev/null || true

docker run -d --name "$CONTAINER" --network none --cap-add NET_ADMIN --cap-add NET_RAW \
	--entrypoint sleep alpine:3.20 infinity >/dev/null

pid=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
"$(dirname "${BASH_SOURCE[0]}")/build-bridge.sh" "$BRIDGE" --add-port "$VETH_HOST"
ip link set "$VETH_PEER" netns "$pid"
nsenter -t "$pid" -n ip link set lo up
nsenter -t "$pid" -n ip link set "$VETH_PEER" name eth-obs up

docker exec "$CONTAINER" sh -c "apk add --no-cache tcpdump >/dev/null"
docker exec -d "$CONTAINER" tcpdump -i eth-obs -w /tmp/obs.pcap -U 'udp port 67 or udp port 68'

echo "observe-segment: capturing on $BRIDGE for ${SECONDS_TO_CAPTURE}s"
sleep "$SECONDS_TO_CAPTURE"

docker exec "$CONTAINER" pkill tcpdump || true
sleep 1
docker cp "$CONTAINER:/tmp/obs.pcap" "$PCAP"
echo "observe-segment: wrote $PCAP"
