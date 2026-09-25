#!/bin/bash
# Give the observer container a leg on one segment and capture on it
# (issue #1, done means: "the observer captures" a DHCPDISCOVER). The
# container itself never touches the segment's IP space; it only
# listens. Every privileged call here (docker, plus every ip/nsenter
# call touching a real host netns or interface) runs under sudo -n: this
# script runs as the unprivileged lab-host operator, in neither the
# docker group nor holding bare CAP_NET_ADMIN, same shape as up-cell.sh.
# build-bridge.sh itself stays privilege-agnostic so build-bridge-test.sh
# can run it unprivileged inside its own unshare -rnm namespace; this
# script elevates at its own call site instead, as up-cell.sh does.
set -euo pipefail

CELL=${1:?usage: observe-segment.sh <cell-name> <bridge> <pcap-path> <seconds>}
BRIDGE=${2:?}
PCAP=${3:?}
SECONDS_TO_CAPTURE=${4:-25}

# The caller's own synchronization point (issue #1/#3 direction: "the
# observer must be capturing before the network create"). Written only
# once tcpdump is confirmed running inside the container below, never
# on a fixed guess at how long apk/veth setup takes.
READY="$(dirname "$PCAP")/observer.ready"
rm -f "$READY"

# Linux interface names are capped at 15 characters (IFNAMSIZ-1); a
# name built from the cell name directly overflows that for any cell
# longer than a few characters (measured live, issue #1: "veth-obs-ref-only"
# is 18 chars and iproute2 rejects it as "not a valid ifname"). Fill the
# rest with a short deterministic hash of the cell name so the tap name
# is always exactly 15 characters regardless of CELL's length.
cell_hash=$(echo -n "$CELL" | md5sum | cut -c1-5)
VETH_HOST="veth-obs-${cell_hash}h"
VETH_PEER="veth-obs-${cell_hash}c"
CONTAINER="lab-observer-${CELL}"

sudo -n docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
sudo -n ip link del "$VETH_HOST" 2>/dev/null || true

# Started on Docker's own default bridge (has outbound internet via the
# host's NAT) just long enough to install tcpdump, then disconnected
# before the segment leg goes on -- the isolated segment bridge has no
# route out, so apk cannot reach a mirror from it (measured live, issue
# #1: "temporary error" / "no such package" once network none was tried
# first). The container never touches segment IP space either way.
sudo -n docker run -d --name "$CONTAINER" --cap-add NET_ADMIN --cap-add NET_RAW \
	--entrypoint sleep alpine:3.20 infinity >/dev/null
sudo -n docker exec "$CONTAINER" sh -c "apk add --no-cache tcpdump >/dev/null"
sudo -n docker network disconnect bridge "$CONTAINER"

# A plain veth added as a bridge port, as originally designed. Making
# this work end to end needed a separate host fix (issue #1): the
# host's iptables FORWARD chain (Docker's own, default policy drop) was
# dropping bridged IPv4 between two ordinary member ports unless one
# side was docker0 or virbr-mgmt -- measured live, the observer's veth
# saw every IPv6 neighbor-discovery/multicast frame (that chain's IPv6
# counterpart defaults to accept) but not one DHCP broadcast. That is
# fixed at the host level by a lab-owned LAB-SEG accept rule
# (lab-seg-firewall.sh, applied unconditionally by up-cell.sh before the
# VM starts), not here.
sudo -n ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
sudo -n "$(dirname "${BASH_SOURCE[0]}")/build-bridge.sh" "$BRIDGE" --add-port "$VETH_HOST"
pid=$(sudo -n docker inspect -f '{{.State.Pid}}' "$CONTAINER")
sudo -n ip link set "$VETH_PEER" netns "$pid"
sudo -n nsenter -t "$pid" -n ip link set lo up
sudo -n nsenter -t "$pid" -n ip link set "$VETH_PEER" name eth-obs up

sudo -n docker exec -d "$CONTAINER" tcpdump -i eth-obs -w /tmp/obs.pcap -U 'udp port 67 or udp port 68'

# Bounded wait for tcpdump to actually be the running process before
# telling the caller it is safe to generate traffic -- apk/veth setup
# above can take longer than any fixed guess, and a caller that starts
# the DHCPDISCOVER before the capture is live loses the frame silently.
# "-x tcpdump" matches the process's own name only: a "-f" pattern
# containing "tcpdump" would also match the "sh -c \"pgrep -f ...\""
# wrapper's own argv, since that text is right there on its command
# line, so the wait would pass before tcpdump itself had even started.
waited=0
until sudo -n docker exec "$CONTAINER" sh -c "pgrep -x tcpdump >/dev/null" 2>/dev/null; do
	waited=$((waited + 1))
	if [ "$waited" -ge 100 ]; then
		echo "observe-segment: FAIL -- tcpdump did not start inside the 10s bound" >&2
		exit 1
	fi
	sleep 0.1
done
: >"$READY"

echo "observe-segment: capturing on $BRIDGE for ${SECONDS_TO_CAPTURE}s"
sleep "$SECONDS_TO_CAPTURE"

sudo -n docker exec "$CONTAINER" pkill tcpdump || true
sleep 1
sudo -n docker cp "$CONTAINER:/tmp/obs.pcap" "$PCAP"
echo "observe-segment: wrote $PCAP"
