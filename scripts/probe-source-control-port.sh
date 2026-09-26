#!/bin/bash
# issue #2: Kea's control agent binds 127.0.0.1 only
# (source-bind-check.sh's sibling check would be a second static check;
# this is the live half). Only Kea has a network-facing control port at
# all -- isc-dhcp and dnsmasq here have neither omapi nor a control
# socket enabled, so there is nothing to probe for those two. Run from
# the docker host VM, which shares the segment with the source.
set -euo pipefail

MGMT_IP=${1:?usage: probe-source-control-port.sh <docker-host-mgmt-ip> <work-dir> <source-seg-ip> <port>}
WORK=${2:?}
TARGET_IP=${3:?}
PORT=${4:?}
known_hosts="$WORK/known_hosts"

ssh_run() {
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ControlMaster=no -o ControlPath=none \
		-i ~/.ssh/id_ed25519_lab lab@"$MGMT_IP" "$@"
}

raw=$(ssh_run "LC_ALL=C timeout 3 bash -c 'echo >/dev/tcp/$TARGET_IP/$PORT' 2>&1; echo RC=\$?")
echo "probe-source-control-port: raw result from $MGMT_IP against $TARGET_IP:$PORT -- $raw"
if grep -q 'RC=0' <<<"$raw"; then
	echo "probe-source-control-port: FAIL -- $TARGET_IP:$PORT answered from the segment; control port is not loopback-only" >&2
	exit 1
fi
echo "probe-source-control-port: PASS -- $TARGET_IP:$PORT did not answer from the segment"
