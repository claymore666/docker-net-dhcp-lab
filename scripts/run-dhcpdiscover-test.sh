#!/bin/bash
# On the reference Docker host, create a null-IPAM macvlan network on the
# plugin under test and run one container against it. The plugin asks the
# segment for a lease itself, during CreateEndpoint, before the container
# process exists -- this cell has no DHCP server anywhere in it by design
# (issue #1), so that request always times out and `docker run` fails
# before udhcpc inside the container would ever have run. (An earlier
# version of this comment said the point was only "it sends a
# DHCPDISCOVER onto the segment" and carried a udhcpc payload for the
# container to run -- both were wrong about which layer sends the
# DISCOVER; the payload never executed, measured live 2026-09-25, and is
# dropped below.) The pass path is that specific CreateEndpoint DHCP
# timeout; any other failure, or an unexpected success, is a failure.
set -euo pipefail

MGMT_IP=${1:?usage: run-dhcpdiscover-test.sh <mgmt-ip> <work-dir>}
WORK=${2:?usage: run-dhcpdiscover-test.sh <mgmt-ip> <work-dir>}
NET=mv-test
# Same per-cell file up-cell.sh's own wait loop already trusted this
# mgmt address's host key into (issue #1); not reset here, so this call
# reuses that trust instead of re-verifying and racing it.
known_hosts="$WORK/known_hosts"
# The plugin is installed with --alias net-dhcp-under-test, but the
# engine's driver registry keys it by the full reference including the
# tag (measured live, issue #1: `docker info` lists
# "net-dhcp-under-test:latest", and `-d net-dhcp-under-test` alone fails
# "could not resolve driver ... in registry").
DRIVER=net-dhcp-under-test:latest
EXPECT='failed to get initial IP address via DHCP'

ssh_run() {
	# ControlMaster=no/ControlPath=none: see up-cell.sh's wait loop for why
	# -- an operator ssh config's connection multiplexing would otherwise
	# reuse an existing master connection and skip host-key verification
	# on it, defeating UserKnownHostsFile's fresh check below.
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ControlMaster=no -o ControlPath=none \
		-i ~/.ssh/id_ed25519_lab lab@"$MGMT_IP" "$@"
}

ssh_run "sudo docker network rm $NET" >/dev/null 2>&1 || true
ssh_run "sudo docker network create -d $DRIVER --ipam-driver null -o parent=eth1 -o mode=macvlan $NET"

set +e
run_out=$(ssh_run "sudo docker run --rm --network $NET alpine:3.20 true" 2>&1)
run_status=$?
set -e

if [ "$run_status" -eq 0 ]; then
	echo "run-dhcpdiscover-test: FAIL -- container attached although this cell has no DHCP server; that is unexpected, not a pass" >&2
	echo "$run_out" >&2
	ssh_run "sudo docker network rm $NET" >/dev/null 2>&1 || true
	exit 1
fi

if ! grep -qF "$EXPECT" <<<"$run_out"; then
	echo "run-dhcpdiscover-test: FAIL -- docker run failed for a reason other than the expected CreateEndpoint DHCP timeout:" >&2
	echo "$run_out" >&2
	ssh_run "sudo docker network rm $NET" >/dev/null 2>&1 || true
	exit 1
fi

ssh_run "sudo docker network rm $NET"
echo "run-dhcpdiscover-test: sent -- CreateEndpoint's own DHCP request timed out as expected (no server in this cell)"
