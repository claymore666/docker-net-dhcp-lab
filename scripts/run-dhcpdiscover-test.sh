#!/bin/bash
# On the reference Docker host, create a null-IPAM macvlan network on the
# plugin under test and run one container against it. It never gets a
# lease -- there is no DHCP server anywhere in this cell (issue #1) -- the
# point is only that it sends a DHCPDISCOVER onto the segment.
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
ssh_run "sudo docker run --rm --network $NET alpine:3.20 sh -c 'udhcpc -i eth0 -n -q -T 2 -t 1 -x hostname:lab-test || true'"
ssh_run "sudo docker network rm $NET"
echo "run-dhcpdiscover-test: sent"
