#!/bin/bash
# On the reference Docker host, create a null-IPAM macvlan network on the
# plugin under test and run one container against it. It never gets a
# lease -- there is no DHCP server anywhere in this cell (issue #1) -- the
# point is only that it sends a DHCPDISCOVER onto the segment.
set -euo pipefail

MGMT_IP=${1:?usage: run-dhcpdiscover-test.sh <mgmt-ip>}
NET=mv-test
# The plugin is installed with --alias net-dhcp-under-test, but the
# engine's driver registry keys it by the full reference including the
# tag (measured live, issue #1: `docker info` lists
# "net-dhcp-under-test:latest", and `-d net-dhcp-under-test` alone fails
# "could not resolve driver ... in registry").
DRIVER=net-dhcp-under-test:latest

ssh_run() {
	ssh -o StrictHostKeyChecking=accept-new -i ~/.ssh/id_ed25519_lab lab@"$MGMT_IP" "$@"
}

ssh_run "sudo docker network rm $NET" >/dev/null 2>&1 || true
ssh_run "sudo docker network create -d $DRIVER --ipam-driver null -o parent=eth1 -o mode=macvlan $NET"
ssh_run "sudo docker run --rm --network $NET alpine:3.20 sh -c 'udhcpc -i eth0 -n -q -T 2 -t 1 -x hostname:lab-test || true'"
ssh_run "sudo docker network rm $NET"
echo "run-dhcpdiscover-test: sent"
