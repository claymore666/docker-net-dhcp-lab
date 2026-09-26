#!/bin/bash
# On the reference docker host, create a null-IPAM macvlan network on the
# plugin under test and run one container against it, in a cell that HAS
# an IP source (issue #2, unlike issue #1's no-source cell): the
# plugin's own DHCP request during CreateEndpoint should succeed this
# time, leased by that cell's own source. Leaves the container running
# so its lease can be cross-checked against the source's own table
# afterward; prints the leased MAC and address as raw evidence.
set -euo pipefail

MGMT_IP=${1:?usage: run-source-lease-test.sh <mgmt-ip> <work-dir>}
WORK=${2:?usage: run-source-lease-test.sh <mgmt-ip> <work-dir>}
NET=mv-test
known_hosts="$WORK/known_hosts"
DRIVER=net-dhcp-under-test:latest

ssh_run() {
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ControlMaster=no -o ControlPath=none \
		-i ~/.ssh/id_ed25519_lab lab@"$MGMT_IP" "$@"
}

ssh_run "sudo docker rm -f mv-test-c" >/dev/null 2>&1 || true
ssh_run "sudo docker network rm $NET" >/dev/null 2>&1 || true
ssh_run "sudo docker network create -d $DRIVER --ipam-driver null -o parent=eth1 -o mode=macvlan $NET"

if ! ssh_run "sudo docker run -d --name mv-test-c --network $NET alpine:3.20 sleep 300"; then
	echo "run-source-lease-test: FAIL -- docker run did not start; this cell has a source and should succeed" >&2
	ssh_run "sudo docker network rm $NET" >/dev/null 2>&1 || true
	exit 1
fi

mac=$(ssh_run "sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' mv-test-c")
addr=$(ssh_run "sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mv-test-c")
if [ -z "$mac" ] || [ -z "$addr" ]; then
	echo "run-source-lease-test: FAIL -- container has no MAC/address reported by the plugin" >&2
	ssh_run "sudo docker rm -f mv-test-c" >/dev/null 2>&1 || true
	ssh_run "sudo docker network rm $NET" >/dev/null 2>&1 || true
	exit 1
fi

echo "run-source-lease-test: container leased mac=$mac address=$addr"
echo "run-source-lease-test: sent -- CreateEndpoint's DHCP request succeeded (container running as mv-test-c)"
