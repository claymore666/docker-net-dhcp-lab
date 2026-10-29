#!/bin/bash
# Pull the container image every scenario runs onto a cell's Docker host
# during bring-up (lab #93): run 2 pulled it inside the first scenario and
# that scenario's `docker run` failed with exit 125 while the pull was still
# going. A failed pull is retried a bounded number of times, then fails the
# bring-up; it is never swallowed.
set -euo pipefail

usage='usage: pull-scenario-image.sh <docker-host-mgmt-ip> <known-hosts-file>'
host=${1:?$usage}
known_hosts=${2:?$usage}

# The tag internal/scenario runs; scripts/pull-scenario-image-test.sh fails
# when that code names any other.
SCENARIO_IMAGE=alpine:3.20
attempts=${LAB_PULL_ATTEMPTS:-5}
pause=${LAB_PULL_SLEEP:-10}

for i in $(seq 1 "$attempts"); do
	if ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
		-o ControlMaster=no -o ControlPath=none -i ~/.ssh/id_ed25519_lab \
		lab@"$host" "sudo docker pull -q $SCENARIO_IMAGE >/dev/null"; then
		echo "pull-scenario-image: $SCENARIO_IMAGE is on $host"
		exit 0
	fi
	echo "pull-scenario-image: attempt $i of $attempts failed" >&2
	[ "$i" -eq "$attempts" ] || sleep "$pause"
done
echo "pull-scenario-image: $SCENARIO_IMAGE could not be pulled onto $host" >&2
exit 1
