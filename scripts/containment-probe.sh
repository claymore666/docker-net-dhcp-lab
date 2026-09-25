#!/bin/bash
# The load-bearing containment check (issue #1/#3 direction):
# containment-preflight.sh only proves the ci_dmz drop rule is present in
# the ruleset text -- it never proves traffic is actually dropped. This
# generates real outbound TCP attempts from inside the cell's Docker host
# VM and confirms the host's own /24 drop counter rises because of them.
#
# No literal home-network address is written into this file. The targets
# are supplied by the caller at the command line and never stored in any
# tracked file; the /24 drop rule itself is matched by shape (an nft rule
# that drops by a /24 destination), the same way containment-preflight.sh
# matches its own rule by shape rather than by address. This is this
# repo's own small, committed version of the proof containment-
# preflight.sh's header names -- `dmz-probe.sh`, a private script that is
# never copied into this repo.
set -euo pipefail

MGMT_IP=${1:?usage: containment-probe.sh <mgmt-ip> <work-dir> <target-ip> [<target-ip> ...]}
WORK=${2:?usage: containment-probe.sh <mgmt-ip> <work-dir> <target-ip> [<target-ip> ...]}
shift 2
if [ "$#" -eq 0 ]; then
	echo "containment-probe: usage: containment-probe.sh <mgmt-ip> <work-dir> <target-ip> [<target-ip> ...]" >&2
	exit 1
fi
TARGETS=("$@")

known_hosts="$WORK/known_hosts"

ssh_run() {
	# Same options as run-dhcpdiscover-test.sh's ssh_run -- see up-cell.sh's
	# wait loop for why ControlMaster/ControlPath matter here too.
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ControlMaster=no -o ControlPath=none \
		-i ~/.ssh/id_ed25519_lab lab@"$MGMT_IP" "$@"
}

# Matched by shape, never by a literal address: see the header comment.
dmz_drop_counter() {
	sudo -n nft -a list table inet ci_dmz 2>&1 \
		| grep -oE 'ip daddr [0-9.]+/[0-9]+ counter packets [0-9]+ bytes [0-9]+ drop' \
		| grep -m1 '/24 ' \
		| grep -oE 'packets [0-9]+' \
		| grep -oE '[0-9]+'
}

before=$(dmz_drop_counter || true)
if [ -z "$before" ]; then
	echo "containment-probe: FAIL -- no /24 drop rule found in ci_dmz (run containment-preflight.sh first)" >&2
	exit 1
fi

for t in "${TARGETS[@]}"; do
	for port in 80 443 22; do
		# Expected to fail every time -- the probe's job is to generate the
		# attempt and let the host firewall drop it, not to connect.
		ssh_run "timeout 2 bash -c 'echo >/dev/tcp/$t/$port' " >/dev/null 2>&1 || true
	done
done

after=$(dmz_drop_counter || true)
if [ -z "$after" ]; then
	echo "containment-probe: FAIL -- /24 drop rule disappeared mid-probe" >&2
	exit 1
fi

echo "containment-probe: ci_dmz /24 drop counter before=$before after=$after"
if [ "$after" -le "$before" ]; then
	echo "containment-probe: FAIL -- /24 drop counter did not rise" >&2
	exit 1
fi
echo "containment-probe: PASS -- /24 drop counter rose ($before -> $after)"
