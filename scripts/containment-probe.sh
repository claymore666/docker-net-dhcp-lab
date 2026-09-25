#!/bin/bash
# The load-bearing containment check (issue #1/#3 direction):
# containment-preflight.sh only proves the ci_dmz drop rule is present in
# the ruleset text -- it never proves traffic is actually dropped. This
# generates real outbound TCP attempts from inside the cell's Docker host
# VM, fails outright if any of them actually connects, and confirms the
# host's own /24 drop counter also rose. No literal home-network address
# is written here: targets come from the caller's command line and are
# never stored, and the drop rule is matched by shape, the same way
# containment-preflight.sh matches its own rule. This repo's own version
# of the proof named in that script's header (`dmz-probe.sh`, private).
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

connected=""
for t in "${TARGETS[@]}"; do
	for port in 80 443 22; do
		# Expected to fail every time -- the probe's job is to generate the
		# attempt and let the host firewall drop it, not to connect. A
		# successful connection is checked explicitly by its own marker,
		# never inferred from ssh's exit code -- ssh itself can fail for
		# reasons (a dropped control session, a remote timeout) that have
		# nothing to do with whether the target actually answered.
		#
		# CONNECTED (rc 0): the port answered outright.
		# REACHED: bash's own connect() came straight back with
		# "connection refused" -- a RST, sent by the target's own
		# kernel, proves the SYN reached it past the firewall, so this
		# counts as a failure too. LC_ALL=C pins the message to English
		# regardless of the remote host's locale, the same reason
		# numeric awk/sort runs under LC_ALL=C elsewhere in this repo.
		# BLOCKED: a genuine 2s timeout (rc 124, the SYN was silently
		# dropped) or any other fast failure such as "no route to
		# host"/"network unreachable" -- a routing fact, not evidence
		# the packet reached anything -- both the expected, passing
		# outcome.
		raw=$(ssh_run "out=\$(LC_ALL=C timeout 2 bash -c 'echo >/dev/tcp/$t/$port' 2>&1); rc=\$?; printf '%s|RC=%s' \"\$out\" \"\$rc\"" 2>/dev/null || printf '|RC=124')
		rc=${raw##*RC=}
		msg=${raw%|RC=*}
		if [ "$rc" = "0" ]; then
			result=CONNECTED
		elif [ "$rc" = "124" ]; then
			result=BLOCKED
		elif grep -qi refused <<<"$msg"; then
			result=REACHED
		else
			result=BLOCKED
		fi
		if [ "$result" = "CONNECTED" ] || [ "$result" = "REACHED" ]; then
			echo "containment-probe: FAIL -- $result $t:$port; containment did not hold" >&2
			connected=1
		fi
	done
done
if [ -n "$connected" ]; then
	exit 1
fi

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
