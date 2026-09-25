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
# The /24 drop counter this script reads is host-wide, not scoped to one
# cell: run only one cell's probe at a time, or a concurrent probe on
# this host will move the same counter.
set -euo pipefail

MGMT_IP=${1:?usage: containment-probe.sh <mgmt-ip> <work-dir> <target-ip> [<target-ip> ...]}
WORK=${2:?usage: containment-probe.sh <mgmt-ip> <work-dir> <target-ip> [<target-ip> ...]}
shift 2
if [ "$#" -eq 0 ]; then
	echo "containment-probe: usage: containment-probe.sh <mgmt-ip> <work-dir> <target-ip> [<target-ip> ...]" >&2
	exit 1
fi
TARGETS=("$@")
PORTS=(80 443 22)
# A single blocked attempt sends a varying number of packets (the SYN,
# plus however many retries the local stack fires before the 2s timeout
# below cuts it off), so the counter cannot be checked against a total
# count across every attempt. Instead the counter is read immediately
# before and after each individual attempt, and that one attempt must
# raise it by at least 1 -- an attempt that times out without ever
# raising it has escaped the drop rule silently (nothing answers it, but
# nothing dropped it locally either), and counts as a leak.
ATTEMPTS=$((${#TARGETS[@]} * ${#PORTS[@]}))

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
leaked=""
for t in "${TARGETS[@]}"; do
	for port in "${PORTS[@]}"; do
		pre=$(dmz_drop_counter || true)
		if [ -z "$pre" ]; then
			echo "containment-probe: FAIL -- /24 drop rule disappeared mid-probe" >&2
			exit 1
		fi
		# Expected to fail every time; success is checked by its own
		# marker, never ssh's exit code (which can fail for unrelated
		# reasons). CONNECTED (rc 0): the port answered. REACHED: the
		# remote connect() reported "refused" -- a RST proves the SYN
		# reached the target, so this counts as a failure too. LC_ALL=C
		# pins that text to English regardless of the remote host's
		# locale. BLOCKED: a genuine timeout (rc 124) or any other fast
		# failure ("no route to host" etc, a routing fact, not evidence
		# of reaching anything) -- both pass this classification, but
		# still have to clear the per-attempt counter check below.
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

		post=$(dmz_drop_counter || true)
		if [ -z "$post" ]; then
			echo "containment-probe: FAIL -- /24 drop rule disappeared mid-probe" >&2
			exit 1
		fi
		delta=$((post - pre))
		if [ "$delta" -lt 1 ]; then
			echo "containment-probe: FAIL -- LEAK $t:$port; $result but the /24 drop counter did not rise (before=$pre after=$post)" >&2
			leaked=1
		fi
	done
done
if [ -n "$connected" ] || [ -n "$leaked" ]; then
	exit 1
fi

after=$(dmz_drop_counter || true)
echo "containment-probe: ci_dmz /24 drop counter before=$before after=${after:-$before}"
echo "containment-probe: PASS -- all $ATTEMPTS attempts blocked, each one confirmed by its own rise in the /24 drop counter"
