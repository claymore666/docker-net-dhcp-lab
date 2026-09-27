#!/bin/bash
# Redo every corroborate() capture check for one cell once its whole-cell
# capture is final (issue #8): corroborate() cannot read observer.pcap
# while shapes are still running (capture-stop.sh only writes it after
# the last one), so every capture-check evidence file starts out
# deferred, carrying only the mac it needs. This replays each one
# against $EVIDENCE_DIR/<cell>.pcap and overwrites it in place. Only a
# file still carrying the deferred marker is touched -- a resumed run
# starts a fresh, narrower capture in the same evidence dir, so a file
# already final, or a deferred mac that capture never ran during, must
# not be judged against it as if it were a disagreement.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/dhcp-exchange-check.sh
. "$REPO_ROOT/scripts/dhcp-exchange-check.sh"

CELL=${1:?usage: capture-check-regenerate.sh <cell-name> <evidence-dir>}
EVIDENCE_DIR=${2:?}
PCAP="$EVIDENCE_DIR/$CELL.pcap"

shopt -s nullglob
clean=0
other=0
for f in "$EVIDENCE_DIR/$CELL"-*-capture-check.txt; do
	if ! grep -qE '^capture check deferred to the final pcap, mac ' "$f"; then
		# Already final (clean, disagreement, or an earlier error): a
		# capture this script replays never covers more than the
		# deferred shapes, so a file that already has a real verdict
		# is left exactly as it is.
		continue
	fi
	mac=$(grep -oE 'mac [0-9a-fA-F:]+' "$f" | head -1 | awk '{print $2}')
	if [ -z "$mac" ]; then
		echo "capture-check-regenerate: WARNING -- $f has no recorded mac, left as is" >&2
		continue
	fi
	rc=0
	reason=$(dhcp_exchange_reason "$PCAP" "$mac") || rc=$?
	if [ "$rc" -ne 0 ]; then
		# $reason already carries dhcp_exchange_reason's own "capture
		# unreadable: ..." text; only the mac needs adding here.
		text="$reason, mac $mac"
		other=$((other + 1))
	elif [ -z "$reason" ]; then
		text="clean 4-message exchange for mac $mac in the cell capture"
		clean=$((clean + 1))
	elif [ "$(dhcp_exchange_mac_seen "$PCAP" "$mac")" = "0" ]; then
		# The mac has zero packets in this capture at all -- not a
		# broken exchange, a capture that never ran during it (the
		# usual cause: a resumed run's capture starts after an
		# earlier run's shapes already finished).
		text="capture check error, mac $mac: this mac has no packets in the replayed capture, the capture likely postdates its exchange"
		other=$((other + 1))
	else
		text="capture disagreement for mac $mac: $reason"
		other=$((other + 1))
	fi
	echo "$text" >"$f"
done
echo "capture-check-regenerate: $PCAP -- $clean clean, $other other"
