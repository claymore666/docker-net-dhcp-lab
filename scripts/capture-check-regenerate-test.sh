#!/bin/bash
# Offline cases for capture-check-regenerate.sh (issue #8): a deferred
# capture-check evidence file, written while the whole-cell capture was
# still in progress, must be replayed correctly once the final pcap
# exists.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DATA="$REPO_ROOT/scripts/testdata"
GOOD_MAC=da:b6:45:5b:ef:fe
fail=0

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cp "$DATA/dhcp-good.pcap" "$work/cellA.pcap"
echo "capture check deferred to the final pcap, mac $GOOD_MAC" >"$work/cellA-bridge-A1-capture-check.txt"
echo "capture check deferred to the final pcap, mac aa:bb:cc:dd:ee:ff" >"$work/cellA-macvlan-A14-capture-check.txt"

"$REPO_ROOT/scripts/capture-check-regenerate.sh" cellA "$work" >/dev/null

got_clean=$(cat "$work/cellA-bridge-A1-capture-check.txt")
if [[ "$got_clean" != *"clean 4-message exchange"* ]] || [[ "$got_clean" != *"$GOOD_MAC"* ]]; then
	echo "capture-check-regenerate-test: FAIL -- case A (mac present in the capture): expected a clean match, got \"$got_clean\"" >&2
	fail=1
fi

got_other=$(cat "$work/cellA-macvlan-A14-capture-check.txt")
if [[ "$got_other" != *"disagreement"* ]] || [[ "$got_other" == *"deferred"* ]]; then
	echo "capture-check-regenerate-test: FAIL -- case B (mac absent from the capture): expected a disagreement, got \"$got_other\"" >&2
	fail=1
fi

# Case C: the final pcap itself is missing -- every file must read as a
# capture error, never a disagreement and never left as "deferred".
work2=$(mktemp -d)
trap 'rm -rf "$work" "$work2"' EXIT
echo "capture check deferred to the final pcap, mac $GOOD_MAC" >"$work2/cellB-bridge-A1-capture-check.txt"
"$REPO_ROOT/scripts/capture-check-regenerate.sh" cellB "$work2" >/dev/null
got_missing=$(cat "$work2/cellB-bridge-A1-capture-check.txt")
if [[ "$got_missing" != *"capture unreadable"* ]]; then
	echo "capture-check-regenerate-test: FAIL -- case C (no final pcap): expected a capture-unreadable error, got \"$got_missing\"" >&2
	fail=1
fi
if [[ "$got_missing" == *"disagreement"* ]]; then
	echo "capture-check-regenerate-test: FAIL -- case C (no final pcap): a missing capture read as a disagreement" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "capture-check-regenerate-test: PASS"
