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

"$REPO_ROOT/scripts/capture-check-regenerate.sh" cellA "$work" >/dev/null

got_clean=$(cat "$work/cellA-bridge-A1-capture-check.txt")
if [[ "$got_clean" != *"clean 4-message exchange"* ]] || [[ "$got_clean" != *"$GOOD_MAC"* ]]; then
	echo "capture-check-regenerate-test: FAIL -- case A (mac present in the capture): expected a clean match, got \"$got_clean\"" >&2
	fail=1
fi

# Case B: a genuine disagreement -- the mac is present in the capture,
# but its own exchange never completes (stops after OFFER). This must
# still read as a real disagreement, not the "absent from the replayed
# capture" error case D below. A separate cell name so it gets its own
# pcap, never touching cellA's.
cp "$DATA/dhcp-stops-after-offer.pcap" "$work/cellPartial.pcap"
echo "capture check deferred to the final pcap, mac $GOOD_MAC" >"$work/cellPartial-macvlan-A14-capture-check.txt"
"$REPO_ROOT/scripts/capture-check-regenerate.sh" cellPartial "$work" >/dev/null

got_disagreement=$(cat "$work/cellPartial-macvlan-A14-capture-check.txt")
if [[ "$got_disagreement" != *"capture disagreement"* ]] || [[ "$got_disagreement" == *"deferred"* ]] || [[ "$got_disagreement" == *"capture check error"* ]]; then
	echo "capture-check-regenerate-test: FAIL -- case B (mac present, exchange incomplete): expected a real disagreement, got \"$got_disagreement\"" >&2
	fail=1
fi

# Case D: the deferred mac never appears in the replayed capture at
# all (the usual cause: a resumed run's capture starts after an
# earlier run's shapes already finished). This is an error, never a
# disagreement -- there is nothing to disagree with.
echo "capture check deferred to the final pcap, mac aa:bb:cc:dd:ee:ff" >"$work/cellA-macvlan-A14-capture-check.txt"
"$REPO_ROOT/scripts/capture-check-regenerate.sh" cellA "$work" >/dev/null
got_absent=$(cat "$work/cellA-macvlan-A14-capture-check.txt")
if [[ "$got_absent" == *"disagreement"* ]] || [[ "$got_absent" == *"deferred"* ]]; then
	echo "capture-check-regenerate-test: FAIL -- case D (mac absent from the replayed capture): expected an error, got \"$got_absent\"" >&2
	fail=1
fi
if [[ "$got_absent" != *"aa:bb:cc:dd:ee:ff"* ]]; then
	echo "capture-check-regenerate-test: FAIL -- case D (mac absent from the replayed capture): expected the mac in the error text, got \"$got_absent\"" >&2
	fail=1
fi

# Case E: a file that already has a real verdict (from an earlier
# regenerate, or written final by some other path) is never rewritten,
# even when replayed against a capture that would produce a different
# reading. Reuses case A's already-clean file.
before=$(cat "$work/cellA-bridge-A1-capture-check.txt")
cp "$DATA/dhcp-wrong-mac.pcap" "$work/cellA.pcap"
"$REPO_ROOT/scripts/capture-check-regenerate.sh" cellA "$work" >/dev/null
after=$(cat "$work/cellA-bridge-A1-capture-check.txt")
if [ "$before" != "$after" ]; then
	echo "capture-check-regenerate-test: FAIL -- case E (already-final file): rewritten, was \"$before\", now \"$after\"" >&2
	fail=1
fi

# Case F: a file that already reads a real disagreement (not the
# deferred marker) is left exactly as it is on replay, written directly
# rather than produced by an earlier regenerate call, since the guard
# must not care how the file got there. cellA.pcap is set to the clean
# fixture first, so a mutant that only recognises the guard's clean text
# would reprocess this file and overwrite it with a clean verdict.
cp "$DATA/dhcp-good.pcap" "$work/cellA.pcap"
echo "capture disagreement for mac $GOOD_MAC: an earlier, unrelated reason" >"$work/cellA-bridge-A2-capture-check.txt"
before_disagreement=$(cat "$work/cellA-bridge-A2-capture-check.txt")
"$REPO_ROOT/scripts/capture-check-regenerate.sh" cellA "$work" >/dev/null
after_disagreement=$(cat "$work/cellA-bridge-A2-capture-check.txt")
if [ "$before_disagreement" != "$after_disagreement" ]; then
	echo "capture-check-regenerate-test: FAIL -- case F (already-final disagreement file): rewritten, was \"$before_disagreement\", now \"$after_disagreement\"" >&2
	fail=1
fi

# Case G: a file that already reads a capture error is left exactly as
# it is on replay too, same reasoning as case F.
echo "capture check error, mac $GOOD_MAC: this mac has no packets in the replayed capture, the capture likely postdates its exchange" >"$work/cellA-bridge-A3-capture-check.txt"
before_error=$(cat "$work/cellA-bridge-A3-capture-check.txt")
"$REPO_ROOT/scripts/capture-check-regenerate.sh" cellA "$work" >/dev/null
after_error=$(cat "$work/cellA-bridge-A3-capture-check.txt")
if [ "$before_error" != "$after_error" ]; then
	echo "capture-check-regenerate-test: FAIL -- case G (already-final error file): rewritten, was \"$before_error\", now \"$after_error\"" >&2
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
