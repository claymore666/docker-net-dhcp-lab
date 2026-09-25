#!/bin/bash
# Mutation cases for wiring-check.sh's unreachable_reason (issue #1). Each
# case is the smallest fixture that reproduces one evasion shape -- an
# anchored grep on the call line alone would pass every one of these,
# the same way it would still pass with the preflight/firewall call in
# up-cell.sh wrapped in each of these. A clean, unconditional call
# (case E) proves the check does not also flag real, reachable calls.
# Cases F and G (round 4) close two more: a "true || \" guard that reads
# like and_guarded's shape but never runs at all, and a function whose
# only apparent caller is itself unreachable, which a single-level
# reachability check would miss.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/wiring-check.sh
. "$REPO_ROOT/scripts/wiring-check.sh"

fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

expect_reason() {
	local name=$1 file=$2 line=$3 want_substr=$4
	local got
	got=$(unreachable_reason "$file" "$line")
	if [ -z "$got" ]; then
		echo "wiring-check-test: FAIL -- $name: expected a reason mentioning \"$want_substr\", got none (evasion was not caught)" >&2
		fail=1
	elif [[ "$got" != *"$want_substr"* ]]; then
		echo "wiring-check-test: FAIL -- $name: expected a reason mentioning \"$want_substr\", got \"$got\"" >&2
		fail=1
	fi
}

expect_clean() {
	local name=$1 file=$2 line=$3
	local got
	got=$(unreachable_reason "$file" "$line")
	if [ -n "$got" ]; then
		echo "wiring-check-test: FAIL -- $name: expected no reason (a real, reachable call), got \"$got\"" >&2
		fail=1
	fi
}

# Case A: a leading "[ ... ] && \" continuation on the line before the
# call. Depth stays 0 (no if/for/while/until/case token), so only
# and_guarded catches it.
caseA="$tmp/caseA.sh"
cat >"$caseA" <<'FIXTURE'
echo unrelated
[ -n "$REPO_ROOT" ] && \
sudo -n "$REPO_ROOT/scripts/thing.sh"
FIXTURE
expect_reason "case A (&& continuation)" "$caseA" 3 '"&&" line-continuation'

# Case B: the call sits inside a function that is never called anywhere
# else in the file.
caseB="$tmp/caseB.sh"
cat >"$caseB" <<'FIXTURE'
unused_wrapper() {
	sudo -n "$REPO_ROOT/scripts/thing.sh"
}
FIXTURE
expect_reason "case B (uncalled function)" "$caseB" 2 'never called'

# Case C: the call sits inside a ": <<'SKIP' ... SKIP" heredoc body,
# the same no-op-comment idiom the repo already guards build-bridge.sh's
# own gate with.
caseC="$tmp/caseC.sh"
cat >"$caseC" <<'FIXTURE'
: <<'SKIP'
sudo -n "$REPO_ROOT/scripts/thing.sh"
SKIP
FIXTURE
expect_reason "case C (heredoc body)" "$caseC" 2 'heredoc block'

# Case D: a plain "if" wrap -- the evasion the wiring check already
# caught before cases A-C were added (kept here as a regression case,
# not new coverage).
caseD="$tmp/caseD.sh"
cat >"$caseD" <<'FIXTURE'
if [ -n "$REPO_ROOT" ]; then
	sudo -n "$REPO_ROOT/scripts/thing.sh"
fi
FIXTURE
expect_reason "case D (if wrap)" "$caseD" 2 'conditional block'

# Case E: a real, unconditional, reachable call, plus a function that
# IS called elsewhere -- proves the four checks above do not also flag
# ordinary, correctly-wired code.
caseE="$tmp/caseE.sh"
cat >"$caseE" <<'FIXTURE'
called_wrapper() {
	sudo -n "$REPO_ROOT/scripts/thing.sh"
}
called_wrapper
sudo -n "$REPO_ROOT/scripts/other.sh"
FIXTURE
expect_clean "case E1 (function that is called)" "$caseE" 2
expect_clean "case E2 (top-level unconditional call)" "$caseE" 5

# Case F: a leading "true || \" continuation on the line before the call.
# Reads like and_guarded's "&&" shape, but the other way round: since
# "true" always succeeds, "||" short-circuits and the call after it
# never runs at all. Depth stays 0 and and_guarded does not match
# (it is "||", not "&&"), so only true_or_guarded catches it.
caseF="$tmp/caseF.sh"
cat >"$caseF" <<'FIXTURE'
echo unrelated
true || \
sudo -n "$REPO_ROOT/scripts/thing.sh"
FIXTURE
expect_reason "case F (true || continuation)" "$caseF" 3 '"true ||" line-continuation'

# Case G: a function whose only apparent caller itself sits inside
# "if false" -- a single-level reachability check finds the call site's
# text and stops there; only a transitive check (this call site is
# itself unreachable, so it does not count) still flags the wrapped
# function as never really called.
caseG="$tmp/caseG.sh"
cat >"$caseG" <<'FIXTURE'
wrapped() {
	sudo -n "$REPO_ROOT/scripts/thing.sh"
}
if false; then
	wrapped
fi
FIXTURE
expect_reason "case G (caller sits in if false)" "$caseG" 2 'never called'

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "wiring-check-test: PASS -- all seven cases behaved as expected"
