#!/bin/bash
# Fixture tests for commit-message-check.sh (issue #3). Runs the real
# script against a throwaway git repo's own commits, never this repo's,
# so a case can carry a disallowed word without ever being a real
# commit here.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fixture_repo="$tmp/repo"
mkdir -p "$fixture_repo"
git init -q "$fixture_repo"
git -C "$fixture_repo" config user.email test@example.invalid
git -C "$fixture_repo" config user.name test
git -C "$fixture_repo" commit -q --allow-empty -m "base commit"
base=$(git -C "$fixture_repo" rev-parse HEAD)

run_case() {
	local desc=$1 subject=$2 body=$3 want=$4 # want: ok | fail
	git -C "$fixture_repo" reset -q --hard "$base"
	if [ -n "$body" ]; then
		git -C "$fixture_repo" commit -q --allow-empty -m "$subject" -m "$body"
	else
		git -C "$fixture_repo" commit -q --allow-empty -m "$subject"
	fi
	if (cd "$fixture_repo" && "$REPO_ROOT/scripts/commit-message-check.sh" "$base..HEAD") >/dev/null 2>&1; then
		got=ok
	else
		got=fail
	fi
	if [ "$got" != "$want" ]; then
		echo "commit-message-check-test: FAIL -- $desc: wanted $want, got $got" >&2
		return 1
	fi
}

fail=0
# A clean subject with no process detail must pass.
run_case "clean commit" "fix: tidy up the lease parser (#3)" "" ok || fail=1
# The existing role-word catch must still work.
run_case "role word: reviewer" "fix: apply the reviewer's note (#3)" "" fail || fail=1
# A short round tag (r-plus-number) must be caught.
run_case "round tag: r3" "fix: address r3 feedback (#3)" "" fail || fail=1
# The same letter-digit shape as part of a longer token must stay clean
# (word-boundary check, not a bare substring match).
run_case "r-plus-digits inside a longer token stays clean" \
	"fix: keep r12ax untouched (#3)" "" ok || fail=1
# The spelled-out phrase must be caught too, not just the short tag.
run_case "review round phrase" "fix: apply the review round's note (#3)" "" fail || fail=1
# A review finding's number on the same line must be caught.
run_case "finding number, same line" "fix: address finding 5 (#3)" "" fail || fail=1
# The reported gap: the number can land on the next line after a wrap.
run_case "finding split across a line break" \
	"fix: tidy the lease parser (#3)" \
	$'note: this addresses finding\n5 raised earlier' fail || fail=1
# The bare word, with no number anywhere on either side, is ordinary
# English and must stay clean.
run_case "finding word alone, no number anywhere" \
	"fix: note a finding worth mentioning (#3)" "" ok || fail=1
# The ordinary English word "round" alone, with no "review" before it,
# must stay clean.
run_case "ordinary prose with the word round" \
	"fix: make the timer round to the nearest second (#3)" "" ok || fail=1

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "commit-message-check-test: PASS -- all 9 cases behaved as expected"
