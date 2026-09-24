#!/bin/bash
# Fixture tests for hygiene-check.sh (issue #1). Runs the real script
# against a throwaway git repo, never the working tree, so a case can
# carry a disallowed address without ever being published itself.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fixture_repo="$tmp/repo"
mkdir -p "$fixture_repo/scripts"
git init -q "$fixture_repo"
git -C "$fixture_repo" config user.email test@example.invalid
git -C "$fixture_repo" config user.name test
cp "$REPO_ROOT/scripts/hygiene-check.sh" "$fixture_repo/scripts/hygiene-check.sh"

run_case() {
	local desc=$1 content=$2 want=$3 # want: ok | fail
	printf '%s' "$content" >"$fixture_repo/note.txt"
	git -C "$fixture_repo" add -A
	if (cd "$fixture_repo" && ./scripts/hygiene-check.sh) >/dev/null 2>&1; then
		got=ok
	else
		got=fail
	fi
	if [ "$got" != "$want" ]; then
		echo "hygiene-check-test: FAIL -- $desc: wanted $want, got $got" >&2
		return 1
	fi
}

fail=0
# The reported bug: a disallowed address on the file's last line, with no
# trailing newline, must still be caught.
run_case "disallowed address, no trailing newline" \
	$'note: host at 192.168.7.7' fail || fail=1
# Same address, same line, but with the trailing newline the original
# code already handled -- must stay caught.
run_case "disallowed address, with trailing newline" \
	$'note: host at 192.168.7.7\n' fail || fail=1
# A lab-range address must still pass, on both an unterminated and a
# terminated last line.
run_case "lab-range address, no trailing newline" \
	$'note: host at 10.200.1.1' ok || fail=1
run_case "lab-range address, with trailing newline" \
	$'note: host at 10.200.1.1\n' ok || fail=1
# No candidate address at all.
run_case "no address" $'note: nothing here\n' ok || fail=1

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "hygiene-check-test: PASS -- all 5 cases behaved as expected"
