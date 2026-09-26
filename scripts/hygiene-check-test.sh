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
	local desc=$1 content=$2 want=$3 file=${4:-note.txt} # want: ok | fail
	# Every fixture file this suite ever writes to starts each case clean,
	# so a violation left behind by an earlier case (in a file other than
	# the one this case targets) can never leak forward and contaminate
	# a later "ok" expectation.
	: >"$fixture_repo/note.txt"
	: >"$fixture_repo/verify.sh"
	: >"$fixture_repo/sample_test.go"
	printf '%s' "$content" >"$fixture_repo/$file"
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
# A session agent name or a review-exchange marker must be caught even
# with no address anywhere on the line.
run_case "agent-name marker, no address" \
	$'note: ping lab-rev-z about this\n' fail || fail=1
run_case "exchange marker, no address" \
	$'note: closed at exchange-1\n' fail || fail=1
# Plain "lab" prose must still pass -- only the dashed agent-name shape
# and the exchange-N shape are process detail.
run_case "plain lab prose, no marker" \
	$'note: the lab host reads lab.yaml\n' ok || fail=1
# Role words that name how this project is worked on must be caught,
# each on its own, with no address anywhere on the line.
run_case "role word: lead" \
	$'note: ask the lead about this\n' fail || fail=1
run_case "role word: coordinator" \
	$'note: the coordinator asked for this\n' fail || fail=1
run_case "role word: maintainer" \
	$'note: the maintainer approved it\n' fail || fail=1
run_case "role word: reviewer" \
	$'note: the reviewer held it\n' fail || fail=1
# A word that merely contains a role word as a substring must stay clean
# (word-boundary check, not a bare substring match).
run_case "substring, not a role word" \
	$'note: a leading indent, a leaderboard entry\n' ok || fail=1
# A capitalised role word must be caught too -- the reviewer's own case.
run_case "role word, capitalised" \
	$'Lead and Reviewer agreed this in round 2.\n' fail || fail=1
# verify.sh must no longer be blanket-exempt: the same address and role-
# word violations that are caught in any other file must be caught here.
run_case "verify.sh, address no longer exempt" \
	$'note: host at 192.168.7.7\n' fail verify.sh || fail=1
run_case "verify.sh, agent tag and role word no longer exempt" \
	$'# as the lead asked at exchange-2, ping lab-rev-z\n' fail verify.sh || fail=1
# A line that IS the pattern definition (the marker verify.sh itself
# carries on its process/role-word grep) must stay clean, on a file that
# is otherwise fully scanned. The words are joined by "|", the same
# regex-alternation shape verify.sh's own grep uses, not plain prose.
run_case "verify.sh, marked pattern-literal line stays clean" \
	$'match \\b(lead|coordinator|maintainer|reviewer)\\b # hygiene: pattern literal, not prose\n' \
	ok verify.sh || fail=1
# The same line without the marker is ordinary prose and must be caught.
run_case "verify.sh, same words with no marker" \
	$'match lead coordinator maintainer reviewer\n' fail verify.sh || fail=1
# Prose that merely ends with the exact marker text, with no "|"
# alternation anywhere on the line, must NOT be exempted -- the marker
# on its own used to be enough, and this is exactly the shape that let
# real prose ride through as if it were a pattern literal.
run_case "verify.sh, prose ending with the marker is not exempt" \
	$'match lead coordinator maintainer reviewer # hygiene: pattern literal, not prose\n' \
	fail verify.sh || fail=1
# A review finding's own number must be caught, with no address or role
# word anywhere on the line.
run_case "finding number" \
	$'note: fixed in finding 5\n' fail || fail=1
# A review verdict word, all-caps, must be caught even alone on the line.
run_case "verdict word: HOLD" \
	$'note: the review came back HOLD\n' fail || fail=1
run_case "verdict word: CLEAR" \
	$'note: the review gave a CLEAR\n' fail || fail=1
# The ordinary English verb, lowercase, is not the verdict word and must
# stay clean.
run_case "ordinary prose, not a verdict word" \
	$'note: this fix will hold up, and make the intent clear\n' ok || fail=1
# A private record a public reader cannot open (a handover) and the
# instruction it recorded (a directive) must be caught, each on its
# own, with no address anywhere on the line.
run_case "handover pointer" \
	$'note: recorded in the handover, not reproduced here\n' fail || fail=1
run_case "directive word" \
	$'note: per the directive, drop it\n' fail || fail=1
# A word that merely contains "directive" as a substring must stay
# clean (word-boundary check, not a bare substring match), the same
# shape as the role-word substring case above.
run_case "substring, not the directive word" \
	$'note: reloads a handful of directives but not a new lease\n' ok || fail=1
# A .claude path is never openable by a public reader and must be
# caught as a fixed string, regardless of what precedes or follows it.
run_case ".claude path" \
	$'note: see .claude/tracks/lab.md for background\n' fail || fail=1
# A _test.go fixture legitimately carries a made-up private address for
# its own synthetic data and must still pass -- only the address check
# keeps skipping test files.
run_case "test file, private address only" \
	$'// addr := "192.168.7.7"\n' ok sample_test.go || fail=1
# The same shape of file carrying a role word must now be caught: the
# process/path check no longer skips test files, only the address
# check does -- this is the miss the wrapped "lead directive" leftovers
# in *_test.go slipped through before.
run_case "test file, role word" \
	$'// as the lead noted, this fixture is synthetic\n' fail sample_test.go || fail=1
run_case "test file, handover pointer" \
	$'// (.claude/handover/some-file.md)\n' fail sample_test.go || fail=1

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "hygiene-check-test: PASS -- all 31 cases behaved as expected"
