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
cp "$REPO_ROOT/scripts/hygiene-patterns.sh" "$fixture_repo/scripts/hygiene-patterns.sh"

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
# 172.16.0.0/16 is not one of Docker's default bridge pools
# (172.17.0.0/16 through 172.31.0.0/16) and must stay refused; the
# first pool Docker actually hands out must still pass.
run_case "172.16.x address, not a docker default pool, refused" \
	$'note: two networks: 172.16.0.2 plus the lease\n' fail || fail=1
run_case "172.17.x address, a real docker default pool, packs" \
	$'note: two networks: 172.17.0.2 plus the lease\n' ok || fail=1
# The ULA is exactly fd42:200::/48 (#23 group D): another /48 that only
# shares the leading characters is refused, every form inside it allowed.
run_case "ULA, different /48 sharing a prefix string, refused" \
	$'note: fd42:2001::1\n' fail || fail=1
run_case "ULA, different /48 in the third group, refused" \
	$'note: fd42:200:1::1\n' fail || fail=1
run_case "ULA, cell segment address, allowed" \
	$'note: fd42:200:0:300::2\n' ok || fail=1
run_case "ULA, the /48 itself, allowed" \
	$'note: ula_prefix "fd42:200::/48"\n' ok || fail=1
run_case "ULA, zero third group with leading zeros, allowed" \
	$'note: fd42:200:0000:100::1\n' ok || fail=1
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
# A citation to an internal decision a public reader cannot resolve
# ("ruling item N") is the same dead-reference shape a role word is,
# and must be caught the same way.
run_case "internal citation: ruling" \
	$'note: fixed per ruling item 3\n' fail || fail=1
# A word that merely contains a role word as a substring must stay clean
# (word-boundary check, not a bare substring match).
run_case "substring, not a role word" \
	$'note: a leading indent, a leaderboard entry\n' ok || fail=1
run_case "substring, not the ruling word" \
	$'note: overruling a previous decision\n' ok || fail=1
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
# The same path, differently cased, is the same private path and must be
# caught too -- a plain case-sensitive fixed-string match let a
# capitalised or all-caps rendering of the path through uncaught.
run_case ".claude path, different case" \
	$'note: see .CLAUDE/tracks/lab.md for background\n' fail || fail=1
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
# commit-message-check-test.sh is the same shape of file as
# hygiene-check-test.sh itself: a fixture suite that deliberately
# carries disallowed-looking strings inside a throwaway git repo it
# builds at run time, never a real commit here. It needs the same
# blanket exemption hygiene-check.sh already gives its own fixture
# file, or its own fixtures trip this check just by existing.
run_case "commit-message-check-test.sh, role word, exempt" \
	$'run_case "x" "fix: apply the reviewer note" "" fail\n' ok scripts/commit-message-check-test.sh || fail=1
# A review-round label ("review r1") must be caught even with no other
# marker on the line -- the shape a review finding's fix comment used
# to cite itself with (issue #3).
run_case "review-round label" \
	$'// found gone (issue #3, review r1)\n' fail || fail=1
# The bare "fix round" phrase, the shape a pack.sh comment used to
# carry, must be caught too, with no other marker on the line.
run_case "fix round phrase" \
	$'// fixed for new runs, issue #4 fix round\n' fail || fail=1
# The bare "the review" stand-in for the process itself must be caught
# too, the same leftover shape ("the review's own F1 requirement").
run_case "the review, bare phrase" \
	$'// that is the review'"'"'s own requirement\n' fail || fail=1
# A finding cited by its short label ("F2"), all-caps, must be caught
# even alone on the line, with no other marker present.
run_case "finding citation, short label" \
	$'// pool (F2, issue #3)\n' fail || fail=1
# The ordinary, always-lowercase shell flag shape this codebase itself
# uses (cut -d: -fN, the same idiom verify.sh and demo-source-cell.sh
# run live) must stay clean -- only the all-caps finding label is
# process detail, never a field-selector flag.
run_case "cut field flag, not a finding label" \
	$'line=$(grep -n x f | cut -d: -f1)\n' ok || fail=1
run_case "cut field flag 2, not a finding label" \
	$'field=$(cut -d: -f2 <<<"$x")\n' ok || fail=1
# A word that merely contains an uppercase F immediately after a
# non-word character but with no digit run long enough to look like a
# citation stays clean too (word-boundary + digit-run check, not a bare
# substring match) -- an uppercase hex/flag shape, not a finding label.
run_case "uppercase F, no digit, not a finding label" \
	$'note: use -F as the field separator\n' ok || fail=1

# Group F scenario IDs (#20): the catalog name and a README table row's
# first cell are product names and stay clean; a citation in prose, also
# one later on a table row, stays caught.
run_case "scenario name constant, not a finding label" \
	$'NameF1 = "F1-user-class-pool"\n' ok || fail=1
run_case "scenario table row, not a finding label" \
	$'| F2a | IPv6-only preferred, not asked for | what it does |\n' ok || fail=1
run_case "prose citation beside a scenario name" \
	$'// see F2 for why "F1-user-class-pool" differs\n' fail || fail=1
run_case "finding citation inside a table row" \
	$'| F1 | user class pool | fixed as F3 asked |\n' fail || fail=1
run_case "hyphenated finding citation in prose" \
	$'// the F2-finding stays open\n' fail || fail=1
run_case "finding citation as a table first cell" \
	$'| F3 | fixed as asked |\n' fail || fail=1
run_case "a table row head that is not a scenario" \
	$'| F3 | something else | text |\n' fail || fail=1
run_case "finding citation after a hyphen-less ID" \
	$'// the F3 requirement\n' fail || fail=1

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "hygiene-check-test: PASS -- all 52 cases behaved as expected"
