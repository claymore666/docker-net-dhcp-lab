#!/bin/bash
# Fixture tests for pack.sh (issue #4): a throwaway bundle directory per
# case, never the real evidence dir, so a planted violation is never
# itself published.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$REPO_ROOT/scripts/pack.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail=0

# run_case builds bundle_dir/note.txt from $2, runs pack.sh against it
# with $4 as an optional denylist file, and checks the exit against
# want ($3: ok | fail).
run_case() {
	local desc=$1 content=$2 want=$3 denylist=${4:-}
	local case_dir out
	case_dir=$(mktemp -d "$tmp/case-XXXXXX")
	mkdir -p "$case_dir/bundle"
	printf '%s' "$content" >"$case_dir/bundle/note.txt"
	out="$case_dir/out.tar.gz"
	if "$SCRIPT" "$case_dir/bundle" "$out" "$denylist" >/dev/null 2>&1; then
		got=ok
	else
		got=fail
	fi
	if [ "$got" != "$want" ]; then
		echo "pack-test: FAIL -- $desc: wanted $want, got $got" >&2
		return 1
	fi
	if [ "$want" = "ok" ] && [ ! -f "$out" ]; then
		echo "pack-test: FAIL -- $desc: wanted a tarball, none written" >&2
		return 1
	fi
	if [ "$want" = "fail" ] && [ -f "$out" ]; then
		echo "pack-test: FAIL -- $desc: refused case still wrote a tarball" >&2
		return 1
	fi
}

# A clean fixture: no address, no non-lab hostname, packs.
run_case "clean fixture packs" \
	$'result: PASS\nreason: lease confirmed\n' ok || fail=1

# A planted disallowed address must refuse, same range hygiene-check.sh
# itself refuses on -- reused via scripts/hygiene-patterns.sh, not a
# second copy of the pattern.
run_case "planted 192.168.x address refused" \
	$'observed gateway 192.168.7.1\n' fail || fail=1

# A lab-range address must still pass.
run_case "lab-range address, still packs" \
	$'observed gateway 10.200.1.1\n' ok || fail=1

# A journalctl-shaped line whose hostname is not lab-*, the shape a
# plugin journal capture with a real machine name would have.
run_case "non-lab hostname in a journal-shaped line refused" \
	$'Sep 27 10:00:01 realbox dockerd[123]: plugin=abc123 lease granted\n' fail || fail=1

# The same shape, with a lab-generated hostname, must pack.
run_case "lab hostname in a journal-shaped line packs" \
	$'Sep 27 10:00:01 lab-docker-host dockerd[123]: plugin=abc123 lease granted\n' ok || fail=1

# A denylist hit refuses, even with no address and a lab hostname.
deny="$tmp/denylist.txt"
printf '%s\n' "some-other-plugin" >"$deny"
run_case "denylist hit refused" \
	$'note: tested against some-other-plugin for comparison\n' fail "$deny" || fail=1
# The same denylist, no hit, still packs.
run_case "denylist configured, no hit, still packs" \
	$'note: nothing of interest here\n' ok "$deny" || fail=1

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "pack-test: PASS -- all cases behaved as expected"
