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

# An empty denylist file: every "ok" case below packs against this one,
# so each exercises the real, required denylist path rather than an
# empty argument standing in for "no check".
deny="$tmp/denylist.txt"
printf '%s\n' "some-other-plugin-name" >"$deny"

# run_case builds bundle_dir/<name> ($5, default note.txt) from $2, runs
# pack.sh against it with $4 as the denylist file (default: the
# empty-hit one above; a $4 explicitly passed as "" stays empty rather
# than falling back, so the no-denylist case below can actually ask for
# that), and checks the exit against want ($3: ok | fail). "${4-$deny}"
# (no colon) is deliberate: bash's ":-" also substitutes on an explicit
# empty string, which would make that case impossible to write.
run_case() {
	local desc=$1 content=$2 want=$3 denylist=${4-$deny} name=${5:-note.txt}
	local case_dir out
	case_dir=$(mktemp -d "$tmp/case-XXXXXX")
	mkdir -p "$case_dir/bundle"
	printf '%s' "$content" >"$case_dir/bundle/$name"
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

# Docker's own default bridge range and Kea's stock example config
# range are both harmless noise, never LAN detail, and must still pack.
run_case "docker bridge address, still packs" \
	$'two networks: 172.18.0.2 plus the lease\n' ok || fail=1
run_case "kea stock example config address, still packs" \
	$'"data": "10.1.1.202, 10.1.1.203"\n' ok || fail=1

# A journalctl-shaped line whose hostname is not lab-*, the shape a
# plugin journal capture with a real machine name would have.
run_case "non-lab hostname in a journal-shaped line refused" \
	$'Sep 27 10:00:01 realbox dockerd[123]: plugin=abc123 lease granted\n' fail || fail=1

# The same shape, with a lab-generated hostname, must pack.
run_case "lab hostname in a journal-shaped line packs" \
	$'Sep 27 10:00:01 lab-docker-host dockerd[123]: plugin=abc123 lease granted\n' ok || fail=1

# A denylist hit refuses, even with no address and a lab hostname.
run_case "denylist hit refused" \
	$'note: tested against some-other-plugin-name for comparison\n' fail || fail=1
# The same denylist, no hit, still packs.
run_case "denylist configured, no hit, still packs" \
	$'note: nothing of interest here\n' ok || fail=1

# No denylist at all -- neither a third argument nor LAB_PACK_DENYLIST
# -- must refuse: a release pack never passes with that check missing.
run_case "no denylist given refuses" \
	$'note: nothing of interest here\n' fail "" || fail=1

# A denylist path that names no real file must refuse the same way, not
# silently skip the check as though none had been given.
run_case "denylist path that does not exist refuses" \
	$'note: nothing of interest here\n' fail "$tmp/does-not-exist.txt" || fail=1

# An evidence line already relative to the bundle is left alone and
# still packs; one naming a real path elsewhere on the filesystem
# (never inside this bundle) is a leak of the host's own layout and
# refuses the whole pack. Written into a *.verdict-named file: the
# rewrite pack.sh does only reads that file shape, same as a real run.
run_case "relative evidence path packs" \
	$'evidence.leases_after: leases.txt\n' ok "$deny" "test.verdict" || fail=1
run_case "evidence path outside the bundle refused" \
	$'evidence.leases_after: /elsewhere/leases.txt\n' fail "$deny" "test.verdict" || fail=1

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "pack-test: PASS -- all cases behaved as expected"
