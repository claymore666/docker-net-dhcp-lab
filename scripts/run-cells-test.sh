#!/bin/bash
# Tests for run-cells.sh (issue #38). CI-safe: the script runs from a copy
# in a scratch repo root whose run-cell.sh and down-cell.sh are stubs, and
# go, sudo, virsh, docker, df and nproc are stubs on PATH; no libvirt, no
# network, no real cell.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir "$tmp/bin"
cat >"$tmp/bin/sudo" <<'STUB'
#!/bin/bash
[ "${1:-}" = "-n" ] && shift
exec "$@"
STUB
# go run <repo>/cmd/labctl resolve <yaml> <cell>: a fixture file wins,
# else a record whose bridge and addresses are unique to the cell name.
cat >"$tmp/bin/go" <<'STUB'
#!/bin/bash
cell=$5
[ "$cell" = "no-such-cell" ] && exit 1
if [ -f "$LAB_TEST_DIR/resolve.$cell" ]; then
	cat "$LAB_TEST_DIR/resolve.$cell"
	exit 0
fi
idx=$(($(echo -n "$cell" | cksum | cut -d' ' -f1) % 200 + 10))
jq -n --arg c "$cell" --arg d "10.200.255.$idx/24" --arg s "10.200.254.$idx/24" \
	'{cell:{name:$c,segment:{bridge:("lab-br-"+$c)},source:{mgmt_address:$s},docker_host:{mgmt_address:$d}}}'
STUB
cat >"$tmp/bin/virsh" <<'STUB'
#!/bin/bash
[ "$1" = dominfo ] && grep -qxF -- "$2" "$LAB_TEST_DIR/existing" 2>/dev/null
STUB
cat >"$tmp/bin/docker" <<'STUB'
#!/bin/bash
[ "$1" = inspect ] && grep -qxF -- "$2" "$LAB_TEST_DIR/existing" 2>/dev/null
STUB
cat >"$tmp/bin/df" <<'STUB'
#!/bin/bash
echo "Avail"
echo "$(cat "$LAB_TEST_DIR/free_mib" 2>/dev/null || echo 900000)M"
STUB
cat >"$tmp/bin/nproc" <<'STUB'
#!/bin/bash
echo "${LAB_TEST_NPROC:-16}"
STUB
chmod +x "$tmp/bin/"*

# The stand-in for run-cell.sh: logs its argv and start/end times, sleeps
# and exits as the cell's spec file says, marks a TERM and exits 143.
write_stub_run_cell() {
	cat >"$1" <<'STUB'
#!/bin/bash
cell=$1
echo "start $cell $(date +%s%N) $2 $3" >>"$LAB_TEST_DIR/calls.log"
secs=0
rc=0
[ -f "$LAB_TEST_DIR/spec.$cell" ] && read -r secs rc <"$LAB_TEST_DIR/spec.$cell"
trap 'echo term >"$LAB_TEST_DIR/term.$cell"; exit 143' TERM
sleep "$secs" &
wait $!
echo "end $cell $(date +%s%N)" >>"$LAB_TEST_DIR/calls.log"
exit "$rc"
STUB
}
write_stub_down_cell() {
	cat >"$1" <<'STUB'
#!/bin/bash
echo "down $1 $2 evidence=${LAB_EVIDENCE_DIR:-}" >>"$LAB_TEST_DIR/down.log"
echo "down $1 $(date +%s%N)" >>"$LAB_TEST_DIR/calls.log"
STUB
}

# A scratch repo root with a copy of run-cells.sh beside the stubs.
new_env() {
	local d
	d=$(mktemp -d "$tmp/env-XXXXXX")
	mkdir -p "$d/repo/scripts" "$d/state" "$d/root"
	cp "$REPO_ROOT/scripts/run-cells.sh" "$d/repo/scripts/"
	write_stub_run_cell "$d/repo/scripts/run-cell.sh"
	write_stub_down_cell "$d/repo/scripts/down-cell.sh"
	chmod +x "$d/repo/scripts/"*.sh
	: >"$d/repo/lab.yaml"
	: >"$d/state/calls.log"
	: >"$d/state/down.log"
	echo "$d"
}

# cells <env> <args...>: runs run-cells.sh with --root set; prints nothing,
# leaves output in <env>/out and the exit code in <env>/rc.
cells() {
	local d=$1 rc=0
	shift
	LAB_TEST_DIR="$d/state" LAB_MEMINFO="$d/meminfo" PATH="$tmp/bin:$PATH" \
		"$d/repo/scripts/run-cells.sh" --root "$d/root" --stagger 0 "$@" >"$d/out" 2>&1 || rc=$?
	echo "$rc" >"$d/rc"
}

expect() { # name, expected rc, env
	local rc
	rc=$(cat "$3/rc")
	if [ "$rc" != "$2" ]; then
		echo "run-cells-test: FAIL -- $1: exit $rc, wanted $2" >&2
		cat "$3/out" >&2
		fail=1
	fi
}

has() { # name, env, pattern
	if ! grep -qE -- "$3" "$2/out"; then
		echo "run-cells-test: FAIL -- $1: no match for /$3/ in:" >&2
		cat "$2/out" >&2
		fail=1
	fi
}

started() { # env -> number of run-cell calls
	grep -c '^start ' "$1/state/calls.log" || true
}

meminfo() { printf 'MemAvailable: %d kB\n' $(($2 * 1048576)) >"$1/meminfo"; }

# Case 1: the same cell twice. Refuses, names the duplicate, starts nothing.
e=$(new_env)
meminfo "$e" 60
cells "$e" --check kea kea
expect "case 1 (same cell twice)" 1 "$e"
has "case 1" "$e" "REFUSED -- duplicate cell name 'kea'"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 1: a cell was started" >&2; fail=1; }
cells "$e" kea kea
expect "case 1b (same cell twice, no --check)" 1 "$e"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 1b: a cell was started" >&2; fail=1; }

# Case 2: two cells whose observer veth hashes collide. cell394 and
# cell676 share the first five md5 hex characters (found offline).
h1=$(echo -n cell394 | md5sum | cut -c1-5)
h2=$(echo -n cell676 | md5sum | cut -c1-5)
if [ "$h1" != "$h2" ]; then
	echo "run-cells-test: FAIL -- case 2: fixture pair no longer collides ($h1 $h2)" >&2
	fail=1
fi
e=$(new_env)
meminfo "$e" 60
cells "$e" --check cell394 cell676
expect "case 2 (veth collision)" 1 "$e"
has "case 2" "$e" "REFUSED -- duplicate observer veth 'veth-obs-${h1}h' \(cells cell394 and cell676\)"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 2: a cell was started" >&2; fail=1; }

# Case 3: shared bridge, shared management address, a docker host address
# equal to another cell's source address: each refuses and names it.
e=$(new_env)
meminfo "$e" 60
for c in alpha beta; do
	jq -n '{cell:{segment:{bridge:"lab-br-shared"},source:{mgmt_address:"10.200.254.5/24"},docker_host:{mgmt_address:"10.200.255.9/24"}}}' >"$e/state/resolve.$c"
done
cells "$e" --check alpha beta
expect "case 3 (shared bridge and addresses)" 1 "$e"
has "case 3 bridge" "$e" "duplicate bridge 'lab-br-shared'"
has "case 3 address" "$e" "duplicate management address '10.200.255.9'"
e=$(new_env)
meminfo "$e" 60
jq -n '{cell:{segment:{bridge:"lab-br-x"},source:{mgmt_address:"10.200.255.7/24"},docker_host:{mgmt_address:"10.200.255.6/24"}}}' >"$e/state/resolve.x"
jq -n '{cell:{segment:{bridge:"lab-br-y"},source:{mgmt_address:"10.200.255.8/24"},docker_host:{mgmt_address:"10.200.255.7/24"}}}' >"$e/state/resolve.y"
cells "$e" --check x y
expect "case 3b (docker host address equals another cell's source)" 1 "$e"
has "case 3b" "$e" "duplicate management address '10.200.255.7'"

# Case 4: a domain, then an observer container, already on the host.
e=$(new_env)
meminfo "$e" 60
echo "lab-kea-dockerhost" >"$e/state/existing"
cells "$e" kea dnsmasq
expect "case 4 (domain exists)" 1 "$e"
has "case 4" "$e" "REFUSED -- domain lab-kea-dockerhost already exists"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 4: a cell was started" >&2; fail=1; }
e=$(new_env)
meminfo "$e" 60
echo "lab-observer-dnsmasq" >"$e/state/existing"
cells "$e" kea dnsmasq
expect "case 4b (observer exists)" 1 "$e"
has "case 4b" "$e" "REFUSED -- observer container lab-observer-dnsmasq already exists"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 4b: a cell was started" >&2; fail=1; }

e=$(new_env)
meminfo "$e" 60
echo "lab-dnsmasq-source" >"$e/state/existing"
cells "$e" kea dnsmasq
expect "case 4c (source domain exists)" 1 "$e"
has "case 4c" "$e" "REFUSED -- domain lab-dnsmasq-source already exists"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 4c: a cell was started" >&2; fail=1; }
e=$(new_env)
meminfo "$e" 60
echo "lab-kea-ha-partner" >"$e/state/existing"
cells "$e" kea kea-ha
expect "case 4d (failover partner domain exists)" 1 "$e"
has "case 4d" "$e" "REFUSED -- domain lab-kea-ha-partner already exists"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 4d: a cell was started" >&2; fail=1; }

# A relay VM left by an earlier run of a relay cell (#11).
e=$(new_env)
meminfo "$e" 60
echo "lab-dnsmasq-relay" >"$e/state/existing"
cells "$e" kea dnsmasq
expect "case 4d (relay domain exists)" 1 "$e"
has "case 4d" "$e" "REFUSED -- domain lab-dnsmasq-relay already exists"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 4d: a cell was started" >&2; fail=1; }

# Case 5: a cell that lab.yaml does not know refuses before any start,
# even when it comes after cells that would have been fine.
e=$(new_env)
meminfo "$e" 60
cells "$e" kea no-such-cell
expect "case 5 (unknown cell)" 1 "$e"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 5: a cell was started" >&2; fail=1; }

# Case 6: --check with distinct cells prints the table, exits 0, starts nothing.
e=$(new_env)
meminfo "$e" 60
cells "$e" --check kea dnsmasq
expect "case 6 (--check passes)" 0 "$e"
has "case 6" "$e" "^kea +lab-br-kea "
has "case 6" "$e" "^dnsmasq +lab-br-dnsmasq "
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 6: --check started a cell" >&2; fail=1; }

# Case 7: the paths handed to run-cell.sh are <root>/work/<cell> and
# <root>/evidence/<cell>, absolute even for a relative --root; evidence
# is never inside work.
e=$(new_env)
meminfo "$e" 60
(
	cd "$e"
	LAB_TEST_DIR="$e/state" LAB_MEMINFO="$e/meminfo" PATH="$tmp/bin:$PATH" \
		"$e/repo/scripts/run-cells.sh" --root rel-root --stagger 0 kea >"$e/out" 2>&1
) || {
	echo "run-cells-test: FAIL -- case 7: run failed" >&2
	cat "$e/out" >&2
	fail=1
}
got=$(awk '$1=="start"{print $2, $4, $5}' "$e/state/calls.log")
if [ "$got" != "kea $e/rel-root/work/kea $e/rel-root/evidence/kea" ]; then
	echo "run-cells-test: FAIL -- case 7: run-cell.sh was handed '$got', wanted <root>/work/kea and <root>/evidence/kea:" >&2
	fail=1
fi

# Case 8: one failure does not stop the pool; the wrapper exits 1 and the
# table lists every rc. A stale rc file from an earlier run is not read.
e=$(new_env)
meminfo "$e" 60
echo "1 1" >"$e/state/spec.a"
echo "0 0" >"$e/state/spec.b"
echo "0 0" >"$e/state/spec.c"
mkdir -p "$e/root/logs"
echo 7 >"$e/root/logs/b.rc"
cells "$e" -j 2 a b c
expect "case 8 (one failure)" 1 "$e"
[ "$(started "$e")" -eq 3 ] || { echo "run-cells-test: FAIL -- case 8: expected three cells started" >&2; fail=1; }
has "case 8 a" "$e" "^a +1 "
has "case 8 b" "$e" "^b +0 "
has "case 8 c" "$e" "^c +0 "
if [ "$(cat "$e/root/logs/a.rc")" != 1 ] || [ "$(cat "$e/root/logs/b.rc")" != 0 ]; then
	echo "run-cells-test: FAIL -- case 8: rc files are not this run's results" >&2
	fail=1
fi

# Case 9: the pool never runs more than -j at once. Five one-second cells
# at -j 2: from the recorded times, never three overlapping, and the third
# start is not before the first end.
e=$(new_env)
meminfo "$e" 60
for c in a b c d f; do echo "1 0" >"$e/state/spec.$c"; done
cells "$e" -j 2 a b c d f
expect "case 9 (pool bound)" 0 "$e"
max=$(awk '$1=="start"{print $3, 1} $1=="end"{print $3, -1}' "$e/state/calls.log" | sort -k1,1n -k2,2n | awk '{n+=$2; if (n>m) m=n} END{print m+0}')
if [ "$max" -ne 2 ]; then
	echo "run-cells-test: FAIL -- case 9: peak overlap $max, wanted exactly 2" >&2
	fail=1
fi
third=$(awk '$1=="start"{print $3}' "$e/state/calls.log" | sort -n | sed -n 3p)
first_end=$(awk '$1=="end"{print $3}' "$e/state/calls.log" | sort -n | sed -n 1p)
if [ "$third" -lt "$first_end" ]; then
	echo "run-cells-test: FAIL -- case 9: third start before the first end" >&2
	fail=1
fi

# Case 10: -j rules. Default from cpu and memory, never below 1, never
# above the cell count; an explicit -j above the bound says overcommit.
e=$(new_env)
meminfo "$e" 60
LAB_TEST_NPROC=8 cells "$e" --check a b c
has "case 10 cpu bound" "$e" "-j 2 \(cells 3; cpu bound 2 from 8 vCPU"
meminfo "$e" 10
cells "$e" --check a b c
has "case 10 memory bound" "$e" "-j 2 \(cells 3; cpu bound 4 from 16 vCPU, memory bound 2 from 10 GiB"
LAB_TEST_NPROC=2 cells "$e" --check a b
has "case 10 floor" "$e" "-j 1 \("
meminfo "$e" 60
cells "$e" --check a
has "case 10 cell cap" "$e" "-j 1 \(cells 1;"
cells "$e" -j 6 --check a b c
has "case 10 overcommit" "$e" "overcommit -- -j 6 is above the computed bound 4"
cells "$e" -j 0 a
expect "case 10 -j 0" 2 "$e"
cells "$e" -j two a
expect "case 10 -j text" 2 "$e"
cells "$e" '../etc'
expect "case 10 bad cell name" 2 "$e"
cells "$e"
expect "case 10 no cells" 2 "$e"

# Case 11: disk guard. Below the bound a cell is skipped-disk, run-cell.sh
# is not called, the wrapper exits 1. A disk that frees up mid-wait lets
# the cell start.
e=$(new_env)
meminfo "$e" 60
echo 1000 >"$e/state/free_mib"
LAB_DISK_WAIT=2 LAB_DISK_POLL=1 cells "$e" a
expect "case 11 (disk low)" 1 "$e"
has "case 11" "$e" "^a +skipped-disk "
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 11: run-cell.sh was called under the disk bound" >&2; fail=1; }
[ "$(cat "$e/root/logs/a.rc")" = skipped-disk ] || { echo "run-cells-test: FAIL -- case 11: rc file is not skipped-disk" >&2; fail=1; }
e=$(new_env)
meminfo "$e" 60
echo 1000 >"$e/state/free_mib"
(
	sleep 1
	echo 900000 >"$e/state/free_mib"
) &
freer=$!
LAB_DISK_WAIT=20 LAB_DISK_POLL=1 cells "$e" a
wait "$freer"
expect "case 11b (disk frees up)" 0 "$e"
[ "$(started "$e")" -eq 1 ] || { echo "run-cells-test: FAIL -- case 11b: the cell did not start once the disk freed up" >&2; fail=1; }
e=$(new_env)
meminfo "$e" 60
echo 14336 >"$e/state/free_mib"
LAB_DISK_WAIT=1 LAB_DISK_POLL=1 cells "$e" a
expect "case 11c (one MiB-step under 15 GiB)" 1 "$e"
echo 15360 >"$e/state/free_mib"
cells "$e" a
expect "case 11d (exactly 15 GiB)" 0 "$e"

# Case 12: TERM to the wrapper reaches every running cell, the wrapper
# waits for them, runs down-cell.sh for exactly the cells that were
# started and had not finished, and exits 130. a and c run long, b has
# already finished by the time the signal arrives.
e=$(new_env)
meminfo "$e" 60
echo "30 0" >"$e/state/spec.a"
echo "0 0" >"$e/state/spec.b"
echo "30 0" >"$e/state/spec.c"
t0=$SECONDS
(
	LAB_TEST_DIR="$e/state" LAB_MEMINFO="$e/meminfo" PATH="$tmp/bin:$PATH" \
		exec "$e/repo/scripts/run-cells.sh" --root "$e/root" --stagger 0 -j 2 a b c >"$e/out" 2>&1
) &
wpid=$!
n=0
until grep -q '^start c ' "$e/state/calls.log" && grep -q '^start a ' "$e/state/calls.log"; do
	n=$((n + 1))
	if [ "$n" -gt 100 ]; then
		echo "run-cells-test: FAIL -- case 12: cells a and c never started" >&2
		break
	fi
	sleep 0.1
done
kill -TERM "$wpid"
wrc=0
wait "$wpid" || wrc=$?
if [ "$wrc" -ne 130 ]; then
	echo "run-cells-test: FAIL -- case 12: exit $wrc, wanted 130" >&2
	cat "$e/out" >&2
	fail=1
fi
for c in a c; do
	[ -f "$e/state/term.$c" ] || { echo "run-cells-test: FAIL -- case 12: the TERM did not reach cell $c" >&2; fail=1; }
done
[ ! -f "$e/state/term.b" ] || { echo "run-cells-test: FAIL -- case 12: cell b got a TERM after it had finished" >&2; fail=1; }
if [ "$(sort "$e/state/down.log")" != "$(printf 'down a %s evidence=%s\ndown c %s evidence=%s' "$e/root/work/a" "$e/root/evidence/a" "$e/root/work/c" "$e/root/evidence/c")" ]; then
	echo "run-cells-test: FAIL -- case 12: down-cell.sh was not run for exactly a and c:" >&2
	cat "$e/state/down.log" >&2
	fail=1
fi
has "case 12 table" "$e" "^a +terminated "
has "case 12 table" "$e" "^b +0 "
if [ $((SECONDS - t0)) -ge 8 ]; then
	echo "run-cells-test: FAIL -- case 12: took $((SECONDS - t0)) s; the wrapper waited out the 30 s cells" >&2
	fail=1
fi

# Case 13: a TERM during the disk wait ends the wait at once.
e=$(new_env)
meminfo "$e" 60
echo 1000 >"$e/state/free_mib"
t0=$SECONDS
(
	LAB_TEST_DIR="$e/state" LAB_MEMINFO="$e/meminfo" PATH="$tmp/bin:$PATH" LAB_DISK_WAIT=300 LAB_DISK_POLL=100 \
		exec "$e/repo/scripts/run-cells.sh" --root "$e/root" --stagger 0 a >"$e/out" 2>&1
) &
wpid=$!
n=0
until grep -q 'want 15; waiting' "$e/out" 2>/dev/null; do
	n=$((n + 1))
	[ "$n" -gt 100 ] && break
	sleep 0.1
done
kill -TERM "$wpid"
wrc=0
wait "$wpid" || wrc=$?
if [ "$wrc" -ne 130 ] || [ $((SECONDS - t0)) -ge 20 ]; then
	echo "run-cells-test: FAIL -- case 13: exit $wrc after $((SECONDS - t0)) s; wanted 130 well before the 100 s poll" >&2
	cat "$e/out" >&2
	fail=1
fi

# Case 14: an rc file from an earlier run is gone the moment its cell
# starts again, so a wrapper that dies mid-run never leaves a stale result
# standing for this run.
e=$(new_env)
meminfo "$e" 60
echo "3 0" >"$e/state/spec.a"
mkdir -p "$e/root/logs"
echo 7 >"$e/root/logs/a.rc"
(
	LAB_TEST_DIR="$e/state" LAB_MEMINFO="$e/meminfo" PATH="$tmp/bin:$PATH" \
		exec "$e/repo/scripts/run-cells.sh" --root "$e/root" --stagger 0 a >"$e/out" 2>&1
) &
wpid=$!
n=0
until grep -q '^start a ' "$e/state/calls.log"; do
	n=$((n + 1))
	[ "$n" -gt 100 ] && break
	sleep 0.1
done
if [ -f "$e/root/logs/a.rc" ]; then
	echo "run-cells-test: FAIL -- case 14: the previous run's rc file is still there while the cell runs" >&2
	fail=1
fi
wait "$wpid" || true
[ "$(cat "$e/root/logs/a.rc")" = 0 ] || { echo "run-cells-test: FAIL -- case 14: final rc file is not 0" >&2; fail=1; }

# Case 15: a queued cell whose domain appears on the host after the
# up-front check is not started; the table names it and the wrapper exits 1.
e=$(new_env)
meminfo "$e" 60
echo "2 0" >"$e/state/spec.a"
(
	LAB_TEST_DIR="$e/state" LAB_MEMINFO="$e/meminfo" PATH="$tmp/bin:$PATH" \
		exec "$e/repo/scripts/run-cells.sh" --root "$e/root" --stagger 0 -j 1 a b >"$e/out" 2>&1
) &
wpid=$!
n=0
until grep -q '^start a ' "$e/state/calls.log"; do
	n=$((n + 1))
	[ "$n" -gt 100 ] && break
	sleep 0.1
done
echo "lab-b-dockerhost" >"$e/state/existing"
wrc=0
wait "$wpid" || wrc=$?
[ "$wrc" -eq 1 ] || { echo "run-cells-test: FAIL -- case 15: exit $wrc, wanted 1" >&2; fail=1; }
if grep -q '^start b ' "$e/state/calls.log"; then
	echo "run-cells-test: FAIL -- case 15: b was started over a domain that appeared while it waited" >&2
	fail=1
fi
has "case 15 table" "$e" "^b +skipped-exists "
has "case 15 message" "$e" "domain lab-b-dockerhost already exists"
[ "$(cat "$e/root/logs/b.rc")" = skipped-exists ] || { echo "run-cells-test: FAIL -- case 15: b.rc is not skipped-exists" >&2; fail=1; }

# Case 16: the real run-cell.sh has no signal trap. A stand-in without one,
# whose child would outlive it, must still lose that child on a TERM to the
# wrapper (the group kill; without setsid only the stand-in itself dies).
e=$(new_env)
meminfo "$e" 60
cat >"$e/repo/scripts/run-cell.sh" <<'STUB'
#!/bin/bash
sleep 30 &
echo $! >"$LAB_TEST_DIR/child.$1"
wait
STUB
chmod +x "$e/repo/scripts/run-cell.sh"
(
	LAB_TEST_DIR="$e/state" LAB_MEMINFO="$e/meminfo" PATH="$tmp/bin:$PATH" \
		exec "$e/repo/scripts/run-cells.sh" --root "$e/root" --stagger 0 a >"$e/out" 2>&1
) &
wpid=$!
n=0
until [ -s "$e/state/child.a" ]; do
	n=$((n + 1))
	[ "$n" -gt 100 ] && break
	sleep 0.1
done
child=$(cat "$e/state/child.a" 2>/dev/null || true)
kill -TERM "$wpid"
wrc=0
wait "$wpid" || wrc=$?
sleep 0.3
if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
	echo "run-cells-test: FAIL -- case 16: the cell's child $child outlived the TERM" >&2
	kill -KILL "$child" 2>/dev/null || true
	fail=1
fi
[ -n "$child" ] || { echo "run-cells-test: FAIL -- case 16: the stand-in never started" >&2; fail=1; }

# Case 17: --stagger puts a gap between launches, asserted as call order
# against a stub sleep that logs "gap" for the stagger-sized value and
# returns once the start before it is logged; no wall time is measured. 100 s keeps the remaining
# gap (100 or 99, depending on the second boundary) apart from every
# other sleep the wrapper and the stubs make.
mkdir "$tmp/gapbin"
cat >"$tmp/gapbin/sleep" <<STUB
#!/bin/bash
case "\$1" in
[5-9][0-9] | 1[0-9][0-9])
	# the cell stub logs its start from the background: wait for the
	# start this gap follows, or the log order says nothing
	for _ in \$(seq 1 100); do
		[ "\$(grep -c '^start ' "\$LAB_TEST_DIR/calls.log")" -gt "\$(grep -c '^gap ' "\$LAB_TEST_DIR/calls.log")" ] && break
		$(command -v sleep) 0.05
	done
	echo "gap \$1" >>"\$LAB_TEST_DIR/calls.log"
	exit 0
	;;
esac
exec $(command -v sleep) "\$@"
STUB
chmod +x "$tmp/gapbin/sleep"
order() { awk '$1=="start"||$1=="gap"{print $1}' "$1/state/calls.log" | tr '\n' ' '; }
gapped() { # env, args...: like cells, with the gap stub first on PATH
	local d=$1 rc=0
	shift
	LAB_TEST_DIR="$d/state" LAB_MEMINFO="$d/meminfo" PATH="$tmp/gapbin:$tmp/bin:$PATH" \
		"$d/repo/scripts/run-cells.sh" --root "$d/root" "$@" >"$d/out" 2>&1 || rc=$?
	echo "$rc" >"$d/rc"
}
e=$(new_env)
meminfo "$e" 60
gapped "$e" --stagger 100 -j 3 a b c
expect "case 17 (stagger)" 0 "$e"
[ "$(order "$e")" = "start gap start gap start " ] || { echo "run-cells-test: FAIL -- case 17: order is '$(order "$e")', wanted start gap start gap start (no gap before the first or after the last)" >&2; fail=1; }
e=$(new_env)
meminfo "$e" 60
gapped "$e" -j 2 a b
expect "case 17b (default stagger)" 0 "$e"
[ "$(order "$e")" = "start gap start " ] || { echo "run-cells-test: FAIL -- case 17b: no gap with the default --stagger: '$(order "$e")'" >&2; fail=1; }
grep -qE '^gap (59|60)$' "$e/state/calls.log" || { echo "run-cells-test: FAIL -- case 17b: the default gap is not 60 s" >&2; fail=1; }
e=$(new_env)
meminfo "$e" 60
gapped "$e" --stagger 0 -j 3 a b c
expect "case 17c (stagger 0)" 0 "$e"
[ "$(order "$e")" = "start start start " ] || { echo "run-cells-test: FAIL -- case 17c: --stagger 0 still leaves a gap: '$(order "$e")'" >&2; fail=1; }
for bad in -5 x 1.5 ""; do
	e=$(new_env)
	meminfo "$e" 60
	cells "$e" --stagger "$bad" a
	expect "case 17d (--stagger '$bad')" 2 "$e"
	has "case 17d" "$e" "REFUSED -- --stagger wants a non-negative integer"
done

# Case 18: a cell whose run-cell.sh exits non-zero is torn down at once,
# through down-cell.sh with its evidence dir, logged in its own cell log;
# a cell that exits 0 is not, and the other cell keeps running meanwhile.
e=$(new_env)
meminfo "$e" 60
echo "0 1" >"$e/state/spec.a"
cells "$e" -j 2 a b
expect "case 18 (a fails, b passes)" 1 "$e"
want=$(printf 'down a %s evidence=%s' "$e/root/work/a" "$e/root/evidence/a")
[ "$(cat "$e/state/down.log")" = "$want" ] || { echo "run-cells-test: FAIL -- case 18: down.log is not exactly the failed cell:" >&2; cat "$e/state/down.log" >&2; fail=1; }
grep -q 'tearing down a' "$e/root/logs/a.log" || { echo "run-cells-test: FAIL -- case 18: the teardown is not logged in a's cell log" >&2; fail=1; }
if grep -q 'tearing down' "$e/root/logs/b.log"; then echo "run-cells-test: FAIL -- case 18: b (rc 0) was torn down" >&2; fail=1; fi
e=$(new_env)
meminfo "$e" 60
cells "$e" -j 2 a b
expect "case 18b (both pass)" 0 "$e"
[ ! -s "$e/state/down.log" ] || { echo "run-cells-test: FAIL -- case 18b: a cell that exited 0 was torn down" >&2; fail=1; }
e=$(new_env)
meminfo "$e" 60
echo "0 1" >"$e/state/spec.a"
echo "3 0" >"$e/state/spec.b"
cells "$e" -j 2 a b
got=$(awk '$1=="end"||$1=="down"{print $1, $2}' "$e/state/calls.log" | tr '\n' ',')
[ "$got" = "end a,down a,end b," ] || { echo "run-cells-test: FAIL -- case 18c: the failed cell waited for the other: '$got'" >&2; fail=1; }

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "run-cells-test: PASS -- all cases behaved as expected"
