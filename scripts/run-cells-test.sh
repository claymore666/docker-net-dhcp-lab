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
k=$(grep -c "^start $cell " "$LAB_TEST_DIR/calls.log")
# what labctl remaining would see: the verdicts in the evidence dir at start
find "$3" -maxdepth 1 -name '*.verdict' 2>/dev/null | wc -l >"$LAB_TEST_DIR/verdicts-at-start.$cell.$k"
secs=0
rc=0
[ -f "$LAB_TEST_DIR/spec.$cell" ] && read -r secs rc <"$LAB_TEST_DIR/spec.$cell"
[ -f "$LAB_TEST_DIR/spec.$cell.$k" ] && read -r secs rc <"$LAB_TEST_DIR/spec.$cell.$k"
trap 'echo term >"$LAB_TEST_DIR/term.$cell"; exit 143' TERM
sleep "$secs" &
wait $!
# emit.<cell>.<run>: "file|reason[|result[|scenario]]" lines, written as
# verdicts into the evidence dir (result defaults to FAIL, scenario to x)
if [ -f "$LAB_TEST_DIR/emit.$cell.$k" ]; then
	mkdir -p "$3"
	while IFS='|' read -r f reason res scen; do
		printf 'scenario: %s\ncell: %s\nresult: %s\nreason: %b\n' "${scen:-x}" "$cell" "${res:-FAIL}" "$reason" >"$3/$f"
	done <"$LAB_TEST_DIR/emit.$cell.$k"
fi
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

# The load gate (#79) reads LAB_LOADAVG; every run gets an idle file unless a
# case writes its own, so no case reads the box this runs on.
idle() { echo "0.00 0.00 0.00 1/1 1" >"$1/loadavg"; }
busy() { echo "${2:-9.00} 9.00 9.00 1/1 1" >"$1/loadavg"; }
export LAB_LOADAVG="$tmp/loadavg.idle"
echo "0.00 0.00 0.00 1/1 1" >"$LAB_LOADAVG"

# A scratch repo root with a copy of run-cells.sh beside the stubs.
new_env() {
	local d
	d=$(mktemp -d "$tmp/env-XXXXXX")
	mkdir -p "$d/repo/scripts" "$d/state" "$d/root"
	cp "$REPO_ROOT/scripts/run-cells.sh" "$REPO_ROOT/scripts/load-gate.sh" "$REPO_ROOT/scripts/image-path.sh" "$d/repo/scripts/"
	write_stub_run_cell "$d/repo/scripts/run-cell.sh"
	write_stub_down_cell "$d/repo/scripts/down-cell.sh"
	chmod +x "$d/repo/scripts/"*.sh
	: >"$d/repo/lab.yaml"
	: >"$d/state/calls.log"
	: >"$d/state/down.log"
	idle "$d"
	echo "$d"
}

# cells <env> <args...>: runs run-cells.sh with --root set; prints nothing,
# leaves output in <env>/out and the exit code in <env>/rc.
cells() {
	local d=$1 rc=0
	shift
	LAB_TEST_DIR="$d/state" LAB_MEMINFO="$d/meminfo" LAB_LOADAVG="$d/loadavg" LAB_LOAD_POLL=1 PATH="$tmp/bin:$PATH" \
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
expect "case 4e (relay domain exists)" 1 "$e"
has "case 4e" "$e" "REFUSED -- domain lab-dnsmasq-relay already exists"
[ "$(started "$e")" -eq 0 ] || { echo "run-cells-test: FAIL -- case 4e: a cell was started" >&2; fail=1; }

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
	LAB_TEST_DIR="$d/state" LAB_MEMINFO="$d/meminfo" LAB_LOADAVG="$d/loadavg" PATH="$tmp/gapbin:$tmp/bin:$PATH" \
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

# Cases 19 to 21 (#79): the load gate, longest-first order, one retry pass.
# Wall time is never asserted; every claim is a call order, a log line or a
# file that the stubs and the script leave behind.
nlines() { grep -c -- "$2" "$1/out" || true; }
starts_of() { awk -v c="$2" '$1=="start" && $2==c' "$1/state/calls.log" | wc -l; }
start_order() { awk '$1=="start"{print $2}' "$1/state/calls.log" | tr '\n' ' '; }
bad() { echo "run-cells-test: FAIL -- $1" >&2; fail=1; }

# Case 19: load gate. Idle: no wait. Busy then idle: the start is after the
# recorded moment the file went idle, one wait line. Busy for good: the cell
# still starts after the bound. 0 disables. The edge load1 == ncpu/2 waits.
e=$(new_env)
meminfo "$e" 60
cells "$e" -j 2 --load-wait 600 a b
expect "case 19 (idle host)" 0 "$e"
[ "$(nlines "$e" 'load gate')" -eq 0 ] || bad "case 19: an idle host (load1 0.00) logged a load gate line"
[ "$(started "$e")" -eq 2 ] || bad "case 19: wanted two starts on an idle host"

e=$(new_env)
meminfo "$e" 60
busy "$e" 9.00
(
	sleep 2
	date +%s%N >"$e/state/idle.at"
	idle "$e"
) &
flip=$!
cells "$e" -j 1 --load-wait 60 a
wait "$flip"
expect "case 19b (busy then idle)" 0 "$e"
begun=$(awk '$1=="start"{print $3}' "$e/state/calls.log")
if [ -z "$begun" ] || [ "$begun" -le "$(cat "$e/state/idle.at")" ]; then
	bad "case 19b: the cell started at ${begun:-never} while load1 was still 9.00 (idle at $(cat "$e/state/idle.at"))"
fi
[ "$(nlines "$e" 'load gate: load1 9.00 .*waiting up to 60s')" -eq 1 ] || bad "case 19b: wanted exactly one 'waiting' line"
has "case 19b" "$e" 'load gate: load1 0.00 after [0-9]+s; starting'

e=$(new_env)
meminfo "$e" 60
busy "$e" 9.00
cells "$e" -j 1 --load-wait 2 a
expect "case 19c (busy past the bound still starts)" 0 "$e"
[ "$(started "$e")" -eq 1 ] || bad "case 19c: a cell that waited out the bound was not started"
has "case 19c" "$e" 'load gate: load1 9.00 still at or above 8.0 after [0-9]+s; starting anyway'
[ "$(nlines "$e" 'waiting up to')" -eq 1 ] || bad "case 19c: wanted one waiting line for the whole wait, not one per poll"

e=$(new_env)
meminfo "$e" 60
busy "$e" 9.00
cells "$e" -j 1 --load-wait 0 a
expect "case 19d (--load-wait 0)" 0 "$e"
[ "$(nlines "$e" 'load gate')" -eq 0 ] || bad "case 19d: --load-wait 0 still gated"

e=$(new_env)
meminfo "$e" 60
rm -f "$e/loadavg"
cells "$e" -j 1 --load-wait 5 a
expect "case 19e (no loadavg file)" 0 "$e"
[ "$(nlines "$e" 'load gate')" -eq 0 ] || bad "case 19e: an unreadable loadavg gated"

e=$(new_env)
meminfo "$e" 60
busy "$e" 7.99
cells "$e" -j 1 --load-wait 1 a
[ "$(nlines "$e" 'load gate')" -eq 0 ] || bad "case 19f: load1 7.99 on 16 cpus waited"
e=$(new_env)
meminfo "$e" 60
busy "$e" 8.00
cells "$e" -j 1 --load-wait 1 a
[ "$(nlines "$e" 'waiting up to')" -eq 1 ] || bad "case 19f: load1 8.00 on 16 cpus (== ncpu/2) did not wait"

for badw in -1 x 1.5 ""; do
	e=$(new_env)
	meminfo "$e" 60
	cells "$e" --load-wait "$badw" a
	expect "case 19g (--load-wait '$badw')" 2 "$e"
	has "case 19g" "$e" "REFUSED -- --load-wait wants a non-negative integer"
done

# a TERM during a load wait ends the wait at once (as case 13 for the disk)
e=$(new_env)
meminfo "$e" 60
busy "$e" 9.00
t0=$SECONDS
(
	LAB_TEST_DIR="$e/state" LAB_MEMINFO="$e/meminfo" LAB_LOADAVG="$e/loadavg" LAB_LOAD_POLL=100 PATH="$tmp/bin:$PATH" \
		exec "$e/repo/scripts/run-cells.sh" --root "$e/root" --stagger 0 --load-wait 300 a >"$e/out" 2>&1
) &
wpid=$!
n=0
until grep -q 'waiting up to' "$e/out" 2>/dev/null; do
	n=$((n + 1))
	[ "$n" -gt 100 ] && break
	sleep 0.1
done
kill -TERM "$wpid"
wrc=0
wait "$wpid" || wrc=$?
if [ "$wrc" -ne 130 ] || [ $((SECONDS - t0)) -ge 20 ]; then
	bad "case 19h: exit $wrc after $((SECONDS - t0)) s; wanted 130 well before the 100 s poll"
fi

# Case 20: order. Known durations descending, unknown last in the given
# order, --check prints the order the real run then uses, bad rows ignored.
e=$(new_env)
meminfo "$e" 60
printf 'a\t10\nb\t500\nc\t100\n' >"$e/durations.tsv"
cells "$e" -j 1 --durations "$e/durations.tsv" a b c
expect "case 20 (order)" 0 "$e"
[ "$(start_order "$e")" = "b c a " ] || bad "case 20: start order '$(start_order "$e")', wanted b c a"

e=$(new_env)
meminfo "$e" 60
printf 'a\t10\nb\t500\n' >"$e/durations.tsv"
cells "$e" -j 1 --durations "$e/durations.tsv" e a f b
[ "$(start_order "$e")" = "b a e f " ] || bad "case 20b: start order '$(start_order "$e")', wanted b a e f (unknown after known, given order among unknown)"

e=$(new_env)
meminfo "$e" 60
printf 'a\t10\nb\t500\nc\t100\n' >"$e/durations.tsv"
cells "$e" --check --durations "$e/durations.tsv" a b c
has "case 20c (--check order)" "$e" 'order, longest first from .*: b c a$'
table=$(awk '/^cell +bridge/{f=1;next} /^run-cells:/{f=0} f&&NF{print $1}' "$e/out" | tr '\n' ' ')
[ "$table" = "b c a " ] || bad "case 20c: the --check table lists '$table', wanted b c a"
cells "$e" -j 1 --durations "$e/durations.tsv" a b c
[ "$(start_order "$e")" = "$table" ] || bad "case 20c: --check printed '$table' but the run started '$(start_order "$e")'"

e=$(new_env)
meminfo "$e" 60
cells "$e" --durations "$e/no-such-file" a
expect "case 20d (missing durations file)" 2 "$e"
has "case 20d" "$e" "REFUSED -- --durations file"
[ "$(started "$e")" -eq 0 ] || bad "case 20d: a cell started"

e=$(new_env)
meminfo "$e" 60
printf 'a\tx\n\nb\t5\nc' >"$e/durations.tsv"
cells "$e" -j 1 --durations "$e/durations.tsv" a b
expect "case 20e (malformed rows)" 0 "$e"
[ "$(start_order "$e")" = "b a " ] || bad "case 20e: start order '$(start_order "$e")', wanted b a"

# the default file under the root is read when it exists
e=$(new_env)
meminfo "$e" 60
printf 'b\t99\n' >"$e/root/durations.tsv"
cells "$e" -j 1 a b
[ "$(start_order "$e")" = "b a " ] || bad "case 20f: default <root>/durations.tsv not used: '$(start_order "$e")'"

# every run writes one row per cell that finished 0; rows of other cells
# survive; a cell that failed keeps its old row
e=$(new_env)
meminfo "$e" 60
echo "1 0" >"$e/state/spec.a"
echo "1 0" >"$e/state/spec.b"
cells "$e" -j 2 a b
d="$e/root/durations.tsv"
for c in a b; do
	secs=$(awk -F'\t' -v c="$c" '$1==c{print $2}' "$d" 2>/dev/null)
	if ! [[ "$secs" =~ ^[0-9]+$ ]] || [ "$secs" -lt 1 ] || [ "$secs" -gt 30 ]; then
		bad "case 20g: $c has duration '$secs' in $d (stub slept 1 s)"
	fi
done
[ "$(wc -l <"$d")" -eq 2 ] || bad "case 20g: wanted two rows"
e=$(new_env)
meminfo "$e" 60
printf 'z\t7\na\t999\n' >"$e/root/durations.tsv"
echo "0 1" >"$e/state/spec.a"
cells "$e" -j 2 a b
d="$e/root/durations.tsv"
[ "$(awk -F'\t' '$1=="z"{print $2}' "$d")" = 7 ] || bad "case 20h: another cell's row was dropped"
[ "$(awk -F'\t' '$1=="a"{print $2}' "$d")" = 999 ] || bad "case 20h: a cell that failed replaced its row"
awk -F'\t' '$1=="b"{f=1} END{exit !f}' "$d" || bad "case 20h: the cell that passed has no row"

# Case 21: one retry pass.
SIG='failed to create endpoint c on network n: Post "http://plugin.moby.localhost/NetworkDriver.CreateEndpoint": context deadline exceeded (Client.Timeout exceeded while awaiting headers)'
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s\nA2.verdict|ordinary failure\n' "$SIG" >"$e/state/emit.a.1"
printf 'A1.verdict|second look passed\n' >"$e/state/emit.a.2"
cells "$e" -j 1 a
expect "case 21 (retry)" 0 "$e"
ev="$e/root/evidence/a"
[ "$(starts_of "$e" a)" -eq 2 ] || bad "case 21: cell a started $(starts_of "$e" a) times, wanted 2"
grep -q "^reason: $SIG" "$ev/retried/A1.verdict" 2>/dev/null || bad "case 21: the first verdict is not kept under retried/"
grep -q '^reason: second look passed' "$ev/A1.verdict" || bad "case 21: the rerun's verdict is not in place"
grep -q 'ordinary failure' "$ev/A2.verdict" || bad "case 21: a verdict without the signature was moved"
has "case 21 log" "$e" 'retry pass: a has 1 verdict\(s\) that are FAILs with an engine-to-plugin call timeout .*A1.verdict'
has "case 21 log" "$e" 'retry pass: rerunning a once, -j 1'
[ "$(tr -d ' ' <"$e/state/verdicts-at-start.a.2")" = 1 ] || bad "case 21: the rerun started with $(cat "$e/state/verdicts-at-start.a.2") verdicts in place, wanted only the one without the signature (a copy leaves the old one for labctl remaining to skip)"
if [ ! -f "$e/root/logs/a.first.log" ] || [ ! -f "$e/root/logs/a.log" ]; then bad "case 21: the first attempt's log is gone"; fi
has "case 21 table" "$e" '^a +0 \(retried\)'

# two signature rounds: the retry's own verdicts are final, no second pass
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|first %s\n' "$SIG" >"$e/state/emit.a.1"
printf 'A1.verdict|second %s\n' "$SIG" >"$e/state/emit.a.2"
printf 'A1.verdict|third %s\n' "$SIG" >"$e/state/emit.a.3"
cells "$e" -j 1 a
expect "case 21b (retry hits the signature)" 0 "$e"
[ "$(starts_of "$e" a)" -eq 2 ] || bad "case 21b: a started $(starts_of "$e" a) times; one retry pass, never two"
grep -q '^reason: second' "$e/root/evidence/a/A1.verdict" || bad "case 21b: the second verdict is not final"
grep -q '^reason: first' "$e/root/evidence/a/retried/A1.verdict" || bad "case 21b: the first verdict is not under retried/"
# a name already under retried/ is never overwritten
e=$(new_env)
meminfo "$e" 60
mkdir -p "$e/root/evidence/a/retried"
echo "older" >"$e/root/evidence/a/retried/A1.verdict"
printf 'A1.verdict|%s\n' "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 a
[ "$(cat "$e/root/evidence/a/retried/A1.verdict")" = older ] || bad "case 21c: an earlier retried/ file was overwritten"
[ "$(grep -l "^reason: $SIG" "$e"/root/evidence/a/retried/* | wc -l)" -eq 1 ] || bad "case 21c: the moved verdict is not kept beside the older one"

# What the selector matches, spelling by spelling. Strings are the engine's
# and the plugin's, copied from host runs rc1 and rc2 (#79); a is one cell
# per spelling so a rerun of the cell is the verdict that it matched.
PRE='docker: Error response from daemon: failed to set up container networking: failed to create endpoint c on network n:'
sel() { # name, reason, [result], [scenario] -> number of starts of cell a
	local n=$1
	e=$(new_env)
	meminfo "$e" 60
	printf 'A1.verdict|%s|%s|%s\n' "$2" "${3:-FAIL}" "${4:-x}" >"$e/state/emit.a.1"
	cells "$e" -j 1 a
	expect "case 21d ($n)" 0 "$e"
	starts_of "$e" a
}
for spell in \
	"$PRE"' Post "http://plugin.moby.localhost/NetworkDriver.CreateEndpoint": context deadline exceeded (Client.Timeout exceeded while awaiting headers)' \
	"$PRE"' Post "http://plugin.moby.localhost/NetworkDriver.CreateEndpoint": net/http: request canceled (Client.Timeout exceeded while awaiting headers)' \
	"$PRE"' Post "http://plugin.moby.localhost/NetworkDriver.CreateEndpoint": context deadline exceeded Run docker run --help' \
	"$PRE"' Post "http://plugin.moby.localhost/IpamDriver.RequestAddress": context deadline exceeded (Client.Timeout exceeded while awaiting headers)' \
	"$PRE"' Post "http://plugin.moby.localhost/IpamDriver.RequestAddress": net/http: request canceled (Client.Timeout exceeded while awaiting headers)' \
	"$PRE"' Post "http://plugin.moby.localhost/NetworkDriver.ProgramExternalConnectivity": net/http: request canceled (Client.Timeout exceeded while awaiting headers)' \
	"$PRE"' Post "http://%2Frun%2Fdocker%2Fplugins%2F18485%2Fnet-dhcp.sock/NetworkDriver.CreateEndpoint": net/http: request canceled (Client.Timeout exceeded while awaiting headers)'; do
	[ "$(sel "matched spelling" "$spell")" -eq 2 ] || bad "case 21d: not retried: $spell"
done
# not matched: the words alone, the words in the old order, a split line, a
# PASS quoting the timeout (D3c), a BLOCKED, the plugin's own DHCP timeout,
# a refused call, a containerd deadline and a non-plugin Post
for spell in \
	'CreateEndpoint failed' \
	'Client.Timeout alone' \
	'Client.Timeout exceeded in CreateEndpoint' \
	'CreateEndpoint: Post http://x: Client.Timeout exceeded while awaiting headers' \
	"$PRE"' NetworkDriver.CreateEndpoint: failed to get initial IP address via DHCP: context deadline exceeded' \
	"$PRE"' NetworkDriver.CreateEndpoint: failed to get initial IPv6 address via DHCPv6: context deadline exceeded' \
	"$PRE"' Post "http://plugin.moby.localhost/NetworkDriver.CreateEndpoint": connection refused' \
	'failed to create task for container: DeadlineExceeded: failed to create shim task: context deadline exceeded' \
	'Post "http://registry.example/v2/": context deadline exceeded (Client.Timeout exceeded while awaiting headers)' \
	'CreateEndpoint failed\nPost "http://plugin.moby.localhost/NetworkDriver.CreateEndpoint": context deadline exceeded'; do
	[ "$(sel "unmatched spelling" "$spell")" -eq 1 ] || bad "case 21d: retried: $spell"
done
D3C="$PRE"' Post "http://plugin.moby.localhost/NetworkDriver.CreateEndpoint": context deadline exceeded (Client.Timeout exceeded while awaiting headers)'
[ "$(sel "PASS quoting the timeout" "auto: 3 Solicits unanswered; the endpoint failed ($D3C)" PASS D3c-auto-silent-dhcpv6-server)" -eq 1 ] || bad "case 21d: a PASS that quotes the timeout was moved and rerun"
for res in BLOCKED N/A; do
	[ "$(sel "$res with the timeout" "$D3C" "$res")" -eq 1 ] || bad "case 21d: a $res verdict was rerun"
done
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s|PASS|D3c-auto-silent-dhcpv6-server\n' "$D3C" >"$e/state/emit.a.1"
cells "$e" -j 1 a
[ -f "$e/root/evidence/a/A1.verdict" ] && [ ! -e "$e/root/evidence/a/retried" ] || bad "case 21d: a PASS was moved under retried/"

# one cell per spelling in one run: only the cells with a match are rerun
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|CreateEndpoint failed\nA2.verdict|Client.Timeout alone\n' >"$e/state/emit.a.1"
printf 'B1.verdict|%s\n' "$SIG" >"$e/state/emit.b.1"
cells "$e" -j 2 a b
expect "case 21d (only the signature cell)" 0 "$e"
[ "$(starts_of "$e" a)" -eq 1 ] || bad "case 21d: a (no signature) was rerun"
[ "$(starts_of "$e" b)" -eq 2 ] || bad "case 21d: b (signature) was not rerun"
# the mixed cell: the FAIL with the signature moves, the PASS and the plugin's
# own DHCP timeout stay in place
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s\nA2.verdict|%s|PASS|D2b\nA3.verdict|%s NetworkDriver.CreateEndpoint: failed to get initial IP address via DHCP: context deadline exceeded\n' "$SIG" "$D3C" "$PRE" >"$e/state/emit.a.1"
cells "$e" -j 1 a
[ -f "$e/root/evidence/a/retried/A1.verdict" ] && [ -f "$e/root/evidence/a/A2.verdict" ] && [ -f "$e/root/evidence/a/A3.verdict" ] || bad "case 21d: the mixed cell moved the wrong files: $(ls "$e/root/evidence/a" "$e/root/evidence/a/retried" 2>&1 | tr '\n' ' ')"
[ ! -e "$e/root/evidence/a/retried/A2.verdict" ] && [ ! -e "$e/root/evidence/a/retried/A3.verdict" ] || bad "case 21d: a PASS or a DHCP timeout was moved"
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|CreateEndpoint failed\\nPost "http://plugin.moby.localhost/NetworkDriver.CreateEndpoint": context deadline exceeded\n' >"$e/state/emit.a.1"
cells "$e" -j 1 a
[ "$(starts_of "$e" a)" -eq 1 ] || bad "case 21d: a signature split over two lines matched"

# case 21g: the skip list. E3b is not rerun; --retry-skip replaces the list.
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s|FAIL|E3b-vlan-parent\n' "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 a
expect "case 21g (E3b skipped)" 0 "$e"
[ "$(starts_of "$e" a)" -eq 1 ] || bad "case 21g: E3b-vlan-parent was rerun"
[ -f "$e/root/evidence/a/A1.verdict" ] && [ ! -e "$e/root/evidence/a/retried" ] || bad "case 21g: E3b-vlan-parent was moved"
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s|FAIL|E3b-vlan-parent\n' "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 --retry-skip '' a
[ "$(starts_of "$e" a)" -eq 2 ] || bad "case 21g: --retry-skip '' still skipped E3b-vlan-parent"
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s|FAIL|A8-fleet-burst\nA2.verdict|%s|FAIL|E3b-vlan-parent\n' "$SIG" "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 --retry-skip 'A8-fleet-burst|B1' a
[ -e "$e/root/evidence/a/A1.verdict" ] && [ -e "$e/root/evidence/a/retried/A2.verdict" ] || bad "case 21g: --retry-skip did not replace the default list"
# a scenario name that only contains a skipped name is not skipped
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s|FAIL|E3b-vlan-parent-2\n' "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 a
[ "$(starts_of "$e" a)" -eq 2 ] || bad "case 21g: the skip matched a longer scenario name"

# --no-retry never reruns and never moves
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s\n' "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 --no-retry a
expect "case 21e (--no-retry)" 0 "$e"
[ "$(starts_of "$e" a)" -eq 1 ] || bad "case 21e: --no-retry reran a"
if [ ! -f "$e/root/evidence/a/A1.verdict" ] || [ -d "$e/root/evidence/a/retried" ]; then bad "case 21e: --no-retry moved a verdict"; fi
has "case 21e" "$e" 'retry pass disabled'

# the pass runs one cell at a time unless --retry-jobs says more (#79: the
# rc2 pass at two met the same stall)
for rjopt in "" "--retry-jobs 2" "--retry-jobs 3"; do
	e=$(new_env)
	meminfo "$e" 60
	for c in a b c d; do
		echo "1 0" >"$e/state/spec.$c"
		printf 'A1.verdict|%s\n' "$SIG" >"$e/state/emit.$c.1"
	done
	# shellcheck disable=SC2086
	cells "$e" -j 4 $rjopt a b c d
	expect "case 21f (retry pool, '$rjopt')" 0 "$e"
	max=$(awk '$1=="start"{n[$2]++; if (n[$2]==2) print $3, 1} $1=="end"{m[$2]++; if (m[$2]==2) print $3, -1}' "$e/state/calls.log" | sort -k1,1n -k2,2n | awk '{n+=$2; if (n>m) m=n} END{print m+0}')
	want=${rjopt##* }
	[ -n "$want" ] || want=1
	[ "$max" -eq "$want" ] || bad "case 21f: the retry pass with '$rjopt' peaked at $max running, wanted exactly $want"
	has "case 21f log" "$e" "retry pass: rerunning a b c d once, -j $want"
done
for bad_rj in 0 x -1 1.5 ""; do
	e=$(new_env)
	meminfo "$e" 60
	cells "$e" --retry-jobs "$bad_rj" a
	expect "case 21f (--retry-jobs '$bad_rj')" 2 "$e"
	has "case 21f" "$e" "REFUSED -- --retry-jobs wants a positive integer"
	[ "$(started "$e")" -eq 0 ] || bad "case 21f: a cell started on a refused --retry-jobs"
done

# the pass still goes through the load gate: busy when the first pass ends
e=$(new_env)
meminfo "$e" 60
printf 'A1.verdict|%s\n' "$SIG" >"$e/state/emit.a.1"
busy "$e" 9.00
cells "$e" -j 1 --load-wait 1 a
expect "case 21h (retry through the gate)" 0 "$e"
[ "$(nlines "$e" 'run-cells: a: load gate: load1 9.00 still at or above 8.0')" -eq 2 ] || bad "case 21h: wanted the load gate to speak before the first start and before the retry start"

# the exit code is the second rc
e=$(new_env)
meminfo "$e" 60
echo "0 1" >"$e/state/spec.a.1"
echo "0 0" >"$e/state/spec.a.2"
printf 'A1.verdict|%s\n' "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 a
expect "case 21g (first rc 1, retried rc 0)" 0 "$e"
e=$(new_env)
meminfo "$e" 60
echo "0 0" >"$e/state/spec.a.1"
echo "0 1" >"$e/state/spec.a.2"
printf 'A1.verdict|%s\n' "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 a
expect "case 21g (first rc 0, retried rc 1)" 1 "$e"

# a cell that never ran is not retried, whatever sits in its evidence dir
e=$(new_env)
meminfo "$e" 60
echo 1000 >"$e/state/free_mib"
mkdir -p "$e/root/evidence/a"
printf 'scenario: x\nreason: %s\n' "$SIG" >"$e/root/evidence/a/old.verdict"
LAB_DISK_WAIT=0 cells "$e" -j 1 a
[ "$(started "$e")" -eq 0 ] || bad "case 21h: a skipped cell was started by the retry pass"
[ -f "$e/root/evidence/a/old.verdict" ] || bad "case 21h: a verdict of a cell that never ran was moved"

# durations.tsv keeps the first run's length: the retry runs under the
# pool cap and says nothing about how long the cell takes at full load
e=$(new_env)
meminfo "$e" 60
echo "1 0" >"$e/state/spec.a.1"
echo "5 0" >"$e/state/spec.a.2"
printf 'A1.verdict|%s\n' "$SIG" >"$e/state/emit.a.1"
cells "$e" -j 1 a
expect "case 21i (durations of a retried cell)" 0 "$e"
secs=$(awk -F'\t' '$1=="a"{print $2}' "$e/root/durations.tsv" 2>/dev/null)
if [[ ! "$secs" =~ ^[0-9]+$ ]] || [ "$secs" -gt 3 ]; then bad "case 21i: durations.tsv has '$secs' seconds for a; the first run took about 1, the retry about 5"; fi

# Case 22 (lab #14): a cell on a built base image that is not on this host
# is skipped-image, never started, never a failure by itself.
# built_cell ENV CELL SRC_KIND SRC_IMAGE [HOST_KIND HOST_IMAGE]: resolve
# fixture with the images the gate reads; bridge and addresses unique per cell.
built_cell() {
	local idx
	idx=$(($(echo -n "$2" | cksum | cut -d' ' -f1) % 200 + 10))
	jq -n --arg c "$2" --arg d "10.200.255.$idx/24" --arg s "10.200.254.$idx/24" \
		--arg sk "$3" --arg sn "$4" --arg hk "${5:-qcow2}" --arg hn "${6:-debian-13-generic-amd64}" \
		'{cell:{name:$c,segment:{bridge:("lab-br-"+$c)},source:{mgmt_address:$s},docker_host:{mgmt_address:$d}},
		  source_image:{name:$sn,kind:$sk}, docker_host_image:{name:$hn,kind:$hk}}' >"$1/state/resolve.$2"
}
witness() { # env cell -> number of run-cell.sh calls for the cell
	grep -c "^start $2 " "$1/state/calls.log" || true
}

# 22a: image absent. Exit 0, rc file, table row, log line, marker, no start.
e=$(new_env)
meminfo "$e" 60
mkdir -p "$e/cache"
built_cell "$e" w built windows-2025-eval
LAB_IMAGE_CACHE="$e/cache" cells "$e" w
expect "case 22a (image absent)" 0 "$e"
[ "$(cat "$e/root/logs/w.rc")" = skipped-image ] || bad "case 22a: rc file is '$(cat "$e/root/logs/w.rc" 2>/dev/null)', not skipped-image"
has "case 22a table" "$e" "^w +skipped-image "
has "case 22a message" "$e" "w not started: built image windows-2025-eval is not on this host \($e/cache/windows-2025-eval.qcow2 is missing\)"
[ "$(witness "$e" w)" -eq 0 ] || bad "case 22a: run-cell.sh was called for a cell whose image is absent"
[ ! -e "$e/root/logs/w.first.log" ] || bad "case 22a: the retry pass picked a skipped-image cell up"
if grep -q 'retry pass: .*rerunning' "$e/out"; then bad "case 22a: a retry pass reran something"; fi
[ ! -s "$e/state/down.log" ] || bad "case 22a: down-cell.sh ran for a cell that never started"
if [ "$(jq -r '[.cell, .reason] | join("|")' "$e/root/evidence/w/image-not-built.json" 2>/dev/null)" != "w|image not built" ]; then
	bad "case 22a: image-not-built.json is missing or does not carry the cell and reason"
fi
[[ "$(jq -r .date "$e/root/evidence/w/image-not-built.json" 2>/dev/null)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$ ]] || bad "case 22a: the marker date is not RFC 3339 UTC"
# The renderer reads what the runner wrote (lab #14): one BLOCKED column.
page=$(cd "$REPO_ROOT" && go run ./cmd/labctl matrix --root "$e/root/evidence" "$e/root/evidence/w" 2>&1) || bad "case 22a: labctl matrix refused the runner's marker: $page"
grep -q '^| scenario | w |$' <<<"$page" || bad "case 22a: the matrix has no single column for w: $page"
grep -q '^- \*\*w\*\*: not run, image not built, ' <<<"$page" || bad "case 22a: the matrix header does not say why w did not run: $page"
[ "$(grep -c '\[BLOCKED\](w/image-not-built.json)' <<<"$page")" -ge 1 ] || bad "case 22a: no BLOCKED link to the marker: $page"

# 22b: --check says what the start says, from the same function, exit 0.
LAB_IMAGE_CACHE="$e/cache" cells "$e" --check w
expect "case 22b (--check, image absent)" 0 "$e"
has "case 22b" "$e" "w would be skipped-image: built image windows-2025-eval is not on this host \($e/cache/windows-2025-eval.qcow2 is missing\)"
has "case 22b summary" "$e" "1 cell\(s\) would be skipped-image, which is not a failure"
want_reason=$(sed -n 's/^run-cells: w would be skipped-image: //p' "$e/out")
LAB_IMAGE_CACHE="$e/cache" cells "$e" w
[ "$(sed -n 's/^run-cells: w not started: //p' "$e/out")" = "$want_reason" ] || bad "case 22b: --check and the start give different reasons"

# 22c: the path is the one fetch-base-image.sh uses. Another cache dir, a
# sidecar or a directory by that name does not count; the file does.
mkdir -p "$e/other"
touch "$e/other/windows-2025-eval.qcow2" "$e/cache/windows-2025-eval.build-id"
LAB_IMAGE_CACHE="$e/cache" cells "$e" w
[ "$(cat "$e/root/logs/w.rc")" = skipped-image ] || bad "case 22c: a sidecar or another cache dir's image counted as present"
mkdir -p "$e/dircache/windows-2025-eval.qcow2"
LAB_IMAGE_CACHE="$e/dircache" cells "$e" w
[ "$(cat "$e/root/logs/w.rc")" = skipped-image ] || bad "case 22c: a directory named like the image counted as present"
fetch_err=$(LAB_IMAGE_CACHE="$e/cache" "$REPO_ROOT/scripts/fetch-base-image.sh" windows-2025-eval "" built 2>&1 >/dev/null || true)
case "$fetch_err" in *"$e/cache/windows-2025-eval.qcow2 is a built image and is not there"*) ;; *) bad "case 22c: fetch-base-image.sh names another path: $fetch_err" ;; esac
[ "$(env -u LAB_IMAGE_CACHE bash -c ". '$REPO_ROOT/scripts/image-path.sh'; base_image_path x")" = /srv/lab/images/x.qcow2 ] || bad "case 22c: the default path moved"
# present: the cell starts whatever its sidecar says (stale is up-source.sh's red)
touch "$e/cache/windows-2025-eval.qcow2"
echo "0 0" >"$e/state/spec.w"
echo "an-older-build-id" >"$e/cache/windows-2025-eval.build-id"
mkdir -p "$e/root/evidence/w"
echo stale >"$e/root/evidence/w/image-not-built.json"
LAB_IMAGE_CACHE="$e/cache" cells "$e" w
expect "case 22c (present, stale sidecar)" 0 "$e"
[ "$(witness "$e" w)" -eq 1 ] || bad "case 22c: a present image with a stale sidecar was not started"
[ ! -e "$e/root/evidence/w/image-not-built.json" ] || bad "case 22c: a stale marker survived a real start"
[ "$(cat "$e/root/logs/w.rc")" = 0 ] || bad "case 22c: rc is not 0"

# 22d: a built host image is gated like a source image; no cell name is read.
e=$(new_env)
meminfo "$e" 60
mkdir -p "$e/cache"
built_cell "$e" x qcow2 debian-13-generic-amd64 built openwrt-25.12.5-x86-64
LAB_IMAGE_CACHE="$e/cache" cells "$e" x
[ "$(cat "$e/root/logs/x.rc")" = skipped-image ] || bad "case 22d: a missing built docker host image was not skipped"
has "case 22d" "$e" "built image openwrt-25.12.5-x86-64 is not on this host"
# qcow2 and archive images are never gated: the download is their fetch
built_cell "$e" y archive some-archive-image
LAB_IMAGE_CACHE="$e/cache" cells "$e" y
[ "$(witness "$e" y)" -eq 1 ] || bad "case 22d: an archive image was gated"

# 22e: the gate comes before the disk wait and the load wait. With 5 s
# bounds a gate placed after either would end as skipped-disk or start late.
e=$(new_env)
meminfo "$e" 60
mkdir -p "$e/cache"
built_cell "$e" w built windows-2025-eval
echo 1000 >"$e/state/free_mib"
busy "$e" 99.00
LAB_IMAGE_CACHE="$e/cache" LAB_DISK_WAIT=5 LAB_DISK_POLL=1 LAB_LOAD_WAIT=5 cells "$e" w
expect "case 22e (disk low, load high, image absent)" 0 "$e"
[ "$(cat "$e/root/logs/w.rc")" = skipped-image ] || bad "case 22e: rc is '$(cat "$e/root/logs/w.rc")', not skipped-image"
if grep -q 'waiting' "$e/out"; then bad "case 22e: the run waited before skipping"; fi

# 22f: exit codes. skipped-image alone is 0 (22a); beside a failure or a
# skipped-disk it is still 1, and beside a pass it is 0.
e=$(new_env)
meminfo "$e" 60
mkdir -p "$e/cache"
built_cell "$e" w built windows-2025-eval
echo "0 1" >"$e/state/spec.a"
LAB_IMAGE_CACHE="$e/cache" cells "$e" -j 1 w a
expect "case 22f (skipped-image beside a failed cell)" 1 "$e"
has "case 22f table w" "$e" "^w +skipped-image "
has "case 22f table a" "$e" "^a +1 "
e=$(new_env)
meminfo "$e" 60
mkdir -p "$e/cache"
built_cell "$e" w built windows-2025-eval
echo 1000 >"$e/state/free_mib"
LAB_IMAGE_CACHE="$e/cache" LAB_DISK_WAIT=0 cells "$e" -j 1 w a
expect "case 22f (skipped-image beside skipped-disk)" 1 "$e"
has "case 22f disk" "$e" "^a +skipped-disk "
has "case 22f image" "$e" "^w +skipped-image "
e=$(new_env)
meminfo "$e" 60
mkdir -p "$e/cache"
built_cell "$e" w built windows-2025-eval
echo "0 0" >"$e/state/spec.a"
LAB_IMAGE_CACHE="$e/cache" cells "$e" -j 1 w a
expect "case 22f (skipped-image beside a passing cell)" 0 "$e"
[ "$(witness "$e" a)" -eq 1 ] || bad "case 22f: the passing cell did not run beside a skipped-image one"
if [ -e "$e/root/durations.tsv" ] && grep -q '^w' "$e/root/durations.tsv"; then bad "case 22f: a duration was recorded for the skipped-image cell"; fi

# 22g: an earlier run's verdicts are the cell's evidence and stay; the
# retry pass leaves them and no marker is written beside them.
e=$(new_env)
meminfo "$e" 60
mkdir -p "$e/cache" "$e/root/evidence/w"
built_cell "$e" w built windows-2025-eval
printf 'scenario: x\nreason: %s\n' "CreateEndpoint Client.Timeout" >"$e/root/evidence/w/old.verdict"
LAB_IMAGE_CACHE="$e/cache" cells "$e" w
expect "case 22g (earlier verdicts, image gone)" 0 "$e"
[ -f "$e/root/evidence/w/old.verdict" ] || bad "case 22g: an earlier verdict was moved"
[ ! -e "$e/root/evidence/w/image-not-built.json" ] || bad "case 22g: a marker was written beside earlier verdicts"
[ ! -e "$e/root/evidence/w/retried" ] || bad "case 22g: the retry pass touched a skipped-image cell"

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "run-cells-test: PASS -- all cases behaved as expected"
