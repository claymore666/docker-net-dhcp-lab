#!/bin/bash
# Run several cells at once on one host (issue #38): a job pool over the
# unchanged run-cell.sh, one evidence bundle and one log per cell. Refuses
# before the first start when two cells would share a name, domain,
# bridge, management address, observer or directory, or when one of them
# already exists on the host. down-cell.sh owns teardown; this script
# never destroys a domain itself.
set -euo pipefail

# wait -n -p (which finished job) is bash 5.1; Debian 13 ships 5.2.
if [ "${BASH_VERSINFO[0]}" -lt 5 ] || { [ "${BASH_VERSINFO[0]}" -eq 5 ] && [ "${BASH_VERSINFO[1]}" -lt 1 ]; }; then
	echo "run-cells: REFUSED -- needs bash 5.1 or newer, have $BASH_VERSION" >&2
	exit 1
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"
RUN_CELL="$REPO_ROOT/scripts/run-cell.sh"
DOWN_CELL="$REPO_ROOT/scripts/down-cell.sh"
MIN_FREE_GIB=${LAB_MIN_FREE_GIB:-15}
DISK_WAIT=${LAB_DISK_WAIT:-600}
DISK_POLL=${LAB_DISK_POLL:-30}

usage() {
	echo "usage: run-cells.sh [-j N] [--stagger SECONDS] [--root DIR] [--check] <cell-name> [<cell-name> ...]" >&2
}

JOBS=""
ROOT=""
STAGGER=60
CHECK_ONLY=0
CELLS=()
while [ $# -gt 0 ]; do
	case "$1" in
	-j | --root)
		if [ $# -lt 2 ]; then
			usage
			exit 2
		fi
		if [ "$1" = "-j" ]; then JOBS=$2; else ROOT=$2; fi
		shift 2
		;;
	--stagger)
		if [ $# -lt 2 ]; then
			usage
			exit 2
		fi
		STAGGER=$2
		shift 2
		;;
	--check)
		CHECK_ONLY=1
		shift
		;;
	-*)
		usage
		exit 2
		;;
	*)
		CELLS+=("$1")
		shift
		;;
	esac
done
if [ "${#CELLS[@]}" -eq 0 ]; then
	usage
	exit 2
fi
if ! [[ "$STAGGER" =~ ^[0-9]+$ ]]; then
	echo "run-cells: REFUSED -- --stagger wants a non-negative integer, got '$STAGGER'" >&2
	exit 2
fi
if [ -n "$JOBS" ] && ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
	echo "run-cells: REFUSED -- -j wants a positive integer, got '$JOBS'" >&2
	exit 2
fi
for cell in "${CELLS[@]}"; do
	if ! [[ "$cell" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
		echo "run-cells: REFUSED -- '$cell' is not a usable cell name" >&2
		exit 2
	fi
done
for tool in jq setsid flock; do
	if ! command -v "$tool" >/dev/null; then
		echo "run-cells: REFUSED -- $tool is not installed" >&2
		exit 1
	fi
done

# Absolute, so every path handed to run-cell.sh and rm means the same
# thing whatever the caller's working directory is.
ROOT=$(realpath -m -- "${ROOT:-/srv/lab/work/$(whoami)}")

### ---------- --check: resolve every cell, refuse on any shared name ----------
declare -A OWNER=()
refusals=()
claim() {
	local key="$1|$2"
	if [ -n "${OWNER[$key]:-}" ]; then
		refusals+=("duplicate $1 '$2' (cells ${OWNER[$key]} and $3)")
	else
		OWNER[$key]=$3
	fi
}

T_BRIDGE=()
T_DOCKER=()
T_SOURCE=()
T_VETH=()
for i in "${!CELLS[@]}"; do
	cell=${CELLS[$i]}
	if ! json=$(go run "$REPO_ROOT/cmd/labctl" resolve "$LAB_YAML" "$cell"); then
		echo "run-cells: REFUSED -- labctl resolve failed for cell $cell; nothing was started" >&2
		exit 1
	fi
	bridge=$(jq -r '.cell.segment.bridge // empty' <<<"$json")
	docker_addr=$(jq -r '.cell.docker_host.mgmt_address // empty' <<<"$json")
	source_addr=$(jq -r '.cell.source.mgmt_address // empty' <<<"$json")
	if [ -z "$bridge" ] || [ -z "$docker_addr" ]; then
		echo "run-cells: REFUSED -- cell $cell resolves without a bridge or docker host address; nothing was started" >&2
		exit 1
	fi
	cell_hash=$(echo -n "$cell" | md5sum | cut -c1-5)
	veth="veth-obs-${cell_hash}h"
	T_BRIDGE[i]=$bridge
	T_DOCKER[i]=${docker_addr%%/*}
	T_SOURCE[i]=${source_addr%%/*}
	T_VETH[i]=$veth

	claim "cell name" "$cell" "$cell"
	claim "domain" "lab-${cell}-dockerhost" "$cell"
	claim "bridge" "$bridge" "$cell"
	claim "management address" "${T_DOCKER[i]}" "$cell"
	if [ -n "${T_SOURCE[i]}" ]; then
		claim "domain" "lab-${cell}-source" "$cell"
		claim "management address" "${T_SOURCE[i]}" "$cell"
	fi
	claim "observer container" "lab-observer-${cell}" "$cell"
	claim "observer veth" "$veth" "$cell"
	claim "work dir" "$ROOT/work/$cell" "$cell"
	claim "evidence dir" "$ROOT/evidence/$cell" "$cell"
done

# Whatever is already on the host belongs to a run that is not ours.
# Asked again right before each start: a queued cell can wait a long
# time, and another run may define its domain meanwhile.
host_conflict() {
	local cell=$1 d
	for d in "lab-${cell}-dockerhost" "lab-${cell}-source" "lab-${cell}-partner" "lab-${cell}-relay"; do
		if sudo -n virsh dominfo "$d" >/dev/null 2>&1; then
			echo "domain $d already exists on this host (run down-cell.sh for that cell first)"
			return 0
		fi
	done
	if sudo -n docker inspect "lab-observer-${cell}" >/dev/null 2>&1; then
		echo "observer container lab-observer-${cell} already exists on this host (run down-cell.sh for that cell first)"
		return 0
	fi
	return 1
}
for cell in "${CELLS[@]}"; do
	if msg=$(host_conflict "$cell"); then
		refusals+=("$msg")
	fi
done

echo "run-cells: root $ROOT (work/<cell>, evidence/<cell>, logs/<cell>.log)"
printf '%-18s %-20s %-16s %-16s %s\n' cell bridge docker-mgmt source-mgmt observer-veth
for i in "${!CELLS[@]}"; do
	printf '%-18s %-20s %-16s %-16s %s\n' "${CELLS[$i]}" "${T_BRIDGE[$i]}" "${T_DOCKER[$i]}" "${T_SOURCE[$i]:--}" "${T_VETH[$i]}"
done

### ---------- how many at once ----------
ncells=${#CELLS[@]}
ncpu=$(nproc)
mem_gib=$(awk '/^MemAvailable:/ {print int($2 / 1048576)}' "${LAB_MEMINFO:-/proc/meminfo}")
cpu_bound=$(((ncpu - 2) / 3))
mem_bound=$(((${mem_gib:-0} - 4) / 3))
bound=$cpu_bound
[ "$mem_bound" -lt "$bound" ] && bound=$mem_bound
[ "$bound" -lt 1 ] && bound=1
if [ -z "$JOBS" ]; then
	JOBS=$bound
	[ "$ncells" -lt "$JOBS" ] && JOBS=$ncells
elif [ "$JOBS" -gt "$bound" ]; then
	echo "run-cells: overcommit -- -j $JOBS is above the computed bound $bound"
fi
echo "run-cells: -j $JOBS (cells $ncells; cpu bound $cpu_bound from $ncpu vCPU, memory bound $mem_bound from ${mem_gib:-0} GiB available)"

if [ "${#refusals[@]}" -gt 0 ]; then
	for r in "${refusals[@]}"; do
		echo "run-cells: REFUSED -- $r" >&2
	done
	echo "run-cells: nothing was started" >&2
	exit 1
fi
if [ "$CHECK_ONLY" -eq 1 ]; then
	echo "run-cells: --check OK, ${ncells} cell(s) share no name, domain, bridge, address, observer or directory"
	exit 0
fi

### ---------- the pool ----------
mkdir -p "$ROOT/logs"
declare -A PID_CELL=() RC=() START=() END=()
RUNNING=0
TERMINATING=0
NAP_PID=""
LAST_LAUNCH=""

# Interruptible sleep: a signal ends the wait at once, not after $1 s.
nap() {
	sleep "$1" &
	NAP_PID=$!
	wait "$NAP_PID" || true
	NAP_PID=""
}

free_gib() {
	LC_ALL=C df --output=avail -B1M "$ROOT" | awk 'NR == 2 {print int($1 / 1024)}'
}

# Before every start, not once: earlier cells fill the disk as they go
# (23 GB per overlay, the v0.1.0 run took root to 95 %).
wait_for_disk() {
	local waited=0 free
	while :; do
		free=$(free_gib) || free=0
		[ "${free:-0}" -ge "$MIN_FREE_GIB" ] && return 0
		[ "$waited" -ge "$DISK_WAIT" ] && return 1
		echo "run-cells: $ROOT has ${free:-0} GiB free, want $MIN_FREE_GIB; waiting"
		nap "$DISK_POLL"
		waited=$((waited + DISK_POLL))
	done
}

# A gap between launches, not between finishes: every cell's cloud-init,
# ssh and plugin install ran at once in the first -j 6 run (#38), and the
# slowest guests missed their boot-time bounds. 0 disables.
stagger_gap() {
	local left
	[ "$((10#$STAGGER))" -gt 0 ] && [ -n "$LAST_LAUNCH" ] || return 0
	left=$((10#$STAGGER - (EPOCHSECONDS - LAST_LAUNCH)))
	[ "$left" -gt 0 ] || return 0
	echo "run-cells: waiting ${left}s before the next start (--stagger $STAGGER)"
	nap "$left"
}

start_cell() {
	local cell=$1 pid
	rm -f "$ROOT/logs/$cell.rc"
	START[$cell]=$EPOCHSECONDS
	if ! wait_for_disk; then
		RC[$cell]=skipped-disk
		END[$cell]=$EPOCHSECONDS
		echo "skipped-disk" >"$ROOT/logs/$cell.rc"
		echo "run-cells: $cell not started, under $MIN_FREE_GIB GiB free on $ROOT for ${DISK_WAIT}s" >&2
		return 0
	fi
	if msg=$(host_conflict "$cell"); then
		RC[$cell]=skipped-exists
		END[$cell]=$EPOCHSECONDS
		echo "skipped-exists" >"$ROOT/logs/$cell.rc"
		echo "run-cells: $cell not started: $msg" >&2
		return 0
	fi
	# Own session: a TERM to the group reaches run-cell.sh and everything
	# it started, which run-cell.sh (no signal trap) would never forward.
	setsid "$RUN_CELL" "$cell" "$ROOT/work/$cell" "$ROOT/evidence/$cell" \
		>"$ROOT/logs/$cell.log" 2>&1 </dev/null &
	pid=$!
	PID_CELL[$pid]=$cell
	LAST_LAUNCH=$EPOCHSECONDS
	RUNNING=$((RUNNING + 1))
	echo "run-cells: started $cell (pid $pid), log $ROOT/logs/$cell.log"
}

# One teardown routine for a signal and for a cell that exited non-zero
# (#38): run-cell.sh tears down only on its own success path, so a failed
# cell left its VMs and bridge behind in the first -j 6 run.
teardown_cell() {
	local cell=$1
	echo "run-cells: tearing down $cell"
	echo "run-cells: tearing down $cell" >>"$ROOT/logs/$cell.log"
	LAB_EVIDENCE_DIR="$ROOT/evidence/$cell" "$DOWN_CELL" "$cell" "$ROOT/work/$cell" >>"$ROOT/logs/$cell.log" 2>&1 ||
		echo "run-cells: down-cell.sh failed for $cell; see $ROOT/logs/$cell.log" >&2
}

reap_one() {
	local fin="" rc=0 cell
	wait -n -p fin || rc=$?
	cell=${PID_CELL[$fin]:-}
	[ -n "$cell" ] || return 0
	unset "PID_CELL[$fin]"
	RUNNING=$((RUNNING - 1))
	RC[$cell]=$rc
	END[$cell]=$EPOCHSECONDS
	echo "$rc" >"$ROOT/logs/$cell.rc"
	echo "run-cells: $cell finished rc=$rc"
	[ "$rc" -eq 0 ] || teardown_cell "$cell"
}

print_table() {
	local cell rc mins
	printf '%-18s %-14s %8s  %s\n' cell rc minutes log
	for cell in "${CELLS[@]}"; do
		rc=${RC[$cell]:-not-started}
		mins=-
		if [ -n "${START[$cell]:-}" ] && [ -n "${END[$cell]:-}" ]; then
			mins=$(awk -v s="${START[$cell]}" -v e="${END[$cell]}" 'BEGIN {printf "%.1f", (e - s) / 60}')
		fi
		printf '%-18s %-14s %8s  %s\n' "$cell" "$rc" "$mins" "$ROOT/logs/$cell.log"
	done
}

# Forward the signal to each running cell's session, wait for it, then
# run down-cell.sh for every cell that was started and has not finished,
# so a second run never finds leftover domains.
# shellcheck disable=SC2317 # only reached through the trap below
on_signal() {
	local pid cell n
	[ "$TERMINATING" -eq 1 ] && return 0
	TERMINATING=1
	echo "run-cells: signal received; stopping the running cells" >&2
	[ -n "$NAP_PID" ] && kill "$NAP_PID" 2>/dev/null
	for pid in "${!PID_CELL[@]}"; do
		kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
	done
	for pid in "${!PID_CELL[@]}"; do
		wait "$pid" 2>/dev/null || true
		n=0
		while kill -0 -- "-$pid" 2>/dev/null && [ "$n" -lt 100 ]; do
			sleep 0.1
			n=$((n + 1))
		done
		kill -KILL -- "-$pid" 2>/dev/null || true
	done
	for pid in "${!PID_CELL[@]}"; do
		cell=${PID_CELL[$pid]}
		teardown_cell "$cell"
		RC[$cell]=terminated
		END[$cell]=$EPOCHSECONDS
		echo "terminated" >"$ROOT/logs/$cell.rc"
	done
	print_table
	exit 130
}
trap on_signal INT TERM HUP

next=0
while [ "$next" -lt "$ncells" ] || [ "$RUNNING" -gt 0 ]; do
	while [ "$next" -lt "$ncells" ] && [ "$RUNNING" -lt "$JOBS" ]; do
		stagger_gap
		start_cell "${CELLS[$next]}"
		next=$((next + 1))
	done
	[ "$RUNNING" -gt 0 ] && reap_one
done

print_table
failed=0
for cell in "${CELLS[@]}"; do
	[ "${RC[$cell]:-}" = 0 ] || failed=1
done
exit "$failed"
