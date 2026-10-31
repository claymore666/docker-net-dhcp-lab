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
LOAD_POLL=${LAB_LOAD_POLL:-30}
. "$REPO_ROOT/scripts/load-gate.sh"
. "$REPO_ROOT/scripts/image-path.sh"

usage() {
	echo "usage: run-cells.sh [-j N] [--stagger SECONDS] [--load-wait SECONDS] [--durations FILE] [--no-retry] [--retry-jobs N] [--retry-skip REGEX] [--root DIR] [--check] <cell-name> [<cell-name> ...]" >&2
}

JOBS=""
ROOT=""
STAGGER=60
LOAD_WAIT=${LAB_LOAD_WAIT:-900}
DURATIONS=""
RETRY=1
RETRY_JOBS=1
# Scenarios whose engine-to-plugin timeout is a lab reason, not host load,
# so a rerun cannot help: E3b ran against a source that did not serve the
# VLAN (#121). Matched against the verdict's scenario: line (#79).
RETRY_SKIP='E3b-vlan-parent'
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
	--load-wait | --durations)
		if [ $# -lt 2 ]; then
			usage
			exit 2
		fi
		if [ "$1" = "--load-wait" ]; then LOAD_WAIT=$2; else DURATIONS=$2; fi
		shift 2
		;;
	--no-retry)
		RETRY=0
		shift
		;;
	--retry-jobs | --retry-skip)
		if [ $# -lt 2 ]; then
			usage
			exit 2
		fi
		if [ "$1" = "--retry-jobs" ]; then RETRY_JOBS=$2; else RETRY_SKIP=$2; fi
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
if ! [[ "$LOAD_WAIT" =~ ^[0-9]+$ ]]; then
	echo "run-cells: REFUSED -- --load-wait wants a non-negative integer, got '$LOAD_WAIT'" >&2
	exit 2
fi
if ! [[ "$RETRY_JOBS" =~ ^[1-9][0-9]*$ ]]; then
	echo "run-cells: REFUSED -- --retry-jobs wants a positive integer, got '$RETRY_JOBS'" >&2
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

### ---------- order: longest cell first (#79) ----------
# One reordering, before --check resolves anything, so the table --check
# prints and the order the pool starts in are the same list. A cell with no
# duration sorts after every known one and keeps its given place among them.
if [ -z "$DURATIONS" ]; then
	if [ -f "$ROOT/durations.tsv" ]; then DURATIONS=$ROOT/durations.tsv; fi
elif [ ! -f "$DURATIONS" ]; then
	echo "run-cells: REFUSED -- --durations file '$DURATIONS' does not exist" >&2
	exit 2
fi
order_cells() {
	local -A dur=()
	local c s i=0
	while IFS=$'\t' read -r c s _ || [ -n "$c" ]; do
		if [[ "$s" =~ ^[0-9]+$ ]]; then dur[$c]=$s; fi
	done <"$DURATIONS"
	mapfile -t CELLS < <(
		for c in "${CELLS[@]}"; do
			printf '%s\t%s\t%s\n' "${dur[$c]:--1}" "$i" "$c"
			i=$((i + 1))
		done | LC_ALL=C sort -t$'\t' -k1,1nr -k2,2n | cut -f3
	)
}
if [ -n "$DURATIONS" ]; then
	order_cells
	echo "run-cells: order, longest first from $DURATIONS: ${CELLS[*]}"
else
	echo "run-cells: order, as given (no durations file): ${CELLS[*]}"
fi

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

# image_gate JSON: prints why a built base image the cell needs is not on
# this host and returns 0; returns 1 when every one is there. The one
# definition --check and the start share (lab #14), over the path
# fetch-base-image.sh writes. Only presence is asked: a stale or expired
# image is up-source.sh's refusal, which stays red.
image_gate() {
	local name path
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		path=$(base_image_path "$name")
		if [ ! -f "$path" ]; then
			echo "built image $name is not on this host ($path is missing); run its build script"
			return 0
		fi
	done < <(jq -r '[.source_image, .docker_host_image] | map(select(. != null and .kind == "built") | .name) | unique | .[]' <<<"$1")
	return 1
}

declare -A CELL_JSON=()
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
	CELL_JSON[$cell]=$json
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
would_skip=0
for cell in "${CELLS[@]}"; do
	if msg=$(image_gate "${CELL_JSON[$cell]}"); then
		echo "run-cells: $cell would be skipped-image: $msg"
		would_skip=$((would_skip + 1))
	fi
done
if [ "$CHECK_ONLY" -eq 1 ]; then
	echo "run-cells: --check OK, ${ncells} cell(s) share no name, domain, bridge, address, observer or directory"
	[ "$would_skip" -eq 0 ] || echo "run-cells: --check: $would_skip cell(s) would be skipped-image, which is not a failure"
	exit 0
fi

### ---------- the pool ----------
mkdir -p "$ROOT/logs"
declare -A PID_CELL=() RC=() START=() END=() RETRIED=()
LOAD_NAP=nap
export LAB_LOAD_WAIT="$LOAD_WAIT" LAB_LOAD_POLL="$LOAD_POLL"
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

# The results page reads this file to show the cell as one BLOCKED column
# (internal/matrix, lab #14). Not written over an earlier run's verdicts,
# which stay the cell's evidence.
mark_image_not_built() {
	local cell=$1 msg=$2 ev
	ev=$ROOT/evidence/$cell
	if compgen -G "$ev/*.verdict" >/dev/null; then
		echo "run-cells: $cell keeps the verdicts of an earlier run in $ev; no image-not-built marker written" >&2
		return 0
	fi
	mkdir -p "$ev"
	jq -n --arg cell "$cell" --arg reason "image not built" --arg detail "$msg" \
		--arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		'{cell: $cell, reason: $reason, detail: $detail, date: $date}' >"$ev/image-not-built.json"
}

start_cell() {
	local cell=$1 pid
	rm -f "$ROOT/logs/$cell.rc"
	START[$cell]=$EPOCHSECONDS
	# First, before any wait: a cell whose image cannot exist here is not
	# a disk or a load question, and never reaches run-cell.sh (lab #14).
	if msg=$(image_gate "${CELL_JSON[$cell]}"); then
		RC[$cell]=skipped-image
		END[$cell]=$EPOCHSECONDS
		echo "skipped-image" >"$ROOT/logs/$cell.rc"
		echo "run-cells: $cell not started: $msg" >&2
		mark_image_not_built "$cell" "$msg"
		return 0
	fi
	rm -f "$ROOT/evidence/$cell/image-not-built.json"
	if ! wait_for_disk; then
		RC[$cell]=skipped-disk
		END[$cell]=$EPOCHSECONDS
		echo "skipped-disk" >"$ROOT/logs/$cell.rc"
		echo "run-cells: $cell not started, under $MIN_FREE_GIB GiB free on $ROOT for ${DISK_WAIT}s" >&2
		return 0
	fi
	load_gate "run-cells: $cell" "$LOAD_WAIT" "$LOAD_POLL"
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
		[ -z "${RETRIED[$cell]:-}" ] || rc="$rc (retried)"
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

run_pool() {
	local jobs=$1 next=0 n
	shift
	local -a queue=("$@")
	n=${#queue[@]}
	while [ "$next" -lt "$n" ] || [ "$RUNNING" -gt 0 ]; do
		while [ "$next" -lt "$n" ] && [ "$RUNNING" -lt "$jobs" ]; do
			stagger_gap
			start_cell "${queue[$next]}"
			next=$((next + 1))
		done
		if [ "$RUNNING" -gt 0 ]; then reap_one; fi
	done
}

# Only cells that exited 0 are recorded: a cell that died early would
# otherwise sort last next time. Rows of cells not in this run are kept (#79).
write_durations() {
	local -A fresh=() seen=()
	local cell c s tmp out=$ROOT/durations.tsv
	for cell in "${CELLS[@]}"; do
		if [ "${RC[$cell]:-}" = 0 ] && [ -n "${START[$cell]:-}" ] && [ -n "${END[$cell]:-}" ]; then
			fresh[$cell]=$((END[$cell] - START[$cell]))
		fi
	done
	[ "${#fresh[@]}" -gt 0 ] || return 0
	tmp=$(mktemp "$ROOT/.durations.XXXXXX")
	{
		if [ -f "$out" ]; then
			while IFS=$'\t' read -r c s _ || [ -n "$c" ]; do
				if [[ "$s" =~ ^[0-9]+$ ]] && [ -z "${fresh[$c]:-}" ] && [ -z "${seen[$c]:-}" ]; then
					seen[$c]=1
					printf '%s\t%s\n' "$c" "$s"
				fi
			done <"$out"
		fi
		for c in "${!fresh[@]}"; do
			printf '%s\t%s\n' "$c" "${fresh[$c]}"
		done
	} >"$tmp"
	mv -f -- "$tmp" "$out"
}

# A load casualty is a FAIL whose reason is the engine's call to the plugin
# (NetworkDriver or IpamDriver) running past its timeout, with or without the
# Client.Timeout suffix: 38 such FAILs on rc1 (#79). Not matched: a PASS that
# quotes the timeout (D3c, D2b expect it), the plugin's own "failed to get
# initial IP address via DHCP: context deadline exceeded" (the server did not
# answer; a rerun meets the same silence), and the RETRY_SKIP scenarios.
load_signature() {
	grep -qx -e 'result: FAIL' -- "$1" || return 1
	grep -qE -e "^scenario: ($RETRY_SKIP)\$" -- "$1" && return 1
	grep -qE -e '^reason: .*Post "[^"]*/(NetworkDriver|IpamDriver)\.[A-Za-z]+": (context deadline exceeded|net/http: request canceled)' -- "$1"
}

# Moves, never overwrites: a name already in the target dir gets a number.
move_aside() {
	local dest=$2/${1##*/} n=1
	while [ -e "$dest" ]; do
		dest=$2/${1##*/}.$n
		n=$((n + 1))
	done
	mv -- "$1" "$dest"
}

# One pass, never two (#79): the rerun's verdicts are final even if they
# carry the signature. run-cell.sh resumes, so only the moved verdicts'
# scenarios run again. The pass runs --retry-jobs cells at a time (default 1):
# rc2 reran at -j 2 and met the same stall (#79); each start still passes the
# load gate.
retry_pass() {
	local cell ev f n names queue=() rj=$RETRY_JOBS
	for cell in "${CELLS[@]}"; do
		[[ "${RC[$cell]:-}" =~ ^[0-9]+$ ]] || continue
		ev=$ROOT/evidence/$cell
		n=0
		names=""
		for f in "$ev"/*.verdict; do
			[ -e "$f" ] || continue
			load_signature "$f" || continue
			[ "$n" -gt 0 ] || mkdir -p "$ev/retried"
			names="$names ${f##*/}"
			move_aside "$f" "$ev/retried"
			n=$((n + 1))
		done
		[ "$n" -gt 0 ] || continue
		echo "run-cells: retry pass: $cell has $n verdict(s) that are FAILs with an engine-to-plugin call timeout (load signature); moved to $ev/retried/:$names"
		mv -f -- "$ROOT/logs/$cell.log" "$ROOT/logs/$cell.first.log"
		RETRIED[$cell]=1
		queue+=("$cell")
	done
	if [ "${#queue[@]}" -eq 0 ]; then
		echo "run-cells: retry pass: no verdict carries the load signature"
		return 0
	fi
	echo "run-cells: retry pass: rerunning ${queue[*]} once, -j $rj"
	run_pool "$rj" "${queue[@]}"
}

run_pool "$JOBS" "${CELLS[@]}"
write_durations
if [ "$RETRY" -eq 1 ]; then
	retry_pass
else
	echo "run-cells: retry pass disabled (--no-retry)"
fi

print_table
failed=0
for cell in "${CELLS[@]}"; do
	# skipped-image is the one non-zero result that is not a failure; a
	# skipped-disk, skipped-exists, terminated or missing rc still is.
	case "${RC[$cell]:-}" in 0 | skipped-image) ;; *) failed=1 ;; esac
done
exit "$failed"
