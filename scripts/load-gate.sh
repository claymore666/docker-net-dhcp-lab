#!/bin/bash
# shellcheck shell=bash
# The load gate (#79): run-cells.sh before each cell start and run-cell.sh
# before each shape wait, bounded, while load1 >= ncpu/2. Run 1 measured 38
# CreateEndpoint Client.Timeout verdicts at a median load1 of 11.6 on 16
# vCPUs. The bound is a wait, never a skip. LAB_LOADAVG and LAB_NCPU let a
# test supply both readings. Sourced, never run.

# load_busy: sets LOAD1 and LOAD_LIMIT, returns 0 while load1 >= ncpu/2.
# An unreadable file or a non-numeric reading counts as idle.
load_busy() {
	local ncpu
	ncpu=${LAB_NCPU:-$(nproc)}
	LOAD1=$(LC_ALL=C awk 'NR == 1 {print $1}' "${LAB_LOADAVG:-/proc/loadavg}" 2>/dev/null) || LOAD1=""
	[[ "$LOAD1" =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 1
	[[ "$ncpu" =~ ^[0-9]+$ ]] || return 1
	LOAD_LIMIT=$(LC_ALL=C awk -v n="$ncpu" 'BEGIN {printf "%.1f", n / 2}')
	LC_ALL=C awk -v l="$LOAD1" -v n="$ncpu" 'BEGIN {exit !(l * 2 >= n)}'
}

# load_gate WHO BOUND POLL: WHO prefixes the log lines. BOUND 0 disables.
# One line when a wait starts and one when it ends, either way.
load_gate() {
	local who=$1 bound=$((10#${2:-0})) poll=$((10#${3:-30})) waited=0
	[ "$bound" -gt 0 ] || return 0
	[ "$poll" -ge 1 ] || poll=1
	load_busy || return 0
	echo "$who: load gate: load1 $LOAD1 is at or above ncpu/2 ($LOAD_LIMIT); waiting up to ${bound}s"
	while load_busy; do
		if [ "$waited" -ge "$bound" ]; then
			echo "$who: load gate: load1 $LOAD1 still at or above $LOAD_LIMIT after ${waited}s; starting anyway"
			return 0
		fi
		${LOAD_NAP:-sleep} "$poll"
		waited=$((waited + poll))
	done
	echo "$who: load gate: load1 $LOAD1 after ${waited}s; starting"
}
