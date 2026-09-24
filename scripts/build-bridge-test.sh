#!/bin/bash
# Automated refusal tests for build-bridge.sh (issue #1). Runs inside a
# fresh user+network namespace (unshare -rnm), so it only ever sees
# loopback and the interfaces this script creates -- never the real
# host's NICs or bridges.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILD_BRIDGE="$REPO_ROOT/scripts/build-bridge.sh"

if ! unshare -rnm true 2>/dev/null; then
	if [ "${CI:-}" = "true" ]; then
		echo "build-bridge-test: FAIL -- unshare -rnm not available in CI; a gate never goes quietly green" >&2
		exit 1
	fi
	echo "build-bridge-test: SKIP -- unshare -rnm not available here (not CI)" >&2
	exit 0
fi

# $1 and the function bodies below belong to the inner script, expanded
# only once unshare runs it, not by this outer shell -- single quotes are
# deliberate here.
# shellcheck disable=SC2016
inner='
set -euo pipefail
mount -t sysfs sysfs /sys
ip link set lo up

BUILD_BRIDGE="$1"
fail=0

run_ok() {
	local desc=$1; shift
	if ! "$BUILD_BRIDGE" "$@" >/dev/null 2>&1; then
		echo "build-bridge-test: FAIL -- $desc: wanted ok, got refused" >&2
		fail=1
	fi
}
run_refused() {
	local desc=$1; shift
	if "$BUILD_BRIDGE" "$@" >/dev/null 2>&1; then
		echo "build-bridge-test: FAIL -- $desc: wanted refused, got ok" >&2
		fail=1
	fi
}

# Case A: a lab-named port (standing in for a VM tap) is accepted.
ip link add vnet9 type veth peer name vnet9-peer
run_ok "lab-named port accepted" bridge-a --add-port vnet9

# Case B: --add-port refuses a disallowed name outright.
ip link add eth5 type veth peer name eth5-peer
run_refused "eth5 refused via --add-port" bridge-b --add-port eth5

# Case C: eth0 itself is refused, even standing in as a plain veth --
# the literal-name check runs before anything else.
ip link add eth0 type veth peer name eth0-peer
run_refused "eth0 refused via --add-port" bridge-c --add-port eth0

# Case D: a bridge that already enslaves a non-lab port (added directly
# with ip link, bypassing build-bridge.sh) is refused even with no
# --add-port at all -- a bridge a previous run polluted must not be used
# silently.
ip link add bridge-d type bridge
ip link set bridge-d up
ip link add stray0 type veth peer name stray0-peer
ip link set stray0 master bridge-d
run_refused "pre-existing stray port refused with no --add-port" bridge-d

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "build-bridge-test: PASS -- all 4 cases behaved as expected"
'

unshare -rnm bash -c "$inner" bash "$BUILD_BRIDGE"
