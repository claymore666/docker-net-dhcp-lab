#!/bin/bash
# CI-safe tests for capture-start.sh/capture-stop.sh's own orchestration
# logic (issue #3): every docker/ip/nsenter/build-bridge.sh call is
# intercepted by a stub, never real docker or netns state. The kernel
# operations these scripts drive (real bridge, real veth, real tcpdump)
# are exercised live by run-group-a.sh, not here.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# capture-start.sh calls build-bridge.sh by its own script-relative path
# (BASH_SOURCE-derived), never through PATH: a PATH stub alone cannot
# reach it, so both scripts are copied beside a stub build-bridge.sh.
mkdir -p "$tmp/scripts"
cp "$REPO_ROOT/scripts/capture-start.sh" "$REPO_ROOT/scripts/capture-stop.sh" "$tmp/scripts/"
cat >"$tmp/scripts/build-bridge.sh" <<'STUB'
#!/bin/bash
[ -n "${CALLS_LOG:-}" ] && echo "build-bridge $*" >>"$CALLS_LOG"
exit 0
STUB
chmod +x "$tmp/scripts/capture-start.sh" "$tmp/scripts/capture-stop.sh" "$tmp/scripts/build-bridge.sh"

bindir="$tmp/bin"
mkdir -p "$bindir"

# Pass-through sudo, same shape as down-cell-test.sh's own stub, plus its
# own SUDO_LOG: reaching the ip/docker stub proves nothing about *how* a
# call got there, so this logs every sudo invocation verbatim (before
# stripping -n) and a test can grep it for a bare "sudo <cmd>" line that
# skipped -n -- a regression the pass-through alone would never surface,
# since it reaches the same downstream stub either way.
cat >"$bindir/sudo" <<'STUB'
#!/bin/bash
[ -n "${SUDO_LOG:-}" ] && echo "sudo $*" >>"$SUDO_LOG"
[ "${1:-}" = "-n" ] && shift
exec "$@"
STUB
chmod +x "$bindir/sudo"

cat >"$bindir/ip" <<'STUB'
#!/bin/bash
[ -n "${CALLS_LOG:-}" ] && echo "ip $*" >>"$CALLS_LOG"
exit 0
STUB
chmod +x "$bindir/ip"

cat >"$bindir/nsenter" <<'STUB'
#!/bin/bash
[ -n "${CALLS_LOG:-}" ] && echo "nsenter $*" >>"$CALLS_LOG"
exit 0
STUB
chmod +x "$bindir/nsenter"

# TCPDUMP_UP gates capture-start.sh's own bounded wait; OBSERVER_EXISTS
# gates capture-stop.sh's existence check. docker cp writes a real fake
# pcap to its destination argument, so a test can assert on real bytes
# landing at the real path capture-stop.sh reports.
cat >"$bindir/docker" <<'STUB'
#!/bin/bash
[ -n "${CALLS_LOG:-}" ] && echo "docker $*" >>"$CALLS_LOG"
case "$*" in
"rm -f "*) exit 0 ;;
"run -d --name "*) echo fake-container-id; exit 0 ;;
*"apk add"*) exit 0 ;;
"network disconnect bridge "*) exit 0 ;;
*"State.Pid"*) echo 12345; exit 0 ;;
*"pgrep -x tcpdump"*)
	[ "${TCPDUMP_UP:-1}" = "1" ] && exit 0 || exit 1
	;;
"exec -d "*"tcpdump"*) exit 0 ;;
*"pkill tcpdump"*) exit 0 ;;
"cp "*)
	dest="${3:-}"
	[ -n "$dest" ] && echo "fake pcap bytes" >"$dest"
	exit 0
	;;
"inspect "*)
	[ "${OBSERVER_EXISTS:-1}" = "1" ] && exit 0 || exit 1
	;;
*) exit 0 ;;
esac
STUB
chmod +x "$bindir/docker"

hash1=$(echo -n case1 | md5sum | cut -c1-5)

# Case 1: a clean run -- tcpdump reports running immediately, so
# capture-start.sh must succeed, name its container/veth deterministically
# from the cell name, and become ready quickly (well inside its 10s bound).
work1="$tmp/work1"
mkdir -p "$work1"
calls1="$tmp/calls1.log"
sudo1="$tmp/sudo1.log"
: >"$calls1"
: >"$sudo1"
start_t=$(date +%s)
if ! CALLS_LOG="$calls1" SUDO_LOG="$sudo1" TCPDUMP_UP=1 PATH="$bindir:$PATH" "$tmp/scripts/capture-start.sh" case1 br-case1 "$work1" >"$tmp/out1.log" 2>&1; then
	echo "capture-lifecycle-test: FAIL -- case 1: capture-start.sh refused although tcpdump reported running" >&2
	cat "$tmp/out1.log" >&2
	fail=1
fi
elapsed1=$(($(date +%s) - start_t))
if [ "$elapsed1" -gt 5 ]; then
	echo "capture-lifecycle-test: FAIL -- case 1: took ${elapsed1}s to become ready although tcpdump was already up" >&2
	fail=1
fi
if [ ! -f "$work1/observer.ready" ]; then
	echo "capture-lifecycle-test: FAIL -- case 1: observer.ready was not written" >&2
	fail=1
fi
if ! grep -qE "^docker run -d --name lab-observer-case1 " "$calls1"; then
	echo "capture-lifecycle-test: FAIL -- case 1: container was not named deterministically from the cell name" >&2
	cat "$calls1" >&2
	fail=1
fi
if ! grep -qE "^ip link add veth-obs-${hash1}h type veth peer name veth-obs-${hash1}c\$" "$calls1"; then
	echo "capture-lifecycle-test: FAIL -- case 1: veth pair was not named deterministically from the cell name" >&2
	cat "$calls1" >&2
	fail=1
fi
if ! grep -qE "^build-bridge br-case1 --add-port veth-obs-${hash1}h\$" "$calls1"; then
	echo "capture-lifecycle-test: FAIL -- case 1: build-bridge.sh was not asked to add the observer's veth to the segment bridge" >&2
	cat "$calls1" >&2
	fail=1
fi
if [ ! -s "$sudo1" ] || grep -qvE "^sudo -n " "$sudo1"; then
	echo "capture-lifecycle-test: FAIL -- case 1: capture-start.sh made a privileged call without sudo -n" >&2
	cat "$sudo1" >&2
	fail=1
fi

# Case 1 continued: capture-stop.sh on the same work dir must copy the
# pcap out, remove the observer container, and remove its host-side veth.
calls1b="$tmp/calls1b.log"
sudo1b="$tmp/sudo1b.log"
: >"$calls1b"
: >"$sudo1b"
if ! CALLS_LOG="$calls1b" SUDO_LOG="$sudo1b" OBSERVER_EXISTS=1 PATH="$bindir:$PATH" "$tmp/scripts/capture-stop.sh" case1 "$work1" >"$tmp/out1b.log" 2>&1; then
	echo "capture-lifecycle-test: FAIL -- case 1: capture-stop.sh failed while the observer existed" >&2
	cat "$tmp/out1b.log" >&2
	fail=1
fi
if [ ! -s "$work1/observer.pcap" ]; then
	echo "capture-lifecycle-test: FAIL -- case 1: capture-stop.sh did not write a non-empty pcap" >&2
	fail=1
fi
if ! grep -qE "^docker rm -f lab-observer-case1\$" "$calls1b"; then
	echo "capture-lifecycle-test: FAIL -- case 1: capture-stop.sh did not remove the observer container" >&2
	cat "$calls1b" >&2
	fail=1
fi
if ! grep -qE "^ip link del veth-obs-${hash1}h\$" "$calls1b"; then
	echo "capture-lifecycle-test: FAIL -- case 1: capture-stop.sh did not remove the observer's host-side veth" >&2
	cat "$calls1b" >&2
	fail=1
fi
if [ ! -s "$sudo1b" ] || grep -qvE "^sudo -n " "$sudo1b"; then
	echo "capture-lifecycle-test: FAIL -- case 1: capture-stop.sh made a privileged call without sudo -n" >&2
	cat "$sudo1b" >&2
	fail=1
fi

# Case 2: tcpdump never reports running -- capture-start.sh must refuse
# within its bound (never hang) and must not write observer.ready.
work2="$tmp/work2"
mkdir -p "$work2"
calls2="$tmp/calls2.log"
: >"$calls2"
if CALLS_LOG="$calls2" TCPDUMP_UP=0 PATH="$bindir:$PATH" "$tmp/scripts/capture-start.sh" case2 br-case2 "$work2" >"$tmp/out2.log" 2>&1; then
	echo "capture-lifecycle-test: FAIL -- case 2: capture-start.sh exited 0 although tcpdump never came up" >&2
	fail=1
fi
if ! grep -q "did not start inside the 10s bound" "$tmp/out2.log"; then
	echo "capture-lifecycle-test: FAIL -- case 2: did not report the 10s-bound failure" >&2
	cat "$tmp/out2.log" >&2
	fail=1
fi
if [ -f "$work2/observer.ready" ]; then
	echo "capture-lifecycle-test: FAIL -- case 2: observer.ready was written although tcpdump never came up" >&2
	fail=1
fi

# Case 3: capture-stop.sh on a cell whose capture was never started (no
# observer container) must still exit 0 -- best-effort cleanup, never a
# hard failure -- and must warn rather than silently claim a pcap.
work3="$tmp/work3"
mkdir -p "$work3"
calls3="$tmp/calls3.log"
: >"$calls3"
if ! out3=$(CALLS_LOG="$calls3" OBSERVER_EXISTS=0 PATH="$bindir:$PATH" "$tmp/scripts/capture-stop.sh" case3 "$work3" 2>&1); then
	echo "capture-lifecycle-test: FAIL -- case 3: capture-stop.sh failed on a cell that was never captured" >&2
	echo "$out3" >&2
	fail=1
fi
if ! grep -q "WARNING" <<<"$out3"; then
	echo "capture-lifecycle-test: FAIL -- case 3: did not warn about the missing pcap" >&2
	fail=1
fi
if [ -f "$work3/observer.pcap" ]; then
	echo "capture-lifecycle-test: FAIL -- case 3: a pcap appeared although the observer never existed" >&2
	fail=1
fi

# Case 4: proves the sudo-log check above catches a real regression on
# capture-stop.sh itself, not only on a well-behaved script. Dropping
# "-n" from the veth cleanup line is invisible to exit code, stdout, and
# the CALLS_LOG mechanism alike: the pass-through sudo stub reaches the
# same "ip" stub either way. Mutates a temp copy, never the real script.
# shellcheck disable=SC2016 # intentional: literal "$VETH_HOST", not expansion
orig_veth_del_count=$(grep -cE '^sudo -n ip link del "\$VETH_HOST" 2>/dev/null \|\| true$' "$REPO_ROOT/scripts/capture-stop.sh")
if [ "$orig_veth_del_count" -ne 1 ]; then
	echo "capture-lifecycle-test: FAIL -- case 4 setup: expected exactly 1 veth cleanup line in capture-stop.sh, found $orig_veth_del_count -- this test needs updating to match the current script" >&2
	fail=1
else
	mutant="$tmp/scripts/capture-stop-mutant.sh"
	# shellcheck disable=SC2016 # intentional: literal "$VETH_HOST", not expansion
	sed -E 's/^sudo -n ip link del "\$VETH_HOST"/sudo ip link del "$VETH_HOST"/' \
		"$REPO_ROOT/scripts/capture-stop.sh" >"$mutant"
	chmod +x "$mutant"
	# shellcheck disable=SC2016 # intentional: literal "$VETH_HOST", not expansion
	mutated_count=$(grep -cE '^sudo ip link del "\$VETH_HOST" 2>/dev/null \|\| true$' "$mutant" || true)
	if [ "$mutated_count" -ne 1 ]; then
		echo "capture-lifecycle-test: FAIL -- case 4 setup: mutation did not produce exactly 1 bare \"sudo ip link del\" line, found $mutated_count -- the sed pattern needs updating" >&2
		fail=1
	else
		work4="$tmp/work4"
		mkdir -p "$work4"
		calls4="$tmp/calls4.log"
		sudo4="$tmp/sudo4.log"
		: >"$calls4"
		: >"$sudo4"
		if ! CALLS_LOG="$calls4" SUDO_LOG="$sudo4" OBSERVER_EXISTS=0 PATH="$bindir:$PATH" "$mutant" case4 "$work4" >"$tmp/out4.log" 2>&1; then
			echo "capture-lifecycle-test: FAIL -- case 4 setup: the mutant exited non-zero, so it cannot prove the mutation is invisible to exit code" >&2
			cat "$tmp/out4.log" >&2
			fail=1
		elif grep -qvE "^sudo -n " "$sudo4"; then
			: # expected: the mutant's veth cleanup call is missing -n
		else
			echo "capture-lifecycle-test: FAIL -- case 4: the sudo-log mechanism did not catch a veth cleanup call with -n dropped" >&2
			cat "$sudo4" >&2
			fail=1
		fi
	fi
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "capture-lifecycle-test: PASS -- all three cases behaved as expected, and the sudo -n check catches a real -n regression (case 4)"
