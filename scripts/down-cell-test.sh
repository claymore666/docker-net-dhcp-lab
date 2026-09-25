#!/bin/bash
# Refusal and pcap-preservation tests for down-cell.sh (issue #1). CI-safe:
# every case runs against a stubbed sudo/virsh on PATH, never real libvirt.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$REPO_ROOT/scripts/down-cell.sh"

fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# A pass-through sudo: down-cell.sh must call every virsh through it, so a
# case that stubs virsh directly (without going through this) exposes a
# call that skipped sudo -n.
cat >"$tmp/sudo" <<'STUB'
#!/bin/bash
[ "${1:-}" = "-n" ] && shift
exec "$@"
STUB
chmod +x "$tmp/sudo"

# Case 1: the domain never existed (dominfo always fails). Must proceed:
# move the pcap to the evidence dir, remove $WORK, print "torn down".
case1=$(mktemp -d "$tmp/case1-XXXXXX")
work1="$case1/work"
mkdir -p "$work1"
echo fake >"$work1/capture.pcap"
cat >"$tmp/virsh" <<'STUB'
#!/bin/bash
exit 1
STUB
chmod +x "$tmp/virsh"
evdir1="$case1/evidence"
out1=$(LAB_EVIDENCE_DIR="$evdir1" PATH="$tmp:$PATH" "$SCRIPT" case1cell "$work1" 2>&1) || {
	echo "down-cell-test: FAIL -- case 1: refused although the domain never existed" >&2
	echo "$out1" >&2
	fail=1
}
if ! find "$evdir1" -maxdepth 1 -name '*case1cell*capture.pcap' 2>/dev/null | grep -q .; then
	echo "down-cell-test: FAIL -- case 1: pcap was not moved to the evidence dir" >&2
	fail=1
fi
if [ -d "$work1" ]; then
	echo "down-cell-test: FAIL -- case 1: work dir was not removed" >&2
	fail=1
fi
if ! grep -q "torn down" <<<"$out1"; then
	echo "down-cell-test: FAIL -- case 1: did not print the torn-down confirmation" >&2
	fail=1
fi

# Case 2: the domain persists no matter what destroy/undefine do (dominfo
# always succeeds). Must refuse, must not remove $WORK, must not print
# "torn down" -- and the pcap already sitting under $WORK must still be
# there afterwards, since nothing was actually torn down.
case2=$(mktemp -d "$tmp/case2-XXXXXX")
work2="$case2/work"
mkdir -p "$work2"
echo fake >"$work2/capture.pcap"
cat >"$tmp/virsh" <<'STUB'
#!/bin/bash
case "$1" in
dominfo) exit 0 ;;
*) exit 0 ;;
esac
STUB
chmod +x "$tmp/virsh"
evdir2="$case2/evidence"
if out2=$(LAB_EVIDENCE_DIR="$evdir2" PATH="$tmp:$PATH" "$SCRIPT" case2cell "$work2" 2>&1); then
	echo "down-cell-test: FAIL -- case 2: exited 0 although the domain still exists" >&2
	fail=1
else
	out2_captured="$out2"
fi
if grep -q "torn down" <<<"${out2_captured:-}"; then
	echo "down-cell-test: FAIL -- case 2: printed the torn-down confirmation although the domain still exists" >&2
	fail=1
fi
if [ ! -d "$work2" ] || [ ! -f "$work2/capture.pcap" ]; then
	echo "down-cell-test: FAIL -- case 2: work dir or its pcap was removed although the domain still exists" >&2
	fail=1
fi

# Case 3: proves the observer container and its host-side veth are
# actually targeted for removal (issue #1/#3 direction: down-cell.sh used
# to leave both behind), and that a "no such container"/"cannot find
# device" failure from an already-absent one does not fail the script --
# the same shape as up-cell.sh's own idempotent-rerun guarantee. docker
# and ip are logged, not just stubbed, so a call that goes bare (skips
# the sudo -n wrapper above them) or is missing entirely is caught either
# way: a bare call never reaches this stub at all, since PATH here has no
# real docker/ip ahead of the pass-through sudo's exec.
case3=$(mktemp -d "$tmp/case3-XXXXXX")
work3="$case3/work"
mkdir -p "$work3"
cat >"$tmp/virsh" <<'STUB'
#!/bin/bash
exit 1
STUB
chmod +x "$tmp/virsh"
calls3="$case3/calls.log"
: >"$calls3"
cat >"$tmp/docker" <<STUB
#!/bin/bash
echo "docker \$*" >>"$calls3"
exit 1
STUB
chmod +x "$tmp/docker"
cat >"$tmp/ip" <<STUB
#!/bin/bash
echo "ip \$*" >>"$calls3"
exit 1
STUB
chmod +x "$tmp/ip"
evdir3="$case3/evidence"
out3=$(LAB_EVIDENCE_DIR="$evdir3" PATH="$tmp:$PATH" "$SCRIPT" case3cell "$work3" 2>&1) || {
	echo "down-cell-test: FAIL -- case 3: teardown failed although the observer container/veth were merely absent" >&2
	echo "$out3" >&2
	fail=1
}
hash3=$(echo -n case3cell | md5sum | cut -c1-5)
if ! grep -qE "^docker rm -f lab-observer-case3cell\$" "$calls3"; then
	echo "down-cell-test: FAIL -- case 3: observer container was never targeted for removal" >&2
	cat "$calls3" >&2
	fail=1
fi
if ! grep -qE "^ip link del veth-obs-${hash3}h\$" "$calls3"; then
	echo "down-cell-test: FAIL -- case 3: observer veth was never targeted for removal" >&2
	cat "$calls3" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "down-cell-test: PASS -- all three cases behaved as expected"
