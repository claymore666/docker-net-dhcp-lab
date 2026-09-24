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

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "down-cell-test: PASS -- both cases behaved as expected"
