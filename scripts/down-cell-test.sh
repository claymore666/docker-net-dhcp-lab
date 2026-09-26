#!/bin/bash
# Refusal and pcap-preservation tests for down-cell.sh (issue #1), plus
# the source VM's own teardown (issue #2, cases 5-6). CI-safe: every case
# runs against a stubbed sudo/virsh on PATH, never real libvirt.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$REPO_ROOT/scripts/down-cell.sh"

fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# A pass-through sudo: down-cell.sh must call every virsh through it, so a
# case that stubs virsh directly (without going through this) exposes a
# call that skipped sudo -n.
# LAB_SUDO_LOG, when set, also records every call this stub passes
# through -- proving a specific command went via sudo -n, not just
# reached the real stub underneath it by some other, unprefixed path.
cat >"$tmp/sudo" <<'STUB'
#!/bin/bash
[ "${1:-}" = "-n" ] && shift
[ -n "${LAB_SUDO_LOG:-}" ] && echo "$*" >>"$LAB_SUDO_LOG"
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
sudolog1="$case1/sudo.log"
: >"$sudolog1"
out1=$(LAB_EVIDENCE_DIR="$evdir1" LAB_SUDO_LOG="$sudolog1" PATH="$tmp:$PATH" "$SCRIPT" case1cell "$work1" 2>&1) || {
	echo "down-cell-test: FAIL -- case 1: refused although the domain never existed" >&2
	echo "$out1" >&2
	fail=1
}
# Proves both the initial existence check and the post-destroy recheck went
# through sudo -n specifically: a call that goes through bare virsh instead
# never reaches this stub at all, so it would never appear in the log --
# a plain pass-through sudo (with no log) cannot tell the two apart.
dominfo_calls1=$(grep -cE '^virsh dominfo lab-case1cell-dockerhost$' "$sudolog1" || true)
if [ "$dominfo_calls1" -ne 2 ]; then
	echo "down-cell-test: FAIL -- case 1: expected 2 sudo -n virsh dominfo calls (initial check + recheck), saw $dominfo_calls1" >&2
	cat "$sudolog1" >&2
	fail=1
fi
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
sudolog2="$case2/sudo.log"
: >"$sudolog2"
if out2=$(LAB_EVIDENCE_DIR="$evdir2" LAB_SUDO_LOG="$sudolog2" PATH="$tmp:$PATH" "$SCRIPT" case2cell "$work2" 2>&1); then
	echo "down-cell-test: FAIL -- case 2: exited 0 although the domain still exists" >&2
	fail=1
else
	out2_captured="$out2"
fi
dominfo_calls2=$(grep -cE '^virsh dominfo lab-case2cell-dockerhost$' "$sudolog2" || true)
if [ "$dominfo_calls2" -ne 2 ]; then
	echo "down-cell-test: FAIL -- case 2: expected 2 sudo -n virsh dominfo calls (initial check + recheck), saw $dominfo_calls2" >&2
	cat "$sudolog2" >&2
	fail=1
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

# Case 4: proves the LAB_SUDO_LOG mechanism above catches a real
# regression on down-cell.sh itself, not only on a well-behaved script.
# Dropping "sudo -n" from just the "domain still exists" re-check (the
# second dominfo call, distinct from the pre-destroy existence check
# above it) is invisible to exit code and output alike: the pass-through
# sudo stub reaches the same stub virsh either way. Mutates a temp copy
# of the real down-cell.sh -- not a fixture -- so this proves the
# mechanism against the actual re-check line, wherever it is in the file.
# shellcheck disable=SC2016 # intentional: literal "$domain", not expansion
orig_recheck_count=$(grep -cE '^if sudo -n virsh dominfo "\$domain" >/dev/null 2>&1; then$' "$SCRIPT")
if [ "$orig_recheck_count" -ne 2 ]; then
	echo "down-cell-test: FAIL -- case 4 setup: expected exactly 2 \"sudo -n virsh dominfo\" existence-check lines in down-cell.sh (initial check + recheck), found $orig_recheck_count -- this test needs updating to match the current script" >&2
	fail=1
else
	mutant_script="$tmp/down-cell-mutant.sh"
	awk '
	/^if sudo -n virsh dominfo "\$domain" >\/dev\/null 2>&1; then$/ {
		n++
		if (n == 2) {
			print "if virsh dominfo \"$domain\" >/dev/null 2>&1; then"
			next
		}
	}
	{ print }
	' "$SCRIPT" >"$mutant_script"
	chmod +x "$mutant_script"
	# shellcheck disable=SC2016 # intentional: literal "$domain", not expansion
	mutated_recheck_count=$(grep -cE '^if virsh dominfo "\$domain" >/dev/null 2>&1; then$' "$mutant_script" || true)
	if [ "$mutated_recheck_count" -ne 1 ]; then
		echo "down-cell-test: FAIL -- case 4 setup: mutation did not produce exactly 1 bare \"virsh dominfo\" re-check line, found $mutated_recheck_count -- the awk pattern needs updating" >&2
		fail=1
	else
		# Same stub shape as case 2: the domain persists no matter what, so
		# the recheck path always runs.
		case4=$(mktemp -d "$tmp/case4-XXXXXX")
		work4="$case4/work"
		mkdir -p "$work4"
		cat >"$tmp/virsh" <<'STUB'
#!/bin/bash
case "$1" in
dominfo) exit 0 ;;
*) exit 0 ;;
esac
STUB
		chmod +x "$tmp/virsh"
		evdir4="$case4/evidence"
		sudolog4="$case4/sudo.log"
		: >"$sudolog4"
		LAB_EVIDENCE_DIR="$evdir4" LAB_SUDO_LOG="$sudolog4" PATH="$tmp:$PATH" "$mutant_script" case4cell "$work4" >/dev/null 2>&1 || true
		mutant_dominfo_calls=$(grep -cE '^virsh dominfo lab-case4cell-dockerhost$' "$sudolog4" || true)
		if [ "$mutant_dominfo_calls" -eq 2 ]; then
			echo "down-cell-test: FAIL -- case 4: the sudo-log mechanism did not catch a bare-virsh re-check; still saw 2 logged calls with the mutant (expected 1: only the untouched initial check goes through sudo)" >&2
			fail=1
		fi
	fi
fi

# Case 5: the source domain persists no matter what (issue #2). The
# docker-host domain never existed, which isolates the
# source domain's own refusal. Must refuse, must not remove $WORK, and
# the recheck must have gone through sudo -n exactly twice -- the same
# shape as case 2's docker-host assertion, but for the source domain.
case5=$(mktemp -d "$tmp/case5-XXXXXX")
work5="$case5/work"
mkdir -p "$work5"
cat >"$tmp/virsh" <<'STUB'
#!/bin/bash
case "$2" in
*-dockerhost) exit 1 ;;
*) exit 0 ;;
esac
STUB
chmod +x "$tmp/virsh"
evdir5="$case5/evidence"
sudolog5="$case5/sudo.log"
: >"$sudolog5"
if out5=$(LAB_EVIDENCE_DIR="$evdir5" LAB_SUDO_LOG="$sudolog5" PATH="$tmp:$PATH" "$SCRIPT" case5cell "$work5" 2>&1); then
	echo "down-cell-test: FAIL -- case 5: exited 0 although the source domain still exists" >&2
	fail=1
else
	out5_captured="$out5"
fi
dominfo_calls5=$(grep -cE '^virsh dominfo lab-case5cell-source$' "$sudolog5" || true)
if [ "$dominfo_calls5" -ne 2 ]; then
	echo "down-cell-test: FAIL -- case 5: expected 2 sudo -n virsh dominfo calls on the source domain (initial check + recheck), saw $dominfo_calls5" >&2
	cat "$sudolog5" >&2
	fail=1
fi
if grep -q "torn down" <<<"${out5_captured:-}"; then
	echo "down-cell-test: FAIL -- case 5: printed the torn-down confirmation although the source domain still exists" >&2
	fail=1
fi
if [ ! -d "$work5" ]; then
	echo "down-cell-test: FAIL -- case 5: work dir was removed although the source domain still exists" >&2
	fail=1
fi

# Case 6: the source domain exists once, then is gone on the recheck
# (issue #2) -- teardown succeeds, which lets this case
# assert destroy/undefine were actually called for it, not just that
# dominfo agreed to be asked. A dominfo call count alone cannot tell
# "destroy ran and the VM died" apart from "destroy never ran and dominfo
# just says so" -- only the log lines below can.
case6=$(mktemp -d "$tmp/case6-XXXXXX")
work6="$case6/work"
mkdir -p "$work6"
cat >"$tmp/virsh" <<STUB
#!/bin/bash
case "\$2" in
*-dockerhost) exit 1 ;;
*-source)
	if [ "\$1" = "dominfo" ]; then
		n=\$(cat "$case6/dominfo-n" 2>/dev/null || echo 0)
		n=\$((n + 1))
		echo "\$n" >"$case6/dominfo-n"
		[ "\$n" -eq 1 ] && exit 0 || exit 1
	fi
	exit 0
	;;
*) exit 0 ;;
esac
STUB
chmod +x "$tmp/virsh"
evdir6="$case6/evidence"
sudolog6="$case6/sudo.log"
: >"$sudolog6"
out6=$(LAB_EVIDENCE_DIR="$evdir6" LAB_SUDO_LOG="$sudolog6" PATH="$tmp:$PATH" "$SCRIPT" case6cell "$work6" 2>&1) || {
	echo "down-cell-test: FAIL -- case 6: teardown failed although the source domain was gone by the recheck" >&2
	echo "$out6" >&2
	fail=1
}
if ! grep -qE '^virsh destroy lab-case6cell-source$' "$sudolog6"; then
	echo "down-cell-test: FAIL -- case 6: the source domain was never destroyed" >&2
	cat "$sudolog6" >&2
	fail=1
fi
if ! grep -qE '^virsh undefine lab-case6cell-source --nvram$' "$sudolog6"; then
	echo "down-cell-test: FAIL -- case 6: the source domain was never undefined" >&2
	cat "$sudolog6" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "down-cell-test: PASS -- all six cases behaved as expected"
