#!/bin/bash
# Refusal and idempotency tests for lab-seg-firewall.sh (issue #1).
# CI-safe: every case runs against a stateful fake iptables/ip6tables on
# PATH, never the real lab host or any real netfilter state. Run by
# verify.sh on every push.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIREWALL="$REPO_ROOT/scripts/lab-seg-firewall.sh"

fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/fake-ipt" <<'STUB'
#!/bin/bash
# Stateful fake iptables/ip6tables. STATE_DIR selects which table's state
# to use, so v4 and v6 never share rows in the same test case.
set -euo pipefail
: "${STATE_DIR:?STATE_DIR must be set}"
mkdir -p "$STATE_DIR"
CHAINS_FILE="$STATE_DIR/chains"
touch "$CHAINS_FILE"

chain_exists() { grep -qxF -- "$1" "$CHAINS_FILE" 2>/dev/null; }
rules_file() { echo "$STATE_DIR/rules_$1"; }

case "$1" in
-N)
	chain=$2
	if chain_exists "$chain"; then
		exit 1
	fi
	echo "$chain" >>"$CHAINS_FILE"
	touch "$(rules_file "$chain")"
	;;
-C)
	chain=$2
	shift 2
	rule="$*"
	f=$(rules_file "$chain")
	[ -f "$f" ] && grep -qxF -- "$rule" "$f"
	;;
-A)
	chain=$2
	shift 2
	rule="$*"
	f=$(rules_file "$chain")
	touch "$f"
	echo "$rule" >>"$f"
	;;
-D)
	chain=$2
	shift 2
	rule="$*"
	f=$(rules_file "$chain")
	[ -f "$f" ] || exit 1
	if grep -qxF -- "$rule" "$f"; then
		tmp2=$(mktemp)
		awk -v r="$rule" '($0==r && !done){done=1; next} {print}' "$f" >"$tmp2"
		mv "$tmp2" "$f"
		exit 0
	fi
	exit 1
	;;
-I)
	chain=$2
	pos=$3
	shift 3
	rule="$*"
	f=$(rules_file "$chain")
	touch "$f"
	# LAB_SEG_TEST_INSERT_BUG exists only for the two dedicated landing-
	# check cases below; every other case leaves it unset and this block
	# is a no-op.
	if [ "${LAB_SEG_TEST_INSERT_BUG:-}" = "wrong-position" ]; then
		pos=1
	fi
	tmp2=$(mktemp)
	awk -v r="$rule" -v p="$pos" 'NR==p{print r} {print} END{if (p>NR) print r}' "$f" >"$tmp2"
	mv "$tmp2" "$f"
	if [ "${LAB_SEG_TEST_INSERT_BUG:-}" = "concurrent-shift" ] && [ "${rule#*lab segments}" != "$rule" ]; then
		# Stands in for an unrelated, concurrent actor landing a rule
		# above the DMZ jump in the instant between this script's own
		# insert and its post-insert reads -- both jumps shift down
		# together, staying correctly adjacent.
		tmp3=$(mktemp)
		{ echo '-m comment --comment "concurrent actor" -j ACCEPT'; cat "$f"; } >"$tmp3"
		mv "$tmp3" "$f"
	fi
	;;
-L)
	chain=$2
	shift 2
	numbered=0
	for a in "$@"; do [ "$a" = "--line-numbers" ] && numbered=1; done
	if ! chain_exists "$chain"; then
		exit 1
	fi
	f=$(rules_file "$chain")
	touch "$f"
	if [ "$numbered" -eq 1 ]; then
		awk '{print NR, $0}' "$f"
	else
		cat "$f"
	fi
	;;
*)
	echo "fake-ipt: unsupported args: $*" >&2
	exit 2
	;;
esac
STUB
chmod +x "$tmp/fake-ipt"
ln -s fake-ipt "$tmp/iptables"
ln -s fake-ipt "$tmp/ip6tables"

# Two dispatchers, one per protocol, each reading its own state dir from
# an env var set fresh by run_firewall on every call -- this is what lets
# one test case give lab-seg-firewall.sh independent v4 and v6 state.
cat >"$tmp/ipt-v4" <<EOF
#!/bin/bash
exec env STATE_DIR="\$LAB_SEG_TEST_V4_STATE" "$tmp/fake-ipt" "\$@"
EOF
cat >"$tmp/ipt-v6" <<EOF
#!/bin/bash
exec env STATE_DIR="\$LAB_SEG_TEST_V6_STATE" "$tmp/fake-ipt" "\$@"
EOF
chmod +x "$tmp/ipt-v4" "$tmp/ipt-v6"

# Seeds a chain with rules directly via the stub, standing in for state
# the real DMZ script already put there before lab-seg-firewall.sh ever
# runs.
seed_chain() {
	local state=$1 chain=$2
	shift 2
	STATE_DIR="$state" PATH="$tmp:$PATH" iptables -N "$chain" >/dev/null 2>&1 || true
	for rule in "$@"; do
		# shellcheck disable=SC2086
		STATE_DIR="$state" PATH="$tmp:$PATH" iptables -A "$chain" $rule >/dev/null
	done
}

run_firewall() {
	local v4state=$1 v6state=$2
	LAB_SEG_TEST_V4_STATE="$v4state" LAB_SEG_TEST_V6_STATE="$v6state" \
		LAB_SEG_IPTABLES="$tmp/ipt-v4" LAB_SEG_IP6TABLES="$tmp/ipt-v6" \
		PATH="$tmp:$PATH" "$FIREWALL"
}

line_of() {
	local state=$1 chain=$2 comment=$3
	STATE_DIR="$state" PATH="$tmp:$PATH" iptables -L "$chain" -n --line-numbers 2>/dev/null |
		awk -v c="$comment" '$0 ~ c {print $1; exit}'
}

count_of() {
	local state=$1 chain=$2 comment=$3
	STATE_DIR="$state" PATH="$tmp:$PATH" iptables -L "$chain" -n --line-numbers 2>/dev/null |
		awk -v c="$comment" '$0 ~ c {n++} END{print n+0}'
}

new_case() {
	local d
	d=$(mktemp -d "$tmp/case-XXXXXX")
	echo "$d"
}

# Case 1: no "CI DMZ containment" jump in iptables DOCKER-USER at all.
# Must refuse before ever touching ip6tables.
case1=$(new_case)
v4=$case1/v4
seed_chain "$v4" DOCKER-USER
if run_firewall "$v4" "$case1/v6-unused" >/dev/null 2>&1; then
	echo "lab-seg-firewall-test: FAIL -- case 1: passed with no DMZ jump in iptables DOCKER-USER" >&2
	fail=1
fi

# Case 2: both DMZ jumps present -- iptables DOCKER-USER, ip6tables
# FORWARD. Must install a jump directly after each, and must not touch
# ip6 DOCKER-USER at all (this design never creates or reads it).
case2=$(new_case)
v4=$case2/v4
v6=$case2/v6
seed_chain "$v4" DOCKER-USER '-j ACCEPT' # a harmless earlier rule
seed_chain "$v4" DOCKER-USER '-m comment --comment "CI DMZ containment" -j CI-DMZ-FWD'
seed_chain "$v6" FORWARD '-m comment --comment "CI DMZ containment" -j CI-DMZ-V6'
out=$(run_firewall "$v4" "$v6" 2>&1) || {
	echo "lab-seg-firewall-test: FAIL -- case 2: refused with both DMZ jumps present" >&2
	echo "$out" >&2
	fail=1
}
dmz_line=$(line_of "$v4" DOCKER-USER "CI DMZ containment")
lab_line=$(line_of "$v4" DOCKER-USER "lab segments")
if [ -z "$lab_line" ] || [ "$lab_line" -ne "$((dmz_line + 1))" ]; then
	echo "lab-seg-firewall-test: FAIL -- case 2: v4 jump (line ${lab_line:-none}) is not directly after the DMZ jump (line $dmz_line)" >&2
	fail=1
fi
v6_dmz_line=$(line_of "$v6" FORWARD "CI DMZ containment")
v6_lab_line=$(line_of "$v6" FORWARD "lab segments")
if [ -z "$v6_lab_line" ] || [ "$v6_lab_line" -ne "$((v6_dmz_line + 1))" ]; then
	echo "lab-seg-firewall-test: FAIL -- case 2: v6 jump (line ${v6_lab_line:-none}) is not directly after the v6 DMZ jump in FORWARD (line $v6_dmz_line)" >&2
	fail=1
fi
if STATE_DIR="$v6" PATH="$tmp:$PATH" iptables -L DOCKER-USER -n >/dev/null 2>&1; then
	echo "lab-seg-firewall-test: FAIL -- case 2: an ip6 DOCKER-USER chain was created; this design must never touch it" >&2
	fail=1
fi

# The LAB-SEG rule body itself, not just the jump to it: a mutant that
# drops "-o lab-br+" or reduces the rule to a bare "-j ACCEPT" (accepting
# everything forwarded after the DMZ jump, not just bridged lab traffic)
# must be caught here.
expected_rule='-m physdev --physdev-is-bridged -i lab-br+ -o lab-br+ -j ACCEPT'
v4_labseg_rule=$(cat "$v4/rules_LAB-SEG" 2>/dev/null || true)
if [ "$v4_labseg_rule" != "$expected_rule" ]; then
	echo "lab-seg-firewall-test: FAIL -- case 2: v4 LAB-SEG chain rule body is \"$v4_labseg_rule\", not \"$expected_rule\"" >&2
	fail=1
fi
v6_labseg_rule=$(cat "$v6/rules_LAB-SEG" 2>/dev/null || true)
if [ "$v6_labseg_rule" != "$expected_rule" ]; then
	echo "lab-seg-firewall-test: FAIL -- case 2: v6 LAB-SEG chain rule body is \"$v6_labseg_rule\", not \"$expected_rule\"" >&2
	fail=1
fi

# Case 3: iptables DOCKER-USER has its DMZ jump, but ip6tables FORWARD
# does not. Must refuse -- never install the v6 rule at a guessed
# position (e.g. the top of FORWARD).
case3=$(new_case)
v4=$case3/v4
v6=$case3/v6
seed_chain "$v4" DOCKER-USER '-m comment --comment "CI DMZ containment" -j CI-DMZ-FWD'
seed_chain "$v6" FORWARD '-j ACCEPT'
if run_firewall "$v4" "$v6" >/dev/null 2>&1; then
	echo "lab-seg-firewall-test: FAIL -- case 3: passed with no DMZ jump in ip6tables FORWARD" >&2
	fail=1
fi
if [ "$(count_of "$v6" FORWARD "lab segments")" -ne 0 ]; then
	echo "lab-seg-firewall-test: FAIL -- case 3: a v6 jump was installed anyway despite the refusal" >&2
	fail=1
fi

# Case 4: idempotency. Two full runs over the same state (both DMZ jumps
# present) must leave exactly one lab-segments jump in each chain, and
# must leave the DMZ script's own jumps exactly as they were.
case4=$(new_case)
v4=$case4/v4
v6=$case4/v6
seed_chain "$v4" DOCKER-USER '-m comment --comment "CI DMZ containment" -j CI-DMZ-FWD'
seed_chain "$v6" FORWARD '-m comment --comment "CI DMZ containment" -j CI-DMZ-V6'
run_firewall "$v4" "$v6" >/dev/null
run_firewall "$v4" "$v6" >/dev/null
if [ "$(count_of "$v4" DOCKER-USER "lab segments")" -ne 1 ]; then
	echo "lab-seg-firewall-test: FAIL -- case 4: v4 re-run left more than one lab-segments jump" >&2
	fail=1
fi
if [ "$(count_of "$v6" FORWARD "lab segments")" -ne 1 ]; then
	echo "lab-seg-firewall-test: FAIL -- case 4: v6 re-run left more than one lab-segments jump" >&2
	fail=1
fi
if [ "$(count_of "$v4" DOCKER-USER "CI DMZ containment")" -ne 1 ] ||
	[ "$(count_of "$v6" FORWARD "CI DMZ containment")" -ne 1 ]; then
	echo "lab-seg-firewall-test: FAIL -- case 4: the DMZ script's own jumps were not left alone across a re-run" >&2
	fail=1
fi

# Case 5: iptables DOCKER-USER does not exist as a chain at all (not
# merely missing the DMZ jump). Must refuse loudly, never exit silently.
case5=$(new_case)
v4=$case5/v4-nonexistent
v6=$case5/v6-unused
if out=$(run_firewall "$v4" "$v6" 2>&1); then
	echo "lab-seg-firewall-test: FAIL -- case 5: passed with no DOCKER-USER chain at all" >&2
	fail=1
fi
if ! grep -q "does not exist" <<<"$out"; then
	echo "lab-seg-firewall-test: FAIL -- case 5: no loud refusal message when DOCKER-USER does not exist at all" >&2
	echo "$out" >&2
	fail=1
fi

# Case 6: a broken insert lands the new jump at the wrong position,
# ignoring the requested line entirely. v6 is seeded validly (unlike
# cases 1/3/5's v6-unused) so a passing run would go on to succeed
# outright -- nothing else in this run would otherwise catch the v4
# bug (there is no RETURN and no stray jump, and no external position
# assertion runs against this case), so this proves the landing check
# has reachable value on its own, not just alongside case 7's
# reordering assertion below or the RETURN guard. Must refuse.
case6=$(new_case)
v4=$case6/v4
v6=$case6/v6
seed_chain "$v4" DOCKER-USER '-j ACCEPT' # a harmless earlier rule
seed_chain "$v4" DOCKER-USER '-m comment --comment "CI DMZ containment" -j CI-DMZ-FWD'
seed_chain "$v6" FORWARD '-m comment --comment "CI DMZ containment" -j CI-DMZ-V6'
if LAB_SEG_TEST_INSERT_BUG=wrong-position run_firewall "$v4" "$v6" >/dev/null 2>&1; then
	echo "lab-seg-firewall-test: FAIL -- case 6: passed although the insert landed at the wrong position" >&2
	fail=1
fi

# Case 7: a benign, concurrent insert lands above the DMZ jump in the
# instant after this script's own insert -- both jumps shift down
# together and stay correctly adjacent. Must NOT refuse: this is what
# tells a fresh re-read of the DMZ jump's position (compared against
# itself, both taken after the insert) apart from comparing back
# against the value read before the insert, which would see only the
# stale, pre-shift position and refuse a state that is actually fine.
case7=$(new_case)
v4=$case7/v4
v6=$case7/v6
seed_chain "$v4" DOCKER-USER '-j ACCEPT' # a harmless earlier rule
seed_chain "$v4" DOCKER-USER '-m comment --comment "CI DMZ containment" -j CI-DMZ-FWD'
seed_chain "$v6" FORWARD '-m comment --comment "CI DMZ containment" -j CI-DMZ-V6'
if ! out=$(LAB_SEG_TEST_INSERT_BUG=concurrent-shift run_firewall "$v4" "$v6" 2>&1); then
	echo "lab-seg-firewall-test: FAIL -- case 7: refused although its own jump is still directly after the (shifted) DMZ jump" >&2
	echo "$out" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "lab-seg-firewall-test: fake-ipt cases PASS -- 7 cases behaved as expected"

# Cases 8-12 run against the real iptables/ip6tables binaries in a fresh
# user+network namespace (unshare -rnm), never the fake above: real
# `-L -n --line-numbers` prints a target NAME in its own column
# ("RETURN"), never a "-j RETURN" flag pair, and only the real binary
# proves the RETURN guard, the post-delete re-read, and a genuine
# rule-add failure against that.
if ! unshare -rnm true 2>/dev/null; then
	if [ "${CI:-}" = "true" ]; then
		echo "lab-seg-firewall-test: FAIL -- unshare -rnm not available in CI; a gate never goes quietly green" >&2
		exit 1
	fi
	echo "lab-seg-firewall-test: SKIP -- unshare -rnm not available here (not CI)" >&2
	echo "lab-seg-firewall-test: PASS -- 7 fake-ipt cases behaved as expected, real-iptables cases skipped"
	exit 0
fi

# $1 is FIREWALL, expanded only once unshare runs it -- single quotes
# are deliberate.
# shellcheck disable=SC2016
real_inner='
set -euo pipefail
PATH=/usr/sbin:/usr/bin:$PATH
mount -t sysfs sysfs /sys
ip link set lo up

FIREWALL="$1"
fail=0

# Case 8: the DMZ jump is present, but an earlier, unconditional RETURN
# already sits above where the LAB-SEG jump would land against real
# iptables. Must refuse instead of exiting 0.
iptables -N DOCKER-USER
iptables -A DOCKER-USER -j RETURN
iptables -A DOCKER-USER -m comment --comment "CI DMZ containment" -j ACCEPT
ip6tables -A FORWARD -m comment --comment "CI DMZ containment" -j ACCEPT
if LAB_SEG_IPTABLES=iptables LAB_SEG_IP6TABLES=ip6tables "$FIREWALL" >/dev/null 2>&1; then
	echo "lab-seg-firewall-test: FAIL -- case 8: passed although its own jump would land after a real RETURN in DOCKER-USER" >&2
	fail=1
fi

# Case 9: a stray LAB-SEG-commented jump already sits ABOVE the DMZ
# jump before this run (leftover state, a hand edit). delete_own_jump
# removes it, which shifts the DMZ jump up by one line -- a dmz_line
# read before that removal is stale by the time it is used to insert.
iptables -F DOCKER-USER
iptables -N LAB-SEG 2>/dev/null || true
iptables -A LAB-SEG -m physdev --physdev-is-bridged -i lab-br+ -o lab-br+ -j ACCEPT 2>/dev/null || true
iptables -A DOCKER-USER -m comment --comment "lab segments" -j LAB-SEG
iptables -A DOCKER-USER -m comment --comment "CI DMZ containment" -j ACCEPT
if ! LAB_SEG_IPTABLES=iptables LAB_SEG_IP6TABLES=ip6tables "$FIREWALL" >/dev/null 2>&1; then
	echo "lab-seg-firewall-test: FAIL -- case 9: refused with a stray jump above the DMZ jump, wanted a correct re-landing" >&2
	fail=1
fi
listing=$(iptables -L DOCKER-USER -n --line-numbers 2>/dev/null)
dmz_line=$(awk "\$0 ~ /CI DMZ containment/ {print \$1; exit}" <<<"$listing")
lab_line=$(awk "\$0 ~ /lab segments/ {print \$1; exit}" <<<"$listing")
if [ "$(grep -c "lab segments" <<<"$listing")" -ne 1 ] || [ -z "$dmz_line" ] || [ "$lab_line" != "$((dmz_line + 1))" ]; then
	echo "lab-seg-firewall-test: FAIL -- case 9: expected exactly one lab-segments jump directly after the DMZ jump, got:" >&2
	echo "$listing" >&2
	fail=1
fi

# Case 10: v4 is entirely fine, but the v6 FORWARD chain has an
# unconditional RETURN sitting above where its own jump would land.
# Must refuse overall, and must not leave the v4 jump installed either
# -- all or nothing across both protocols, proven against real iptables
# state, not just by reading the script.
iptables -F DOCKER-USER
ip6tables -F FORWARD
iptables -A DOCKER-USER -m comment --comment "CI DMZ containment" -j ACCEPT
ip6tables -A FORWARD -j RETURN
ip6tables -A FORWARD -m comment --comment "CI DMZ containment" -j ACCEPT
if LAB_SEG_IPTABLES=iptables LAB_SEG_IP6TABLES=ip6tables "$FIREWALL" >/dev/null 2>&1; then
	echo "lab-seg-firewall-test: FAIL -- case 10: passed although the v6 jump would land after a real RETURN in FORWARD" >&2
	fail=1
fi
if [ "$(iptables -L DOCKER-USER -n --line-numbers 2>/dev/null | grep -c "lab segments")" -ne 0 ]; then
	echo "lab-seg-firewall-test: FAIL -- case 10: the v4 jump was left installed after the v6 refusal, not rolled back" >&2
	fail=1
fi

# Case 11: a conditional RETURN (matches only tcp/22, not all traffic)
# sits above the DMZ jump. Must still refuse -- this script cannot
# prove lab traffic never matches it -- but the message must call it
# conditional, never claim it "would never run", since most traffic
# still reaches the jump below it.
iptables -F DOCKER-USER
ip6tables -F FORWARD
iptables -A DOCKER-USER -p tcp --dport 22 -j RETURN
iptables -A DOCKER-USER -m comment --comment "CI DMZ containment" -j ACCEPT
ip6tables -A FORWARD -m comment --comment "CI DMZ containment" -j ACCEPT
if out=$(LAB_SEG_IPTABLES=iptables LAB_SEG_IP6TABLES=ip6tables "$FIREWALL" 2>&1); then
	echo "lab-seg-firewall-test: FAIL -- case 11: passed although a conditional RETURN sits above the DMZ jump" >&2
	fail=1
fi
if ! grep -q "conditional RETURN" <<<"$out" || grep -q "unconditional RETURN" <<<"$out"; then
	echo "lab-seg-firewall-test: FAIL -- case 11: refusal message did not correctly call this RETURN conditional" >&2
	echo "$out" >&2
	fail=1
fi

# Case 12: the LAB-SEG rule-add itself fails against real iptables (the
# regression this case guards: build_chain runs inside a subshell whose
# own -e is off, so only its own explicit check -- not -e -- can catch
# this). Must not report "installed" and must exit non-zero.
iptables -F DOCKER-USER
ip6tables -F FORWARD
iptables -F LAB-SEG 2>/dev/null || true
iptables -X LAB-SEG 2>/dev/null || true
iptables -A DOCKER-USER -m comment --comment "CI DMZ containment" -j ACCEPT
ip6tables -A FORWARD -m comment --comment "CI DMZ containment" -j ACCEPT
if out=$(LAB_SEG_IPTABLES="$2" LAB_SEG_IP6TABLES=ip6tables "$FIREWALL" 2>&1); then
	echo "lab-seg-firewall-test: FAIL -- case 12: passed although the LAB-SEG rule add failed" >&2
	fail=1
fi
if grep -qi "installed" <<<"$out"; then
	echo "lab-seg-firewall-test: FAIL -- case 12: claimed installed although the rule add failed" >&2
	echo "$out" >&2
	fail=1
fi
if [ "$(iptables -L DOCKER-USER -n --line-numbers 2>/dev/null | grep -c "lab segments")" -ne 0 ]; then
	echo "lab-seg-firewall-test: FAIL -- case 12: a lab-segments jump was left installed despite the rule-add failure" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "lab-seg-firewall-test: real-iptables cases PASS -- 5 cases behaved as expected"
'

# Passes every call through to the real binary except the one this case
# needs to fail: "-A LAB-SEG ..." is build_chain's own rule-add, and
# nothing else in this script ever adds to that chain by that name.
cat >"$tmp/ipt-fail-add" <<'WRAP'
#!/bin/bash
if [ "$1" = "-A" ] && [ "$2" = "LAB-SEG" ]; then
	echo "ipt-fail-add: simulated failure" >&2
	exit 1
fi
exec iptables "$@"
WRAP
chmod +x "$tmp/ipt-fail-add"

unshare -rnm bash -c "$real_inner" bash "$FIREWALL" "$tmp/ipt-fail-add"
echo "lab-seg-firewall-test: PASS -- all 12 cases behaved as expected"
