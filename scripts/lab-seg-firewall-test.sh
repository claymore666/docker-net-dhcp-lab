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
	tmp2=$(mktemp)
	awk -v r="$rule" -v p="$pos" 'NR==p{print r} {print} END{if (p>NR) print r}' "$f" >"$tmp2"
	mv "$tmp2" "$f"
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

# Case 6: the DMZ jump is present, but an earlier, unconditional RETURN
# already sits above where the LAB-SEG jump would land. Installing the
# jump there would leave it dead on arrival; must verify the final order
# and refuse instead of exiting 0.
case6=$(new_case)
v4=$case6/v4
v6=$case6/v6
seed_chain "$v4" DOCKER-USER '-j RETURN'
seed_chain "$v4" DOCKER-USER '-m comment --comment "CI DMZ containment" -j CI-DMZ-FWD'
seed_chain "$v6" FORWARD '-m comment --comment "CI DMZ containment" -j CI-DMZ-V6'
if run_firewall "$v4" "$v6" >/dev/null 2>&1; then
	echo "lab-seg-firewall-test: FAIL -- case 6: passed although its own jump would land after an earlier RETURN in DOCKER-USER" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "lab-seg-firewall-test: PASS -- all 6 cases behaved as expected"
