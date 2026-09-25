#!/bin/bash
# Refusal and pass-path tests for containment-probe.sh (issue #1/#3).
# CI-safe: every case stubs sudo/nft/ssh on PATH, never touches the real
# lab host, a real VM, or any real nftables state. Only documentation-
# range addresses (192.0.2.0/24, RFC 5737) appear in the fixtures.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$REPO_ROOT/scripts/containment-probe.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

work="$tmp/work"
mkdir -p "$work"
: >"$work/known_hosts"

# Pass-through sudo, same shape as down-cell-test.sh's stub.
cat >"$tmp/sudo" <<'STUB'
#!/bin/bash
[ "${1:-}" = "-n" ] && shift
exec "$@"
STUB
chmod +x "$tmp/sudo"

# A no-op ssh: prints nothing, so the script's own CONNECTED/BLOCKED
# marker check never sees a false CONNECTED from this stub.
cat >"$tmp/ssh" <<'STUB'
#!/bin/bash
exit 0
STUB
chmod +x "$tmp/ssh"

# Case 1: no target given. Must refuse before touching nft or ssh at all.
mkdir -p "$tmp/case1-bin"
cp "$tmp/sudo" "$tmp/case1-bin/"
cp "$tmp/ssh" "$tmp/case1-bin/"
cat >"$tmp/case1-bin/nft" <<'STUB'
#!/bin/bash
echo "containment-probe-test: case 1 must not call nft" >&2
exit 1
STUB
chmod +x "$tmp/case1-bin/nft"
if PATH="$tmp/case1-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" >/dev/null 2>&1; then
	echo "containment-probe-test: FAIL -- case 1: passed with zero targets" >&2
	fail=1
fi

# Case 2: no /24 drop rule anywhere in ci_dmz. Must refuse.
mkdir -p "$tmp/case2-bin"
cp "$tmp/sudo" "$tmp/case2-bin/"
cp "$tmp/ssh" "$tmp/case2-bin/"
cat >"$tmp/case2-bin/nft" <<'STUB'
#!/bin/bash
cat <<'OUT'
table inet ci_dmz {
	chain forward {
		ip daddr 192.0.2.0/32 counter packets 0 bytes 0 drop
	}
}
OUT
STUB
chmod +x "$tmp/case2-bin/nft"
if PATH="$tmp/case2-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" 192.0.2.50 >/dev/null 2>&1; then
	echo "containment-probe-test: FAIL -- case 2: passed with no /24 drop rule present" >&2
	fail=1
fi

# Case 3: the /24 drop counter does not move between before and after.
# Must refuse -- traffic reached the rule's *text* but nothing proves it
# was actually exercised.
mkdir -p "$tmp/case3-bin"
cp "$tmp/sudo" "$tmp/case3-bin/"
cp "$tmp/ssh" "$tmp/case3-bin/"
cat >"$tmp/case3-bin/nft" <<'STUB'
#!/bin/bash
echo 'ip daddr 192.0.2.0/24 counter packets 0 bytes 0 drop'
STUB
chmod +x "$tmp/case3-bin/nft"
if PATH="$tmp/case3-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" 192.0.2.50 >/dev/null 2>&1; then
	echo "containment-probe-test: FAIL -- case 3: passed although the /24 drop counter never rose" >&2
	fail=1
fi

# Case 4: the /24 drop rule vanishes between the before and after read
# (a rule reload mid-probe). Must refuse.
mkdir -p "$tmp/case4-bin"
cp "$tmp/sudo" "$tmp/case4-bin/"
cp "$tmp/ssh" "$tmp/case4-bin/"
cat >"$tmp/case4-bin/nft" <<STUB
#!/bin/bash
count_file="$tmp/case4-bin/.calls"
n=0
[ -f "\$count_file" ] && n=\$(cat "\$count_file")
n=\$((n + 1))
echo "\$n" >"\$count_file"
if [ "\$n" -eq 1 ]; then
	echo 'ip daddr 192.0.2.0/24 counter packets 0 bytes 0 drop'
else
	echo 'table inet ci_dmz { chain forward { } }'
fi
STUB
chmod +x "$tmp/case4-bin/nft"
if PATH="$tmp/case4-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" 192.0.2.50 >/dev/null 2>&1; then
	echo "containment-probe-test: FAIL -- case 4: passed although the /24 drop rule disappeared mid-probe" >&2
	fail=1
fi

# Case 5: the /24 drop counter rises between before and after. Must pass
# -- this is the actual proof the check exists for.
mkdir -p "$tmp/case5-bin"
cp "$tmp/sudo" "$tmp/case5-bin/"
cp "$tmp/ssh" "$tmp/case5-bin/"
cat >"$tmp/case5-bin/nft" <<STUB
#!/bin/bash
# Each read must be higher than the last: the script reads the counter
# twice per attempt now (before and after that one attempt), not once
# for the whole run, so a stub that only changes value once no longer
# reflects a real counter (see case 9's own comment for why that gap
# matters).
count_file="$tmp/case5-bin/.calls"
n=0
[ -f "\$count_file" ] && n=\$(cat "\$count_file")
n=\$((n + 1))
echo "\$n" >"\$count_file"
echo "ip daddr 192.0.2.0/24 counter packets \$((n * 3)) bytes 0 drop"
STUB
chmod +x "$tmp/case5-bin/nft"
out5=$(PATH="$tmp/case5-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" 192.0.2.50 192.0.2.51 2>&1) || {
	echo "containment-probe-test: FAIL -- case 5: refused although the /24 drop counter rose" >&2
	echo "$out5" >&2
	fail=1
}
if ! grep -q 'PASS' <<<"$out5"; then
	echo "containment-probe-test: FAIL -- case 5: did not print a PASS line" >&2
	echo "$out5" >&2
	fail=1
fi

# Case 6: the counter rises exactly as case 5's, but one attempt actually
# connects. Must refuse -- a rising drop counter proves nothing about the
# other targets/ports the probe also tried, so a live connection anywhere
# must fail the whole run on its own, independent of the counter. The
# stub stands in for the remote read-connect-and-report command: a bare
# "|RC=0" is an empty connect message with a 0 exit, i.e. CONNECTED.
mkdir -p "$tmp/case6-bin"
cp "$tmp/sudo" "$tmp/case6-bin/"
cat >"$tmp/case6-bin/ssh" <<'STUB'
#!/bin/bash
printf '|RC=0'
STUB
chmod +x "$tmp/case6-bin/ssh"
cat >"$tmp/case6-bin/nft" <<STUB
#!/bin/bash
# Monotonic, same reasoning as case 5's stub: a real counter never
# reads the same value twice across the run's repeated before/after
# reads.
count_file="$tmp/case6-bin/.calls"
n=0
[ -f "\$count_file" ] && n=\$(cat "\$count_file")
n=\$((n + 1))
echo "\$n" >"\$count_file"
echo "ip daddr 192.0.2.0/24 counter packets \$((n * 3)) bytes 0 drop"
STUB
chmod +x "$tmp/case6-bin/nft"
if out6=$(PATH="$tmp/case6-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" 192.0.2.50 2>&1); then
	echo "containment-probe-test: FAIL -- case 6: passed although a target actually connected" >&2
	echo "$out6" >&2
	fail=1
fi
if ! grep -q 'FAIL -- CONNECTED' <<<"${out6:-}"; then
	echo "containment-probe-test: FAIL -- case 6: did not name the connected target" >&2
	echo "${out6:-}" >&2
	fail=1
fi

# Case 7: no port answers, but the remote connect attempt comes straight
# back with "connection refused" -- a RST from the target's own kernel,
# proving the SYN got past the firewall. Must refuse and call it REACHED,
# never BLOCKED, even though the drop counter also rises (the counter
# proves some other packet was dropped, not this one).
mkdir -p "$tmp/case7-bin"
cp "$tmp/sudo" "$tmp/case7-bin/"
cat >"$tmp/case7-bin/ssh" <<'STUB'
#!/bin/bash
printf 'bash: connect: Connection refused|RC=1'
STUB
chmod +x "$tmp/case7-bin/ssh"
cat >"$tmp/case7-bin/nft" <<STUB
#!/bin/bash
# Monotonic, same reasoning as case 5's stub.
count_file="$tmp/case7-bin/.calls"
n=0
[ -f "\$count_file" ] && n=\$(cat "\$count_file")
n=\$((n + 1))
echo "\$n" >"\$count_file"
echo "ip daddr 192.0.2.0/24 counter packets \$((n * 3)) bytes 0 drop"
STUB
chmod +x "$tmp/case7-bin/nft"
if out7=$(PATH="$tmp/case7-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" 192.0.2.50 2>&1); then
	echo "containment-probe-test: FAIL -- case 7: passed although a target reset the connection" >&2
	echo "$out7" >&2
	fail=1
fi
if ! grep -q 'FAIL -- REACHED' <<<"${out7:-}"; then
	echo "containment-probe-test: FAIL -- case 7: a connection refused was not classified REACHED" >&2
	echo "${out7:-}" >&2
	fail=1
fi

# Case 8: no port answers, and the remote connect attempt fails fast with
# "no route to host" (a routing fact, not a firewall drop). Must PASS --
# this must never be classified REACHED just because it failed fast
# rather than timing out.
mkdir -p "$tmp/case8-bin"
cp "$tmp/sudo" "$tmp/case8-bin/"
cat >"$tmp/case8-bin/ssh" <<'STUB'
#!/bin/bash
printf 'bash: connect: No route to host|RC=1'
STUB
chmod +x "$tmp/case8-bin/ssh"
cat >"$tmp/case8-bin/nft" <<STUB
#!/bin/bash
# Monotonic, same reasoning as case 5's stub.
count_file="$tmp/case8-bin/.calls"
n=0
[ -f "\$count_file" ] && n=\$(cat "\$count_file")
n=\$((n + 1))
echo "\$n" >"\$count_file"
echo "ip daddr 192.0.2.0/24 counter packets \$((n * 3)) bytes 0 drop"
STUB
chmod +x "$tmp/case8-bin/nft"
out8=$(PATH="$tmp/case8-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" 192.0.2.50 2>&1) || {
	echo "containment-probe-test: FAIL -- case 8: refused although \"no route\" is not evidence of reaching the target" >&2
	echo "$out8" >&2
	fail=1
}
if ! grep -q 'PASS' <<<"$out8"; then
	echo "containment-probe-test: FAIL -- case 8: did not print a PASS line" >&2
	echo "$out8" >&2
	fail=1
fi

# Case 9: 2 targets x 3 ports = 6 attempts. Attempt 1 is genuinely
# blocked; every attempt after it leaks silently (times out, but
# nothing actually dropped it). The /24 drop counter is state-driven,
# not indexed by call number: the fake connect step is the only thing
# that ever changes it (+2 for a blocked attempt, matching the measured
# real-iptables SYN+retry ratio, +0 for a leak), and the nft stub always
# reports whatever the true running value currently is, however many
# times or in whatever order the probe calls it. A call-number-indexed
# stub cannot do this: a mutant that changes how many times, or when,
# the probe reads the counter (e.g. reusing the initial "before" read
# as every attempt's "pre" instead of a fresh per-attempt read) still
# gets a plausible-looking value keyed to its position in a canned
# sequence, and can pass by accident; a state-driven stub gives every
# mutant the one true value there actually is to work with, so it
# cannot be fooled by a shifted call count.
mkdir -p "$tmp/case9-bin"
cp "$tmp/sudo" "$tmp/case9-bin/"
echo 0 >"$tmp/case9-bin/.counter"

# ssh stub simulates the remote connect attempt and is the only thing
# that ever changes the shared counter file. Its own call-count file
# only picks which attempt this is, never fabricates the counter's
# value. Every attempt times out either way (rc 124, via
# containment-probe.sh's own fallback for a failed ssh call) -- nothing
# ever answers, blocked or leaking.
cat >"$tmp/case9-bin/ssh" <<STUB
#!/bin/bash
call_file="$tmp/case9-bin/.ssh-calls"
n=0
[ -f "\$call_file" ] && n=\$(cat "\$call_file")
n=\$((n + 1))
echo "\$n" >"\$call_file"
counter_file="$tmp/case9-bin/.counter"
cur=\$(cat "\$counter_file")
if [ "\$n" -eq 1 ]; then
	echo "\$((cur + 2))" >"\$counter_file"
fi
exit 1
STUB
chmod +x "$tmp/case9-bin/ssh"
cat >"$tmp/case9-bin/nft" <<STUB
#!/bin/bash
counter_file="$tmp/case9-bin/.counter"
[ -f "\$counter_file" ] || echo 0 >"\$counter_file"
echo "ip daddr 192.0.2.0/24 counter packets \$(cat "\$counter_file") bytes 0 drop"
STUB
chmod +x "$tmp/case9-bin/nft"
if out9=$(PATH="$tmp/case9-bin:$PATH" "$SCRIPT" 10.200.255.10 "$work" 192.0.2.50 192.0.2.51 2>&1); then
	echo "containment-probe-test: FAIL -- case 9: passed although 5 of 6 attempts leaked" >&2
	echo "$out9" >&2
	fail=1
fi
leaks=$(grep -c 'FAIL -- LEAK' <<<"${out9:-}" || true)
if [ "$leaks" -ne 5 ]; then
	echo "containment-probe-test: FAIL -- case 9: expected 5 leaks (every attempt but the first), got $leaks" >&2
	echo "${out9:-}" >&2
	fail=1
fi
if grep -q 'FAIL -- LEAK 192.0.2.50:80;' <<<"${out9:-}"; then
	echo "containment-probe-test: FAIL -- case 9: the first attempt (genuinely blocked) was wrongly flagged as a leak" >&2
	echo "${out9:-}" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "containment-probe-test: PASS -- all 9 cases behaved as expected"
