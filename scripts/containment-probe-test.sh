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

# A no-op ssh: every real call in the script is wrapped in `|| true`, so
# this only needs to exist and return control.
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
count_file="$tmp/case5-bin/.calls"
n=0
[ -f "\$count_file" ] && n=\$(cat "\$count_file")
n=\$((n + 1))
echo "\$n" >"\$count_file"
if [ "\$n" -eq 1 ]; then
	echo 'ip daddr 192.0.2.0/24 counter packets 0 bytes 0 drop'
else
	echo 'ip daddr 192.0.2.0/24 counter packets 9 bytes 540 drop'
fi
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

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "containment-probe-test: PASS -- all 5 cases behaved as expected"
