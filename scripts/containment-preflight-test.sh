#!/bin/bash
# Refusal tests for containment-preflight.sh (issue #1). CI-safe: every
# case stubs `nft` on PATH, never touches the real lab host or any real
# nftables state. Run by verify.sh on every push.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PREFLIGHT="$REPO_ROOT/scripts/containment-preflight.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail=0

# Case 1: no `nft` at all, or the table/chain does not exist -- today's
# real state on the lab host. Must refuse.
mkdir -p "$tmp/case-missing"
cat >"$tmp/case-missing/nft" <<'EOF'
#!/bin/bash
echo "Error: No such file or directory" >&2
exit 1
EOF
chmod +x "$tmp/case-missing/nft"
if PATH="$tmp/case-missing:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
	echo "containment-preflight-test: FAIL -- passed with a missing ci_dmz table" >&2
	fail=1
fi

# Case 2: the chain exists but has no forward hook (e.g. a chain used for
# something else, or a rename in progress). Must refuse.
mkdir -p "$tmp/case-no-hook"
cat >"$tmp/case-no-hook/nft" <<'EOF'
#!/bin/bash
cat <<'OUT'
table inet ci_dmz {
	chain forward {
		ip daddr 10.200.0.0/16 accept
	}
}
OUT
EOF
chmod +x "$tmp/case-no-hook/nft"
if PATH="$tmp/case-no-hook:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
	echo "containment-preflight-test: FAIL -- passed with no hook line at all" >&2
	fail=1
fi

# Case 3: a forward hook at the wrong priority. Must refuse.
mkdir -p "$tmp/case-wrong-prio"
cat >"$tmp/case-wrong-prio/nft" <<'EOF'
#!/bin/bash
cat <<'OUT'
table inet ci_dmz {
	chain forward {
		type filter hook forward priority 0; policy accept;
	}
}
OUT
EOF
chmod +x "$tmp/case-wrong-prio/nft"
if PATH="$tmp/case-wrong-prio:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
	echo "containment-preflight-test: FAIL -- passed with a priority-0 hook" >&2
	fail=1
fi

# Case 4a: the hook at priority -10, numeric spelling, plus a real
# destination-based drop rule. Must pass.
mkdir -p "$tmp/case-ok-numeric"
cat >"$tmp/case-ok-numeric/nft" <<'EOF'
#!/bin/bash
cat <<'OUT'
table inet ci_dmz {
	chain forward {
		type filter hook forward priority -10; policy accept;
		ip daddr 192.0.2.0/24 drop
	}
}
OUT
EOF
chmod +x "$tmp/case-ok-numeric/nft"
if ! PATH="$tmp/case-ok-numeric:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
	echo "containment-preflight-test: FAIL -- refused a valid numeric -10 hook with a drop rule" >&2
	fail=1
fi

# Case 4b: the hook at priority -10, symbolic spelling, plus a real
# destination-based drop rule. Must pass.
mkdir -p "$tmp/case-ok-symbolic"
cat >"$tmp/case-ok-symbolic/nft" <<'EOF'
#!/bin/bash
cat <<'OUT'
table inet ci_dmz {
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		ip daddr 192.0.2.0/24 drop
	}
}
OUT
EOF
chmod +x "$tmp/case-ok-symbolic/nft"
if ! PATH="$tmp/case-ok-symbolic:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
	echo "containment-preflight-test: FAIL -- refused a valid 'filter - 10' hook with a drop rule" >&2
	fail=1
fi

# Case 5: the hook at priority -10 but the chain enforces nothing at
# all -- just "policy accept" and no rules. Must refuse.
mkdir -p "$tmp/case-hook-no-rules"
cat >"$tmp/case-hook-no-rules/nft" <<'EOF'
#!/bin/bash
cat <<'OUT'
table inet ci_dmz {
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
	}
}
OUT
EOF
chmod +x "$tmp/case-hook-no-rules/nft"
if PATH="$tmp/case-hook-no-rules:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
	echo "containment-preflight-test: FAIL -- passed a hook with no rules behind it" >&2
	fail=1
fi

# Cases 6a-6d: the hook at priority -10 with one rule each that proves
# the chain exists but drops nothing by destination -- an accept, a
# counter, a match with an implicit accept, and a bare comment. All four
# must refuse: none of them is containment.
run_inert_case() {
	local name=$1 rule=$2
	mkdir -p "$tmp/$name"
	cat >"$tmp/$name/nft" <<EOF
#!/bin/bash
cat <<OUT
table inet ci_dmz {
	chain forward {
		type filter hook forward priority -10; policy accept;
		$rule
	}
}
OUT
EOF
	chmod +x "$tmp/$name/nft"
	if PATH="$tmp/$name:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
		echo "containment-preflight-test: FAIL -- passed an inert rule ($name: $rule)" >&2
		fail=1
	fi
}
run_inert_case case-inert-accept 'accept'
run_inert_case case-inert-counter 'counter packets 0 bytes 0'
run_inert_case case-inert-iifname-lo 'iifname "lo" accept'
run_inert_case case-inert-comment 'comment "todo"'

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "containment-preflight-test: PASS -- all 10 cases behaved as expected"
