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

# Case 4a: the hook at priority -10, numeric spelling, plus a real rule.
# Must pass.
mkdir -p "$tmp/case-ok-numeric"
cat >"$tmp/case-ok-numeric/nft" <<'EOF'
#!/bin/bash
cat <<'OUT'
table inet ci_dmz {
	chain forward {
		type filter hook forward priority -10; policy accept;
		ip daddr 10.200.0.0/16 accept
	}
}
OUT
EOF
chmod +x "$tmp/case-ok-numeric/nft"
if ! PATH="$tmp/case-ok-numeric:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
	echo "containment-preflight-test: FAIL -- refused a valid numeric -10 hook with a rule" >&2
	fail=1
fi

# Case 4b: the hook at priority -10, symbolic spelling, plus a real rule.
# Must pass.
mkdir -p "$tmp/case-ok-symbolic"
cat >"$tmp/case-ok-symbolic/nft" <<'EOF'
#!/bin/bash
cat <<'OUT'
table inet ci_dmz {
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		ip daddr 10.200.0.0/16 accept
	}
}
OUT
EOF
chmod +x "$tmp/case-ok-symbolic/nft"
if ! PATH="$tmp/case-ok-symbolic:$PATH" "$PREFLIGHT" >/dev/null 2>&1; then
	echo "containment-preflight-test: FAIL -- refused a valid 'filter - 10' hook with a rule" >&2
	fail=1
fi

# Case 5: the hook at priority -10 but the chain enforces nothing --
# just "policy accept" and no rules. Must refuse: a hook with nothing
# behind it is not containment.
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

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "containment-preflight-test: PASS -- all 6 cases behaved as expected"
