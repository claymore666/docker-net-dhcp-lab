#!/bin/bash
# Refuse to attach a VM to net-mgmt unless the host's ci_dmz forward hook
# is actually in place and enforcing something (issue #1). ci_dmz itself
# is a separate host fix, tracked outside this repo; this script only
# checks it, it never creates or edits it.
#
# Exit 0: the hook is present at priority -10 AND the chain has at least
# one rule beyond the hook/policy line. Exit 1 otherwise, including when
# `nft` is missing or the table/chain does not exist yet -- both are
# expected today, before the host fix lands.
set -euo pipefail

if ! out=$(nft list chain inet ci_dmz forward 2>&1); then
	echo "containment-preflight: REFUSED -- 'nft list chain inet ci_dmz forward' did not succeed: $out" >&2
	exit 1
fi

hook_line=$(grep -E 'hook[[:space:]]+forward[[:space:]]+priority' <<<"$out" || true)
if [ -z "$hook_line" ]; then
	echo "containment-preflight: REFUSED -- no forward hook found in ci_dmz" >&2
	exit 1
fi

# nft prints a numeric priority (-10) or a symbolic one (filter - 10)
# depending on how it was declared; either spelling is accepted.
if ! grep -qE '(^|[^0-9-])-10([^0-9]|$)' <<<"$hook_line" && ! grep -qE 'filter[[:space:]]*-[[:space:]]*10' <<<"$hook_line"; then
	echo "containment-preflight: REFUSED -- forward hook is not at priority -10: $hook_line" >&2
	exit 1
fi

# A hook with nothing but "type filter hook forward priority ...; policy
# accept;" enforces nothing: that's a chain that exists, not containment.
# Strip the structural lines (table/chain declarations, the hook line
# itself, braces, blanks) and require something left over.
body=$(grep -vE '^[[:space:]]*(table[[:space:]]|chain[[:space:]]+forward[[:space:]]*\{|\}[[:space:]]*$|type[[:space:]]+filter[[:space:]]+hook[[:space:]]+forward[[:space:]]+priority|[[:space:]]*$)' <<<"$out" || true)
if [ -z "$body" ]; then
	echo "containment-preflight: REFUSED -- ci_dmz forward hook has no rules, nothing is actually enforced" >&2
	exit 1
fi

echo "containment-preflight: ok (ci_dmz forward hook at priority -10, enforcing rules)"
