#!/bin/bash
# Refuse to attach a VM to net-mgmt unless the host's ci_dmz forward hook
# is present at priority -10 and contains a rule that drops by
# destination (issue #1). ci_dmz is a separate host firewall fix, owned
# outside this repo; this script only checks it, never creates or edits
# it. Presence only: an honest yes/no on the ruleset text, never proof
# traffic is actually blocked end to end -- that proof is `dmz-probe.sh
# ""` inside the Docker host VM at a live run, never this script. Exit 0
# needs the hook AND a matching `ip daddr ... drop` rule; exit 1
# otherwise, including a missing `nft` or an absent table/chain, since
# that table's state is this host's own, not anything owned here.
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

# An accept, counter or comment rule proves the chain exists, not that
# it drops anything: require an explicit destination-based drop.
if ! grep -qE 'ip[[:space:]]+daddr[[:space:]].*\bdrop\b' <<<"$out"; then
	echo "containment-preflight: REFUSED -- ci_dmz forward has no 'ip daddr ... drop' rule: $out" >&2
	exit 1
fi

echo "containment-preflight: ok (ci_dmz forward hook at priority -10, with a destination-based drop rule)"
