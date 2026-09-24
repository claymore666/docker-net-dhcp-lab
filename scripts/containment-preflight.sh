#!/bin/bash
# Refuse to attach a VM to net-mgmt unless the host's ci_dmz forward hook
# is actually in place, at the priority the lead's firewall design fixes
# it to (issue #1, coordinator decision "every lab VM boots under UEFI",
# task 2). ci_dmz itself is a separate, lead-owned fix (defeat list, "Open
# finding, owned by the lead"); this script only checks it exists, it
# never creates or edits it.
#
# Exit 0: the hook is present at priority -10. Exit 1 otherwise, including
# when `nft` is missing or the table/chain does not exist yet -- both are
# expected today, before the firewall fix lands.
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

echo "containment-preflight: ok (ci_dmz forward hook at priority -10)"
