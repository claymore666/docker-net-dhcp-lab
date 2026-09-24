#!/bin/bash
# Tear down one cell brought up by up-cell.sh: destroy and undefine its
# domain (its per-VM NVRAM copy included, issue #1), then remove
# its work directory. Never touches the segment bridge or net-mgmt
# themselves -- other cells may still use them. Idempotent: safe to run
# on a cell that is already down or was never fully brought up.
set -euo pipefail

CELL=${1:?usage: down-cell.sh <cell-name> <work-dir>}
WORK=${2:?usage: down-cell.sh <cell-name> <work-dir>}
domain="lab-${CELL}-dockerhost"

# sudo -n, matching up-cell.sh: net-mgmt and this domain live under
# qemu:///system, not the empty per-user qemu:///session a plain virsh
# reaches. A plain virsh here would silently miss the real domain under
# an unprivileged caller, and everything below would still run as if the
# teardown had succeeded.
if sudo -n virsh dominfo "$domain" >/dev/null 2>&1; then
	sudo -n virsh destroy "$domain" >/dev/null 2>&1 || true
	# --nvram also removes libvirt's own record of the per-VM VARS copy;
	# harmless if that copy already lives under $WORK and gets removed
	# below by the rm -rf.
	sudo -n virsh undefine "$domain" --nvram >/dev/null 2>&1 || sudo -n virsh undefine "$domain" >/dev/null 2>&1 || true
fi

# Verified, not assumed: only proceed to remove $WORK and report success
# once the domain is actually gone. Printing "torn down" while it still
# exists would leave a running or defined domain with no local record of
# it at all.
if sudo -n virsh dominfo "$domain" >/dev/null 2>&1; then
	echo "down-cell: REFUSED -- $domain still exists after destroy/undefine; not touching $WORK" >&2
	exit 1
fi

# Move any observer pcaps out to an evidence directory, outside $WORK,
# before it is removed below -- a real pcap was lost this way once
# already (issue #1: captured, then deleted unread by this same rm -rf,
# before it was copied off the host). A sibling of $WORK, not inside it,
# so this rm -rf can never reach it again.
evidence_dir="${LAB_EVIDENCE_DIR:-$(dirname "$WORK")/evidence}"
if [ -d "$WORK" ]; then
	mapfile -t pcaps < <(find "$WORK" -type f -name '*.pcap')
	if [ "${#pcaps[@]}" -gt 0 ]; then
		mkdir -p "$evidence_dir"
		ts=$(date -u +%Y%m%dT%H%M%SZ)
		for f in "${pcaps[@]}"; do
			mv "$f" "$evidence_dir/${CELL}-${ts}-$(basename "$f")"
		done
		echo "down-cell: moved ${#pcaps[@]} pcap(s) to $evidence_dir"
	fi
fi

rm -rf "$WORK"
echo "down-cell: $CELL torn down, $WORK removed"
