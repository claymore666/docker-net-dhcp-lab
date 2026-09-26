#!/bin/bash
# Tear down one cell brought up by up-cell.sh: destroy and undefine its
# domain (its per-VM NVRAM copy included, issue #1), remove the
# observer's own container and its host-side veth (issue #1/#3
# direction: left behind by every prior version of this script), then
# remove the work directory. Never touches the segment bridge or
# net-mgmt themselves -- other cells may still use them. Idempotent:
# safe to run on a cell that is already down or was never fully brought
# up, or one that never had an observer at all.
set -euo pipefail

CELL=${1:?usage: down-cell.sh <cell-name> <work-dir>}
WORK=${2:?usage: down-cell.sh <cell-name> <work-dir>}
domain="lab-${CELL}-dockerhost"
source_domain="lab-${CELL}-source"

# Same naming as observe-segment.sh's own container and host-side veth
# (its comment there has the IFNAMSIZ reasoning for the hash); recomputed
# here rather than shared, matching every other script in this repo.
# sudo -n for the same reason as the virsh calls below -- the operator is
# not in the docker group and has no bare CAP_NET_ADMIN either.
cell_hash=$(echo -n "$CELL" | md5sum | cut -c1-5)
observer_veth="veth-obs-${cell_hash}h"
observer_container="lab-observer-${CELL}"
sudo -n docker rm -f "$observer_container" >/dev/null 2>&1 || true
sudo -n ip link del "$observer_veth" 2>/dev/null || true

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

# A cell's own IP source VM (issue #2), same shape as the docker host
# above: its own overlay/NVRAM under $WORK, the shared base image never
# touched. A cell with no source (issue #1's ref-only) has none defined,
# so every call here is a harmless no-op.
if sudo -n virsh dominfo "$source_domain" >/dev/null 2>&1; then
	sudo -n virsh destroy "$source_domain" >/dev/null 2>&1 || true
	sudo -n virsh undefine "$source_domain" --nvram >/dev/null 2>&1 || sudo -n virsh undefine "$source_domain" >/dev/null 2>&1 || true
fi
if sudo -n virsh dominfo "$source_domain" >/dev/null 2>&1; then
	echo "down-cell: REFUSED -- $source_domain still exists after destroy/undefine; not touching $WORK" >&2
	exit 1
fi

# Move any observer pcaps out to an evidence directory, outside $WORK,
# before it is removed below -- a real pcap was lost this way once
# already (issue #1: captured, then deleted unread by this same rm -rf,
# before it was copied off the host). A sibling of $WORK, not inside it,
# so this rm -rf can never reach it again.
evidence_dir="${LAB_EVIDENCE_DIR:-$(dirname "$WORK")/evidence}"

# Refuse rather than silently destroy: an evidence dir inside $WORK
# would be removed by the rm -rf below right after this script just
# moved the pcaps into it -- the same class of loss the comment above
# already names for a bare pcap, but for the whole bundle (verdicts,
# lease snapshots, config diff, versions, plugin log). Measured live
# 2026-09-26: run-group-a.sh's own EVIDENCE_DIR default nests it inside
# $WORK, and every evidence bundle from a run that hit this path was
# gone by the time down-cell.sh printed "torn down".
case "$evidence_dir" in
"$WORK" | "$WORK"/*)
	echo "down-cell: REFUSED -- evidence dir $evidence_dir is inside $WORK; the rm -rf below would destroy it. Pass an evidence dir that is a sibling of \$WORK, never inside it." >&2
	exit 1
	;;
esac

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

# Named explicitly, ahead of the rm -rf below: the per-cell known_hosts
# file (issue #1) is the one piece of $WORK whose absence another script
# depends on being provable on its own, not just swept up incidentally.
rm -f "$WORK/known_hosts"

rm -rf "$WORK"
echo "down-cell: $CELL torn down, $WORK removed"
