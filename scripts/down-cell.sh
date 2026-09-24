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

if virsh dominfo "$domain" >/dev/null 2>&1; then
	virsh destroy "$domain" >/dev/null 2>&1 || true
	# --nvram also removes libvirt's own record of the per-VM VARS copy;
	# harmless if that copy already lives under $WORK and gets removed
	# below by the rm -rf.
	virsh undefine "$domain" --nvram >/dev/null 2>&1 || virsh undefine "$domain" >/dev/null 2>&1 || true
fi

rm -rf "$WORK"
echo "down-cell: $CELL torn down, $WORK removed"
