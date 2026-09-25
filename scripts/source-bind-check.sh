#!/bin/bash
# Static check for a known injection risk (issue #2): a source
# daemon must bind only eth1 (the segment), never eth0/mgmt or "all
# interfaces" -- refuses any cloud-init template that says anything else.
# Complements, never replaces, the live capture on virbr-mgmt during a
# real bring-up.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

fail=0

kea_line=$(grep -c '"interfaces-config": { "interfaces": \[ "eth1" \] }' cloud-init/kea-user-data.tmpl.yaml || true)
if [ "$kea_line" -ne 1 ]; then
	echo "source-bind-check: FAIL -- kea-user-data.tmpl.yaml does not bind exactly eth1" >&2
	fail=1
fi

isc_line=$(grep -c '^[[:space:]]*INTERFACESv4="eth1"$' cloud-init/isc-dhcp-user-data.tmpl.yaml || true)
if [ "$isc_line" -ne 1 ]; then
	echo "source-bind-check: FAIL -- isc-dhcp-user-data.tmpl.yaml does not bind exactly eth1" >&2
	fail=1
fi

dm_iface=$(grep -c '^[[:space:]]*interface=eth1$' cloud-init/dnsmasq-user-data.tmpl.yaml || true)
dm_bind=$(grep -c '^[[:space:]]*bind-interfaces$' cloud-init/dnsmasq-user-data.tmpl.yaml || true)
dm_other=$(grep -cE '^[[:space:]]*interface=' cloud-init/dnsmasq-user-data.tmpl.yaml || true)
if [ "$dm_iface" -ne 1 ] || [ "$dm_bind" -ne 1 ] || [ "$dm_other" -ne 1 ]; then
	echo "source-bind-check: FAIL -- dnsmasq-user-data.tmpl.yaml does not bind exactly eth1" >&2
	fail=1
fi

[ "$fail" -eq 0 ] || exit 1
echo "source-bind-check: ok -- kea, isc-dhcp and dnsmasq all bind eth1 only"
