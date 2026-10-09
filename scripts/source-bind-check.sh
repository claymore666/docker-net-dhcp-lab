#!/bin/bash
# Static check that each source daemon's config binds only eth1 (the
# segment), never eth0/mgmt or "all interfaces" (issue #2) -- refuses any
# cloud-init template that says anything else.
# Complements, never replaces, the live capture on virbr-mgmt during a
# real bring-up.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

fail=0

# kea-dhcp4 and kea-dhcp6 each carry one interfaces-config, and radvd
# (kea and isc cells) one interface block (#23 group D).
kea_line=$(grep -c '"interfaces-config": { "interfaces": \[ "eth1" \] }' cloud-init/kea-user-data.tmpl.yaml || true)
kea_any=$(grep -c '"interfaces-config"' cloud-init/kea-user-data.tmpl.yaml || true)
if [ "$kea_line" -ne 2 ] || [ "$kea_any" -ne 2 ]; then
	echo "source-bind-check: FAIL -- kea-user-data.tmpl.yaml does not bind exactly eth1" >&2
	fail=1
fi

for t in kea isc-dhcp; do
	ra_eth1=$(grep -c '^[[:space:]]*interface eth1 {$' "cloud-init/$t-user-data.tmpl.yaml" || true)
	ra_any=$(grep -c '^[[:space:]]*interface ' "cloud-init/$t-user-data.tmpl.yaml" || true)
	if [ "$ra_eth1" -ne 1 ] || [ "$ra_any" -ne 1 ]; then
		echo "source-bind-check: FAIL -- $t-user-data.tmpl.yaml radvd does not advertise on exactly eth1" >&2
		fail=1
	fi
done

isc_line=$(grep -c '^[[:space:]]*INTERFACESv4="eth1"$' cloud-init/isc-dhcp-user-data.tmpl.yaml || true)
isc6_line=$(grep -c '^[[:space:]]*INTERFACESv6="eth1"$' cloud-init/isc-dhcp-user-data.tmpl.yaml || true)
isc_any=$(grep -c '^[[:space:]]*INTERFACESv[46]=' cloud-init/isc-dhcp-user-data.tmpl.yaml || true)
if [ "$isc_line" -ne 1 ] || [ "$isc6_line" -ne 1 ] || [ "$isc_any" -ne 2 ]; then
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
echo "source-bind-check: ok -- kea, isc-dhcp and dnsmasq (v4 and v6) and radvd all bind eth1 only"
