#!/bin/bash
# The OpenWrt overlay as build-openwrt-image.sh renders it for the cell
# (lab #9): no br-lan or wan (D13, N1), odhcpd's RA and DHCPv6 off on
# every interface with its own section shipped (D13, D13b), no ULA
# (D13c), the B5 band equal to up-source.sh's, and a build id that moves
# with the overlay (N2). No ImageBuilder, network or VM is touched.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() {
	echo "build-openwrt-image-test: $*" >&2
	fail=1
}
export LAB_PUBKEY="ssh-ed25519 AAAA render-only"

id=$(./scripts/build-openwrt-image.sh --render openwrt "$tmp/o")
net="$tmp/o/etc/config/network"
dhcp="$tmp/o/etc/config/dhcp"
conf="$tmp/o/etc/dnsmasq.conf"

grep -qE 'br-lan|bridge|wan|globals|ula_prefix' "$net" && bad "network carries a bridge, wan or ULA: $(tr '\n' '|' <"$net")"
seg=$(go run ./cmd/labctl resolve lab.yaml openwrt | jq -r '.cell.source.seg_address')
grep -qxF "	list ipaddr '$seg'" "$net" || bad "network has no $seg"
awk '/^config interface .lan./{on=1} on && /option device/{print $3; exit}' "$net" | grep -qx "'eth1'" || bad "lan is not eth1"
awk '/^config interface .mgmt./{on=1} on && /option device/{print $3; exit}' "$net" | grep -qx "'eth0'" || bad "mgmt is not eth0"

# Every dhcp interface section turns ra and dhcpv6 off, mgmt serves none.
for sec in lan mgmt; do
	body=$(awk -v s="config dhcp '$sec'" '$0 == s {on=1; next} on && /^config /{exit} on' "$dhcp")
	for k in ra dhcpv6 ndp; do
		grep -qxF "	option $k 'disabled'" <<<"$body" || bad "dhcp $sec does not disable $k"
	done
done
mgmt=$(awk "\$0 == \"config dhcp 'mgmt'\" {on=1; next} on && /^config /{exit} on" "$dhcp")
grep -qxF "	option ignore '1'" <<<"$mgmt" || bad "dhcp mgmt is not ignored"
[ "$(grep -c '^config dhcp ' "$dhcp")" -eq 2 ] || bad "dhcp has a section besides lan and mgmt"
grep -qx "config odhcpd 'odhcpd'" "$dhcp" || bad "no odhcpd section: 15_odhcpd would turn ra and dhcpv6 on"
grep -qxF "	option maindhcp '0'" "$dhcp" || bad "odhcpd is the main DHCP server"

# The B5 band: the same host octets as up-source.sh (lab #23).
for v in class_first_host class_last_host; do
	a=$(grep -E "^$v=" scripts/up-source.sh)
	b=$(grep -E "^$v=" scripts/build-openwrt-image.sh)
	[ "$a" = "$b" ] || bad "$v: up-source.sh '$a', build script '$b'"
done
grep -qE '^dhcp-range=tag:b5,10\.200\.15\.221,10\.200\.15\.230,12h$' "$conf" || bad "class range: $(tr '\n' '|' <"$conf")"

boot="$tmp/o/etc/uci-defaults/99-lab"
shellcheck -s sh "$boot" || bad "99-lab is not clean sh"
[ "$(tail -n 2 "$boot" | head -n 1)" = "cp /etc/lab-build-id /etc/lab-bootstrap-done || exit 1" ] || bad "99-lab does not write the marker last"
[ "$(cat "$tmp/o/etc/lab-build-id")" = "$id" ] || bad "the overlay's id file is not the printed id"
[ "$(./scripts/build-openwrt-image.sh --id openwrt)" = "$id" ] || bad "--id and --render disagree"
# The build renders into a directory that already holds the stock
# copies, under whatever umask its caller has; seed_baked compares that
# id with --id (lab #9).
mkdir -p "$tmp/b/root/lab-stock-config"
echo stock >"$tmp/b/root/lab-stock-config/dhcp.stock"
b=$(umask 0002 && ./scripts/build-openwrt-image.sh --render openwrt "$tmp/b")
[ "$b" = "$id" ] || bad "a render beside the stock copies prints $b, a clean one $id"
[ "$(umask 0077 && ./scripts/build-openwrt-image.sh --id openwrt)" = "$id" ] || bad "--id moves with the umask"
# shellcheck disable=SC2016 # the literal line in the build script (lab #9)
grep -qx 'id=$(render_with_id "$work/files")' scripts/build-openwrt-image.sh || bad "the build does not take its id from render_with_id"

sed '/^  - name: openwrt$/,$ s/pool_end: 10\.200\.15\.200/pool_end: 10.200.15.199/' lab.yaml >"$tmp/lab.yaml"
[ "$(LAB_YAML="$tmp/lab.yaml" ./scripts/build-openwrt-image.sh --id openwrt)" != "$id" ] || bad "a pool edit left the id unchanged"
[ "$(LAB_PUBKEY="ssh-ed25519 BBBB other" ./scripts/build-openwrt-image.sh --id openwrt)" != "$id" ] || bad "a key change left the id unchanged"
if ./scripts/build-openwrt-image.sh --id dnsmasq >/dev/null 2>&1; then bad "a dnsmasq cell was accepted"; fi
grep -qE '^IB_SHA256=[0-9a-f]{64}$' scripts/build-openwrt-image.sh || bad "the ImageBuilder sum is not pinned"

[ "$fail" -eq 0 ] && echo "build-openwrt-image-test: PASS"
exit "$fail"
