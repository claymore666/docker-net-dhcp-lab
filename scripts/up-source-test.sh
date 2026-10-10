#!/bin/bash
# up-source.sh's IPv6 gate is driven by the source type (lab #10, #23): a
# type that serves DHCPv6 is refused without its v6 fields, a v4-only type
# (udhcpd, pihole) passes without them and renders no v6 address. UP_SOURCE_RENDER_ONLY
# stops the script after the seed files, so no VM, image or key is touched.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

# Case 1: each v4-only cell (udhcpd, pihole) passes and its network-config
# has no v6 address. The placeholder up-source.sh hands the renderer for the
# dropped item (the literal none) must never reach an address: no code line
# contains it, and eth1's address list is exactly one IPv4 item.
for typ in udhcpd pihole; do
	w="$tmp/w1-$typ"
	if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh "$typ" "$w" 2>&1); then
		echo "up-source-test: $typ cell refused: $out" >&2
		fail=1
		continue
	fi
	nc="$w/seed-source/network-config"
	if grep -q '::\|SEG_ADDR6\|""' "$nc"; then
		echo "up-source-test: $typ network-config carries a v6 address" >&2
		cat "$nc" >&2
		fail=1
	fi
	if grep -v '^[[:space:]]*#' "$nc" | grep -qw 'none'; then
		echo "up-source-test: $typ network-config carries the literal none" >&2
		cat "$nc" >&2
		fail=1
	fi
	eth1_addrs=$(awk '/set-name: eth1/{on=1;next} on && /addresses:/{print;exit}' "$nc")
	if ! grep -qE '^[[:space:]]+addresses: \[[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}\]$' <<<"$eth1_addrs"; then
		echo "up-source-test: $typ eth1 addresses is not exactly one IPv4 item: $eth1_addrs" >&2
		fail=1
	fi
done

# Case 2: the kea cell with its v6 fields passes and keeps the v6 address.
if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh kea "$tmp/w2" 2>&1); then
	echo "up-source-test: kea cell refused: $out" >&2
	fail=1
elif ! grep -q 'fd42:200:0:100::2/64' "$tmp/w2/seed-source/network-config"; then
	echo "up-source-test: kea network-config lost its v6 address" >&2
	fail=1
fi

# Case 3: the kea cell without its v6 block (the schema allows it; the
# script must not) is refused, naming the missing field.
awk '
/^  - name: /{ inkea = ($3 == "kea") }
inkea && /^[[:space:]]+(subnet6|seg_address6|pool6_start|pool6_end|temp6_pool):/ { next }
{ print }' lab.yaml >"$tmp/nov6.yaml"
if out=$(LAB_YAML="$tmp/nov6.yaml" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh kea "$tmp/w3" 2>&1); then
	echo "up-source-test: kea cell without v6 was accepted" >&2
	fail=1
elif ! grep -q 'has no seg_subnet6' <<<"$out"; then
	echo "up-source-test: kea refusal does not name the missing field: $out" >&2
	fail=1
fi

# Case 4: the kea-ha partner (#12) renders into its own seed dir with its
# own hostname and the HA template, inside the seed hook (#9).
w4="$tmp/w4"
if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh kea-ha "$w4" partner 2>&1); then
	echo "up-source-test: kea-ha partner refused: $out" >&2
	fail=1
elif [ -e "$w4/seed-source" ] || ! grep -qx 'local-hostname: lab-kea-partner' "$w4/seed-partner/meta-data" ||
	! grep -q '^hostname: lab-kea-partner$' "$w4/seed-partner/user-data" ||
	! grep -q 'fd42:200:0:800::3/64' "$w4/seed-partner/network-config"; then
	echo "up-source-test: kea-ha partner seed is not its own: $(ls "$w4")" >&2
	fail=1
fi

# Case 5: the chr cell (#9) renders its three RouterOS scripts and the key
# with every placeholder filled, and the seed script disables the stock
# admin and sets the identity ready_qga waits for as its last line.
w5="$tmp/w5"
if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh chr "$w5" 2>&1); then
	echo "up-source-test: chr cell refused: $out" >&2
	fail=1
else
	d="$w5/seed-source"
	if grep -l '__' "$d"/*.rsc >&2; then
		echo "up-source-test: chr seed keeps a placeholder" >&2
		fail=1
	fi
	grep -qx 'ssh-ed25519 AAAA render-only' "$d/lab.pub" || {
		echo "up-source-test: chr lab.pub is not the key" >&2
		fail=1
	}
	for want in 'lab-mgmt.rsc:address=10.200.255.141/24}' 'lab-mgmt.rsc:gateway=10.200.255.1}' \
		'lab-baseline.rsc:address=10.200.14.2/24$' 'lab-baseline.rsc:ranges=10.200.14.100-10.200.14.200}' \
		'lab-baseline.rsc:ranges=10.200.14.221-10.200.14.230}' 'lab-baseline.rsc:gateway=10.200.14.2$' \
		'lab-seed.rsc:^/user set \[find name=admin\] disabled=yes$'; do
		grep -q "${want#*:}" "$d/${want%%:*}" || {
			echo "up-source-test: chr ${want%%:*} lacks ${want#*:}" >&2
			fail=1
		}
	done
	[ "$(grep -v '^#' "$d/lab-mgmt.rsc" | head -1)" = ':if ([:len [/file find name=lab-stock.rsc]] = 0) do={/export file=lab-stock}' ] || {
		echo "up-source-test: chr lab-mgmt.rsc does not keep the vendor export before its first change" >&2
		fail=1
	}
	# printf keeps the service name off the ssh-call gate in verify.sh (lab #9).
	[ "$(grep -v '^#' "$d/lab-mgmt.rsc" | sed -n 2,3p | tr '\n' '|')" = "$(printf '/ip service disable [find name!=%s dynamic=no]|/ipv6 settings set disable-ipv6=yes|' "ssh")" ] || {
		echo "up-source-test: chr lab-mgmt.rsc does not close the stock services and IPv6 right after the export" >&2
		fail=1
	}
	[ "$(grep -v '^#' "$d/lab-seed.rsc" | tail -1)" = '/system identity set name=lab-ready' ] || {
		echo "up-source-test: chr lab-seed.rsc does not end on the identity" >&2
		fail=1
	}
fi

# Case 6: the baked seed (#9) passes only when the cache's build id is
# the one the build script derives from the cell as lab.yaml has it now;
# a pool edit after the build is refused (defeat N2).
cache="$tmp/cache"
mkdir -p "$cache"
LAB_PUBKEY="ssh-ed25519 AAAA render-only" ./scripts/build-openwrt-image.sh --id openwrt >"$cache/openwrt-25.12.5-x86-64.build-id"
if ! out=$(LAB_IMAGE_CACHE="$cache" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh openwrt "$tmp/w6" 2>&1); then
	echo "up-source-test: openwrt refused a current build id: $out" >&2
	fail=1
fi
sed '/^  - name: openwrt$/,$ s/pool_end: 10\.200\.15\.200/pool_end: 10.200.15.199/' lab.yaml >"$tmp/stale.yaml"
if cmp -s lab.yaml "$tmp/stale.yaml"; then
	echo "up-source-test: the openwrt pool edit did not apply" >&2
	fail=1
elif out=$(LAB_YAML="$tmp/stale.yaml" LAB_IMAGE_CACHE="$cache" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh openwrt "$tmp/w6b" 2>&1) ||
	! grep -q 'run scripts/build-openwrt-image.sh openwrt' <<<"$out"; then
	echo "up-source-test: openwrt accepted a stale image: $out" >&2
	fail=1
fi

[ "$fail" -eq 0 ] && echo "up-source-test: ok"
exit "$fail"
