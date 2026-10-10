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

[ "$fail" -eq 0 ] && echo "up-source-test: ok"
exit "$fail"
