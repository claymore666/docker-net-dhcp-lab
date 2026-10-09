#!/bin/bash
# up-source.sh's IPv6 gate is driven by the source type (lab #10, #23): a
# type that serves DHCPv6 is refused without its v6 fields, a v4-only type
# (udhcpd) passes without them and renders no v6 address. UP_SOURCE_RENDER_ONLY
# stops the script after the seed files, so no VM, image or key is touched.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

# Case 1: the udhcpd cell passes and its network-config has no v6 address.
if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh udhcpd "$tmp/w1" 2>&1); then
	echo "up-source-test: udhcpd cell refused: $out" >&2
	fail=1
elif grep -q '::\|SEG_ADDR6\|""' "$tmp/w1/seed-source/network-config"; then
	echo "up-source-test: udhcpd network-config carries a v6 address" >&2
	cat "$tmp/w1/seed-source/network-config" >&2
	fail=1
fi

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

[ "$fail" -eq 0 ] && echo "up-source-test: ok"
exit "$fail"
