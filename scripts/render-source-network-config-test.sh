#!/bin/bash
# render-source-network-config.sh (#11): a cell with no relay renders
# the template's lines minus the route placeholder, a relay cell gets
# exactly one route on eth1, and half a route or a missing v6 address
# (#23 group D) is refused.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
R="$REPO_ROOT/scripts/render-source-network-config.sh"
T="$REPO_ROOT/cloud-init/source-network-config.tmpl.yaml"
args=("$T" 10.200.255.111/24 10.200.255.1 52:54:00:31:55:26 52:54:00:31:55:27 10.200.11.2/24 fd42:200:0:a00::2/64)
fail=0

plain=$("$R" "${args[@]}")
if grep -qE '__|routes' <<<"$plain"; then
	echo "render-source-network-config-test: FAIL -- the no-relay render keeps a placeholder or a route" >&2
	fail=1
fi
if [ "$(wc -l <<<"$plain")" -ne "$(($(wc -l <"$T") - 1))" ]; then
	echo "render-source-network-config-test: FAIL -- the no-relay render is not the template minus one line" >&2
	fail=1
fi

relay=$("$R" "${args[@]}" 10.200.10.0/24 10.200.11.1)
if grep -q '__' <<<"$relay"; then
	echo "render-source-network-config-test: FAIL -- the relay render keeps a placeholder" >&2
	fail=1
fi
if [ "$(diff <(echo "$plain") <(echo "$relay") | grep -c '^>')" -ne 1 ]; then
	echo "render-source-network-config-test: FAIL -- the relay render adds more than the one route line" >&2
	fail=1
fi
if command -v python3 >/dev/null && python3 -c 'import yaml' 2>/dev/null; then
	python3 -I -c '
import sys, yaml
cfg = yaml.safe_load(sys.stdin)
got = cfg["ethernets"]["seg0"].get("routes")
want = [{"to": "10.200.10.0/24", "via": "10.200.11.1"}]
if got != want or "routes" in cfg["ethernets"]["mgmt0"]:
    sys.exit(f"routes {got!r}, want {want!r} on seg0 only")
' <<<"$relay" || fail=1
fi

if "$R" "${args[@]}" 10.200.10.0/24 >/dev/null 2>&1; then
	echo "render-source-network-config-test: FAIL -- a route without a next hop was rendered" >&2
	fail=1
fi
if "$R" "${args[@]:0:6}" >/dev/null 2>&1; then
	echo "render-source-network-config-test: FAIL -- a render without the v6 segment address succeeded" >&2
	fail=1
fi
if ! grep -q 'fd42:200:0:a00::2/64' <<<"$plain"; then
	echo "render-source-network-config-test: FAIL -- the v6 segment address is missing from eth1" >&2
	fail=1
fi
[ "$fail" -eq 0 ] && echo "render-source-network-config-test: PASS"
exit "$fail"
