#!/bin/bash
# Two issue #8 facts about the rendered network-config seed file, both
# measured live. Unquoted, an all-digit MAC octet string is a valid
# YAML 1.1 sexagesimal integer, not a string ("Not all expected
# physical devices present: {41135154926}" from "52:54:00:31:55:26").
# A top-level `network:` wrapper key makes cloud-init 20.4.1 (Debian
# 11) log "missing 'config' or 'version'" and skip applying the config
# entirely, leaving both NICs unconfigured -- NoCloud reads this
# file's version/ethernets keys directly, unwrapped. The checks below
# make both regressions impossible; the dynamic one reproduces the
# parse through PyYAML, cloud-init's own YAML loader.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

templates=(cloud-init/network-config.tmpl.yaml cloud-init/source-network-config.tmpl.yaml cloud-init/relay-network-config.tmpl.yaml)

fail=0
for t in "${templates[@]}"; do
	unquoted=$(grep -nE 'macaddress:[[:space:]]+__[A-Z_]+__[[:space:]]*$' "$t" || true)
	if [ -n "$unquoted" ]; then
		echo "cloud-init-mac-quote-test: $t has an unquoted macaddress placeholder:" >&2
		echo "$unquoted" >&2
		fail=1
	fi
	quoted_count=$(grep -cE 'macaddress:[[:space:]]+"__[A-Z_]+__"' "$t" || true)
	if [ "${quoted_count:-0}" -lt 2 ]; then
		echo "cloud-init-mac-quote-test: $t does not have two quoted macaddress placeholders (mgmt + seg)" >&2
		fail=1
	fi
	wrapped=$(grep -nE '^network:[[:space:]]*$' "$t" || true)
	if [ -n "$wrapped" ]; then
		echo "cloud-init-mac-quote-test: $t has a top-level 'network:' wrapper key" >&2
		echo "$wrapped" >&2
		fail=1
	fi
	top_version=$(grep -cE '^version:[[:space:]]*2[[:space:]]*$' "$t" || true)
	if [ "${top_version:-0}" -lt 1 ]; then
		echo "cloud-init-mac-quote-test: $t does not have a top-level 'version: 2' key" >&2
		fail=1
	fi
done
[ "$fail" -eq 0 ]

if ! command -v python3 >/dev/null || ! python3 -c 'import yaml' 2>/dev/null; then
	echo "cloud-init-mac-quote-test: python3/PyYAML not available, skipping the dynamic render+parse proof" >&2
	exit 0
fi

# The exact live value from issue #8 (all-digit octets): 52,54,00,31,55,26.
bad_mac="52:54:00:31:55:26"
for t in "${templates[@]}"; do
	rendered=$(sed -e "s#__MGMT_MAC__#$bad_mac#" -e "s#__SEG_MAC__#$bad_mac#" \
		-e "s#__CLI_MAC__#$bad_mac#" -e "s#__SRV_MAC__#$bad_mac#" \
		-e "s#__MGMT_ADDR__#10.200.255.50/24#" -e "s#__MGMT_GW__#10.200.255.1#g" \
		-e "s#__SEG_ADDR__#10.200.100.5/24#" "$t")
	python3 -c "
import sys, yaml
cfg = yaml.safe_load(sys.stdin)
if 'network' in cfg:
    print('top-level network wrapper key survived rendering', file=sys.stderr)
    sys.exit(1)
for name, eth in cfg['ethernets'].items():
    mac = eth['match']['macaddress']
    if not isinstance(mac, str):
        print(f'{name}: macaddress parsed as {type(mac).__name__} ({mac!r}), not str', file=sys.stderr)
        sys.exit(1)
" <<<"$rendered" || {
		echo "cloud-init-mac-quote-test: $t: rendered network-config did not survive as expected" >&2
		exit 1
	}
done

echo "cloud-init-mac-quote-test: PASS"
