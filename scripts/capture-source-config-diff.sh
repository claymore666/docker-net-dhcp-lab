#!/bin/bash
# A measured config diff from stock for one source cell (issue #2):
# pulls the stock backup each cloud-init template makes before it writes
# its own config, plus the live file, off the running VM, and diffs
# them, never hand-typed. Headed with the commit this ran at and a UTC
# timestamp, matching the "Done when" evidence rule. Comment and blank
# lines go on both sides first (issues #32, #46). The live file is
# checked raw, comments included: a disallowed address ends the capture.
# The Pi-hole toml's comment-only lines are vendor help text (#10).
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/scripts/config-diff-lib.sh"
CELL=${1:?usage: capture-source-config-diff.sh <cell> <source-type> <mgmt-ip> <work-dir> <evidence-dir>}
SOURCE_TYPE=${2:?}
MGMT_IP=${3:?}
WORK=${4:?}
EVIDENCE_DIR=${5:?}
known_hosts="$WORK/known_hosts"

ssh_run() {
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ControlMaster=no -o ControlPath=none \
		-i ~/.ssh/id_ed25519_lab lab@"$MGMT_IP" "$@"
}

. "$REPO_ROOT/scripts/source-types.sh"
pairs_text=$(source_config_pairs "$SOURCE_TYPE") || {
	echo "capture-source-config-diff: unknown source type $SOURCE_TYPE" >&2
	exit 1
}
mapfile -t pairs <<<"$pairs_text"
# Every arm resolves before the first read (#9): an arm that fails or
# prints nothing refuses the capture with no ssh and no diff file, never
# an empty command sent to the cell.
refuse_arm() {
	echo "capture-source-config-diff: REFUSED -- source type $SOURCE_TYPE has no $1 arm in source-types.sh" >&2
	exit 1
}
if ! mask_stock=$(source_stock_mask "$SOURCE_TYPE") || [ -z "$mask_stock" ]; then
	refuse_arm source_stock_mask
fi
stock_cmds=()
live_cmds=()
for pair in "${pairs[@]}"; do
	if ! cmd=$(source_stock_cmd "$SOURCE_TYPE" "${pair%%:*}") || [ -z "$cmd" ]; then
		refuse_arm source_stock_cmd
	fi
	stock_cmds+=("$cmd")
	if ! cmd=$(source_live_cmd "$SOURCE_TYPE" "${pair##*:}") || [ -z "$cmd" ]; then
		refuse_arm source_live_cmd
	fi
	live_cmds+=("$cmd")
done

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
sha=$(cd "$REPO_ROOT" && git rev-parse HEAD)
ts=$(date -u +%Y%m%dT%H%M%SZ)
echo "# config diff for cell $CELL ($SOURCE_TYPE), commit $sha, captured $ts" >"$scratch/out"
for i in "${!pairs[@]}"; do
	pair=${pairs[$i]}
	stock_name=${pair%%:*}
	live_path=${pair##*:}
	# Each side lands in a file under set -e: a failed read ends the
	# capture instead of diffing against nothing.
	# RouterOS ends its lines in CR (#9); no other source writes one.
	ssh_run "${stock_cmds[$i]}" | tr -d '\r' >"$scratch/stock" ||
		{ echo "capture-source-config-diff: REFUSED -- could not read the stock backup $stock_name" >&2; exit 1; }
	if [ "$mask_stock" -eq 1 ]; then
		config_mask_vendor_examples "$scratch/stock" ||
			{ echo "capture-source-config-diff: REFUSED -- the stock backup $stock_name kept a disallowed address after masking" >&2; exit 1; }
	fi
	ssh_run "${live_cmds[$i]}" | tr -d '\r' >"$scratch/live" ||
		{ echo "capture-source-config-diff: REFUSED -- could not read $live_path" >&2; exit 1; }
	if [ ! -s "$scratch/live" ]; then
		echo "capture-source-config-diff: REFUSED -- $live_path is empty on the cell" >&2
		exit 1
	fi
	# Pi-hole's toml carries vendor help text with example addresses (#10).
	# Its comment-only lines are blanked for this one check, so line
	# numbers hold; code lines stay checked raw.
	check_file="$scratch/live"
	scope="comments included"
	if [ "$SOURCE_TYPE" = pihole ]; then
		scope="code lines only"
		sed -E 's/^[[:space:]]*#.*$//' "$scratch/live" >"$scratch/live-code"
		check_file="$scratch/live-code"
	fi
	lines=$(config_live_disallowed_lines "$check_file" | tr '\n' ' ')
	if [ -n "$lines" ]; then
		echo "capture-source-config-diff: REFUSED -- $live_path carries a disallowed address at line(s) ${lines% }, $scope; nothing written" >&2
		exit 1
	fi
	{
		echo "## $live_path"
		config_diff_render "$scratch/stock" "$scratch/live"
	} >>"$scratch/out"
done

mkdir -p "$EVIDENCE_DIR"
out="$EVIDENCE_DIR/${CELL}-config-diff-${ts}.txt"
cat "$scratch/out" >"$out"
echo "capture-source-config-diff: wrote $out"
