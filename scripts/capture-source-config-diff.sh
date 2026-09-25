#!/bin/bash
# A measured config diff from stock for one source cell (issue #2):
# pulls the stock backup each cloud-init template makes before it writes
# its own config, plus the live file, off the running VM, and diffs
# them -- never hand-typed. Headed with the commit this ran at and a UTC
# timestamp, matching the "Done when" evidence rule.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
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

case "$SOURCE_TYPE" in
kea) pairs=("kea-dhcp4.conf.stock:/etc/kea/kea-dhcp4.conf" "kea-ctrl-agent.conf.stock:/etc/kea/kea-ctrl-agent.conf") ;;
isc-dhcp) pairs=("dhcpd.conf.stock:/etc/dhcp/dhcpd.conf" "isc-dhcp-server.stock:/etc/default/isc-dhcp-server") ;;
dnsmasq) pairs=("dnsmasq.conf.stock:/etc/dnsmasq.conf") ;;
*)
	echo "capture-source-config-diff: unknown source type $SOURCE_TYPE" >&2
	exit 1
	;;
esac

mkdir -p "$EVIDENCE_DIR"
sha=$(cd "$REPO_ROOT" && git rev-parse HEAD)
ts=$(date -u +%Y%m%dT%H%M%SZ)
out="$EVIDENCE_DIR/${CELL}-config-diff-${ts}.txt"
{
	echo "# config diff for cell $CELL ($SOURCE_TYPE), commit $sha, captured $ts"
	for pair in "${pairs[@]}"; do
		stock_name=${pair%%:*}
		live_path=${pair##*:}
		echo "## $live_path"
		diff -u <(ssh_run "sudo cat /root/lab-stock-config/$stock_name") <(ssh_run "sudo cat $live_path") || true
	done
} >"$out"
echo "capture-source-config-diff: wrote $out"
