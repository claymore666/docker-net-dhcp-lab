#!/bin/bash
# Bring up one cell from lab.yaml: segment bridge, per-run VM overlay, the
# reference Docker host, and the observer's leg on the segment (issue #1).
# Idempotent enough to re-run after a power cut (track file, "Power").
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CELL=${1:?usage: up-cell.sh <cell-name> <work-dir>}
WORK=${2:?usage: up-cell.sh <cell-name> <work-dir>}
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$LAB_YAML" "$CELL")
bridge=$(jq -r '.cell.segment.bridge' <<<"$RESOLVED")
mgmt_addr=$(jq -r '.cell.docker_host.mgmt_address' <<<"$RESOLVED")
mgmt_gw=$(jq -r '.management.gateway' <<<"$RESOLVED")
plugin_tag=$(jq -r '.cell.docker_host.plugin_tag' <<<"$RESOLVED")
vcpus=$(jq -r '.cell.docker_host.vcpus' <<<"$RESOLVED")
mem=$(jq -r '.cell.docker_host.memory_mib' <<<"$RESOLVED")
diskgib=$(jq -r '.cell.docker_host.disk_gib' <<<"$RESOLVED")
domain="lab-${CELL}-dockerhost"

echo "== segment bridge =="
"$REPO_ROOT/scripts/build-bridge.sh" "$bridge"

echo "== base image cache =="
base_path=$("$REPO_ROOT/scripts/fetch-base-image.sh")

mkdir -p "$WORK"
overlay="$WORK/${domain}.qcow2"
if [ ! -f "$overlay" ]; then
	qemu-img create -f qcow2 -F qcow2 -b "$base_path" "$overlay" "${diskgib}G"
fi

if [ ! -f ~/.ssh/id_ed25519_lab.pub ]; then
	ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519_lab -C lab-controller >/dev/null
fi
pubkey=$(cat ~/.ssh/id_ed25519_lab.pub)

seed_dir="$WORK/seed"
mkdir -p "$seed_dir"
sed -e "s#__PLUGIN_TAG__#$plugin_tag#g" -e "s#__SSH_PUBKEY__#$pubkey#" \
	"$REPO_ROOT/cloud-init/docker-host-user-data.tmpl.yaml" >"$seed_dir/user-data"
sed -e "s#__MGMT_ADDR__#$mgmt_addr#" -e "s#__MGMT_GW__#$mgmt_gw#g" \
	"$REPO_ROOT/cloud-init/network-config.tmpl.yaml" >"$seed_dir/network-config"
: >"$seed_dir/meta-data"
echo "instance-id: $domain" >"$seed_dir/meta-data"
echo "local-hostname: lab-docker-host" >>"$seed_dir/meta-data"

seed_iso="$WORK/${domain}-seed.iso"
genisoimage -output "$seed_iso" -volid cidata -joliet -rock \
	"$seed_dir/user-data" "$seed_dir/meta-data" "$seed_dir/network-config" >/dev/null

echo "== VM =="
if ! virsh dominfo "$domain" >/dev/null 2>&1; then
	virt-install \
		--name "$domain" \
		--memory "$mem" --vcpus "$vcpus" \
		--disk path="$overlay",format=qcow2,bus=virtio \
		--disk path="$seed_iso",device=cdrom \
		--network network=net-mgmt,model=virtio \
		--network bridge="$bridge",model=virtio \
		--os-variant debian13 \
		--graphics none \
		--noautoconsole \
		--import
else
	virsh start "$domain" >/dev/null 2>&1 || true
fi

echo "== wait for cloud-init (bounded) =="
mgmt_ip=${mgmt_addr%%/*}
ok=0
for _ in $(seq 1 60); do
	if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=3 -i ~/.ssh/id_ed25519_lab \
		lab@"$mgmt_ip" 'test -f /var/lib/cloud/lab-bootstrap-done' 2>/dev/null; then
		ok=1
		break
	fi
	sleep 10
done
[ "$ok" -eq 1 ] || {
	echo "up-cell: cloud-init did not finish inside the bound" >&2
	exit 1
}

echo "up-cell: $CELL ready, docker host at $mgmt_ip, segment bridge $bridge"
