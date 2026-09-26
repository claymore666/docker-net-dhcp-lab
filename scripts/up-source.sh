#!/bin/bash
# Bring up one cell's IP source VM (issue #2): its own per-run overlay,
# dual-homed like the docker host, on the segment bridge up-cell.sh has
# already built. Call after up-cell.sh; this script never touches the
# bridge itself.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CELL=${1:?usage: up-source.sh <cell-name> <work-dir>}
WORK=${2:?usage: up-source.sh <cell-name> <work-dir>}
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$LAB_YAML" "$CELL")
source_type=$(jq -r '.cell.source.type // empty' <<<"$RESOLVED")
if [ -z "$source_type" ]; then
	echo "up-source: cell $CELL has no source in lab.yaml, nothing to do" >&2
	exit 1
fi
seg_subnet=$(jq -r '.cell.segment.subnet' <<<"$RESOLVED")
mgmt_addr=$(jq -r '.cell.source.mgmt_address' <<<"$RESOLVED")
mgmt_gw=$(jq -r '.management.gateway' <<<"$RESOLVED")
seg_addr=$(jq -r '.cell.source.seg_address' <<<"$RESOLVED")
pool_start=$(jq -r '.cell.source.pool_start' <<<"$RESOLVED")
pool_end=$(jq -r '.cell.source.pool_end' <<<"$RESOLVED")
vcpus=$(jq -r '.cell.source.vcpus' <<<"$RESOLVED")
mem=$(jq -r '.cell.source.memory_mib' <<<"$RESOLVED")
diskgib=$(jq -r '.cell.source.disk_gib' <<<"$RESOLVED")
domain="lab-${CELL}-source"

# Same deterministic-MAC scheme as up-cell.sh, own domain name so the two
# VMs on one cell never collide.
mac_from() {
	echo -n "$1" | md5sum | cut -c1-6 | sed -E 's/(..)(..)(..)/52:54:00:\1:\2:\3/'
}
mgmt_mac=$(mac_from "${domain}-mgmt")
seg_mac=$(mac_from "${domain}-seg")

base_path=$("$REPO_ROOT/scripts/fetch-base-image.sh")

mkdir -p "$WORK"
known_hosts="$WORK/known_hosts"
[ -f "$known_hosts" ] || : >"$known_hosts"

overlay="$WORK/${domain}.qcow2"
if [ ! -f "$overlay" ]; then
	qemu-img create -f qcow2 -F qcow2 -b "$base_path" "$overlay" "${diskgib}G"
fi

if [ ! -f ~/.ssh/id_ed25519_lab.pub ]; then
	ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519_lab -C lab-controller >/dev/null
fi
pubkey=$(cat ~/.ssh/id_ed25519_lab.pub)

# This repo's segments are always a /24 (lab.yaml's own convention,
# issue #1); the isc-dhcp template needs network+netmask, not CIDR.
seg_network=${seg_subnet%/*}
seg_netmask=255.255.255.0

tmpl="$REPO_ROOT/cloud-init/${source_type}-user-data.tmpl.yaml"
seed_dir="$WORK/seed-source"
mkdir -p "$seed_dir"
sed -e "s#__SSH_PUBKEY__#$pubkey#" \
	-e "s#__SEG_SUBNET__#$seg_subnet#g" -e "s#__SEG_NETWORK__#$seg_network#g" \
	-e "s#__SEG_NETMASK__#$seg_netmask#g" \
	-e "s#__POOL_START__#$pool_start#g" -e "s#__POOL_END__#$pool_end#g" \
	"$tmpl" >"$seed_dir/user-data"
sed -e "s#__MGMT_ADDR__#$mgmt_addr#" -e "s#__MGMT_GW__#$mgmt_gw#g" \
	-e "s#__MGMT_MAC__#$mgmt_mac#" -e "s#__SEG_MAC__#$seg_mac#" \
	-e "s#__SEG_ADDR__#$seg_addr#" \
	"$REPO_ROOT/cloud-init/source-network-config.tmpl.yaml" >"$seed_dir/network-config"
echo "instance-id: $domain" >"$seed_dir/meta-data"
echo "local-hostname: lab-${source_type}-source" >>"$seed_dir/meta-data"

seed_iso="$WORK/${domain}-seed.iso"
rm -f "$seed_iso"
genisoimage -output "$seed_iso" -volid cidata -joliet -rock \
	"$seed_dir/user-data" "$seed_dir/meta-data" "$seed_dir/network-config" >/dev/null

ovmf_code=/usr/share/OVMF/OVMF_CODE_4M.fd
ovmf_vars_template=/usr/share/OVMF/OVMF_VARS_4M.fd
nvram="$WORK/${domain}-VARS.fd"

bridge=$(jq -r '.cell.segment.bridge' <<<"$RESOLVED")
echo "== source VM ($source_type) =="
if ! sudo -n virsh dominfo "$domain" >/dev/null 2>&1; then
	sudo -n virt-install \
		--name "$domain" \
		--memory "$mem" --vcpus "$vcpus" \
		--disk path="$overlay",format=qcow2,bus=virtio \
		--disk path="$seed_iso",device=cdrom \
		--network network=net-mgmt,model=virtio,mac="$mgmt_mac" \
		--network bridge="$bridge",model=virtio,mac="$seg_mac" \
		--os-variant debian13 \
		--cpu host-model \
		--boot loader="$ovmf_code",loader_ro=yes,loader_type=pflash,loader_secure=off,nvram_template="$ovmf_vars_template",nvram="$nvram" \
		--graphics none \
		--noautoconsole \
		--import
else
	sudo -n virsh start "$domain" >/dev/null 2>&1 || true
fi

echo "== wait for cloud-init (bounded) =="
mgmt_ip=${mgmt_addr%%/*}
ok=0
for _ in $(seq 1 60); do
	if ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ConnectTimeout=3 \
		-o ControlMaster=no -o ControlPath=none -i ~/.ssh/id_ed25519_lab \
		lab@"$mgmt_ip" 'test -f /var/lib/cloud/lab-bootstrap-done' 2>/dev/null; then
		ok=1
		break
	fi
	sleep 10
done
[ "$ok" -eq 1 ] || {
	echo "up-source: cloud-init did not finish inside the bound" >&2
	exit 1
}

echo "up-source: $CELL source ($source_type) ready at $mgmt_ip, segment address ${seg_addr%%/*}"
