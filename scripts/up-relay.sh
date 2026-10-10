#!/bin/bash
# Bring up a relay cell's relay VM (#11): eth0 on net-mgmt, eth1 on the
# Docker host's segment bridge, eth2 on the source's server bridge, both
# built by up-cell.sh first. Same overlay, seed and bounded cloud-init
# wait as up-source.sh; its two config files come from `labctl resolve`.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CELL=${1:?usage: up-relay.sh <cell-name> <work-dir>}
WORK=${2:?usage: up-relay.sh <cell-name> <work-dir>}
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$LAB_YAML" "$CELL")
if [ -z "$(jq -r '.cell.relay.client_address // empty' <<<"$RESOLVED")" ]; then
	echo "up-relay: cell $CELL has no relay in lab.yaml, nothing to do" >&2
	exit 1
fi
mgmt_addr=$(jq -r '.cell.relay.mgmt_address' <<<"$RESOLVED")
mgmt_gw=$(jq -r '.management.gateway' <<<"$RESOLVED")
cli_addr=$(jq -r '.cell.relay.client_address' <<<"$RESOLVED")
srv_addr=$(jq -r '.cell.relay.server_address' <<<"$RESOLVED")
cli_bridge=$(jq -r '.cell.segment.bridge' <<<"$RESOLVED")
srv_bridge=$(jq -r '.cell.relay.server_segment.bridge' <<<"$RESOLVED")
vcpus=$(jq -r '.cell.relay.vcpus' <<<"$RESOLVED")
mem=$(jq -r '.cell.relay.memory_mib' <<<"$RESOLVED")
diskgib=$(jq -r '.cell.relay.disk_gib' <<<"$RESOLVED")
defaults_b64=$(jq -j '.relay_files.defaults' <<<"$RESOLVED" | base64 -w0)
nft_b64=$(jq -j '.relay_files.nft' <<<"$RESOLVED" | base64 -w0)
domain="lab-${CELL}-relay"

# Same deterministic-MAC scheme as up-cell.sh and up-source.sh.
mac_from() {
	echo -n "$1" | md5sum | cut -c1-6 | sed -E 's/(..)(..)(..)/52:54:00:\1:\2:\3/'
}
mgmt_mac=$(mac_from "${domain}-mgmt")
cli_mac=$(mac_from "${domain}-cli")
srv_mac=$(mac_from "${domain}-srv")

image_name=$(jq -r '.relay_image.name' <<<"$RESOLVED")
image_url=$(jq -r '.relay_image.url' <<<"$RESOLVED")
os_variant=$(jq -r '.relay_image.os_variant' <<<"$RESOLVED")
base_path=$("$REPO_ROOT/scripts/fetch-base-image.sh" "$image_name" "$image_url")

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

seed_dir="$WORK/seed-relay"
mkdir -p "$seed_dir"
sed -e "s#__SSH_PUBKEY__#$pubkey#" -e "s#__RELAY_HOSTNAME__#$domain#" \
	-e "s#__RELAY_DEFAULTS_B64__#$defaults_b64#" -e "s#__RELAY_NFT_B64__#$nft_b64#" \
	"$REPO_ROOT/cloud-init/relay-user-data.tmpl.yaml" >"$seed_dir/user-data"
sed -e "s#__MGMT_ADDR__#$mgmt_addr#" -e "s#__MGMT_GW__#$mgmt_gw#g" \
	-e "s#__MGMT_MAC__#$mgmt_mac#" -e "s#__CLI_MAC__#$cli_mac#" -e "s#__SRV_MAC__#$srv_mac#" \
	-e "s#__CLI_ADDR__#$cli_addr#" -e "s#__SRV_ADDR__#$srv_addr#" \
	"$REPO_ROOT/cloud-init/relay-network-config.tmpl.yaml" >"$seed_dir/network-config"
echo "instance-id: $domain" >"$seed_dir/meta-data"
echo "local-hostname: $domain" >>"$seed_dir/meta-data"

# Removed, never overwritten in place: libvirt owns it once the domain
# has started (up-cell.sh has the measurement, #1).
seed_iso="$WORK/${domain}-seed.iso"
rm -f "$seed_iso"
genisoimage -output "$seed_iso" -volid cidata -joliet -rock \
	"$seed_dir/user-data" "$seed_dir/meta-data" "$seed_dir/network-config" >/dev/null

ovmf_code=/usr/share/OVMF/OVMF_CODE_4M.fd
ovmf_vars_template=/usr/share/OVMF/OVMF_VARS_4M.fd
nvram="$WORK/${domain}-VARS.fd"

echo "== relay VM =="
if ! sudo -n virsh dominfo "$domain" >/dev/null 2>&1; then
	sudo -n virt-install \
		--name "$domain" \
		--memory "$mem" --vcpus "$vcpus" \
		--disk path="$overlay",format=qcow2,bus=virtio \
		--disk path="$seed_iso",device=cdrom \
		--network network=net-mgmt,model=virtio,mac="$mgmt_mac" \
		--network bridge="$cli_bridge",model=virtio,mac="$cli_mac" \
		--network bridge="$srv_bridge",model=virtio,mac="$srv_mac" \
		--os-variant "$os_variant" \
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
	echo "up-relay: cloud-init did not finish inside the bound" >&2
	exit 1
}

echo "up-relay: $CELL relay ready at $mgmt_ip, client leg ${cli_addr%%/*} on $cli_bridge, server leg ${srv_addr%%/*} on $srv_bridge"
