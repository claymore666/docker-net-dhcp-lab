#!/bin/bash
# Bring up one cell's IP source VM (issue #2): its own per-run overlay,
# dual-homed like the docker host, on the segment bridge up-cell.sh has
# already built. Call after up-cell.sh; this script never touches the
# bridge itself.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CELL=${1:?usage: up-source.sh <cell-name> <work-dir> [primary|partner]}
WORK=${2:?usage: up-source.sh <cell-name> <work-dir> [primary|partner]}
PEER=${3:-primary}
case "$PEER" in primary | partner) ;; *)
	echo "up-source: peer must be primary or partner, got $PEER" >&2
	exit 2
	;;
esac
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$LAB_YAML" "$CELL")
source_type=$(jq -r '.cell.source.type // empty' <<<"$RESOLVED")
if [ -z "$source_type" ]; then
	echo "up-source: cell $CELL has no source in lab.yaml, nothing to do" >&2
	exit 1
fi
seg_subnet=$(jq -r '.cell.segment.subnet' <<<"$RESOLVED")
mgmt_gw=$(jq -r '.management.gateway' <<<"$RESOLVED")
primary_seg=$(jq -r '.cell.source.seg_address' <<<"$RESOLVED")
partner_seg=$(jq -r '.cell.source.partner.seg_address // empty' <<<"$RESOLVED")
if [ "$PEER" = partner ] && [ -z "$partner_seg" ]; then
	echo "up-source: cell $CELL has no source.partner in lab.yaml" >&2
	exit 1
fi
if [ "$PEER" = partner ]; then
	mgmt_addr=$(jq -r '.cell.source.partner.mgmt_address' <<<"$RESOLVED")
	seg_addr=$partner_seg
	domain="lab-${CELL}-partner"
else
	mgmt_addr=$(jq -r '.cell.source.mgmt_address' <<<"$RESOLVED")
	seg_addr=$primary_seg
	domain="lab-${CELL}-source"
fi
pool_start=$(jq -r '.cell.source.pool_start' <<<"$RESOLVED")
pool_end=$(jq -r '.cell.source.pool_end' <<<"$RESOLVED")
vcpus=$(jq -r '.cell.source.vcpus' <<<"$RESOLVED")
mem=$(jq -r '.cell.source.memory_mib' <<<"$RESOLVED")
diskgib=$(jq -r '.cell.source.disk_gib' <<<"$RESOLVED")
# The IPv6 side (#23 group D): a source type that serves v6 needs it, and
# the adapters' Ready reads the v6 configs, so such a cell stops here
# without it. A v4-only type (labyaml.SourceServesV6, lab #10) carries none.
serves_v6=$(jq -r '.source_serves_v6' <<<"$RESOLVED")
seg_subnet6=$(jq -r '.cell.segment.subnet6 // empty' <<<"$RESOLVED")
seg_addr6=$(jq -r '.cell.source.seg_address6 // empty' <<<"$RESOLVED")
if [ "$PEER" = partner ]; then
	seg_addr6=$(jq -r '.cell.source.partner.seg_address6 // empty' <<<"$RESOLVED")
fi
pool6_start=$(jq -r '.cell.source.pool6_start // empty' <<<"$RESOLVED")
pool6_end=$(jq -r '.cell.source.pool6_end // empty' <<<"$RESOLVED")
temp6_pool=$(jq -r '.cell.source.temp6_pool // empty' <<<"$RESOLVED")
if [ "$serves_v6" = true ]; then
	for v in seg_subnet6 seg_addr6 pool6_start pool6_end temp6_pool; do
		if [ -z "${!v}" ]; then
			echo "up-source: cell $CELL has no $v in lab.yaml" >&2
			exit 1
		fi
	done
fi

# Same deterministic-MAC scheme as up-cell.sh, own domain name so the two
# VMs on one cell never collide.
mac_from() {
	echo -n "$1" | md5sum | cut -c1-6 | sed -E 's/(..)(..)(..)/52:54:00:\1:\2:\3/'
}
mgmt_mac=$(mac_from "${domain}-mgmt")
seg_mac=$(mac_from "${domain}-seg")

image_name=$(jq -r '.source_image.name' <<<"$RESOLVED")
image_url=$(jq -r '.source_image.url' <<<"$RESOLVED")
os_variant=$(jq -r '.source_image.os_variant' <<<"$RESOLVED")
image_kind=$(jq -r '.source_image.kind' <<<"$RESOLVED")
image_sums=$(jq -r '.source_image.checksum_url // ""' <<<"$RESOLVED")
seed_kind=$(jq -r '.source_image.seed' <<<"$RESOLVED")
case "$seed_kind" in
cloud-init | qga | baked) seed_hook=${seed_kind//-/_} ;;
*)
	echo "up-source: REFUSED -- unknown seed kind '$seed_kind' for $image_name" >&2
	exit 1
	;;
esac

mkdir -p "$WORK"
known_hosts="$WORK/known_hosts"
[ -f "$known_hosts" ] || : >"$known_hosts"

# UP_SOURCE_RENDER_ONLY=1 stops after the seed files are written, with no
# image fetch, overlay, key or VM: scripts/up-source-test.sh (lab #10).
overlay="$WORK/${domain}.qcow2"
if [ -n "${UP_SOURCE_RENDER_ONLY:-}" ]; then
	pubkey="ssh-ed25519 AAAA render-only"
else
	base_path=$("$REPO_ROOT/scripts/fetch-base-image.sh" "$image_name" "$image_url" "$image_kind" "$image_sums")
	if [ ! -f "$overlay" ]; then
		qemu-img create -f qcow2 -F qcow2 -b "$base_path" "$overlay" "${diskgib}G"
	fi
	if [ ! -f ~/.ssh/id_ed25519_lab.pub ]; then
		ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519_lab -C lab-controller >/dev/null
	fi
	pubkey=$(cat ~/.ssh/id_ed25519_lab.pub)
fi

# This repo's segments are always a /24 (lab.yaml's own convention,
# issue #1); the isc-dhcp template needs network+netmask, not CIDR.
seg_network=${seg_subnet%/*}
seg_netmask=255.255.255.0

# The DHCP server's own router option (issue #3, A13 redesign): the
# source VM's seg_address stripped of its CIDR suffix, mirroring a real
# Fritz.Box, where the DHCP server and the LAN gateway are the same box.
# A pair (#12) hands out the primary's address from both peers.
seg_addr_ip=${primary_seg%%/*}
gateway_ip=$seg_addr_ip

# A relay cell (#11): the source sits on the relay's server segment, the
# router a container is handed is the relay's client leg, and the
# source routes the client segment back through the relay's server leg.
relay_client=$(jq -r '.cell.relay.client_address // empty' <<<"$RESOLVED")
bridge=$(jq -r '.cell.segment.bridge' <<<"$RESOLVED")
route_args=()
if [ -n "$relay_client" ]; then
	gateway_ip=${relay_client%%/*}
	bridge=$(jq -r '.cell.relay.server_segment.bridge' <<<"$RESOLVED")
	relay_server=$(jq -r '.cell.relay.server_address' <<<"$RESOLVED")
	route_args=("$seg_subnet" "${relay_server%%/*}")
fi

# Group B (#23): the class pool B5 serves to option 60 "lab-class-b5" is
# a fixed host-octet band above every cell's main pool (.100-.200). The
# same two numbers live in internal/scenario/groupb_addrs.go; a Go test
# reads them out of this file.
class_first_host=221
class_last_host=230
class_prefix=${seg_network%.*}
class_pool_start="$class_prefix.$class_first_host"
class_pool_end="$class_prefix.$class_last_host"

# Seed hooks (#9), one pair per BaseImage.Seed. seed_<kind> runs before
# the VM exists and sets seed_args, the virt-install arguments that hand
# the seed over; ready_<kind> runs after it boots and exits 0 once the
# source has finished its own setup, 1 to be polled again. Both read the
# variables above. qga (CHR) and baked (OpenWrt) are below.
seed_cloud_init() {
	case "${partner_seg:+pair}-$source_type" in
	-*) tmpl_name="$source_type" ;;
	pair-kea) tmpl_name=kea-ha ;;
	pair-isc-dhcp) tmpl_name=isc-dhcp-failover ;;
	*)
		echo "up-source: no pair template for source type $source_type" >&2
		exit 1
		;;
	esac
	tmpl="$REPO_ROOT/cloud-init/${tmpl_name}-user-data.tmpl.yaml"
	if [ "$PEER" = partner ]; then seed_dir="$WORK/seed-partner"; else seed_dir="$WORK/seed-source"; fi
	if [ "$PEER" = partner ]; then host_name="lab-${source_type}-partner"; else host_name="lab-${source_type}-source"; fi
	mkdir -p "$seed_dir"
	sed -e "s#__SSH_PUBKEY__#$pubkey#" \
		-e "s#__SEG_SUBNET__#$seg_subnet#g" -e "s#__SEG_NETWORK__#$seg_network#g" \
		-e "s#__SEG_NETMASK__#$seg_netmask#g" \
		-e "s#__SEG_GATEWAY__#$gateway_ip#g" \
		-e "s#__POOL_START__#$pool_start#g" -e "s#__POOL_END__#$pool_end#g" \
		-e "s#__CLASS_POOL_START__#$class_pool_start#g" -e "s#__CLASS_POOL_END__#$class_pool_end#g" \
		-e "s#__SEG_SUBNET6__#$seg_subnet6#g" -e "s#__POOL6_START__#$pool6_start#g" \
		-e "s#__POOL6_END__#$pool6_end#g" -e "s#__TEMP6_POOL__#$temp6_pool#g" \
		-e "s#__HA_THIS__#$PEER#g" -e "s#^hostname: lab-${source_type}-source\$#hostname: $host_name#" \
		-e "s#__HA_PRIMARY_SEG__#${primary_seg%%/*}#g" -e "s#__HA_PARTNER_SEG__#${partner_seg%%/*}#g" \
		"$tmpl" >"$seed_dir/user-data"
	# A v4-only cell has no __SEG_ADDR6__ item to fill: drop it from the
	# template the renderer reads, and hand it a placeholder it never uses.
	net_tmpl="$REPO_ROOT/cloud-init/source-network-config.tmpl.yaml"
	net_addr6=$seg_addr6
	if [ "$serves_v6" != true ]; then
		net_tmpl="$seed_dir/network-config.tmpl"
		sed 's#, "__SEG_ADDR6__"##' "$REPO_ROOT/cloud-init/source-network-config.tmpl.yaml" >"$net_tmpl"
		net_addr6=none
	fi
	"$REPO_ROOT/scripts/render-source-network-config.sh" "$net_tmpl" \
		"$mgmt_addr" "$mgmt_gw" "$mgmt_mac" "$seg_mac" "$seg_addr" "$net_addr6" "${route_args[@]}" >"$seed_dir/network-config"
	echo "instance-id: $domain" >"$seed_dir/meta-data"
	echo "local-hostname: $host_name" >>"$seed_dir/meta-data"
	if [ -n "${UP_SOURCE_RENDER_ONLY:-}" ]; then
		echo "up-source: render-only, seed in $seed_dir"
		exit 0
	fi

	seed_iso="$WORK/${domain}-seed.iso"
	rm -f "$seed_iso"
	genisoimage -output "$seed_iso" -volid cidata -joliet -rock \
		"$seed_dir/user-data" "$seed_dir/meta-data" "$seed_dir/network-config" >/dev/null
	seed_args=(--disk "path=$seed_iso,device=cdrom")
}

ready_cloud_init() {
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ConnectTimeout=3 \
		-o ControlMaster=no -o ControlPath=none -i ~/.ssh/id_ed25519_lab \
		lab@"$mgmt_ip" 'test -f /var/lib/cloud/lab-bootstrap-done' 2>/dev/null
}

# qga (CHR, #9): RouterOS has no cloud-init. The three scripts and the key
# go to the VM through its guest agent once it boots; seed-chr.sh does it
# from ready_qga, which polls until the identity the seed sets last reads
# back over ssh as lab.
seed_qga() {
	if [ -n "$partner_seg$relay_client" ]; then
		echo "up-source: REFUSED -- the qga seed builds a single source with no relay" >&2
		exit 1
	fi
	seed_dir="$WORK/seed-source"
	mkdir -p "$seed_dir"
	for f in lab-mgmt lab-baseline lab-seed; do
		sed -e "s#__MGMT_ADDR__#$mgmt_addr#g" -e "s#__MGMT_GW__#$mgmt_gw#g" \
			-e "s#__SEG_ADDR__#$seg_addr#g" -e "s#__SEG_SUBNET__#$seg_subnet#g" \
			-e "s#__SEG_GATEWAY__#$gateway_ip#g" \
			-e "s#__POOL_START__#$pool_start#g" -e "s#__POOL_END__#$pool_end#g" \
			-e "s#__CLASS_POOL_START__#$class_pool_start#g" -e "s#__CLASS_POOL_END__#$class_pool_end#g" \
			"$REPO_ROOT/routeros/$f.tmpl.rsc" >"$seed_dir/$f.rsc"
	done
	printf '%s\n' "$pubkey" >"$seed_dir/lab.pub"
	if [ -n "${UP_SOURCE_RENDER_ONLY:-}" ]; then
		echo "up-source: render-only, seed in $seed_dir"
		exit 0
	fi
	seed_args=(--channel "unix,target.type=virtio,target.name=org.qemu.guest_agent.0")
}

# seed-chr.sh exits 1 while the agent or sshd is not up yet; 2 is a refusal.
# A seeded CHR the lab key cannot log in to says why on every poll (#9).
ready_qga() {
	local id
	id=$(ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ConnectTimeout=3 \
		-o ControlMaster=no -o ControlPath=none -i ~/.ssh/id_ed25519_lab \
		lab@"$mgmt_ip" ':put [/system identity get name]' 2>"$WORK/lab-login.err" | tr -d '\r') || true
	[ "$id" = lab-ready ] && return 0
	local rc=0
	"$REPO_ROOT/scripts/seed-chr.sh" "$domain" "$seed_dir" "$mgmt_ip" "$known_hosts" || rc=$?
	if [ "$rc" = 2 ]; then
		echo "up-source: REFUSED -- seed-chr.sh refused $domain" >&2
		exit 1
	fi
	if [ "$rc" = 0 ]; then
		echo "up-source: $domain is seeded, but the lab login read identity \"$id\": $(tr -d '\r' <"$WORK/lab-login.err")" >&2
	fi
	return 1
}

# baked (#9): the image carries the cell's addresses, key and pool, so
# the cache's build id must be the one the build script derives from the
# cell now, an overlay must not predate its base, and the boot marker
# must hold that id, not one a reflashed older image left behind.
seed_baked() {
	if [ "$PEER" != primary ] || [ -n "$relay_client" ]; then
		echo "up-source: REFUSED -- a baked image serves one plain cell, not $PEER${relay_client:+ behind a relay}" >&2
		exit 1
	fi
	local sidecar want build="scripts/build-${image_name%%-*}-image.sh"
	if [ ! -x "$REPO_ROOT/$build" ]; then
		echo "up-source: REFUSED -- the baked image $image_name has no build script $build" >&2
		exit 1
	fi
	sidecar="${LAB_IMAGE_CACHE:-/srv/lab/images}/$image_name.build-id"
	want=$(LAB_PUBKEY="$pubkey" "$REPO_ROOT/$build" --id "$CELL")
	baked_id=$(cat "$sidecar" 2>/dev/null || true)
	if [ "$baked_id" != "$want" ]; then
		echo "up-source: REFUSED -- $sidecar holds '${baked_id:-nothing}', cell $CELL needs $want; run $build $CELL" >&2
		exit 1
	fi
	if [ -n "${UP_SOURCE_RENDER_ONLY:-}" ]; then exit 0; fi
	if [ "$overlay" -ot "$base_path" ]; then
		echo "up-source: REFUSED -- $overlay predates the image it overlays; tear the cell down first" >&2
		exit 1
	fi
}

ready_baked() {
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ConnectTimeout=3 \
		-o ControlMaster=no -o ControlPath=none -i ~/.ssh/id_ed25519_lab \
		lab@"$mgmt_ip" "grep -qxF $baked_id /etc/lab-bootstrap-done" 2>/dev/null
}

seed_args=()
"seed_$seed_hook"

ovmf_code=/usr/share/OVMF/OVMF_CODE_4M.fd
ovmf_vars_template=/usr/share/OVMF/OVMF_VARS_4M.fd
nvram="$WORK/${domain}-VARS.fd"

# CHR 7.24.5 does not boot under OVMF (M3, #9): firmware bios pins SeaBIOS.
# uefi=off stops virt-install (5.0) from picking UEFI for an OS that
# osinfo lists as UEFI-only.
boot_args=(--boot "loader=$ovmf_code,loader_ro=yes,loader_type=pflash,loader_secure=off,nvram_template=$ovmf_vars_template,nvram=$nvram")
if [ "$(jq -r '.source_image.firmware // ""' <<<"$RESOLVED")" = bios ]; then
	boot_args=(--boot uefi=off)
fi

echo "== source VM ($source_type, $PEER) =="
if ! sudo -n virsh dominfo "$domain" >/dev/null 2>&1; then
	sudo -n virt-install \
		--name "$domain" \
		--memory "$mem" --vcpus "$vcpus" \
		--disk path="$overlay",format=qcow2,bus=virtio \
		"${seed_args[@]}" \
		--network network=net-mgmt,model=virtio,mac="$mgmt_mac" \
		--network bridge="$bridge",model=virtio,mac="$seg_mac" \
		--os-variant "$os_variant" \
		--cpu host-model \
		"${boot_args[@]}" \
		--graphics none \
		--noautoconsole \
		--import
else
	sudo -n virsh start "$domain" >/dev/null 2>&1 || true
fi

echo "== wait for $seed_kind (bounded) =="
mgmt_ip=${mgmt_addr%%/*}
ok=0
for _ in $(seq 1 60); do
	if "ready_$seed_hook"; then
		ok=1
		break
	fi
	sleep 10
done
[ "$ok" -eq 1 ] || {
	echo "up-source: $seed_kind did not finish inside the bound" >&2
	exit 1
}

echo "up-source: $CELL source ($source_type, $PEER) ready at $mgmt_ip, segment address ${seg_addr%%/*}"
