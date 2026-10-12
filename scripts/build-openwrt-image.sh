#!/bin/bash
# Build the OpenWrt source image a lab cell boots (lab #9, DESIGN-910
# 3.4): OpenWrt's own ImageBuilder, the stock package set plus sudo,
# ip-full, shadow-useradd and two coreutils, firewall4 left out, and a FILES overlay
# that carries the cell's addresses. The result lands where
# fetch-base-image.sh's built arm looks for it, with a build-id sidecar
# that up-source.sh's seed_baked and ready_baked compare.
#
#   build-openwrt-image.sh <cell>                 build into the image cache
#   build-openwrt-image.sh --render <cell> <dir>  write the overlay, print the id
#   build-openwrt-image.sh --id <cell>            print the id only
set -euo pipefail
# The overlay's modes go into the image and its build id, so they never
# follow the caller's umask (lab #9).
umask 022

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"
CACHE_DIR=${LAB_IMAGE_CACHE:-/srv/lab/images}

OPENWRT_VERSION=25.12.5
IMAGE_NAME=openwrt-$OPENWRT_VERSION-x86-64
IB_BASE=https://downloads.openwrt.org/releases/$OPENWRT_VERSION/targets/x86/64
IB_FILE=openwrt-imagebuilder-$OPENWRT_VERSION-x86-64.Linux-x86_64.tar.zst
IB_SHA256=313221253d9bac534e4a4ee6492a4941b4ba0f43200eceb8d16a4785470ae9df
# busybox here has neither base64 nor truncate; Ready reads the extra
# config files through base64 -w0 and ResetLeases truncates (lab #9).
PACKAGES="sudo ip-full shadow-useradd coreutils-base64 coreutils-truncate -firewall4"
IMG_FILE=openwrt-$OPENWRT_VERSION-x86-64-generic-squashfs-combined-efi.img.gz
ROOTFS_FILE=openwrt-$OPENWRT_VERSION-x86-64-generic-rootfs.tar.gz

usage() {
	echo "usage: build-openwrt-image.sh <cell> | --render <cell> <dir> | --id <cell>" >&2
	exit 2
}
mode=build
case "${1:-}" in
--render)
	mode=render
	CELL=${2:-}
	OUT=${3:-}
	if [ -z "$CELL" ] || [ -z "$OUT" ]; then usage; fi
	;;
--id)
	mode=id
	CELL=${2:-}
	[ -n "$CELL" ] || usage
	;;
'' | -*) usage ;;
*) CELL=$1 ;;
esac

RESOLVED=$(go run "$REPO_ROOT/cmd/labctl" resolve "$LAB_YAML" "$CELL")
field() { jq -r "$1 // empty" <<<"$RESOLVED"; }
source_type=$(field .cell.source.type)
base_image=$(field .cell.source.base_image)
if [ "$source_type" != openwrt ] || [ "$base_image" != "$IMAGE_NAME" ]; then
	echo "build-openwrt-image: REFUSED -- cell $CELL is source type '$source_type' on '$base_image', not openwrt on $IMAGE_NAME" >&2
	exit 1
fi
mgmt_addr=$(field .cell.source.mgmt_address)
mgmt_gw=$(field .management.gateway)
seg_addr=$(field .cell.source.seg_address)
pool_start=$(field .cell.source.pool_start)
pool_end=$(field .cell.source.pool_end)
seg_ip=${seg_addr%%/*}
seg_prefix=${seg_ip%.*}
if [ "${seg_addr#*/}" != 24 ] || [ "${pool_start%.*}" != "$seg_prefix" ] || [ "${pool_end%.*}" != "$seg_prefix" ]; then
	echo "build-openwrt-image: REFUSED -- segment $seg_addr is not a /24 holding the pool $pool_start-$pool_end" >&2
	exit 1
fi
pool_first=${pool_start##*.}
pool_limit=$((${pool_end##*.} - pool_first + 1))
# The B5 class band, the same host octets as up-source.sh (lab #23);
# build-openwrt-image-test.sh compares the two.
class_first_host=221
class_last_host=230

if [ -n "${LAB_PUBKEY:-}" ]; then
	pubkey=$LAB_PUBKEY
else
	if [ "$mode" = build ] && [ ! -f ~/.ssh/id_ed25519_lab.pub ]; then
		ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519_lab -C lab-controller >/dev/null
	fi
	pubkey=$(cat ~/.ssh/id_ed25519_lab.pub)
fi

# render_overlay DIR writes the FILES tree. No br-lan, no wan: the
# image's own config_generate writes those only into an empty
# /etc/config/network, and this one is shipped (lab #9 defeat N1). The
# odhcpd section is shipped whole, else uci-defaults/15_odhcpd turns
# dhcpv6 and ra back on (defeat D13b); no globals ula_prefix (D13c).
# dnsmasq binds lan (eth1) only, as every source does (#2).
render_overlay() {
	local d=$1
	mkdir -p "$d/etc/config" "$d/etc/sudoers.d" "$d/etc/uci-defaults" "$d/etc/lab"
	cat >"$d/etc/config/network" <<EOF
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	list ipaddr '127.0.0.1/8'

config interface 'mgmt'
	option device 'eth0'
	option proto 'static'
	list ipaddr '$mgmt_addr'
	option gateway '$mgmt_gw'

config interface 'lan'
	option device 'eth1'
	option proto 'static'
	list ipaddr '$seg_addr'
EOF
	cat >"$d/etc/config/dhcp" <<EOF
config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '1'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option nonegcache '0'
	option cachesize '1000'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
	option nonwildcard '1'
	list interface 'lan'
	option localservice '1'
	option ednspacket_max '1232'
	option filter_aaaa '0'
	option filter_a '0'

config dhcp 'lan'
	option interface 'lan'
	option start '$pool_first'
	option limit '$pool_limit'
	option leasetime '12h'
	option force '1'
	list tag '!b5'
	option dhcpv4 'server'
	option dhcpv6 'disabled'
	option ra 'disabled'
	option ndp 'disabled'

config dhcp 'mgmt'
	option interface 'mgmt'
	option ignore '1'
	option dhcpv4 'disabled'
	option dhcpv6 'disabled'
	option ra 'disabled'
	option ndp 'disabled'

config odhcpd 'odhcpd'
	option maindhcp '0'
	option leasefile '/tmp/odhcpd.leases'
	option leasetrigger '/usr/sbin/odhcpd-update'
	option loglevel '4'
	option piodir '/tmp/odhcpd-piodir'
	option hostsdir '/tmp/hosts'
EOF
	cat >"$d/etc/dnsmasq.conf" <<EOF
# Lab additions (lab #9): what uci has no key for. dnsmasq.init names
# this file first in the config it generates (conf-file=), and the procd
# jail mounts it.
dhcp-option=3,$seg_ip
dhcp-vendorclass=set:b5,lab-class-b5
dhcp-range=tag:b5,$seg_prefix.$class_first_host,$seg_prefix.$class_last_host,12h
EOF
	cat >"$d/etc/config/dropbear" <<'EOF'
config dropbear 'main'
	option enable '1'
	option PasswordAuth 'off'
	option RootPasswordAuth 'off'
	option Port '22'
	option Interface 'mgmt'
EOF
	echo 'lab ALL=(ALL) NOPASSWD: ALL' >"$d/etc/sudoers.d/lab"
	chmod 0440 "$d/etc/sudoers.d/lab"
	printf '%s\n' "$pubkey" >"$d/etc/lab/authorized_keys"
	cat >"$d/etc/uci-defaults/99-lab" <<'EOF'
#!/bin/sh
# Lab first boot (lab #9). A failed step exits 1, so the boot keeps this
# file and runs it again; the marker is written last.
id lab >/dev/null 2>&1 || useradd -m -d /home/lab -s /bin/ash lab || exit 1
sed -i 's/^lab:[^:]*:/lab:*:/' /etc/shadow || exit 1
mkdir -p /home/lab/.ssh/ /root/lab-stock-config || exit 1
cp /etc/lab/authorized_keys /home/lab/.ssh/authorized_keys || exit 1
chown -R lab:lab /home/lab && chmod 700 /home/lab/.ssh/ && chmod 600 /home/lab/.ssh/authorized_keys || exit 1
chmod 0440 /etc/sudoers.d/lab || exit 1
if [ ! -s /root/lab-stock-config/network.stock ]; then
	mv /etc/config/network /tmp/lab-network || exit 1
	/bin/config_generate
	mv /etc/config/network /root/lab-stock-config/network.stock
	mv /tmp/lab-network /etc/config/network || exit 1
fi
[ -s /root/lab-stock-config/network.stock ] || exit 1
cp /etc/lab-build-id /etc/lab-bootstrap-done || exit 1
exit 0
EOF
	chmod 0755 "$d/etc/uci-defaults/99-lab"
}

# overlay_id is the sha256 over a fresh render of the cell's overlay, the
# ImageBuilder sum and the package list: any change to what the image
# carries moves it (lab #9 defeat N2). It never hashes the caller's
# directory, so the stock copies the build puts beside the overlay
# cannot move it, and the umask above fixes every mode it hashes.
overlay_id() {
	local d
	d=$(mktemp -d)
	render_overlay "$d"
	(
		cd "$d"
		echo "$IB_FILE $IB_SHA256 $PACKAGES"
		find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
		find . -mindepth 1 -printf '%m %p\n' | LC_ALL=C sort
	) | sha256sum | cut -d' ' -f1
	rm -rf "$d"
}

# render_with_id DIR writes the overlay and its id file into DIR and
# prints the id; --render and the build both go through it (lab #9).
render_with_id() {
	local id
	render_overlay "$1"
	id=$(overlay_id)
	echo "$id" >"$1/etc/lab-build-id"
	echo "$id"
}

case "$mode" in
id)
	overlay_id
	exit 0
	;;
render)
	render_with_id "$OUT"
	exit 0
	;;
esac

build_dir=${OPENWRT_BUILD_DIR:-$CACHE_DIR/openwrt-build}
mkdir -p "$build_dir" "$CACHE_DIR"
ib_tar=$build_dir/$IB_FILE
if [ ! -f "$ib_tar" ] || ! echo "$IB_SHA256  $ib_tar" | sha256sum -c --quiet; then
	curl -fsSL -o "$ib_tar.part" "$IB_BASE/$IB_FILE"
	mv "$ib_tar.part" "$ib_tar"
fi
upstream=$(curl -fsSL "$IB_BASE/sha256sums" | awk -v f="*$IB_FILE" '$2 == f {print $1}')
if [ "$upstream" != "$IB_SHA256" ]; then
	echo "build-openwrt-image: REFUSED -- upstream sha256sums lists '$upstream' for $IB_FILE, the script pins $IB_SHA256" >&2
	exit 1
fi
if ! echo "$IB_SHA256  $ib_tar" | sha256sum -c --quiet; then
	echo "build-openwrt-image: REFUSED -- $ib_tar does not match the pinned sha256" >&2
	exit 1
fi
ib=$build_dir/${IB_FILE%.tar.zst}
if [ ! -d "$ib" ]; then
	tar --zstd -xf "$ib_tar" -C "$build_dir"
fi

work=$(mktemp -d "$build_dir/run.XXXXXX")
trap 'rm -rf "$work"' EXIT

# Pass 1, no FILES: the image's own /etc/config/dhcp and /etc/dnsmasq.conf
# become the stock copies capture-source-config-diff.sh reads. The stock
# network file does not exist in a rootfs; 99-lab saves config_generate's.
make -C "$ib" image PROFILE=generic PACKAGES="$PACKAGES" BIN_DIR="$work/stock" >"$work/stock.log" 2>&1 || {
	tail -n 40 "$work/stock.log" >&2
	exit 1
}
mkdir -p "$work/stockroot" "$work/files/root/lab-stock-config"
tar -xzf "$work/stock/$ROOTFS_FILE" -C "$work/stockroot" ./etc/config/dhcp ./etc/dnsmasq.conf
cp "$work/stockroot/etc/config/dhcp" "$work/files/root/lab-stock-config/dhcp.stock"
cp "$work/stockroot/etc/dnsmasq.conf" "$work/files/root/lab-stock-config/dnsmasq.conf.stock"

# Pass 2, the lab overlay.
id=$(render_with_id "$work/files")
make -C "$ib" image PROFILE=generic PACKAGES="$PACKAGES" FILES="$work/files" BIN_DIR="$work/lab" >"$work/lab.log" 2>&1 || {
	tail -n 40 "$work/lab.log" >&2
	exit 1
}

# OpenWrt pads the image after the gzip stream, so gzip reports trailing
# garbage with status 2 on a good image.
rc=0
gzip -dc "$work/lab/$IMG_FILE" >"$work/lab.img" 2>/dev/null || rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
	echo "build-openwrt-image: cannot unpack $IMG_FILE (gzip status $rc)" >&2
	exit 1
fi
dest=$CACHE_DIR/$IMAGE_NAME.qcow2
qemu-img convert -f raw -O qcow2 "$work/lab.img" "$dest.part"
mv "$dest.part" "$dest"
echo "$id" >"$CACHE_DIR/$IMAGE_NAME.build-id"
echo "build-openwrt-image: $dest built, id $id"
