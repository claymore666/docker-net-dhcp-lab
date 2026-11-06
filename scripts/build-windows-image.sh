#!/bin/bash
# Build the Windows Server 2025 evaluation image a lab cell boots (lab #14):
# an unattended install from the ISO placed on the host by hand, the DHCP
# role, OpenSSH with the lab key, the cell's addresses and scope baked in.
# The golden disk lands where fetch-base-image.sh's built arm looks for it,
# with a build-id sidecar that up-source.sh compares. The build is accepted
# only after a second boot reads the marker back over ssh.

#   build-windows-image.sh <cell>                 build into the image cache
#   build-windows-image.sh --render <cell> <dir>  write the seed files, print the id
#   build-windows-image.sh --id <cell>            print the id only
#   build-windows-image.sh --record <cell> <dir>  save fixtures from the running cell
#
# Passwords are drawn per build, live only in the work directory and are
# never needed again: every later login is by key.
set -euo pipefail
umask 022
# A replacement text with '&' must stay literal in the substitutions below.
shopt -u patsub_replacement 2>/dev/null || true

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LAB_YAML="${LAB_YAML:-$REPO_ROOT/lab.yaml}"
CACHE_DIR=${LAB_IMAGE_CACHE:-/srv/lab/images}
ISO_DIR=${LAB_WINDOWS_ISO_DIR:-$CACHE_DIR/iso}
PIN_FILE=${LAB_WINDOWS_ISO_PIN:-$REPO_ROOT/images/windows-2025-eval.sha256}
TMPL_DIR=$REPO_ROOT/cloud-init/windows

IMAGE_NAME=windows-2025-eval
ISO_NAME='windows-server-2025-eval.iso'
# A versioned release, not stable-virtio/: the stable name moves and its
# drivers would change under one build id (lab #14).
VIRTIO_NAME='virtio-win-0.1.302.iso'
VIRTIO_URL=https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.302-1/virtio-win-0.1.302.iso
# Setup selects the image by name; the pin file header records the ISO it
# was written for (lab #14).
WIN_IMAGE_NAME='Windows Server 2025 SERVERSTANDARDCORE'
VM_SHAPE='vcpus=2 memory=4096 disk=20G'
BUILD_BOUND=${WINDOWS_BUILD_TIMEOUT_S:-10800}
TICK=${WINDOWS_BUILD_TICK:-10}
KEY_SLEEP=${WINDOWS_BUILD_KEY_SLEEP:-2}

usage() {
	echo "usage: build-windows-image.sh <cell> | --render <cell> <dir> | --id <cell> | --record <cell> <dir>" >&2
	exit 2
}
mode=build
case "${1:-}" in
--render | --record)
	mode=${1#--}
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
base_image=$(field .cell.source.base_image)
if [ "$base_image" != "$IMAGE_NAME" ]; then
	echo "build-windows-image: REFUSED -- cell $CELL is on '$base_image', not $IMAGE_NAME" >&2
	exit 1
fi
# The type the image serves is windows; its image under another type is a
# cell edited by hand (lab #14).
source_type=$(field .cell.source.type)
if [ "$source_type" != windows ]; then
	echo "build-windows-image: REFUSED -- cell $CELL has source type '$source_type', not windows" >&2
	exit 1
fi
mgmt_addr=$(field .cell.source.mgmt_address)
mgmt_gw=$(field .management.gateway)
seg_addr=$(field .cell.source.seg_address)
pool_start=$(field .cell.source.pool_start)
pool_end=$(field .cell.source.pool_end)
seg_subnet=$(field .cell.segment.subnet)
seg_ip=${seg_addr%%/*}
seg_prefix=${seg_ip%.*}
if [ "${seg_addr#*/}" != 24 ] || [ "${pool_start%.*}" != "$seg_prefix" ] || [ "${pool_end%.*}" != "$seg_prefix" ]; then
	echo "build-windows-image: REFUSED -- segment $seg_addr is not a /24 holding the pool $pool_start-$pool_end" >&2
	exit 1
fi
# The B5 class pool band, the same two numbers as up-source.sh (the test
# compares them); the band between the main pool and it is excluded.
class_first_host=221
class_last_host=230
gap_first=$((${pool_end##*.} + 1))
gap_last=$((class_first_host - 1))
if [ "$gap_first" -gt "$gap_last" ]; then
	echo "build-windows-image: REFUSED -- the pool $pool_start-$pool_end reaches the class pool band .$class_first_host-.$class_last_host" >&2
	exit 1
fi

# The same scheme as up-source.sh's mac_from, so the NICs the image
# matches by MAC are the ones the run gives it; the test compares the two.
mac_from() {
	echo -n "$1" | md5sum | cut -c1-6 | sed -E 's/(..)(..)(..)/52:54:00:\1:\2:\3/'
}
domain="lab-${CELL}-source"
mgmt_mac=$(mac_from "${domain}-mgmt")
seg_mac=$(mac_from "${domain}-seg")

if [ -n "${LAB_PUBKEY:-}" ]; then
	pubkey=$LAB_PUBKEY
else
	if [ "$mode" = build ] && [ ! -f ~/.ssh/id_ed25519_lab.pub ]; then
		ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519_lab -C lab-controller >/dev/null
	fi
	pubkey=$(cat ~/.ssh/id_ed25519_lab.pub)
fi

# pinned_sum FILE prints the sha256 the pin file holds for FILE, or nothing.
pinned_sum() {
	awk -v f="$1" 'NF && $1 !~ /^#/ && $2 == f {print $1; exit}' "$PIN_FILE" 2>/dev/null || true
}

# win_mac turns aa:bb:.. into the AA-BB-.. form Get-NetAdapter reports.
win_mac() { tr 'a-f:' 'A-F-' <<<"$1"; }

# subst VAR... reads the template on stdin; each NAME=value argument
# replaces __NAME__. A bash expansion, so a password is never on an argv.
subst() {
	local text pair
	text=$(cat)
	for pair in "$@"; do
		text=${text//"__${pair%%=*}__"/${pair#*=}}
	done
	printf '%s\n' "$text"
}

# One driver tree only: Setup loads every listed path and fails the whole
# install with 0x80070103 on a second copy of a driver it already loaded
# (measured: viostor 2k25 loaded, the 2k22 copy then stopped Setup, lab #14).
# A path that does not exist is skipped (same run: the D: paths came first).
driver_paths() {
	local n=0 letter drv
	for letter in D E F G; do
		for drv in viostor NetKVM; do
			n=$((n + 1))
			printf '        <PathAndCredentials wcm:action="add" wcm:keyValue="%d"><Path>%s:\\%s\\2k25\\amd64</Path></PathAndCredentials>\n' "$n" "$letter" "$drv"
		done
	done
}

# render_seed DIR ID ADMIN_PW LAB_PW writes the two files the seed CD carries.
render_seed() {
	local d=$1 id=$2 admin=$3 labpw=$4
	mkdir -p "$d"
	subst "IMAGE_NAME=$WIN_IMAGE_NAME" "ADMIN_PASSWORD=$admin" "LAB_PASSWORD=$labpw" \
		"DRIVER_PATHS=$(driver_paths)" <"$TMPL_DIR/autounattend.tmpl.xml" >"$d/autounattend.xml"
	subst "BUILD_ID=$id" "PUBKEY=$pubkey" \
		"MGMT_MAC=$(win_mac "$mgmt_mac")" "MGMT_IP=${mgmt_addr%%/*}" "MGMT_PREFIX=${mgmt_addr#*/}" "MGMT_GW=$mgmt_gw" \
		"SEG_MAC=$(win_mac "$seg_mac")" "SEG_IP=$seg_ip" "SEG_PREFIX=${seg_addr#*/}" \
		"SEG_NETWORK=${seg_subnet%/*}" "SEG_GATEWAY=$seg_ip" \
		"POOL_START=$pool_start" "POOL_END=$pool_end" \
		"CLASS_POOL_START=$seg_prefix.$class_first_host" "CLASS_POOL_END=$seg_prefix.$class_last_host" \
		"GAP_START=$seg_prefix.$gap_first" "GAP_END=$seg_prefix.$gap_last" <"$TMPL_DIR/firstlogon.tmpl.ps1" >"$d/firstlogon.ps1"
}

# image_id is the sha256 over a render with fixed stand-in passwords and
# an id placeholder, the ISO pin and the VM shape: anything the image
# carries moves it, a fresh password draw does not (lab #14).
image_id() {
	local d
	d=$(mktemp -d)
	render_seed "$d" ID-PENDING render-only render-only
	(
		cd "$d"
		echo "$WIN_IMAGE_NAME $ISO_NAME $VM_SHAPE pin=$(pinned_sum "$ISO_NAME") virtio=$(pinned_sum "$VIRTIO_NAME")"
		find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
	) | sha256sum | cut -d' ' -f1
	rm -rf "$d"
}

# render_with_id DIR prints the id after writing the seed files into DIR.
render_with_id() {
	local id
	id=$(image_id)
	render_seed "$1" "$id" render-only render-only
	echo "$id"
}

# ps_ssh CMD: runs PowerShell text on the cell's source as the lab user.
# The command travels as -EncodedCommand (UTF-16LE base64), so no quote
# survives two shells; a non-terminating error exits 1 (lab #14).
ps_ssh() {
	local enc
	enc=$(printf '%s' "\$ErrorActionPreference = 'Stop'; $1; if (-not \$?) { exit 1 }" | iconv -f UTF-8 -t UTF-16LE | base64 -w0)
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
		-o ControlMaster=no -o ControlPath=none -i ~/.ssh/id_ed25519_lab \
		lab@"${mgmt_addr%%/*}" powershell -NonInteractive -EncodedCommand "$enc"
}

case "$mode" in
id)
	image_id
	exit 0
	;;
render)
	render_with_id "$OUT"
	exit 0
	;;
record)
	id=$(image_id)
	known_hosts=$(mktemp)
	stage=$(mktemp -d)
	trap 'rm -rf "$stage" "$known_hosts"' EXIT
	if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
		echo "build-windows-image: REFUSED -- $OUT is not empty" >&2
		exit 1
	fi
	scope=${seg_subnet%/*}
	# One file per read the adapter will make; the header carries the date
	# and the image, so a stale recording is visible in the fixture itself.
	declare -A reads=(
		[leases]="ConvertTo-Json -InputObject @(Get-DhcpServerv4Lease -ScopeId $scope | Select-Object IPAddress, ClientId, HostName, AddressState, @{n='Expiry';e={([DateTimeOffset]\$_.LeaseExpiryTime).ToUnixTimeSeconds()}}) -Depth 3"
		[scope]="ConvertTo-Json -InputObject @(Get-DhcpServerv4Scope -ScopeId $scope) -Depth 3"
		[options]="ConvertTo-Json -InputObject @(Get-DhcpServerv4OptionValue -ScopeId $scope) -Depth 3"
		[setting]="ConvertTo-Json -InputObject (Get-DhcpServerSetting | Select-Object ConflictDetectionAttempts) -Depth 3"
		[service]="(Get-Service -Name DHCPServer).Status.ToString()"
		[clock]="[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()"
		[marker]="Get-Content -Raw C:\\ProgramData\\lab\\bootstrap-done"
		[expiry]="& cscript.exe //nologo \$env:SystemRoot\\System32\\slmgr.vbs /xpr"
		[audit]="Get-Content -Tail 50 (\$env:SystemRoot + '\\System32\\dhcp\\DhcpSrvLog-' + (Get-Date).DayOfWeek.ToString().Substring(0,3) + '.log')"
	)
	for name in "${!reads[@]}"; do
		{
			echo "# recorded $(date -u +%Y-%m-%dT%H:%M:%SZ) from $domain, image $IMAGE_NAME, build $id"
			ps_ssh "${reads[$name]}"
		} >"$stage/$name.txt" || {
			echo "build-windows-image: REFUSED -- the read '$name' failed on $domain; nothing recorded" >&2
			exit 1
		}
	done
	mkdir -p "$OUT"
	cp -- "$stage"/*.txt "$OUT"/
	echo "build-windows-image: ${#reads[@]} reads recorded in $OUT"
	exit 0
	;;
esac

# --- build ---------------------------------------------------------------
refuse() {
	echo "build-windows-image: REFUSED -- $*" >&2
	exit 1
}

pin=$(pinned_sum "$ISO_NAME")
if [ -z "$pin" ]; then
	refuse "no checksum is pinned for the ISO in $PIN_FILE; add '<sha256>  $ISO_NAME' under its header"
fi
if ! [[ "$pin" =~ ^[0-9a-f]{64}$ ]]; then
	refuse "the pinned value in $PIN_FILE is not a sha256"
fi
vpin=$(pinned_sum "$VIRTIO_NAME")
[[ "$vpin" =~ ^[0-9a-f]{64}$ ]] || refuse "no sha256 is pinned for $VIRTIO_NAME in $PIN_FILE"
iso=$ISO_DIR/$ISO_NAME
virtio=$ISO_DIR/$VIRTIO_NAME
[ -f "$iso" ] || refuse "$iso is not there; download the Windows Server 2025 evaluation ISO from the Evaluation Center by hand and place it there"
[ -f "$virtio" ] || refuse "$virtio is not there; download $VIRTIO_URL"
sum=$(sha256sum "$iso" | awk '{print $1}')
vsum=$(sha256sum "$virtio" | awk '{print $1}')
[ "$vsum" = "$vpin" ] || refuse "$virtio is $vsum, $PIN_FILE pins $vpin; download $VIRTIO_URL again"
[ "$sum" = "$pin" ] || refuse "$iso is $sum, $PIN_FILE pins $pin; if this is a newer evaluation ISO from the Evaluation Center, check the image name and replace the pinned line in $PIN_FILE with the new sum, otherwise put the pinned ISO back"
if sudo -n virsh dominfo "$domain" >/dev/null 2>&1; then
	refuse "domain $domain exists and holds this cell's MACs and address; tear the cell down first"
fi

build_dom=lab-build-$IMAGE_NAME
dest=$CACHE_DIR/$IMAGE_NAME.qcow2
part=$dest.part
base=${WINDOWS_BUILD_DIR:-$CACHE_DIR/windows-build}
mkdir -p "$base" "$CACHE_DIR"
work=$(mktemp -d "$base/run.XXXXXX")
chmod 755 "$work"
ok=0
cleanup() {
	if [ "$ok" -ne 1 ]; then
		sudo -n virsh destroy "$build_dom" >/dev/null 2>&1 || true
		sudo -n virsh undefine "$build_dom" --nvram >/dev/null 2>&1 || true
		rm -f "$part"
	fi
	rm -rf "$work"
}
trap cleanup EXIT
sudo -n virsh destroy "$build_dom" >/dev/null 2>&1 || true
sudo -n virsh undefine "$build_dom" --nvram >/dev/null 2>&1 || true
rm -f "$part"

# Two draws, each shown to nobody: they exist in the rendered answer
# file and nowhere else. Windows wants upper, lower, digit and symbol.
draw() { printf '%sAa1!' "$(openssl rand -base64 18 | tr -d '+/=')"; }
admin_pw=$(draw)
lab_pw=$(draw)
id=$(image_id)
render_seed "$work/seed" "$id" "$admin_pw" "$lab_pw"
seed_iso=$work/seed.iso
genisoimage -output "$seed_iso" -volid LABSEED -joliet -rock "$work/seed/autounattend.xml" "$work/seed/firstlogon.ps1" >/dev/null
chmod 644 "$seed_iso"

variant=win2k25
if command -v osinfo-query >/dev/null && ! osinfo-query os short-id=win2k25 >/dev/null 2>&1; then
	variant=win2k22
fi
ovmf_code=/usr/share/OVMF/OVMF_CODE_4M.fd
ovmf_vars_template=/usr/share/OVMF/OVMF_VARS_4M.fd
nvram=$work/build-VARS.fd
known_hosts=$work/known_hosts
: >"$known_hosts"

qemu-img create -f qcow2 "$part" 20G >/dev/null
# The clock is explicit: libvirt's default for a Windows variant is a
# local-time RTC. Only the management NIC exists at build time; the
# segment NIC is addressed by MAC at the first boot of a cell.
sudo -n virt-install \
	--name "$build_dom" \
	--memory 4096 --vcpus 2 \
	--cpu host-model \
	--clock offset=utc \
	--os-variant "$variant" \
	--boot "loader=$ovmf_code,loader_ro=yes,loader_type=pflash,loader_secure=off,nvram_template=$ovmf_vars_template,nvram=$nvram" \
	--disk "path=$part,format=qcow2,bus=virtio,boot.order=2" \
	--disk "path=$iso,device=cdrom,boot.order=1" \
	--disk "path=$virtio,device=cdrom" \
	--disk "path=$seed_iso,device=cdrom" \
	--network "network=net-mgmt,model=virtio,mac=$mgmt_mac" \
	--graphics none --noautoconsole --import

# "Press any key to boot from CD" times out on a blank disk unless
# answered. The key is Enter: a key that reaches the Windows Boot Manager
# stops its countdown, and only Enter then starts Setup (measured: Space
# left the menu waiting for three hours, lab #14). Keys for 90 s, since
# OVMF took over a minute to draw its first screen on the lab host.
for _ in $(seq 1 45); do
	sudo -n virsh send-key "$build_dom" KEY_ENTER >/dev/null 2>&1 || true
	sleep "$KEY_SLEEP"
done

wait_off() {
	local bound=$1
	SECONDS=0
	while [ "$(sudo -n virsh domstate "$build_dom" 2>/dev/null | tr -d '[:space:]')" != shutoff ]; do
		if [ "$SECONDS" -ge "$bound" ]; then return 1; fi
		sleep "$TICK"
	done
}
wait_off "$BUILD_BOUND" || refuse "the install did not power the VM off inside ${BUILD_BOUND}s; destroyed, no image kept"

# Second boot on a fresh NVRAM: the image must come up on its own boot
# path (no entry from the install), and answer over ssh with the marker
# of this build and a running DHCP service.
sudo -n cp -f "$ovmf_vars_template" "$nvram"
sudo -n virsh start "$build_dom" >/dev/null
want="$id Running"
proved=0
got=
for _ in $(seq 1 60); do
	got=$(ps_ssh "(Get-Content -Raw C:\\ProgramData\\lab\\bootstrap-done) + ' ' + (Get-Service -Name DHCPServer).Status" 2>/dev/null | tr -d '\r\n' || true)
	if [ "$got" = "$want" ]; then
		proved=1
		break
	fi
	sleep "$TICK"
done
[ "$proved" -eq 1 ] || refuse "the second boot did not read back '$want' over SSH (last read '${got:-nothing}'); destroyed, no image kept"
ps_ssh "Stop-Computer -Force" >/dev/null 2>&1 || true
wait_off 300 || refuse "the VM did not power off after the proof"

sudo -n virsh undefine "$build_dom" --nvram >/dev/null
mv "$part" "$dest"
echo "$id" >"$CACHE_DIR/$IMAGE_NAME.build-id"
printf '%s  %s\n%s  %s\n' "$sum" "$ISO_NAME" "$vsum" "$VIRTIO_NAME" >"$CACHE_DIR/$IMAGE_NAME.sources"
ok=1
# A dated, read-only copy with its sidecars: cells boot overlays of $dest,
# and a failed or expired rebuild rolls back by copying this one over it
# (the evaluation runs 180 days from install, lab #14).
keep=$CACHE_DIR/$IMAGE_NAME-$(date -u +%Y%m%d)
rm -f "$keep.qcow2" "$keep.build-id" "$keep.sources"
cp --sparse=always "$dest" "$keep.qcow2"
cp "$CACHE_DIR/$IMAGE_NAME.build-id" "$keep.build-id"
cp "$CACHE_DIR/$IMAGE_NAME.sources" "$keep.sources"
chmod 0444 "$keep.qcow2" "$keep.build-id" "$keep.sources"
cmp -s "$dest" "$keep.qcow2" || refuse "the dated copy $keep.qcow2 differs from $dest"
echo "build-windows-image: $dest built, id $id; read-only copy $keep.qcow2"
