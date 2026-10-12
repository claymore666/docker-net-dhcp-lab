#!/bin/bash
# up-source.sh's rendered seed files, its stdout and every qemu-img,
# genisoimage, virt-install and ssh call for the five cloud-init source
# types, pinned to the copy taken at dev b19470b before the per-seed-kind
# hooks landed (#9), then the seed and image kind dispatch and the qga
# (CHR) hooks. Stubs on PATH
# and a copy of the repo, no VM. LAB_GOLDEN_WRITE=1 rewrites the goldens.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIX="$REPO_ROOT/scripts/testdata/up-source-golden"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/repo/scripts" "$tmp/bin" "$tmp/home/.ssh"
cp "$REPO_ROOT"/scripts/*.sh "$tmp/repo/scripts/"
cp -r "$REPO_ROOT/cloud-init" "$tmp/repo/cloud-init"
cp -r "$REPO_ROOT/routeros" "$tmp/repo/routeros"
echo "ssh-ed25519 AAAAC3NzaGolden lab-controller" >"$tmp/home/.ssh/id_ed25519_lab.pub"

cat >"$tmp/repo/scripts/fetch-base-image.sh" <<'EOF'
#!/bin/bash
printf 'fetch-base-image %s %s\n' "$1" "$2" >>"$STUB_LOG"
printf '%s|' "$@" >>"$STUB_LOG.fetch"
echo "${STUB_BASE:-/srv/lab/images/$1.qcow2}"
EOF
cat >"$tmp/bin/go" <<'EOF'
#!/bin/bash
cat "$RESOLVED_FILE"
EOF
cat >"$tmp/bin/genisoimage" <<'EOF'
#!/bin/bash
{ printf 'genisoimage'; printf ' %q' "$@"; echo
for f in "$@"; do
	[ -f "$f" ] || continue
	echo "--- ${f##*/}"; cat "$f"
done; } >>"$STUB_LOG"
EOF
cat >"$tmp/bin/sudo" <<'EOF'
#!/bin/bash
{ printf 'sudo'; printf ' %q' "$@"; echo; } >>"$STUB_LOG"
[ "$2 $3" != "virsh dominfo" ]
EOF
for s in qemu-img ssh-keygen sleep ssh; do
	# shellcheck disable=SC2016 # the stub expands $@ when it runs, not here
	printf '#!/bin/bash\n{ printf %q; printf " %%q" "$@"; echo; } >>"$STUB_LOG"\n' "$s" >"$tmp/bin/$s"
done
# The CHR's ready probe (#9) reads lab-ready, or the stock identity once
# while $STUB_LOG.stock exists, or is refused while $STUB_LOG.lockout
# exists; every other call logs as the generic stub does.
cat >"$tmp/bin/ssh" <<'EOF'
#!/bin/bash
{ printf ssh; printf ' %q' "$@"; echo; } >>"$STUB_LOG"
[ "${*: -1}" = ':put [/system identity get name]' ] || exit 0
if [ -e "$STUB_LOG.stock" ]; then
	rm -f "$STUB_LOG.stock"
	echo MikroTik
elif [ -e "$STUB_LOG.lockout" ]; then
	echo 'lab@10.200.255.141: Permission denied (publickey).' >&2
	exit 255
else
	echo lab-ready
fi
EOF
chmod +x "$tmp"/bin/* "$tmp/repo/scripts/fetch-base-image.sh"

render() {
	local cell=$1 resolved=$2 out=$3
	: >"$tmp/log"
	: >"$tmp/log.fetch"
	{
		STUB_LOG="$tmp/log" RESOLVED_FILE="$resolved" HOME="$tmp/home" PATH="$tmp/bin:$PATH" \
			bash "$tmp/repo/scripts/up-source.sh" "$cell" "$tmp/work-$cell" "${4:-}" 2>&1
		echo "exit=$?"
		echo "=== calls"
		cat "$tmp/log"
	} | sed "s#$tmp#@TMP@#g" >"$out"
}

fail=0
for type in kea isc-dhcp dnsmasq udhcpd pihole; do
	(cd "$REPO_ROOT" && go run ./cmd/labctl resolve "$FIX/lab.yaml" "$type") >"$tmp/resolved-$type.json"
	set +e
	render "$type" "$tmp/resolved-$type.json" "$tmp/got-$type"
	set -e
	if [ "${LAB_GOLDEN_WRITE:-}" = 1 ]; then
		cp "$tmp/got-$type" "$FIX/$type.golden"
	fi
	if ! diff -u "$FIX/$type.golden" "$tmp/got-$type" >"$tmp/diff-$type"; then
		echo "up-source-golden-test: $type differs from $FIX/$type.golden:" >&2
		head -40 "$tmp/diff-$type" >&2
		fail=1
	fi
done
# The ISC failover pair (lab #12): the isc-dhcp cell plus a partner renders
# the failover template for each peer. New goldens only; isc-dhcp.golden
# above stays the plain cell, byte for byte.
jq '.cell.source.partner = {seg_address: "10.200.2.3/24", mgmt_address: "10.200.255.32/24", seg_address6: "fd42:200:0:200::3/64"}' \
	"$tmp/resolved-isc-dhcp.json" >"$tmp/resolved-isc-failover.json"
for peer in primary partner; do
	arg=
	[ "$peer" != partner ] || arg=partner
	set +e
	render isc-dhcp "$tmp/resolved-isc-failover.json" "$tmp/got-isc-failover-$peer" "$arg"
	set -e
	if [ "${LAB_GOLDEN_WRITE:-}" = 1 ]; then
		cp "$tmp/got-isc-failover-$peer" "$FIX/isc-failover-$peer.golden"
	fi
	if ! diff -u "$FIX/isc-failover-$peer.golden" "$tmp/got-isc-failover-$peer" >"$tmp/diff-isc-failover-$peer"; then
		echo "up-source-golden-test: isc-failover $peer differs from $FIX/isc-failover-$peer.golden:" >&2
		head -40 "$tmp/diff-isc-failover-$peer" >&2
		fail=1
	fi
done
# Dispatch on BaseImage.Kind and .Seed (#9): the kind and checksum URL
# reach fetch-base-image.sh, a stub seed kind refuses before any seed or
# VM, an unknown one before the fetch.
bad() {
	echo "up-source-golden-test: $*" >&2
	fail=1
}
grep -qxF 'debian-13-generic-amd64|https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2|qcow2||' "$tmp/log.fetch" ||
	bad "dnsmasq: fetch-base-image.sh got $(cat "$tmp/log.fetch")"
variant() {
	jq "$1" "$tmp/resolved-dnsmasq.json" >"$tmp/resolved-variant.json"
	set +e
	render dnsmasq "$tmp/resolved-variant.json" "$tmp/got-variant"
	set -e
}
variant '.source_image.kind = "archive" | .source_image.checksum_url = "https://example.invalid/SHA256SUMS"'
grep -qF '|archive|https://example.invalid/SHA256SUMS|' "$tmp/log.fetch" || bad "archive: fetch-base-image.sh got $(cat "$tmp/log.fetch")"
cmp -s "$tmp/got-variant" "$FIX/dnsmasq.golden" || bad "archive: the cloud-init bring-up changed"
# baked (#9) on an image no build script makes is refused.
variant '.source_image.seed = "baked"'
{ grep -qx 'exit=1' "$tmp/got-variant" && grep -q "the baked image debian-13-generic-amd64 has no build script" "$tmp/got-variant"; } ||
	bad "baked: the hook did not refuse"
grep -qE '^(genisoimage|sudo -n virt-install|ssh[ ])' "$tmp/got-variant" && bad "baked: another seed kind's hook ran"
# qga (#9): the agent channel goes to virt-install, firmware bios drops
# the OVMF loader, no cloud-init ISO is built, and ready_qga's identity
# read ends the wait.
variant '.source_image.seed = "qga" | .source_image.firmware = "bios"'
grep -qx 'exit=0' "$tmp/got-variant" || bad "qga: up-source did not finish: $(tail -5 "$tmp/got-variant")"
vi=$(grep '^sudo -n virt-install' "$tmp/got-variant" || true)
grep -qF -- '--channel unix\,target.type=virtio\,target.name=org.qemu.guest_agent.0' <<<"$vi" || bad "qga: no agent channel in $vi"
grep -qF -- '--boot uefi=off' <<<"$vi" || bad "qga: firmware bios does not pin uefi=off: $vi"
grep -qF -- 'loader=' <<<"$vi" && bad "qga: firmware bios still passes the OVMF loader"
grep -q '^genisoimage' "$tmp/got-variant" && bad "qga: a cloud-init ISO was built"
grep -qF ':put\ \[/system\ identity\ get\ name\]' "$tmp/got-variant" || bad "qga: ready_qga did not read the identity"
grep -q 'qemu-agent-command' "$tmp/got-variant" && bad "qga: a seeded VM was seeded again"
# The stock identity is not ready: the wait hands the VM to seed-chr.sh.
touch "$tmp/log.stock"
variant '.source_image.seed = "qga" | .source_image.firmware = "bios"'
grep -qx 'exit=0' "$tmp/got-variant" || bad "qga stock: up-source did not finish: $(tail -5 "$tmp/got-variant")"
grep -q '^sudo -n virsh qemu-agent-command .*guest-ping' "$tmp/got-variant" || bad "qga stock: the stock identity counted as ready"
# Seeded, but the lab key is refused: every poll names the failed login.
touch "$tmp/log.lockout"
mv "$tmp/repo/scripts/seed-chr.sh" "$tmp/seed-chr.sh.real"
cat >"$tmp/repo/scripts/seed-chr.sh" <<'EOF'
#!/bin/bash
echo "seed-chr: $1 is seeded"
EOF
chmod +x "$tmp/repo/scripts/seed-chr.sh"
variant '.source_image.seed = "qga" | .source_image.firmware = "bios"'
grep -qx 'exit=1' "$tmp/got-variant" || bad "qga lockout: a refused lab login counted as ready"
grep -qF 'is seeded, but the lab login read identity "": lab@10.200.255.141: Permission denied (publickey).' "$tmp/got-variant" ||
	bad "qga lockout: the wait did not name the failed login: $(tail -5 "$tmp/got-variant")"
mv "$tmp/seed-chr.sh.real" "$tmp/repo/scripts/seed-chr.sh"
rm -f "$tmp/log.lockout"
variant '.source_image.seed = "floppy"'
{ grep -qx 'exit=1' "$tmp/got-variant" && grep -q "unknown seed kind 'floppy'" "$tmp/got-variant"; } || bad "an unknown seed kind was not refused"
grep -q '^fetch-base-image' "$tmp/got-variant" && bad "an unknown seed kind still fetched its image"

# baked (#9) on the openwrt cell: the ready probe asks the boot marker for
# the cache's build id, so a marker a reflashed older image left fails it.
(cd "$REPO_ROOT" && go run ./cmd/labctl resolve lab.yaml openwrt) >"$tmp/resolved-openwrt.json"
mkdir -p "$tmp/cache"
baked=$(RESOLVED_FILE="$tmp/resolved-openwrt.json" PATH="$tmp/bin:$PATH" LAB_PUBKEY="$(cat "$tmp/home/.ssh/id_ed25519_lab.pub")" \
	bash "$tmp/repo/scripts/build-openwrt-image.sh" --id openwrt)
echo "$baked" >"$tmp/cache/openwrt-25.12.5-x86-64.build-id"
set +e
LAB_IMAGE_CACHE="$tmp/cache" render openwrt "$tmp/resolved-openwrt.json" "$tmp/got-openwrt"
set -e
grep -qF "grep\\ -qxF\\ $baked\\ /etc/lab-bootstrap-done" "$tmp/got-openwrt" ||
	bad "openwrt: the ready probe does not ask the marker for build id $baked: $(grep -E '^(ssh|exit=)' "$tmp/got-openwrt")"
grep -qE '^genisoimage' "$tmp/got-openwrt" && bad "openwrt: a baked image got seed media"
# A baked image serves one plain cell: a relay or a partner is refused
# before any VM (lab #9).
jq '.cell.relay.client_address = "10.200.15.9"' "$tmp/resolved-openwrt.json" >"$tmp/resolved-openwrt-relay.json"
jq '.cell.source.partner = {seg_address: "10.200.15.3/24", mgmt_address: "10.200.255.152/24"}' \
	"$tmp/resolved-openwrt.json" >"$tmp/resolved-openwrt-partner.json"
for v in relay partner; do
	peer=
	[ "$v" != partner ] || peer=partner
	set +e
	LAB_IMAGE_CACHE="$tmp/cache" render openwrt "$tmp/resolved-openwrt-$v.json" "$tmp/got-openwrt-$v" "$peer"
	set -e
	{ grep -qx 'exit=1' "$tmp/got-openwrt-$v" && grep -q 'a baked image serves one plain cell' "$tmp/got-openwrt-$v"; } ||
		bad "openwrt $v: not refused: $(tail -5 "$tmp/got-openwrt-$v")"
	grep -q '^sudo -n virt-install' "$tmp/got-openwrt-$v" && bad "openwrt $v: a VM was created"
done
# An overlay older than the image it overlays was cut from a previous
# build and is refused (lab #9).
touch "$tmp/base.qcow2"
touch -d '2020-01-01' "$tmp/work-openwrt/lab-openwrt-source.qcow2"
set +e
STUB_BASE="$tmp/base.qcow2" LAB_IMAGE_CACHE="$tmp/cache" render openwrt "$tmp/resolved-openwrt.json" "$tmp/got-openwrt-stale"
set -e
{ grep -qx 'exit=1' "$tmp/got-openwrt-stale" && grep -q 'predates the image it overlays' "$tmp/got-openwrt-stale"; } ||
	bad "openwrt: a stale overlay was not refused: $(tail -5 "$tmp/got-openwrt-stale")"
grep -q '^sudo -n virt-install' "$tmp/got-openwrt-stale" && bad "openwrt: a stale overlay booted"

[ "$fail" -eq 0 ]
echo "up-source-golden-test: PASS"
