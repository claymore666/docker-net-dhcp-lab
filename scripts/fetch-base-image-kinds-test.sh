#!/bin/bash
# fetch-base-image.sh against file:// fixtures (#9): a .zip, .gz and .bz2
# archive with a matching and a mismatching upstream sum, the TOFU pin,
# the qcow2 and built kinds. qemu-img is a stub that tags its input, so
# the cached image must be the decompressed disk, never the archive.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/up"
cat >"$tmp/bin/qemu-img" <<'STUB'
#!/bin/bash
echo "qemu-img $*" >>"$QEMU_LOG"
[ "$1 $2 $3 $4 $5" = "convert -f raw -O qcow2" ] || exit 9
{ printf 'qcow2-of:'; cat "$6"; } >"$7"
STUB
chmod +x "$tmp/bin/qemu-img"

fail=0
bad() {
	echo "fetch-base-image-kinds-test: $*" >&2
	fail=1
}

# fresh: a repo copy with an empty pin dir and an empty cache.
fresh() {
	rm -rf "$tmp/repo" "$tmp/cache"
	mkdir -p "$tmp/repo/scripts" "$tmp/repo/images" "$tmp/cache"
	cp "$REPO_ROOT/scripts/fetch-base-image.sh" "$tmp/repo/scripts/"
	: >"$tmp/qemu.log"
}

# fetch ARGS...: run the copy; stdout to $tmp/out, stderr to $tmp/err.
fetch() {
	set +e
	LAB_IMAGE_CACHE="$tmp/cache" QEMU_LOG="$tmp/qemu.log" PATH="$tmp/bin:$PATH" \
		bash "$tmp/repo/scripts/fetch-base-image.sh" "$@" >"$tmp/out" 2>"$tmp/err"
	rc=$?
	set -e
}

for ext in zip gz bz2; do
	disk="$tmp/up/disk-$ext.img"
	printf 'RAW-DISK-%s\001\002' "$ext" >"$disk"
	arch="$tmp/up/disk-$ext.img.$ext"
	case "$ext" in
	zip) (cd "$tmp/up" && python3 -I -m zipfile -c "$arch" "disk-$ext.img") ;;
	gz) gzip -c "$disk" >"$arch" ;;
	bz2) bzip2 -c "$disk" >"$arch" ;;
	esac
	(cd "$tmp/up" && sha256sum "disk-$ext.img.$ext" >"$tmp/up/good-$ext.sums")
	printf '%064d *disk-%s.img.%s\n' 0 "$ext" "$ext" >"$tmp/up/bad-$ext.sums"
	want="qcow2-of:$(cat "$disk")"
	dest="$tmp/cache/img-$ext.qcow2"

	fresh
	fetch "img-$ext" "file://$arch" archive "file://$tmp/up/good-$ext.sums"
	[ "$rc" -eq 0 ] || bad "$ext matching sum: exit $rc: $(cat "$tmp/err")"
	[ "$(tail -1 "$tmp/out")" = "$dest" ] || bad "$ext: printed $(tail -1 "$tmp/out"), want $dest"
	[ "$(cat "$dest" 2>/dev/null)" = "$want" ] || bad "$ext: the cached image is not the converted disk"
	cmp -s "$dest" "$arch" && bad "$ext: the archive was left in place as the image"
	grep -qx "$(sha256sum "$arch" | awk '{print $1}')  disk-$ext.img.$ext" "$tmp/repo/images/img-$ext.sha256" ||
		bad "$ext: the pin is not the archive's sum"
	compgen -G "$tmp/cache/*.part" >/dev/null && bad "$ext: a .part file was left behind"
	fetch "img-$ext" "file://$arch" archive "file://$tmp/up/good-$ext.sums"
	{ [ "$rc" -eq 0 ] && [ "$(grep -c convert "$tmp/qemu.log")" -eq 1 ]; } || bad "$ext: a cache hit converted again (exit $rc)"
	printf 'tampered' >"$dest"
	fetch "img-$ext" "file://$arch" archive "file://$tmp/up/good-$ext.sums"
	{ [ "$rc" -eq 0 ] && [ "$(cat "$dest")" = "$want" ]; } || bad "$ext: a tampered cached image was kept"

	fresh
	fetch "img-$ext" "file://$arch" archive "file://$tmp/up/bad-$ext.sums"
	{ [ "$rc" -eq 1 ] && grep -q REFUSED "$tmp/err"; } || bad "$ext mismatching sum: exit $rc, want a refusal"
	{ [ ! -e "$dest" ] && [ ! -e "$tmp/cache/img-$ext.$ext" ]; } || bad "$ext mismatching sum: the download was kept"
	[ ! -s "$tmp/repo/images/img-$ext.sha256" ] || bad "$ext mismatching sum: it was pinned"
	[ ! -s "$tmp/qemu.log" ] || bad "$ext mismatching sum: it was converted"
done

# No upstream sum: TOFU on the archive, then a changed upstream archive
# is refused against the pin.
fresh
arch="$tmp/up/disk-gz.img.gz"
fetch tofu "file://$arch" archive
{ [ "$rc" -eq 0 ] && grep -q 'pinning the checksum' "$tmp/out"; } || bad "TOFU archive: exit $rc"
rm -f "$tmp/cache/tofu.gz"
printf 'other' | gzip -c >"$arch"
fetch tofu "file://$arch" archive
{ [ "$rc" -eq 1 ] && [ ! -e "$tmp/cache/tofu.qcow2" ]; } || bad "TOFU archive: a changed archive was accepted"

# qcow2 is today's path: the file itself is the image, pinned by name.
fresh
printf 'QFI-plain' >"$tmp/up/plain.qcow2"
fetch plain "file://$tmp/up/plain.qcow2"
{ [ "$rc" -eq 0 ] && cmp -s "$tmp/cache/plain.qcow2" "$tmp/up/plain.qcow2"; } || bad "qcow2: exit $rc"
grep -qx "$(sha256sum "$tmp/up/plain.qcow2" | awk '{print $1}')  plain.qcow2" "$tmp/repo/images/plain.sha256" || bad "qcow2: pin line"
printf 'swapped' >"$tmp/cache/plain.qcow2"
fetch plain "file://$tmp/up/plain.qcow2"
{ [ "$rc" -eq 1 ] && [ ! -e "$tmp/cache/plain.qcow2" ]; } || bad "qcow2: a changed cached image was accepted"
[ ! -s "$tmp/qemu.log" ] || bad "qcow2: qemu-img ran"

fresh
fetch made "" built
{ [ "$rc" -eq 1 ] && grep -q 'build script' "$tmp/err"; } || bad "built: a missing image was not refused"
printf 'built' >"$tmp/cache/made.qcow2"
fetch made "" built
{ [ "$rc" -eq 0 ] && [ "$(cat "$tmp/out")" = "$tmp/cache/made.qcow2" ]; } || bad "built: exit $rc"

fetch odd "file://$tmp/up/plain.qcow2" iso
{ [ "$rc" -eq 1 ] && grep -q "unknown image kind" "$tmp/err"; } || bad "unknown kind: exit $rc"
fetch odd "file://$tmp/up/plain.qcow2" archive
{ [ "$rc" -eq 1 ] && grep -q "not a .zip" "$tmp/err"; } || bad "archive without an archive suffix: exit $rc"

[ "$fail" -eq 0 ]
echo "fetch-base-image-kinds-test: PASS"
