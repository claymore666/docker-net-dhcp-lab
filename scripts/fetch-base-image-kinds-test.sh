#!/bin/bash
# fetch-base-image.sh against file:// fixtures (#9): a .zip, .gz and .bz2
# archive with a matching and a mismatching upstream sum, the TOFU pin,
# the qcow2 and built kinds. qemu-img is a stub that tags its input, so
# the cached image must be the decompressed disk, never the archive; its
# info call reports qcow2 for a payload starting QFI, as the real one does.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin" "$tmp/up"
cat >"$tmp/bin/qemu-img" <<'STUB'
#!/bin/bash
echo "qemu-img $*" >>"$QEMU_LOG"
if [ "$1 $2" = "info --output=json" ]; then
	[ "$(head -c 3 "$3")" = QFI ] && echo '{"format":"qcow2"}' || echo '{"format":"raw"}'
	exit 0
fi
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
	cp "$REPO_ROOT/scripts/image-path.sh" "$tmp/repo/scripts/"
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

# only_path LABEL WANT: stdout of the last fetch is the image path and
# nothing else; callers capture it whole as the qemu-img backing file (#92).
only_path() {
	{ [ "$(wc -l <"$tmp/out")" -eq 1 ] && [ "$(cat "$tmp/out")" = "$2" ]; } ||
		bad "$1: stdout is not just $2: $(tr '\n' '|' <"$tmp/out")"
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
	only_path "$ext cold fetch" "$dest"
	grep -q 'converting' "$tmp/err" || bad "$ext: the progress lines are gone from stderr"
	[ "$(cat "$dest" 2>/dev/null)" = "$want" ] || bad "$ext: the cached image is not the converted disk"
	cmp -s "$dest" "$arch" && bad "$ext: the archive was left in place as the image"
	grep -qx "$(sha256sum "$arch" | awk '{print $1}')  disk-$ext.img.$ext" "$tmp/repo/images/img-$ext.sha256" ||
		bad "$ext: the pin is not the archive's sum"
	compgen -G "$tmp/cache/*.part" >/dev/null && bad "$ext: a .part file was left behind"
	mv "$arch" "$arch.away"
	fetch "img-$ext" "file://$arch" archive "file://$tmp/up/good-$ext.sums"
	mv "$arch.away" "$arch"
	{ [ "$rc" -eq 0 ] && [ "$(grep -c convert "$tmp/qemu.log")" -eq 1 ]; } || bad "$ext: a cache hit downloaded or converted again (exit $rc)"
	printf 'tampered' >"$dest"
	fetch "img-$ext" "file://$arch" archive "file://$tmp/up/good-$ext.sums"
	{ [ "$rc" -eq 0 ] && [ "$(cat "$dest")" = "$want" ]; } || bad "$ext: a tampered cached image was kept"
	fetch "img-$ext" "file://$arch" archive "file://$tmp/up/bad-$ext.sums"
	[ "$rc" -eq 1 ] || bad "$ext warm cache, mismatching sum: exit $rc, want a refusal"
	for f in "$dest" "$dest.sha256" "$tmp/cache/img-$ext.$ext"; do
		[ ! -e "$f" ] || bad "$ext warm cache, mismatching sum: ${f##*/} was kept"
	done

	fresh
	fetch "img-$ext" "file://$arch" archive "file://$tmp/up/bad-$ext.sums"
	{ [ "$rc" -eq 1 ] && grep -q REFUSED "$tmp/err"; } || bad "$ext mismatching sum: exit $rc, want a refusal"
	{ [ ! -e "$dest" ] && [ ! -e "$tmp/cache/img-$ext.$ext" ]; } || bad "$ext mismatching sum: the download was kept"
	[ ! -s "$tmp/repo/images/img-$ext.sha256" ] || bad "$ext mismatching sum: it was pinned"
	[ ! -s "$tmp/qemu.log" ] || bad "$ext mismatching sum: it was converted"
done

# The sums file forms: sha256sum's binary "*file", a bare hash, and a
# file that lists only other files, which is a refusal.
arch="$tmp/up/disk-gz.img.gz"
sum=$(sha256sum "$arch" | awk '{print $1}')
printf '%064d  other.img.gz\n%s *disk-gz.img.gz\n' 0 "$sum" >"$tmp/up/star.sums"
printf '%s\n' "$sum" >"$tmp/up/bare.sums"
printf '%s  other.img.gz\n' "$sum" >"$tmp/up/other.sums"
for form in star bare; do
	fresh
	fetch "form-$form" "file://$arch" archive "file://$tmp/up/$form.sums"
	[ "$rc" -eq 0 ] || bad "$form sums line: exit $rc: $(cat "$tmp/err")"
done
fresh
fetch form-other "file://$arch" archive "file://$tmp/up/other.sums"
{ [ "$rc" -eq 1 ] && grep -q "no sum for disk-gz.img.gz" "$tmp/err"; } || bad "a sums file without the archive's line: exit $rc, want a refusal"

# A qcow2 inside the archive is refused, never converted as raw.
printf 'QFI\373nested' | gzip -c >"$tmp/up/nested.img.gz"
fresh
fetch nested "file://$tmp/up/nested.img.gz" archive
{ [ "$rc" -eq 1 ] && grep -q "holds a qcow2 image" "$tmp/err"; } || bad "a qcow2 payload: exit $rc, want a refusal"
{ [ ! -e "$tmp/cache/nested.qcow2" ] && ! grep -q convert "$tmp/qemu.log"; } || bad "a qcow2 payload was converted"
compgen -G "$tmp/cache/*.part" >/dev/null && bad "a qcow2 payload left a .part file"

# No upstream sum: TOFU on the archive, then a changed upstream archive
# is refused against the pin.
fresh
arch="$tmp/up/disk-gz.img.gz"
fetch tofu "file://$arch" archive
{ [ "$rc" -eq 0 ] && grep -q 'pinning the checksum' "$tmp/err"; } || bad "TOFU archive: exit $rc"
only_path "TOFU archive" "$tmp/cache/tofu.qcow2"
rm -f "$tmp/cache/tofu.gz"
printf 'other' | gzip -c >"$arch"
fetch tofu "file://$arch" archive
{ [ "$rc" -eq 1 ] && [ ! -e "$tmp/cache/tofu.qcow2" ]; } || bad "TOFU archive: a changed archive was accepted"

# qcow2 is today's path: the file itself is the image, pinned by name.
fresh
printf 'QFI-plain' >"$tmp/up/plain.qcow2"
fetch plain "file://$tmp/up/plain.qcow2"
{ [ "$rc" -eq 0 ] && cmp -s "$tmp/cache/plain.qcow2" "$tmp/up/plain.qcow2"; } || bad "qcow2: exit $rc"
only_path "qcow2 cold fetch" "$tmp/cache/plain.qcow2"
grep -q 'downloading plain' "$tmp/err" || bad "qcow2: the download line is gone from stderr"
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

# The callers' capture, end to end (#92): a cold chr-style archive fetch
# captured as base_path=$(...) names an existing absolute file, and the
# real qemu-img records exactly that file as the overlay's backing file.
# Run 2 had "fetch-base-image: converting ..." in the string, which
# qemu-img parsed as the protocol "fetch-base-image".
if real=$(command -v qemu-img); then
	fresh
	rm -rf "$tmp/real"
	mkdir -p "$tmp/real"
	"$real" create -q -f raw "$tmp/real/disk.img" 1M
	(cd "$tmp/real" && python3 -I -m zipfile -c disk.img.zip disk.img)
	# the stub tags its input; this section needs the real tool
	rm -f "$tmp/bin/qemu-img"
	ln -s "$real" "$tmp/bin/qemu-img"
	base_path=$(LAB_IMAGE_CACHE="$tmp/cache" PATH="$tmp/bin:$PATH" bash "$tmp/repo/scripts/fetch-base-image.sh" real-chr "file://$tmp/real/disk.img.zip" archive 2>/dev/null)
	case "$base_path" in
	/*) [ -f "$base_path" ] || bad "captured base path $base_path is not a file" ;;
	*) bad "captured base path is not absolute: $base_path" ;;
	esac
	if "$real" create -q -f qcow2 -F qcow2 -b "$base_path" "$tmp/real/overlay.qcow2" 2M 2>"$tmp/real/err"; then
		[ "$("$real" info --output=json "$tmp/real/overlay.qcow2" | jq -r '."full-backing-filename"')" = "$base_path" ] ||
			bad "the overlay's backing file is not $base_path"
	else
		bad "qemu-img refused the captured base path: $(cat "$tmp/real/err")"
	fi
else
	echo "fetch-base-image-kinds-test: no qemu-img on this box, overlay check skipped"
fi

# Every caller captures the script's stdout whole and nothing else, so the
# stdout contract above is what they get (#92).
for caller in up-cell up-relay up-source; do
	# shellcheck disable=SC2016  # the pattern matches the callers' literal text
	grep -qE '^[[:space:]]*base_path=\$\("\$REPO_ROOT/scripts/fetch-base-image\.sh" ' "$REPO_ROOT/scripts/$caller.sh" ||
		bad "$caller.sh no longer captures fetch-base-image.sh as base_path=\$(...)"
done

[ "$fail" -eq 0 ]
echo "fetch-base-image-kinds-test: PASS"
