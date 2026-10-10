#!/bin/bash
# Populate the base image cache (issue #1). Downloads once, verifies the
# checksum every time (including a cache hit), and never accepts a file
# that does not match the pinned value in images/*.sha256.
# name/url come from labctl resolve's docker_host_image/source_image
# (issue #8, host axis): this script is the one place that turns them
# into a cached, checksummed file, for any base image lab.yaml names, not
# only the original debian-13 reference host. kind and checksum-url are
# BaseImage.Kind and .ChecksumURL (#9); kind defaults to qcow2.
set -euo pipefail

usage='usage: fetch-base-image.sh <name> <url> [qcow2|archive|built] [checksum-url]'
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CACHE_DIR=${LAB_IMAGE_CACHE:-/srv/lab/images}
NAME=${1:?$usage}
KIND=${3:-qcow2}
SUMS_URL=${4:-}
PINNED="$REPO_ROOT/images/$NAME.sha256"
DEST="$CACHE_DIR/$NAME.qcow2"

mkdir -p "$CACHE_DIR"

# check_pin FILE LABEL: FILE's sha256 against the first pinned value,
# pinning it on first use; a mismatch deletes FILE and DEST and exits.
check_pin() {
	local file=$1 label=$2 sum pinned
	sum=$(sha256sum "$file" | awk '{print $1}')
	pinned=$(awk 'NF && $1 !~ /^#/ {print $1; exit}' "$PINNED" 2>/dev/null || true)
	if [ -z "$pinned" ]; then
		echo "fetch-base-image: no checksum pinned yet in $PINNED"
		echo "fetch-base-image: pinning the checksum of this download: $sum"
		printf '%s  %s\n' "$sum" "$label" >>"$PINNED"
		echo "fetch-base-image: commit $PINNED before this image is trusted again"
	elif [ "$sum" != "$pinned" ]; then
		echo "fetch-base-image: REFUSED -- $file is $sum, pinned value is $pinned" >&2
		rm -f "$file" "$DEST" "$DEST.sha256"
		exit 1
	fi
}

# Two cells with the same image and a cold cache share one .part (issue
# #38): serialise the download per image and re-test inside the lock, so
# the second cell finds the first one's finished file.
download() {
	local url=$1 out=$2
	if [ ! -f "$out" ]; then
		exec 9>"$CACHE_DIR/$NAME.lock"
		flock 9
		if [ ! -f "$out" ]; then
			echo "fetch-base-image: downloading $NAME"
			curl -fsSL -o "$out.part" "$url"
			mv "$out.part" "$out"
		fi
		exec 9>&-
	fi
}

case "$KIND" in
qcow2)
	download "${2:?$usage}" "$DEST"
	check_pin "$DEST" "$NAME.qcow2"
	;;
archive)
	URL=${2:?$usage}
	case "$URL" in
	*.zip) ext=zip ;;
	*.gz) ext=gz ;;
	*.bz2) ext=bz2 ;;
	*)
		echo "fetch-base-image: REFUSED -- $URL is not a .zip, .gz or .bz2 archive" >&2
		exit 1
		;;
	esac
	ARCHIVE="$CACHE_DIR/$NAME.$ext"
	download "$URL" "$ARCHIVE"
	if [ -n "$SUMS_URL" ]; then
		# A sums file line is "<sha256>  <file>" or "<sha256> *<file>"
		# (sha256sum's text and binary modes); a bare hash also counts.
		upstream=$(curl -fsSL "$SUMS_URL" | awk -v f="${URL##*/}" '
			{ n = $2; sub(/^\*/, "", n) }
			n == f || (NF == 1 && NR == 1) { print $1; exit }')
		sum=$(sha256sum "$ARCHIVE" | awk '{print $1}')
		if [ "$sum" != "${upstream:-none}" ]; then
			echo "fetch-base-image: REFUSED -- $ARCHIVE is $sum, $SUMS_URL lists ${upstream:-no sum for ${URL##*/}}" >&2
			rm -f "$ARCHIVE" "$DEST" "$DEST.sha256"
			exit 1
		fi
	fi
	check_pin "$ARCHIVE" "${URL##*/}"
	# The converted image is checked against the sum taken when it was
	# written; a missing or stale one is converted again from the archive,
	# under the download lock so two cells never share a .part.
	exec 9>"$CACHE_DIR/$NAME.lock"
	flock 9
	if [ ! -f "$DEST" ] || ! (cd "$CACHE_DIR" && sha256sum --status -c "$DEST.sha256" 2>/dev/null); then
		echo "fetch-base-image: converting $ARCHIVE"
		raw="$DEST.raw.part"
		case "$ext" in
		zip)
			if [ "$(unzip -Z1 "$ARCHIVE" | wc -l)" -ne 1 ]; then
				echo "fetch-base-image: REFUSED -- $ARCHIVE holds more than one file" >&2
				exit 1
			fi
			unzip -p "$ARCHIVE" >"$raw"
			;;
		gz) gzip -dc "$ARCHIVE" >"$raw" ;;
		bz2) bzip2 -dc "$ARCHIVE" >"$raw" ;;
		esac
		# convert -f raw takes any payload and only the boot would fail;
		# a qcow2 or vmdk inside the archive is refused here instead.
		fmt=$(qemu-img info --output=json "$raw" | jq -r .format)
		if [ "$fmt" != raw ]; then
			echo "fetch-base-image: REFUSED -- $ARCHIVE holds a $fmt image, not a raw disk" >&2
			rm -f "$raw"
			exit 1
		fi
		qemu-img convert -f raw -O qcow2 "$raw" "$DEST.part"
		rm -f "$raw"
		mv "$DEST.part" "$DEST"
		(cd "$CACHE_DIR" && sha256sum "$NAME.qcow2" >"$DEST.sha256")
	fi
	exec 9>&-
	;;
built)
	if [ ! -f "$DEST" ]; then
		echo "fetch-base-image: REFUSED -- $DEST is a built image and is not there; run its build script first" >&2
		exit 1
	fi
	;;
*)
	echo "fetch-base-image: REFUSED -- unknown image kind '$KIND'" >&2
	exit 1
	;;
esac

echo "$DEST"
