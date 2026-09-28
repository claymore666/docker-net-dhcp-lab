#!/bin/bash
# Populate the base image cache (issue #1). Downloads once, verifies the
# checksum every time (including a cache hit), and never accepts a file
# that does not match the pinned value in images/*.sha256.
# name/url come from labctl resolve's docker_host_image/source_image
# (issue #8, host axis): this script is the one place that turns them
# into a cached, checksummed file, for any base image lab.yaml names, not
# only the original debian-13 reference host.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CACHE_DIR=/srv/lab/images
NAME=${1:?usage: fetch-base-image.sh <name> <url>}
URL=${2:?usage: fetch-base-image.sh <name> <url>}
PINNED="$REPO_ROOT/images/$NAME.sha256"
DEST="$CACHE_DIR/$NAME.qcow2"

mkdir -p "$CACHE_DIR"

if [ ! -f "$DEST" ]; then
	echo "fetch-base-image: downloading $NAME"
	curl -fsSL -o "$DEST.part" "$URL"
	mv "$DEST.part" "$DEST"
fi

sum=$(sha256sum "$DEST" | awk '{print $1}')
pinned=$(awk 'NF && $1 !~ /^#/ {print $1; exit}' "$PINNED" 2>/dev/null || true)

if [ -z "$pinned" ]; then
	echo "fetch-base-image: no checksum pinned yet in $PINNED"
	echo "fetch-base-image: pinning the checksum of this download: $sum"
	printf '%s  %s.qcow2\n' "$sum" "$NAME" >>"$PINNED"
	echo "fetch-base-image: commit $PINNED before this image is trusted again"
elif [ "$sum" != "$pinned" ]; then
	echo "fetch-base-image: REFUSED -- $DEST is $sum, pinned value is $pinned" >&2
	rm -f "$DEST"
	exit 1
fi

echo "$DEST"
