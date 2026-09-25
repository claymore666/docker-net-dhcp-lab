#!/bin/bash
# Populate the base image cache (issue #1). Downloads once, verifies the
# checksum every time (including a cache hit), and never accepts a file
# that does not match the pinned value in images/*.sha256.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CACHE_DIR=/srv/lab/images
NAME=debian-13-generic-amd64
URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2"
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
