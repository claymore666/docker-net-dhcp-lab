#!/bin/bash
# Download-lock tests for fetch-base-image.sh (issue #38). CI-safe: curl
# is a stub on PATH and the script runs from a copy in a scratch repo
# root, so the real images/ directory and the network are never touched.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

PAYLOAD="fake qcow2 bytes"
SUM=$(printf '%s' "$PAYLOAD" | sha256sum | awk '{print $1}')

cat >"$tmp/curl" <<'STUB'
#!/bin/bash
out=
while [ $# -gt 0 ]; do
	[ "$1" = "-o" ] && out=$2
	shift
done
echo x >>"$LAB_TEST_CURL_LOG"
sleep "${LAB_TEST_CURL_SLEEP:-0}"
printf '%s' "$LAB_TEST_PAYLOAD" >"$out"
STUB
chmod +x "$tmp/curl"

# A scratch repo root holding a copy of the script and a pinned checksum.
new_case() {
	local d
	d=$(mktemp -d "$tmp/case-XXXXXX")
	mkdir -p "$d/repo/scripts" "$d/repo/images" "$d/cache"
	cp "$REPO_ROOT/scripts/fetch-base-image.sh" "$d/repo/scripts/"
	printf '%s  img.qcow2\n' "$SUM" >"$d/repo/images/img.sha256"
	: >"$d/curl.log"
	echo "$d"
}

fetch() {
	local d=$1
	LAB_IMAGE_CACHE="$d/cache" LAB_TEST_CURL_LOG="$d/curl.log" LAB_TEST_PAYLOAD="$PAYLOAD" \
		PATH="$tmp:$PATH" "$d/repo/scripts/fetch-base-image.sh" img http://example.invalid/img.qcow2
}

# Case 1: the lock is held while the cache is empty; the holder fills
# the cache and lets go. The script must wait, then find the file and
# never call curl.
c1=$(new_case)
exec 8>"$c1/cache/img.lock"
flock -n 8
fetch "$c1" >"$c1/out" 2>&1 8>&- &
pid1=$!
sleep 1
if ! kill -0 "$pid1" 2>/dev/null; then
	echo "fetch-base-image-test: FAIL -- case 1: finished while the lock was held" >&2
	fail=1
fi
printf '%s' "$PAYLOAD" >"$c1/cache/img.qcow2"
exec 8>&-
wait "$pid1" || {
	echo "fetch-base-image-test: FAIL -- case 1: exited non-zero" >&2
	cat "$c1/out" >&2
	fail=1
}
if [ -s "$c1/curl.log" ]; then
	echo "fetch-base-image-test: FAIL -- case 1: curl was called although the lock holder had filled the cache" >&2
	fail=1
fi

# Case 2: lock free, cache empty: curl once, file in place, path printed.
c2=$(new_case)
out2=$(fetch "$c2" 2>&1) || {
	echo "fetch-base-image-test: FAIL -- case 2: exited non-zero: $out2" >&2
	fail=1
}
if [ "$(wc -l <"$c2/curl.log")" -ne 1 ]; then
	echo "fetch-base-image-test: FAIL -- case 2: expected one curl call" >&2
	fail=1
fi
if ! grep -qxF "$c2/cache/img.qcow2" <<<"$out2"; then
	echo "fetch-base-image-test: FAIL -- case 2: did not print the cache path: $out2" >&2
	fail=1
fi

# Case 3: four cells fetch the same image at once on a cold cache; curl
# is slow. One download, every caller succeeds.
c3=$(new_case)
pids3=()
for i in 1 2 3 4; do
	LAB_TEST_CURL_SLEEP=1 fetch "$c3" >"$c3/out.$i" 2>&1 &
	pids3+=("$!")
done
for p in "${pids3[@]}"; do
	wait "$p" || {
		echo "fetch-base-image-test: FAIL -- case 3: a concurrent fetch exited non-zero" >&2
		cat "$c3"/out.* >&2
		fail=1
	}
done
if [ "$(wc -l <"$c3/curl.log")" -ne 1 ]; then
	echo "fetch-base-image-test: FAIL -- case 3: expected one curl call across four concurrent fetches, saw $(wc -l <"$c3/curl.log")" >&2
	fail=1
fi

# Case 4: a cache hit never takes the lock and never calls curl, and a
# wrong checksum is still refused (the unchanged path after the lock).
c4=$(new_case)
printf 'other bytes' >"$c4/cache/img.qcow2"
if fetch "$c4" >"$c4/out" 2>&1; then
	echo "fetch-base-image-test: FAIL -- case 4: accepted a file that does not match the pinned checksum" >&2
	fail=1
fi
if [ -s "$c4/curl.log" ]; then
	echo "fetch-base-image-test: FAIL -- case 4: curl was called on a cache hit" >&2
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "fetch-base-image-test: PASS -- 4 cases behaved as expected"
