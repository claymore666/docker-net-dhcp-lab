#!/bin/bash
# up-source.sh's rendered seed files, its stdout and every qemu-img,
# genisoimage, virt-install and ssh call for the five cloud-init source
# types, pinned to the copy taken at dev b19470b before the per-seed-kind
# hooks landed (#9), then the seed and image kind dispatch. Stubs on PATH
# and a copy of the repo, no VM. LAB_GOLDEN_WRITE=1 rewrites the goldens.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIX="$REPO_ROOT/scripts/testdata/up-source-golden"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/repo/scripts" "$tmp/bin" "$tmp/home/.ssh"
cp "$REPO_ROOT"/scripts/*.sh "$tmp/repo/scripts/"
cp -r "$REPO_ROOT/cloud-init" "$tmp/repo/cloud-init"
echo "ssh-ed25519 AAAAC3NzaGolden lab-controller" >"$tmp/home/.ssh/id_ed25519_lab.pub"

cat >"$tmp/repo/scripts/fetch-base-image.sh" <<'EOF'
#!/bin/bash
printf 'fetch-base-image %s %s\n' "$1" "$2" >>"$STUB_LOG"
printf '%s|' "$@" >>"$STUB_LOG.fetch"
echo /srv/lab/images/"$1".qcow2
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
chmod +x "$tmp"/bin/* "$tmp/repo/scripts/fetch-base-image.sh"

render() {
	local cell=$1 resolved=$2 out=$3
	: >"$tmp/log"
	: >"$tmp/log.fetch"
	{
		STUB_LOG="$tmp/log" RESOLVED_FILE="$resolved" HOME="$tmp/home" PATH="$tmp/bin:$PATH" \
			bash "$tmp/repo/scripts/up-source.sh" "$cell" "$tmp/work-$cell" 2>&1
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
for seed in qga baked; do
	variant ".source_image.seed = \"$seed\""
	{ grep -qx 'exit=1' "$tmp/got-variant" && grep -q "the $seed seed hook is not built" "$tmp/got-variant"; } ||
		bad "$seed: the stub did not refuse"
	grep -qE '^(genisoimage|sudo -n virt-install|ssh[ ])' "$tmp/got-variant" && bad "$seed: another seed kind's hook ran"
done
variant '.source_image.seed = "floppy"'
{ grep -qx 'exit=1' "$tmp/got-variant" && grep -q "unknown seed kind 'floppy'" "$tmp/got-variant"; } || bad "an unknown seed kind was not refused"
grep -q '^fetch-base-image' "$tmp/got-variant" && bad "an unknown seed kind still fetched its image"

[ "$fail" -eq 0 ]
echo "up-source-golden-test: PASS"
