#!/bin/bash
# The rendered Docker host user-data (issue #27): the Debian 11 cell carries
# the archive.debian.org sources rewrite in bootcmd, ahead of every apt-get,
# and no other base image carries any rewrite. Renders through the same
# script and the same `labctl resolve` JSON as up-cell.sh. Network-free.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() {
	echo "cloud-init-docker-host-test: $*" >&2
	fail=1
}

render() { # <cell> -> $tmp/<cell>.yaml
	go run ./cmd/labctl resolve lab.yaml "$1" |
		./scripts/render-docker-host-user-data.sh "ssh-ed25519 AAAAtest lab-test" >"$tmp/$1.yaml"
}

# bootcmd's script lines, from "bootcmd:" to the next top-level key
bootcmd_of() {
	awk '/^bootcmd:/{on=1; next} on && /^[^[:space:]#]/{exit} on' "$1"
}

# up-cell.sh renders through the shared script and never reads the template
# itself, or this test would prove a path no bring-up takes
grep -qF 'scripts/render-docker-host-user-data.sh' scripts/up-cell.sh || bad "up-cell.sh does not call render-docker-host-user-data.sh"
grep -qF 'docker-host-user-data.tmpl' scripts/up-cell.sh && bad "up-cell.sh reads the docker host template directly"

for cell in host-debian11-docker2010 ref-only host-ubuntu2404; do
	render "$cell"
	f="$tmp/$cell.yaml"
	left=$(grep -vE '^[[:space:]]*#' "$f" | grep -nE '__[A-Z_]+__' || true)
	[ -z "$left" ] || bad "$cell: unsubstituted placeholder: $left"
	[ -n "$(bootcmd_of "$f")" ] || bad "$cell: no bootcmd block"
done

# Debian 11: the rewrite is in bootcmd, before apt-get update, and writes
# exactly the three archive lines when executed
f="$tmp/host-debian11-docker2010.yaml"
fix_line=$(grep -nE '^[^#]*archive\.debian\.org' "$f" | head -1 | cut -d: -f1)
update_line=$(grep -nE '^[[:space:]]*-[[:space:]]+apt-get update' "$f" | head -1 | cut -d: -f1)
pkg_line=$(grep -nE '^package_update:' "$f" | head -1 | cut -d: -f1)
if [ -z "$fix_line" ]; then
	bad "debian 11: no archive.debian.org rewrite in the rendered user-data"
else
	if [ -z "$update_line" ] || [ "$fix_line" -ge "$update_line" ]; then
		bad "debian 11: rewrite (line $fix_line) is not before apt-get update (line ${update_line:-?})"
	fi
	if [ -z "$pkg_line" ] || [ "$fix_line" -ge "$pkg_line" ]; then
		bad "debian 11: rewrite (line $fix_line) is not before package_update (line ${pkg_line:-?})"
	fi
	bootcmd_of "$f" | grep -qF 'archive.debian.org' || bad "debian 11: the rewrite is not inside bootcmd"
	# the init-stage module is what makes it run before package_update;
	# a runcmd entry would run after it (cloud-init 20.4.1 cloud.cfg)
	grep -E '^[[:space:]]*-[[:space:]]+.*archive\.debian\.org' "$f" >/dev/null && bad "debian 11: the rewrite is a runcmd entry"
	script="$tmp/bootcmd.sh"
	bootcmd_of "$f" | sed -E 's/^  - \|$//; s/^    //' |
		sed "s#/etc/apt/sources.list#$tmp/sources.list#" >"$script"
	# cloud-init 20.4.1 runs bootcmd as `/bin/sh file` (cc_bootcmd.py:102), dash on Debian 11
	sh -n "$script" || bad "debian 11: bootcmd script is not valid sh"
	sh "$script" || bad "debian 11: bootcmd script failed under sh"
	want=$(printf '%s\n' \
		'deb [check-valid-until=no] http://archive.debian.org/debian bullseye main' \
		'deb [check-valid-until=no] http://archive.debian.org/debian bullseye-updates main' \
		'deb [check-valid-until=no] http://archive.debian.org/debian-security bullseye-security main')
	[ "$(cat "$tmp/sources.list")" = "$want" ] || bad "debian 11: executed rewrite wrote: $(cat "$tmp/sources.list")"
fi

# every other image: no rewrite anywhere, bootcmd is a no-op
for cell in ref-only host-ubuntu2404; do
	f="$tmp/$cell.yaml"
	grep -qF 'archive.debian.org' "$f" && bad "$cell: carries the archive rewrite"
	grep -vE '^[[:space:]]*#' "$f" | grep -qE 'sources\.list([^.]|$)' && bad "$cell: touches sources.list"
	body=$(bootcmd_of "$f" | sed -E 's/^  - \|$//; s/^[[:space:]]+//; /^$/d')
	[ "$body" = "true" ] || bad "$cell: bootcmd is not a no-op: $body"
done

if command -v python3 >/dev/null && python3 -c 'import yaml' 2>/dev/null; then
	for cell in host-debian11-docker2010 ref-only host-ubuntu2404; do
		python3 -c '
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
bc = cfg.get("bootcmd")
if not (isinstance(bc, list) and bc and all(isinstance(x, str) for x in bc)):
    sys.exit("bootcmd is not a non-empty list of strings: %r" % (bc,))
body = "\n".join(bc)
if sys.argv[2] == "archived":
    for want in ("archive.debian.org/debian bullseye main", "archive.debian.org/debian-security bullseye-security main", "> /etc/apt/sources.list"):
        if want not in body:
            sys.exit("bootcmd lacks %r: %r" % (want, body))
elif body.strip() != "true":
    sys.exit("bootcmd is not the no-op: %r" % (body,))
' "$tmp/$cell.yaml" "$([ "$cell" = host-debian11-docker2010 ] && echo archived || echo plain)" ||
			bad "$cell: rendered user-data bootcmd is not the expected one"
	done
else
	echo "cloud-init-docker-host-test: python3/PyYAML not available, skipping the parse proof" >&2
fi

[ "$fail" -eq 0 ] || exit 1
echo "cloud-init-docker-host-test: PASS"
