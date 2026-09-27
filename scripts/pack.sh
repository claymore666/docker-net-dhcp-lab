#!/bin/bash
# labctl pack (issue #4): one evidence bundle directory -> one
# compressed tarball, meant as a GitHub release asset (attaching it is
# not this script's job). Refuses, and writes nothing, when the bundle
# carries a disallowed address (scripts/hygiene-patterns.sh, shared with
# hygiene-check.sh rather than a second copy), a non-lab hostname in a
# captured journalctl line, an evidence path pointing outside the
# bundle, or a hit against the required denylist file: a local list of
# names that must not appear, kept outside this repo and never
# hardcoded here.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/scripts/hygiene-patterns.sh"

BUNDLE_DIR=${1:?usage: pack.sh <bundle-dir> <out.tar.gz> <denylist-file>}
OUT=${2:?usage: pack.sh <bundle-dir> <out.tar.gz> <denylist-file>}
DENYLIST=${3:-${LAB_PACK_DENYLIST:-}}

if [ ! -d "$BUNDLE_DIR" ]; then
	echo "pack: REFUSED -- $BUNDLE_DIR is not a directory" >&2
	exit 1
fi

# A lab-generated hostname always matches this shape (up-cell.sh's and
# up-source.sh's own cloud-init local-hostname values); anything else in
# a journalctl short-output line's hostname field ("Mon DD HH:MM:SS
# <host> <tag>[pid]: ...", the shape run-group-a.sh captures into
# <cell>-plugin-log.txt) is a real machine name leaking into evidence.
JOURNAL_LINE_RE='^[A-Z][a-z]{2}[[:space:]]+[0-9]{1,2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]+([^[:space:]]+)[[:space:]]'
LAB_HOSTNAME_RE='^lab-[a-z0-9-]+$'

# A release pack never passes with part of this check missing: no third
# argument, no LAB_PACK_DENYLIST, or a path that names no real file is
# refused outright rather than silently skipping the one check that
# catches a name naming what this bundle was tested against.
if [ -z "$DENYLIST" ]; then
	echo "pack: REFUSED -- no denylist given (pass it as a third argument, or set LAB_PACK_DENYLIST)" >&2
	exit 1
fi
if [ ! -f "$DENYLIST" ]; then
	echo "pack: REFUSED -- denylist file $DENYLIST does not exist" >&2
	exit 1
fi
echo "pack: checking against denylist $DENYLIST" >&2

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
STAGED_BUNDLE="$STAGE/$(basename "$BUNDLE_DIR")"
cp -a "$BUNDLE_DIR" "$STAGED_BUNDLE"

fail=0

# A verdict's evidence.<label> line is written by an older run's own
# scenario.Write as a path on the machine that ran it (fixed for new
# runs, issue #4 fix round); normalize every such line here too, so a
# bundle still packs clean from wherever it has since been copied to.
# scenario.Write always puts an evidence file directly beside its
# verdict file, so an absolute value whose base name matches a real
# sibling of vf becomes just that base name; no such sibling is a real
# leak of some other path and refuses the whole pack. A value already
# relative is left alone.
while IFS= read -r -d '' vf; do
	vdir=$(dirname "$vf")
	tmp="$vf.pack-normalized"
	: >"$tmp"
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		evidence.*)
			key=${line%%:*}
			val=${line#*: }
			case "$val" in
			/*)
				base=$(basename "$val")
				if [ -f "$vdir/$base" ]; then
					line="$key: $base"
				else
					echo "pack: REFUSED -- $vf: evidence path $val names no file beside this verdict" >&2
					fail=1
				fi
				;;
			esac
			;;
		esac
		printf '%s\n' "$line" >>"$tmp"
	done <"$vf"
	mv "$tmp" "$vf"
done < <(find "$STAGED_BUNDLE" -maxdepth 1 -name '*.verdict' -print0)
while IFS= read -r -d '' f; do
	rel=${f#"$STAGED_BUNDLE"/}
	# Binary evidence (a capture) is never text-scanned; that is out of
	# scope here, same as hygiene-check.sh only ever scanning tracked text.
	case "$f" in
	*.pcap) continue ;;
	esac
	line_no=0
	while IFS= read -r line || [ -n "$line" ]; do
		line_no=$((line_no + 1))
		addrs=$(hygiene_address_disallowed "$line")
		if [ -n "$addrs" ]; then
			echo "pack: REFUSED -- disallowed address at $rel:$line_no" >&2
			fail=1
		fi
		if [[ "$line" =~ $JOURNAL_LINE_RE ]]; then
			host=${BASH_REMATCH[1]}
			if ! [[ "$host" =~ $LAB_HOSTNAME_RE ]]; then
				echo "pack: REFUSED -- non-lab hostname '$host' at $rel:$line_no" >&2
				fail=1
			fi
		fi
		while IFS= read -r pattern || [ -n "$pattern" ]; do
			[ -z "$pattern" ] && continue
			case "$pattern" in '#'*) continue ;; esac
			if grep -qiF "$pattern" <<<"$line"; then
				echo "pack: REFUSED -- denylist hit at $rel:$line_no" >&2
				fail=1
			fi
		done <"$DENYLIST"
	done <"$f"
done < <(find "$STAGED_BUNDLE" -type f -print0)

if [ "$fail" -ne 0 ]; then
	echo "pack: REFUSED -- $BUNDLE_DIR failed hygiene, no tarball written" >&2
	exit 1
fi

mkdir -p "$(dirname "$OUT")"
tar -czf "$OUT" -C "$STAGE" "$(basename "$STAGED_BUNDLE")"
echo "pack: wrote $OUT"
