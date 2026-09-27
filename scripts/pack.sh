#!/bin/bash
# labctl pack (issue #4): one evidence bundle directory -> one
# compressed tarball, meant as a GitHub release asset (attaching it is
# not this script's job). Refuses, and writes nothing, when the bundle
# carries a disallowed address (scripts/hygiene-patterns.sh, shared with
# hygiene-check.sh rather than a second copy), a non-lab hostname in a
# captured journalctl line, or a hit against an optional external
# denylist file -- never a hardcoded name, so this script names no rival
# itself even red.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/scripts/hygiene-patterns.sh"

BUNDLE_DIR=${1:?usage: pack.sh <bundle-dir> <out.tar.gz> [denylist-file]}
OUT=${2:?usage: pack.sh <bundle-dir> <out.tar.gz> [denylist-file]}
DENYLIST=${3:-${LAB_PACK_DENYLIST:-}}

if [ ! -d "$BUNDLE_DIR" ]; then
	echo "pack: REFUSED -- $BUNDLE_DIR is not a directory" >&2
	exit 1
fi

# A lab-generated hostname always matches this shape (up-cell.sh's and
# up-source.sh's own cloud-init local-hostname values); anything else in
# a journalctl short-output line's hostname field ("Mon DD HH:MM:SS
# <host> <tag>[pid]: ...", the shape run-group-a.sh captures into
# <cell>-plugin-log.txt) is a real machine name or another plugin's own
# name leaking into evidence.
JOURNAL_LINE_RE='^[A-Z][a-z]{2}[[:space:]]+[0-9]{1,2}[[:space:]]+[0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]+([^[:space:]]+)[[:space:]]'
LAB_HOSTNAME_RE='^lab-[a-z0-9-]+$'

if [ -n "$DENYLIST" ] && [ -f "$DENYLIST" ]; then
	echo "pack: checking against denylist $DENYLIST" >&2
elif [ -n "$DENYLIST" ]; then
	echo "pack: denylist file $DENYLIST does not exist, nothing to check against it" >&2
	DENYLIST=""
else
	echo "pack: no denylist configured (no third argument, LAB_PACK_DENYLIST unset); skipping that check" >&2
fi

fail=0
while IFS= read -r -d '' f; do
	rel=${f#"$BUNDLE_DIR"/}
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
		if [ -n "$DENYLIST" ]; then
			while IFS= read -r pattern || [ -n "$pattern" ]; do
				[ -z "$pattern" ] && continue
				case "$pattern" in '#'*) continue ;; esac
				if grep -qiF "$pattern" <<<"$line"; then
					echo "pack: REFUSED -- denylist hit at $rel:$line_no" >&2
					fail=1
				fi
			done <"$DENYLIST"
		fi
	done <"$f"
done < <(find "$BUNDLE_DIR" -type f -print0)

if [ "$fail" -ne 0 ]; then
	echo "pack: REFUSED -- $BUNDLE_DIR failed hygiene, no tarball written" >&2
	exit 1
fi

mkdir -p "$(dirname "$OUT")"
tar -czf "$OUT" -C "$(dirname "$BUNDLE_DIR")" "$(basename "$BUNDLE_DIR")"
echo "pack: wrote $OUT"
