#!/bin/bash
# Publication hygiene (track file: "no address or name from the home
# network"). Pattern-based, not a name list: this script names no home
# address itself, so a failure prints only where the hit is, never what
# it is, and the check's own source stays safe to publish even red. The
# pattern-literal marker below is a heuristic against accidental prose,
# not a proof: a line with a stray "|" elsewhere and its flagged words
# separated by filler could still slip past it.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

# Everything the lab is allowed to publish: its own /16, its own ULA,
# loopback, link-local, and the RFC 5737 / RFC 3849 documentation ranges.
ALLOWED_RE='^(10\.200\.|127\.|169\.254\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|fd42:200)'

# Internal work-tracking tags (e.g. lab-impl-9, lab-rev-z), review
# markers (e.g. exchange-1), and role words that name how this project is
# worked on (lead, coordinator, maintainer, reviewer) never belong in a
# public tracked file; caught by shape, so no real tag or role word
# appears here.
PROCESS_RE='\b(lab-(impl|rev)-[a-zA-Z0-9]+|exchange-[0-9]+|lead|coordinator|maintainer|reviewer)\b'

fail=0
while IFS= read -r -d '' f; do
	case "$f" in
	*/.git/*) continue ;;
	scripts/hygiene-check.sh) continue ;;      # its own regex literals look like addresses but are not
	scripts/hygiene-check-test.sh) continue ;; # deliberately carries disallowed-looking fixtures, never real
	*_test.go) continue ;;                     # synthetic fixtures in a TempDir, never shipped or run anywhere real
	esac
	line_no=0
	# `|| [ -n "$line" ]` picks up a last line with no trailing newline:
	# plain `read` returns non-zero there and a bare `while read` would
	# silently skip that line's body.
	while IFS= read -r line || [ -n "$line" ]; do
		line_no=$((line_no + 1))
		# RFC1918 and link-local candidates only; a public IP is not house detail.
		matches=$(grep -oE '\b(10(\.[0-9]{1,3}){3}|192\.168(\.[0-9]{1,3}){2}|172\.(1[6-9]|2[0-9]|3[01])(\.[0-9]{1,3}){2}|169\.254(\.[0-9]{1,3}){2}|fd[0-9a-f]{2}:[0-9a-f:]+)\b' <<<"$line" || true)
		if [ -n "$matches" ]; then
			while IFS= read -r m; do
				[ -z "$m" ] && continue
				if ! [[ "$m" =~ $ALLOWED_RE ]]; then
					echo "hygiene: candidate at $f:$line_no" >&2
					fail=1
				fi
			done <<<"$matches"
		fi
		# A line that IS the pattern definition, not prose using it, carries
		# this exact trailing marker and is exempt from this one check only
		# -- matched case-sensitively so a differently-cased comment cannot
		# smuggle it in. The marker alone is not enough: prose can carry
		# the same trailing text too, so it is honored only when the line
		# also joins its flagged words with "|" and no space, the shape a
		# real pattern literal has and prose does not.
		if grep -qE '#[[:space:]]*hygiene:[[:space:]]*pattern literal, not prose[[:space:]]*$' <<<"$line"; then
			stripped=$(sed -E 's/#[[:space:]]*hygiene:[[:space:]]*pattern literal, not prose[[:space:]]*$//' <<<"$line")
			if [[ "$stripped" == *'|'* ]] && ! grep -qiE "($PROCESS_RE)[[:space:]]+($PROCESS_RE)" <<<"$stripped"; then
				continue
			fi
		fi
		if grep -qiE "$PROCESS_RE" <<<"$line"; then
			echo "hygiene: process-marker candidate at $f:$line_no" >&2
			fail=1
		fi
	done <"$f"
done < <(git ls-files -z -- . ':!images/*.sha256')

if [ "$fail" -ne 0 ]; then
	echo "hygiene-check: FAILED -- a disallowed address or an internal work-tracking tag was found" >&2
	exit 1
fi
echo "hygiene-check: ok"
