#!/bin/bash
# Publication hygiene: nothing published here may carry a private address
# or name from outside the lab's own ranges. Pattern-based, not a name
# list: this script names no such address itself, so a failure prints only
# where the hit is, never what it is, and the check's own source stays
# safe to publish even red. The pattern-literal marker below is a
# heuristic against accidental prose,
# not a proof: a line with a stray "|" elsewhere and its flagged words
# separated by filler could still slip past it.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

# Address patterns shared with pack.sh (issue #4): one definition of
# "disallowed address", never a second copy to drift out of step.
. "$REPO_ROOT/scripts/hygiene-patterns.sh"

# Internal work-tracking tags (e.g. lab-impl-9, lab-rev-z), review
# markers (e.g. exchange-1), role words that name how this project is
# worked on (lead, coordinator, maintainer, reviewer), a citation to an
# internal decision a public reader cannot resolve (ruling), a private
# record a public reader cannot open (handover) or the instruction it
# recorded (directive), a review finding's own number, a review round
# label (review r1, review r2, ...) and the bare "the review" stand-in
# for the process itself ("the review's own ...") never belong in a
# public tracked file; caught by shape, so no real tag or role word
# appears here.
PROCESS_RE='\b(lab-(impl|rev)-[a-zA-Z0-9]+|exchange-[0-9]+|lead|coordinator|maintainer|reviewer|ruling|finding [0-9]+|handover|directive|review[[:space:]]+r[0-9]+|the[[:space:]]+review)\b'
# A review verdict word is all-caps only in real use; the ordinary
# English verb a comment might use ("this will hold", "make it clear")
# is lowercase and must stay clean, so this one is matched
# case-sensitively instead of joining PROCESS_RE above.
VERDICT_RE='\b(HOLD|CLEAR)\b'
# A review finding's short label ("F2") is the same citation "finding
# [0-9]+" above catches spelled out, but only in its real, all-caps
# shape: `cut -d: -f1`/`awk -F2` are ordinary, always-lowercase flag
# syntax that must stay clean, so this is matched case-sensitively,
# like VERDICT_RE, never folded into the case-insensitive PROCESS_RE.
FINDING_CITE_RE='\bF[0-9]+\b'
# A `.claude/...` path is never openable by a public reader; matched as
# a plain fixed string, not a regex, so it needs no escaping and cannot
# itself be misread as a pattern.
CLAUDE_PATH='.claude'

fail=0
while IFS= read -r -d '' f; do
	case "$f" in
	*/.git/*) continue ;;
	scripts/hygiene-check.sh) continue ;;             # its own regex literals look like addresses but are not
	scripts/hygiene-patterns.sh) continue ;;          # same reasoning, shared with pack.sh
	scripts/hygiene-check-test.sh) continue ;;        # deliberately carries disallowed-looking fixtures, never real
	scripts/commit-message-check-test.sh) continue ;; # same shape: fixtures for a throwaway repo, never real
	esac
	# A _test.go fixture legitimately carries made-up private addresses
	# (a TempDir source, never shipped or run anywhere real), so it
	# skips the address check below -- but not the process/path check
	# further down: a leaked private pointer or role word belongs in no
	# tracked file, test or not, and skipping the whole file missed
	# exactly that in the past.
	skip_addr=0
	case "$f" in
	*_test.go) skip_addr=1 ;;
	esac
	line_no=0
	# `|| [ -n "$line" ]` picks up a last line with no trailing newline:
	# plain `read` returns non-zero there and a bare `while read` would
	# silently skip that line's body.
	while IFS= read -r line || [ -n "$line" ]; do
		line_no=$((line_no + 1))
		if [ "$skip_addr" -eq 0 ]; then
			matches=$(hygiene_address_disallowed "$line")
			if [ -n "$matches" ]; then
				while IFS= read -r m; do
					[ -z "$m" ] && continue
					echo "hygiene: candidate at $f:$line_no" >&2
					fail=1
				done <<<"$matches"
			fi
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
		if grep -qiE "$PROCESS_RE" <<<"$line" || grep -qE "$VERDICT_RE" <<<"$line" || grep -qE "$FINDING_CITE_RE" <<<"$line" || grep -qiF "$CLAUDE_PATH" <<<"$line"; then
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
