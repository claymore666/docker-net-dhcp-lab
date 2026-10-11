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
# label (review r1, review r2, ..., or the bare "fix round") and the
# bare "the review" stand-in for the process itself ("the review's own
# ...") never belong in a public tracked file; caught by shape, so no
# real tag or role word appears here.
PROCESS_RE='\b(lab-(impl|rev)-[a-zA-Z0-9]+|exchange-[0-9]+|lead|coordinator|maintainer|reviewer|ruling|finding [0-9]+|handover|directive|review[[:space:]]+r[0-9]+|fix[[:space:]]+round|the[[:space:]]+review)\b'
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
# Group F's scenario IDs (F1, F2a, F3, ...) have the same shape as that
# label (#20). Only the product names themselves are removed from the
# line before FINDING_CITE_RE runs, each listed in full: the eight
# catalog names ("F1-user-class-pool", ...) and the eight README table
# row heads ("| F1 | user class pool |"). Any other F<n>-word or table
# row stays caught, so "the F2-finding" and "| F3 | fixed as asked |"
# fail. TestGroupFNamesAreInTheHygieneGate keeps the list in step.
SCENARIO_ID_RES=(
	'\bF1-user-class-pool\b' '\bF2a-option-108-not-asked\b' '\bF2b-option-108-forced\b' '\bF3-rapid-commit-v4\b'
	'\bF4-rapid-commit-v6\b' '\bF5-temporary-address\b' '\bF6-prefix-delegation\b' '\bF7-pref64\b'
	'\bF8-forcerenew\b'
	'^\| F1 \| user class pool \|' '^\| F2a \| IPv6-only preferred, not asked for \|'
	'^\| F2b \| IPv6-only preferred, sent unasked \|' '^\| F3 \| rapid commit, IPv4 \|'
	'^\| F4 \| rapid commit, IPv6 \|' '^\| F5 \| temporary address \|'
	'^\| F6 \| prefix delegation \|' '^\| F7 \| NAT64 prefix \|' '^\| F8 \| FORCERENEW, signed and unsigned \|'
)
# A `.claude/...` path is never openable by a public reader; matched as
# a plain fixed string, not a regex, so it needs no escaping and cannot
# itself be misread as a pattern.
CLAUDE_PATH='.claude'

# One pass (#78): the tracked-file list is built once, each pattern set is one
# grep over the whole list, and the per-line exemptions below are applied to
# the hit list only; the per-line loop forked about 22 processes per tracked
# line and was 95 % of the verify lane.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

files=()
while IFS= read -r -d '' f; do
	case "$f" in
	*/.git/*) continue ;;
	scripts/hygiene-check.sh) continue ;;             # its own regex literals look like addresses but are not
	scripts/hygiene-patterns.sh) continue ;;          # same reasoning, shared with pack.sh
	scripts/hygiene-check-test.sh) continue ;;        # deliberately carries disallowed-looking fixtures, never real
	scripts/commit-message-check-test.sh) continue ;; # same shape: fixtures for a throwaway repo, never real
	scripts/pack-test.sh) continue ;;                 # same shape: planted addresses are fixtures, never real
	internal/coverage/data/pinned/*/reference.md) continue ;; # a verbatim copy of the plugin's published docs at a tag; its example addresses are the plugin's, not this lab's
	esac
	files+=("$f")
done < <(git ls-files -z -- . ':!images/*.sha256')

# scan OUT CMD...: run one scan into OUT; exit 0/1 are "hits"/"none", anything
# else (an unreadable tracked file, a failed exec) must not read as clean.
scan() {
	local out=$1 rc=0
	shift
	"$@" >"$out" || rc=$?
	if [ "$rc" -gt 1 ]; then
		echo "hygiene-check: scan failed with exit $rc" >&2
		exit 1
	fi
}

# bash's read drops NUL bytes before the old loop matched anything, so text on
# either side of one joined up; a file holding NUL is scanned as a copy with
# them removed, and a hit is mapped back to the tracked name by position.
nul_list=$work/nul.list
if [ "${#files[@]}" -gt 0 ]; then
	scan "$nul_list" grep -lZaP '\x00' -- "${files[@]}"
else
	: >"$nul_list"
fi
declare -A hasnul=()
while IFS= read -r -d '' f; do
	hasnul[$f]=1
done <"$nul_list"
scan_files=()
addr_files=()
declare -A fidx=()
for i in "${!files[@]}"; do
	f=${files[$i]}
	p=$f
	if [ -n "${hasnul[$f]+x}" ]; then
		p=$work/nul-$i
		tr -d '\0' <"$f" >"$p"
	fi
	fidx[$p]=$i
	scan_files+=("$p")
	# A _test.go fixture legitimately carries made-up private addresses
	# (a TempDir source, never shipped or run anywhere real), so it
	# skips the address pass -- but not the process/path passes: a leaked
	# private pointer or role word belongs in no tracked file, test or
	# not, and skipping the whole file missed exactly that in the past.
	case "$f" in
	*_test.go) ;;
	*) addr_files+=("$p") ;;
	esac
done


declare -A proc_hit=() marker_line=()
records=()

if [ "${#scan_files[@]}" -gt 0 ]; then
	# Address pass: one candidate per match, as hygiene_address_candidates
	# prints them; HYGIENE_ALLOWED_RE is the shared definition, never copied.
	if [ "${#addr_files[@]}" -gt 0 ]; then
		scan "$work/addr" grep -HnZoaE -e "$HYGIENE_ADDR_CANDIDATE_RE" -- "${addr_files[@]}"
		while IFS= read -r -d '' f && IFS= read -r rest; do
			if ! [[ "${rest#*:}" =~ $HYGIENE_ALLOWED_RE ]]; then
				records+=("${fidx[$f]}:${rest%%:*}:0")
			fi
		done <"$work/addr"
	fi

	# Process/path passes: one grep per case-sensitivity class, then the
	# finding-label pass, a sed per file because the scenario-id names are
	# stripped from each line before the label is looked for.
	scan "$work/proc" grep -HnZoaiE -e "$PROCESS_RE" -- "${scan_files[@]}"
	scan "$work/verdict" grep -HnZoaE -e "$VERDICT_RE" -- "${scan_files[@]}"
	scan "$work/dotpath" grep -HnZoaiF -e "$CLAUDE_PATH" -- "${scan_files[@]}"
	for hits in proc verdict dotpath; do
		while IFS= read -r -d '' f && IFS= read -r rest; do
			proc_hit["${fidx[$f]}:${rest%%:*}"]=1
		done <"$work/$hits"
	done
	sed_args=(-n -E)
	for sid_re in "${SCENARIO_ID_RES[@]}"; do
		sed_args+=(-e "s/$sid_re//g")
	done
	sed_args+=(-e "/$FINDING_CITE_RE/=")
	for f in "${scan_files[@]}"; do
		scan "$work/cite" sed "${sed_args[@]}" -- "$f"
		while IFS= read -r n; do
			proc_hit["${fidx[$f]}:$n"]=1
		done <"$work/cite"
	done

	# A line that IS the pattern definition, not prose using it, carries
	# this exact trailing marker and is exempt from the process checks only
	# -- matched case-sensitively so a differently-cased comment cannot
	# smuggle it in. The marker alone is not enough: prose can carry the
	# same trailing text too, so it is honored only when the line also joins
	# its flagged words with "|" and no space, the shape a real pattern
	# literal has and prose does not.
	if [ "${#proc_hit[@]}" -gt 0 ]; then
		scan "$work/marker" grep -HnZaE -e '#[[:space:]]*hygiene:[[:space:]]*pattern literal, not prose[[:space:]]*$' -- "${scan_files[@]}"
		while IFS= read -r -d '' f && IFS= read -r rest; do
			marker_line["${fidx[$f]}:${rest%%:*}"]=${rest#*:}
		done <"$work/marker"
	fi
	for key in "${!proc_hit[@]}"; do
		if [ -n "${marker_line[$key]+x}" ]; then
			stripped=$(sed -E 's/#[[:space:]]*hygiene:[[:space:]]*pattern literal, not prose[[:space:]]*$//' <<<"${marker_line[$key]}")
			if [[ "$stripped" == *'|'* ]] && ! grep -qiE "($PROCESS_RE)[[:space:]]+($PROCESS_RE)" <<<"$stripped"; then
				continue
			fi
		fi
		records+=("$key:1")
	done
fi

# Findings come out in file, then line order, address before process on one
# line, as the per-line loop printed them.
fail=0
if [ "${#records[@]}" -gt 0 ]; then
	fail=1
	while IFS=: read -r i n kind; do
		if [ "$kind" -eq 0 ]; then
			echo "hygiene: candidate at ${files[$i]}:$n" >&2
		else
			echo "hygiene: process-marker candidate at ${files[$i]}:$n" >&2
		fi
	done < <(printf '%s\n' "${records[@]}" | sort -t: -k1,1n -k2,2n -k3,3n)
fi

if [ "$fail" -ne 0 ]; then
	echo "hygiene-check: FAILED -- a disallowed address or an internal work-tracking tag was found" >&2
	exit 1
fi
echo "hygiene-check: ok"
