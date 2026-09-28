#!/bin/bash
# Commit-message hygiene, pulled out of verify.sh so its own catches can
# be fixture-tested against a throwaway git repo's commits (issue #3),
# the same split hygiene-check.sh/hygiene-check-test.sh already use for
# tracked files. Run at the repo root; takes the git log range to scan
# as $1 (e.g. "origin/dev..HEAD" or "HEAD").
set -euo pipefail

range=${1:?usage: commit-message-check.sh <git-log-range>}

# How this project is worked on -- who staffs it, work-tracking tags,
# a review round under either shape it gets tagged with (spelled out,
# or the short r-plus-number form) -- never belongs in a commit that
# ships. Subjects and bodies only; author/committer identity is real
# and out of scope here.
processy=$(git log "$range" --format='%B' 2>/dev/null | grep -inE '\b(lead|coordinator|maintainer|reviewer|review[[:space:]]+round|r[0-9]+|lab-(impl|rev)-[a-zA-Z0-9]+|exchange-[0-9]+)\b' || true) # hygiene: pattern literal, not prose
if [ -n "$processy" ]; then
	echo "commit-message-check: process/role word found in a commit message:" >&2
	echo "$processy" >&2
	exit 1
fi

# A review finding's own number can land on either side of a line break
# in a wrapped commit body; grep is line-based and would miss that
# split, so each commit's own body (never mixed with another commit's)
# is joined to one line before this one check runs, which catches the
# split and the same-line case both.
finding_split=""
while IFS= read -r commit; do
	joined=$(git log -1 --format='%B' "$commit" 2>/dev/null | tr '\n' ' ')
	hit=$(grep -inE '\bfinding[[:space:]]+[0-9]+\b' <<<"$joined" || true)
	if [ -n "$hit" ]; then
		finding_split="$finding_split
$commit: $hit"
	fi
done < <(git log "$range" --format='%H' 2>/dev/null)
if [ -n "$finding_split" ]; then
	echo "commit-message-check: a review finding's number found in a commit message:" >&2
	echo "$finding_split" >&2
	exit 1
fi

echo "commit-message-check: ok"
