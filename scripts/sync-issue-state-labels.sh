#!/usr/bin/env bash
# Issue state labels (#41), ported from the plugin repo's script of the
# same name. Every PR targets `dev`, so GitHub builds no "Development"
# link and an issue with merged work reads as untouched. Two labels on
# open issues restore the signal; `in-dev` wins when both apply:
#
#   in-dev   the work merged into `dev`, awaiting the release
#   has-pr   a PR referencing it is open

# References come from squash-commit subjects, not PR prose: take the
# parenthesised groups at the END of the subject, right to left, while
# each holds only `#<digits>` separated by commas. That keeps `#408` out
# of "fix: make the #408 wait observable (#422) (#437)". A group with
# prose inside stops the walk, so "(#356, step 1 of 2) (#448)" yields
# only 448; loosening that is how a parser starts guessing.

# Parsed refs are intersected with the open-issue list rather than
# classified: a PR number or a closed issue is not in it, and those are
# exactly what must not be labelled.

# One hop: a subject naming only the PR ("... (#473)") cannot be fixed,
# because GitHub's squash subject is immutable. Every ref that is not an
# open issue is looked up as a PR and its title and body go through the
# same parser, without recursion. `closingIssuesReferences` is no help:
# PRs here say "Closes nothing on dev", the release PR does the closing.

# PR text is attacker-controlled on a public repo: never executed or
# checked out, reduced to a bounded integer that must be an open issue.

# Usage:
#   sync-issue-state-labels.sh                apply the plan
#   sync-issue-state-labels.sh --dry-run      print the plan, change nothing
#   sync-issue-state-labels.sh --parse        subjects on stdin, print the refs
#   sync-issue-state-labels.sh --parse-title  titles on stdin, print refs()
#   sync-issue-state-labels.sh --parse-body   PR prose on stdin, print closing refs
#   sync-issue-state-labels.sh --plan DIR     plan for the fixture files in DIR
#   sync-issue-state-labels.sh --unresolved DIR  refs that are not open issues
# Exit: 0 clean, 1 something failed, 2 cannot run (bad usage/inputs).
set -u

MODE="apply"
PLAN_DIR=""
case "${1:-}" in
    "") ;;
    --dry-run) MODE="dry-run" ;;
    --parse) MODE="parse" ;;
    --parse-title) MODE="parse-title" ;;
    --parse-body) MODE="parse-body" ;;
    --plan|--unresolved)
        MODE="${1#--}"
        PLAN_DIR="${2:-}"
        if [ -z "$PLAN_DIR" ] || [ ! -d "$PLAN_DIR" ]; then
            echo "FAIL  $1 needs a directory holding subjects.txt, issues.json, prs.json" >&2
            exit 2
        fi
        ;;
    -h|--help)
        sed -n '/^# Usage:/,/^# Exit:/p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "usage: $0 [--dry-run|--parse|--parse-title|--parse-body|--plan DIR|--unresolved DIR]" >&2
        exit 2
        ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
    echo "FAIL  python3 is required" >&2
    exit 2
fi

# The parser, shared by --parse and the full run. Kept in one place so
# the gate cannot end up testing a second copy that has drifted.
PARSER=$(cat <<'PY'
import re

# A trailing group is refs-only: '#' digits, comma-separated, nothing
# else. The digit cap keeps a pathological subject from producing a
# number no issue could ever have.
_GROUP = re.compile(r"\(\s*#\d{1,7}(?:\s*,\s*#\d{1,7})*\s*\)\s*$")
# GitHub's default subject for the "Create a merge commit" button. It is
# the ONLY thing such a commit says, and it names the PR, never the
# issue — so it is a pure input to the one hop below.
_MERGE_SUBJECT = re.compile(r"^Merge pull request #(\d{1,7}) from \S")
_NUM = re.compile(r"#(\d{1,7})")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_CLOSES = re.compile(
    r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s*(#[0-9]+(?:\s*(?:,|and)\s*#[0-9]+)*)"
)
_NUM_BOUNDED = re.compile(r"#([0-9]{1,7})(?![0-9])")


def refs(subject):
    """Numbers from the trailing ref groups of a commit subject or PR
    title, left-to-right, deduplicated. Prose anywhere stops the walk."""
    rest = subject.rstrip()
    groups = []
    while True:
        m = _GROUP.search(rest)
        if not m:
            break
        groups.append(m.group(0))
        rest = rest[: m.start()].rstrip()
    out = []
    for group in reversed(groups):
        for raw in _NUM.findall(group):
            n = int(raw)
            if n and n not in out:
                out.append(n)
    return out


def commit_refs(subject):
    """Refs from a COMMIT subject: the trailing-group rule, plus the
    merge-commit form.

    Kept separate from refs() rather than folded into it because the two
    have different trust properties. refs() is also run over PR titles,
    which are attacker-controlled and intersected DIRECTLY with the open
    issues; teaching it the merge form would let a PR titled "Merge pull
    request #500 from x" mark issue #500. A commit subject on `dev` has
    already passed review, and the number it yields is only ever a
    candidate for the hop.
    """
    m = _MERGE_SUBJECT.match(subject.strip())
    if m:
        return [int(m.group(1))]
    return refs(subject)


def body_refs(body):
    """Numbers referenced with closing keywords in PR prose (e.g.
    'Closes #123', 'Fixes #45, #67'), deduplicated. HTML comments are
    stripped first so template examples like '<!-- e.g. Closes #123 -->'
    do not create false references."""
    if not body:
        return []
    clean_body = _HTML_COMMENT.sub("", body)
    out = []
    for m in _CLOSES.finditer(clean_body):
        for raw in _NUM_BOUNDED.findall(m.group(1)):
            n = int(raw)
            if n and n not in out:
                out.append(n)
    return out


def pr_refs(pr):
    """Candidate issue refs from an open PR's title and body."""
    out = refs(pr.get("title", "") or "")
    for n in body_refs(pr.get("body", "") or ""):
        if n not in out:
            out.append(n)
    return out
PY
)

if [ "$MODE" = "parse-title" ]; then
    # Bound to refs(), not the merge-aware commit_refs() (#41): a title
    # "Merge pull request #500 from x" must not name issue #500, and the
    # reconciler reads titles with refs(). Output matches what it sees.
    PARSER="$PARSER" python3 -c '
import os
import sys

exec(os.environ["PARSER"])  # noqa: S102 - defines refs()

for line in sys.stdin:
    for n in refs(line.rstrip("\n")):
        print(f"#{n}")
'
    exit $?
fi

if [ "$MODE" = "parse" ]; then
    # python3 -c, not a heredoc: `python3 - <<PY` makes the heredoc the
    # process's stdin, so the subjects being piped in would never be read
    # and this mode would print nothing while exiting 0.
    PARSER="$PARSER" python3 -c '
import os
import sys

exec(os.environ["PARSER"])  # noqa: S102 - defines refs()

for line in sys.stdin:
    for n in commit_refs(line.rstrip("\n")):
        print(f"#{n}")
'
    exit $?
fi

# The body half of the same parser, exposed so a caller never carries a
# second copy that could drift from the one that decides the labels.
if [ "$MODE" = "parse-body" ]; then
    PARSER="$PARSER" python3 -c '
import os
import sys

exec(os.environ["PARSER"])  # noqa: S102 - defines body_refs()

for n in body_refs(sys.stdin.read()):
    print(f"#{n}")
'
    exit $?
fi

# Everything both the planner and the unresolved-ref listing need: the
# open issues, and the refs the dev-window subjects carry. Kept as one
# fragment so the two modes cannot disagree about what a ref is.
LOADER=$(cat <<'PY'
import json
import os

exec(os.environ["PARSER"])  # noqa: S102 - defines refs()

tmp = os.environ["TMP"]

issues = json.load(open(f"{tmp}/issues.json", encoding="utf-8"))
open_numbers = {i["number"] for i in issues}
current = {i["number"]: {lbl["name"] for lbl in i["labels"]} for i in issues}

with open(f"{tmp}/subjects.txt", encoding="utf-8") as fh:
    subject_refs = {n for line in fh for n in commit_refs(line.rstrip("\n"))}

# A ref that is not an open issue is either a PR or an issue already
# closed. Both are things we must not label, and the first is the thing
# worth one lookup — see THE ONE HOP above.
unresolved = sorted(subject_refs - open_numbers)
PY
)

# The reconciliation. Reads the loader's inputs plus an optional
# pr_titles.json ({"473": "...title..."}) carrying the hop's answers, and
# emits the plan as ADD/REMOVE rows plus one SUMMARY row.
PLANNER=$(cat <<'PY'
in_dev = subject_refs & open_numbers

# The hop. A PR title contributes only through the same parser and the
# same intersection, so it can never introduce a number the repo does
# not already list as open. Absent file = no hop, which is what keeps
# the offline fixtures that predate this honest.
titles = {}
titles_path = f"{tmp}/pr_titles.json"
if os.path.exists(titles_path):
    titles = {int(k): v for k, v in json.load(open(titles_path, encoding="utf-8")).items()}
# Bodies are optional and in their own file, so every fixture written
# before this stays valid: absent means no body contribution, never an
# error. That also keeps the pre-existing fixtures as a negative control
# — they must still produce exactly what they did before.
bodies = {}
bodies_path = f"{tmp}/pr_bodies.json"
if os.path.exists(bodies_path):
    bodies = {int(k): v for k, v in json.load(open(bodies_path, encoding="utf-8")).items()}
for number in unresolved:
    title = titles.get(number)
    if title:
        in_dev |= set(refs(title)) & open_numbers
    # The body, with body_refs' closing-keyword rule rather than refs'
    # trailing-"(#N)" rule. A merged PR that names its issue only in the
    # body is the ordinary case here, not an edge one: the squash
    # subject carries the PR's own number and nothing else, so the issue
    # is reachable through the body or not at all.
    body = bodies.get(number)
    if body:
        in_dev |= set(body_refs(body)) & open_numbers

prs = json.load(open(f"{tmp}/prs.json", encoding="utf-8"))
has_pr = {n for pr in prs for n in pr_refs(pr)} & open_numbers

# in-dev is the stronger claim; a later PR must not un-finish an issue.
has_pr -= in_dev

for number in sorted(open_numbers):
    want = set()
    if number in in_dev:
        want.add("in-dev")
    if number in has_pr:
        want.add("has-pr")
    have = current[number] & {"in-dev", "has-pr"}
    for label in sorted(want - have):
        print(f"ADD\t{number}\t{label}")
    for label in sorted(have - want):
        print(f"REMOVE\t{number}\t{label}")

print(f"SUMMARY\t{len(open_numbers)}\t{len(in_dev)}\t{len(has_pr)}")
PY
)

UNRESOLVED=$(cat <<'PY'
for number in unresolved:
    print(number)
PY
)

if [ "$MODE" = "plan" ] || [ "$MODE" = "unresolved" ]; then
    for f in subjects.txt issues.json prs.json; do
        [ -f "$PLAN_DIR/$f" ] || {
            echo "FAIL  missing: $PLAN_DIR/$f" >&2
            exit 2
        }
    done
    if [ "$MODE" = "unresolved" ]; then
        PARSER="$PARSER" TMP="$PLAN_DIR" python3 -c "$LOADER
$UNRESOLVED"
    else
        PARSER="$PARSER" TMP="$PLAN_DIR" python3 -c "$LOADER
$PLANNER"
    fi
    exit $?
fi

for tool in gh git; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FAIL  $tool is required" >&2
        exit 2
    }
done

REPO="${GITHUB_REPOSITORY:-$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null)}"
if [ -z "$REPO" ]; then
    echo "FAIL  cannot determine the repository" >&2
    exit 2
fi

BASE_BRANCH="${STATE_LABELS_BASE:-main}"
DEV_BRANCH="${STATE_LABELS_DEV:-dev}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# What has merged into dev but not yet shipped on main. If the range is
# not resolvable the run is wrong rather than empty — an empty answer
# here would silently strip in-dev off every issue.
if ! git rev-parse --verify --quiet "origin/$BASE_BRANCH" >/dev/null ||
    ! git rev-parse --verify --quiet "origin/$DEV_BRANCH" >/dev/null; then
    echo "FAIL  need both origin/$BASE_BRANCH and origin/$DEV_BRANCH — fetch them first" >&2
    exit 2
fi
# Merges are included (#41): a branch whose own commits never name their
# issue survives only as the merge commit's PR number. Ordinary merge
# subjects ("Merge branch 'main' into dev") parse to nothing.
git log "origin/$BASE_BRANCH..origin/$DEV_BRANCH" --format='%s' > "$TMP/subjects.txt"

gh issue list --repo "$REPO" --state open --limit 1000 \
    --json number,labels > "$TMP/issues.json" || exit 1
gh pr list --repo "$REPO" --state open --base "$DEV_BRANCH" --limit 200 \
    --json number,title,body > "$TMP/prs.json" || exit 1

# THE ONE HOP. Ask about exactly the refs that did not land on an open
# issue — no paged listing to truncate, so a ref can never go unlooked-at
# because it fell outside a fetch window. Most are PRs; the rest 404 as
# closed issues, which is not an error, just an answer.
if ! PARSER="$PARSER" TMP="$TMP" python3 -c "$LOADER
$UNRESOLVED" > "$TMP/unresolved"; then
    echo "FAIL  could not determine which refs need looking up" >&2
    exit 1
fi

echo "{}" > "$TMP/pr_titles.json"
echo "{}" > "$TMP/pr_bodies.json"
looked_up=0
resolved=0
while read -r number; do
    [ -n "$number" ] || continue
    looked_up=$((looked_up + 1))
    # One request, both fields. The body is where a PR that does not name
    # its issue in the title says "Closes #N", and asking for it costs
    # nothing extra: it is the same lookup that was already being made.
    #
    # Written as JSON rather than two delimited values because a body is
    # multi-line arbitrary text — any hand-rolled framing here would be a
    # parser bug waiting to happen.
    if ! gh api "repos/$REPO/pulls/$number" \
            --jq '{title: .title, body: (.body // "")}' > "$TMP/pr.$number" 2>/dev/null ||
       [ ! -s "$TMP/pr.$number" ]; then
        # A 404 is an answer (the ref was a closed issue); any other
        # failure is not (#41). A 403 rate limit or a 5xx would make the
        # ref contribute nothing and the planner would REMOVE in-dev from
        # issues that are in dev. -i is used only here, so the happy path
        # keeps its single --jq request.
        status=$(gh api "repos/$REPO/pulls/$number" -i 2>/dev/null | awk 'NR == 1 { print $2 }')
        if [ "$status" = "404" ]; then
            continue
        fi
        echo "FAIL  could not read repos/$REPO/pulls/$number (HTTP ${status:-unknown})." >&2
        echo "      A ref that cannot be read is not a ref that resolves to nothing." >&2
        echo "      Continuing would plan REMOVE in-dev for issues that ARE in dev." >&2
        exit 2
    fi
    resolved=$((resolved + 1))
done < "$TMP/unresolved"

if [ "$resolved" -ne 0 ]; then
    # Titles AND bodies are attacker-controlled text on a public repo;
    # hand them to python as files rather than through a shell-expanded
    # string. The trust model is unchanged by adding the body: it is
    # reduced to digits by the same parser, and the intersection with the
    # repo's own open-issue list still does all the classifying, so a
    # body can only ever contribute a number that is already an open
    # issue here.
    if ! TMP="$TMP" python3 -c '
import json
import os

tmp = os.environ["TMP"]
titles = {}
bodies = {}
for name in os.listdir(tmp):
    if not name.startswith("pr."):
        continue
    number = name[len("pr."):]
    with open(f"{tmp}/{name}", encoding="utf-8", errors="replace") as fh:
        try:
            pr = json.load(fh)
        except ValueError:
            continue
    title = (pr.get("title") or "").rstrip("\n")
    if title:
        titles[number] = title
    body = pr.get("body") or ""
    if body:
        bodies[number] = body
with open(f"{tmp}/pr_titles.json", "w", encoding="utf-8") as fh:
    json.dump(titles, fh)
with open(f"{tmp}/pr_bodies.json", "w", encoding="utf-8") as fh:
    json.dump(bodies, fh)
'; then
        echo "FAIL  could not collect the PR titles and bodies" >&2
        exit 1
    fi
fi
echo "one-hop lookups: $looked_up ref(s) not an open issue, $resolved resolved to a PR"

if ! PARSER="$PARSER" TMP="$TMP" python3 -c "$LOADER
$PLANNER" > "$TMP/plan"; then
    echo "FAIL  could not build the plan" >&2
    exit 1
fi

summary=$(grep '^SUMMARY' "$TMP/plan" | head -1)
changes=$(grep -cE '^(ADD|REMOVE)' "$TMP/plan" || true)
echo "issue state labels: $(echo "$summary" | cut -f2) open issues, $(echo "$summary" | cut -f3) in-dev, $(echo "$summary" | cut -f4) has-pr, $changes change(s)"

if [ "$changes" -eq 0 ]; then
    echo "nothing to do."
    exit 0
fi

if [ "$MODE" = "dry-run" ]; then
    grep -E '^(ADD|REMOVE)' "$TMP/plan" | sed 's/^/  /'
    exit 0
fi

# Create the labels on first use so there is no out-of-band setup step
# to forget. Already-exists is not an error.
gh label create in-dev --repo "$REPO" --color 0E8A16 \
    --description "Work merged into dev — done, awaiting release" >/dev/null 2>&1 || true
gh label create has-pr --repo "$REPO" --color FBCA04 \
    --description "An open PR references this issue" >/dev/null 2>&1 || true

failed=0
while IFS=$'\t' read -r action number label; do
    case "$action" in
        ADD) flag="--add-label" ;;
        REMOVE) flag="--remove-label" ;;
        *) continue ;;
    esac
    if gh issue edit "$number" --repo "$REPO" "$flag" "$label" >/dev/null; then
        echo "  $action #$number $label"
    else
        echo "FAIL  $action #$number $label" >&2
        failed=$((failed + 1))
    fi
done < <(grep -E '^(ADD|REMOVE)' "$TMP/plan")

if [ "$failed" -ne 0 ]; then
    echo "$failed label edit(s) failed" >&2
    exit 1
fi
