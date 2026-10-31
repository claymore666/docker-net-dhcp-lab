#!/bin/bash
# shellcheck disable=SC2016 # stub bodies expand when each stub runs
# run-cell.sh against a copy in a stub repo, for what a pass leaves in the
# evidence dir: a retry pass keeps the earlier pass's plugin journal (#95),
# the versions file carries each peer's own server package (#99), and a
# shape whose labctl run died on an infrastructure error gets its BLOCKED
# rows asked for with labctl's own last error line (#101).
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
t=run-cell-pass-test

fake="$tmp/repo"
mkdir -p "$fake/scripts" "$tmp/bin"
cp "$REPO_ROOT/scripts/run-cell.sh" "$fake/scripts/run-cell.sh"
cp "$REPO_ROOT/scripts/source-types.sh" "$fake/scripts/source-types.sh"
cp "$REPO_ROOT/scripts/load-gate.sh" "$fake/scripts/load-gate.sh"
echo "0.00 0.00 0.00 1/100 1" >"$tmp/loadavg"
stub() {
	printf '#!/bin/bash\n%s\n' "$2" >"$1"
	chmod +x "$1"
}
stub "$fake/scripts/capture-check-regenerate.sh" 'echo "regen|${3:-none}" >>"$CALLS"'
# UP_RC makes the bring-up fail, with UP_MSG on stderr (#130).
stub "$fake/scripts/up-cell.sh" '[ -z "${UP_RC:-}" ] || { printf "%s\n" "${UP_MSG:-}" >&2; exit "$UP_RC"; }'
for s in capture-source-config-diff.sh down-cell.sh; do
	stub "$fake/scripts/$s" 'exit 0'
done
stub "$fake/scripts/capture-start.sh" ': >"$3/observer.ready"'
stub "$fake/scripts/capture-stop.sh" 'echo "$1" >"$2/observer.pcap"'
stub "$tmp/bin/git" 'echo 0000000'
# every peer answers its own address; the docker host's journal is $JOURNAL
stub "$tmp/bin/ssh" 'case "$*" in
*"journalctl -u docker"*) echo "journal|$*" >>"$CALLS"; echo "plugin=1234 $JOURNAL" ;;
*dpkg-query*) echo "ver-$(echo "$*" | grep -oE "lab@[0-9.]+" | cut -d@ -f2)" ;;
*) echo stub ;;
esac'
# go run <repo>/cmd/labctl <sub> ...: $3 is the subcommand
stub "$tmp/bin/go" 'case "$3" in
resolve) cat "$RESOLVED_FILE" ;;
remaining) echo A1 ;;
run)
	echo "run $7" >>"$CALLS"
	if [ "$7" = "${DIE_SHAPE:-none}" ]; then
		[ -z "$DIE_MSG" ] || echo "labctl run: $DIE_MSG" >&2
		echo "exit status ${DIE_RC:-1}" >&2
		exit "${DIE_RC:-1}"
	fi ;;
abort-blocked) printf "abort|%s|%s|%s\n" "$7" "$8" "$9" >>"$CALLS" ;;
esac'
stub "$tmp/bin/sleep" 'exec /bin/sleep "$@"'

cat >"$tmp/pair.json" <<'JSON'
{"cell": {"segment": {"bridge": "lab-br-t-pair"},
  "docker_host": {"mgmt_address": "10.200.255.110/24", "plugin_tag": "x"},
  "source": {"type": "kea", "mgmt_address": "10.200.255.111/24",
             "partner": {"mgmt_address": "10.200.255.113/24"}}}}
JSON
cat >"$tmp/single.json" <<'JSON'
{"cell": {"segment": {"bridge": "lab-br-t-one"},
  "docker_host": {"mgmt_address": "10.200.255.110/24", "plugin_tag": "x"},
  "source": {"type": "pihole", "mgmt_address": "10.200.255.111/24"}}}
JSON

# run CASE RESOLVED [ENV=VAL ...]; evidence and out land in $tmp/CASE
run() {
	local case=$1 resolved=$2
	shift 2
	mkdir -p "$tmp/$case/evidence"
	: >"$tmp/$case/calls"
	env JOURNAL=J-"$case" DIE_MSG= "$@" PATH="$tmp/bin:$PATH" LAB_LOADAVG="$tmp/loadavg" LAB_NCPU=16 \
		CALLS="$tmp/$case/calls" RESOLVED_FILE="$tmp/$resolved.json" \
		"$fake/scripts/run-cell.sh" t-pair "$tmp/$case/work" "$tmp/$case/evidence" >"$tmp/$case/out" 2>&1
}
# expect DESCRIPTION CONDITION: CONDITION is eval'd; a failing one is reported, never fatal.
expect() {
	if ! eval "$2"; then
		echo "$t: FAIL -- $1" >&2
		fail=1
	fi
}
ev() { echo "$tmp/$1/evidence"; }

# #95: a main pass, a retry pass and a third pass each keep the one before.
start=$(date -u +%s)
run main pair || { cat "$tmp/main/out" >&2; fail=1; }
end=$(date -u +%s)

# #141: the journal is read from the cell's own start, not a fixed window
# a long cell outruns.
since=$(grep '^journal|' "$tmp/main/calls" | grep -oE "since '[^']*'" | head -1)
expect "the journal was not read from an absolute UTC time: $since" 'grep -qxE "since .[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC." <<<"$since"'
# shellcheck disable=SC2034 # read inside the expect strings below
since_s=$(date -u -d "$(echo "$since" | cut -d"'" -f2)" +%s 2>/dev/null || echo 0)
expect "the journal since $since is not the cell's start less 5 min (start $start, end $end)" '[ "$since_s" -ge $((start - 300)) ] && [ "$since_s" -le $((end - 300)) ]'
expect "the main pass's journal is not in t-pair-plugin-log.txt" 'grep -q '\''J-main'\'' "$(ev main)/t-pair-plugin-log.txt"'
expect "a main pass wrote a .retry journal" '[ ! -e "$(ev main)/t-pair-plugin-log.retry.txt" ]'

mkdir -p "$tmp/retry/evidence"
echo MAIN-MARKER >"$tmp/retry/evidence/t-pair-plugin-log.txt"
echo MAIN-PCAP >"$tmp/retry/evidence/t-pair.pcap"
run retry pair || fail=1
expect "the retry pass overwrote the main pass's journal" '[ "$(cat "$(ev retry)/t-pair-plugin-log.txt")" = MAIN-MARKER ]'
expect "the retry pass's journal is not in t-pair-plugin-log.retry.txt" 'grep -q '\''J-retry'\'' "$(ev retry)/t-pair-plugin-log.retry.txt"'

mkdir -p "$tmp/third/evidence"
echo MAIN-MARKER >"$tmp/third/evidence/t-pair-plugin-log.txt"
echo RETRY-MARKER >"$tmp/third/evidence/t-pair-plugin-log.retry.txt"
echo MAIN-PCAP >"$tmp/third/evidence/t-pair.pcap"
echo RETRY-PCAP >"$tmp/third/evidence/t-pair.retry.pcap"
run third pair || fail=1
expect "a third pass overwrote an earlier journal" '[ "$(cat "$(ev third)/t-pair-plugin-log.txt")" = MAIN-MARKER ] && [ "$(cat "$(ev third)/t-pair-plugin-log.retry.txt")" = RETRY-MARKER ]'
expect "the third pass's journal is not in t-pair-plugin-log.retry3.txt" 'grep -q '\''J-third'\'' "$(ev third)/t-pair-plugin-log.retry3.txt"'

# #95: the capture is kept the same way, and the retry's capture checks are
# replayed against the retry's own pcap.
expect "a main pass wrote no plain pcap" '[ -s "$(ev main)/t-pair.pcap" ] && [ ! -e "$(ev main)/t-pair.retry.pcap" ]'
expect "the main pass's regenerate did not get the plain pcap: $(grep '^regen|' "$tmp/main/calls")" '[ "$(grep "^regen|" "$tmp/main/calls")" = "regen|$(ev main)/t-pair.pcap" ]'
expect "the retry pass overwrote the main pass's capture" '[ "$(cat "$(ev retry)/t-pair.pcap")" = MAIN-PCAP ] && [ "$(cat "$(ev retry)/t-pair.retry.pcap")" = t-pair ]'
expect "the retry pass's regenerate did not get t-pair.retry.pcap: $(grep '^regen|' "$tmp/retry/calls")" '[ "$(grep "^regen|" "$tmp/retry/calls")" = "regen|$(ev retry)/t-pair.retry.pcap" ]'
expect "a third pass overwrote an earlier capture" '[ "$(cat "$(ev third)/t-pair.pcap")" = MAIN-PCAP ] && [ "$(cat "$(ev third)/t-pair.retry.pcap")" = RETRY-PCAP ] && [ "$(cat "$(ev third)/t-pair.retry3.pcap")" = t-pair ]'

# #99: each peer's own package version, in a pair cell only.
v=$(ev main)/t-pair-versions.txt
expect "no source package line carrying the primary's own answer in $v" 'grep -qx '\''source package kea-dhcp4-server: ver-10.200.255.111'\'' "$v"'
expect "no partner package line carrying the partner's own answer in $v" 'grep -qx '\''partner package kea-dhcp4-server: ver-10.200.255.113'\'' "$v"'
run single single || fail=1
if grep -qE 'partner|package' "$(ev single)/t-pair-versions.txt"; then
	echo "$t: FAIL -- a single pihole cell got a partner or package line" >&2
	fail=1
fi
expect "a cell without a package line did not run its five shapes" '[ "$(grep -c '\''^run '\'' "$tmp/single/calls")" -eq 5 ]'

# #101: an infrastructure abort asks for BLOCKED rows with labctl's own line.
if run die pair DIE_SHAPE=macvlan DIE_RC=1 'DIE_MSG=IsolateIPAMNetwork: boom'; then
	echo "$t: FAIL -- run-cell exited 0 after an infrastructure abort" >&2
	fail=1
fi
expect "an aborted shape stopped the cell's other shapes" '[ "$(grep -c '\''^run '\'' "$tmp/die/calls")" -eq 5 ]'
expect "the abort call is not exactly one macvlan call with labctl's last line: $(grep '^abort|' "$tmp/die/calls")" '[ "$(grep '\''^abort|'\'' "$tmp/die/calls")" = "abort|macvlan|$(ev die)|labctl run: IsolateIPAMNetwork: boom" ]'
run die-silent pair DIE_SHAPE=bridge DIE_RC=1 || true
expect "a labctl that said nothing gets no generic reason: $(grep '^abort|' "$tmp/die-silent/calls")" '[ "$(grep '\''^abort|'\'' "$tmp/die-silent/calls")" = "abort|bridge|$(ev die-silent)|labctl run exited with status 1" ]'
expect "shapes that finished asked for BLOCKED rows" '[ "$(grep -c '\''^abort|'\'' "$tmp/main/calls")" -eq 0 ]'
run die3 pair DIE_SHAPE=bridge DIE_RC=3 'DIE_MSG=pool too small' || true
expect "exit 3 (its own BLOCKED rows, cell aborted) asked for abort rows or kept running shapes" '[ "$(grep -c '\''^abort|'\'' "$tmp/die3/calls")" -eq 0 ] && [ "$(grep -c '\''^run '\'' "$tmp/die3/calls")" -eq 1 ]'

# #130: a cell that does not come up ends with BLOCKED rows that name the
# reason in every shape, a non-zero exit, and no scenario run.
if run up-fails pair UP_RC=1 'UP_MSG=noise line
up-source: REFUSED -- seed-chr exited 2' ; then
	echo "$t: FAIL -- run-cell exited 0 after a failed bring-up" >&2
	fail=1
fi
expect "a failed bring-up still ran scenarios" '[ "$(grep -c '\''^run '\'' "$tmp/up-fails/calls")" -eq 0 ]'
expect "a failed bring-up did not write BLOCKED rows for the five shapes: $(grep '^abort|' "$tmp/up-fails/calls")" '[ "$(grep -c '\''^abort|'\'' "$tmp/up-fails/calls")" -eq 5 ]'
expect "the BLOCKED rows lack the lab-error reason" '[ "$(grep -c '\''^abort|.*|the cell did not come up (lab error, not a plugin finding): up-source: REFUSED -- seed-chr exited 2$'\'' "$tmp/up-fails/calls")" -eq 5 ]'
expect "the shapes are not the five of a cell" '[ "$(grep "^abort|" "$tmp/up-fails/calls" | cut -d"|" -f2 | tr "\n" " ")" = "bridge macvlan ipvlan bridge-ipam macvlan-ipam " ]'
expect "run-cell printed no FAIL line for a failed bring-up" 'grep -q "^run-cell: FAIL -- the cell did not come up" "$tmp/up-fails/out"'
expect "a failed bring-up left no resolved lab.json for the matrix" '[ -s "$(ev up-fails)/t-pair-resolved-lab.json" ]'
run up-silent pair UP_RC=7 || true
expect "a silent bring-up failure has no named reason: $(grep '^abort|' "$tmp/up-silent/calls" | head -1)" 'grep -q "^abort|bridge|.*|the cell did not come up (lab error, not a plugin finding): up-cell exited with status 7$" "$tmp/up-silent/calls"'

# #130: of several bring-up lines only the last two name the reason, joined by
# a space; earlier ones (the first cause of a cascade) are not in the row.
run up-many pair UP_RC=1 'UP_MSG=up-cell: first cause
up-source: middle
seed-chr: last but one
up-cell: the end' || true
expect "a bring-up with four named lines did not keep exactly the last two: $(grep '^abort|bridge|' "$tmp/up-many/calls")" '[ "$(grep "^abort|bridge|" "$tmp/up-many/calls")" = "abort|bridge|$(ev up-many)|the cell did not come up (lab error, not a plugin finding): seed-chr: last but one up-cell: the end" ]'
expect "an earlier bring-up line leaked into the reason" '! grep -qE "first cause|middle" "$tmp/up-many/calls"'

[ "$fail" -eq 0 ] && echo "$t: PASS"
exit "$fail"
