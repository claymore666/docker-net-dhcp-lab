#!/bin/bash
# shellcheck disable=SC2016 # stub bodies expand when each stub runs
# run-cell.sh in a relay cell (#11), against a copy of the script in a
# stub repo: a failed relay probe runs no shape and still keeps both
# pcaps; a passing probe runs every shape and copies the server pcap.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fake="$tmp/repo"
mkdir -p "$fake/scripts" "$tmp/bin"
cp "$REPO_ROOT/scripts/run-cell.sh" "$fake/scripts/run-cell.sh"
stub() {
	printf '#!/bin/bash\n%s\n' "$2" >"$1"
	chmod +x "$1"
}
for s in up-cell.sh capture-source-config-diff.sh capture-check-regenerate.sh down-cell.sh; do
	stub "$fake/scripts/$s" 'exit 0'
done
stub "$fake/scripts/capture-start.sh" ': >"$3/observer.ready"'
stub "$fake/scripts/capture-stop.sh" 'echo "$1" >"$2/observer.pcap"'
stub "$fake/scripts/relay-probe.sh" 'echo probe >>"$CALLS"; exit "${PROBE_RC:-0}"'
stub "$tmp/bin/git" 'echo 0000000'
stub "$tmp/bin/ssh" 'echo stub'
stub "$tmp/bin/go" 'case "$3" in
resolve) cat "$RESOLVED_FILE" ;;
remaining) echo A1 ;;
run) echo "run $6" >>"$CALLS" ;;
esac'
cat >"$tmp/resolved.json" <<'JSON'
{"cell": {"segment": {"bridge": "lab-br-t-rly"},
  "docker_host": {"mgmt_address": "10.200.255.110/24", "plugin_tag": "x"},
  "source": {"type": "kea", "mgmt_address": "10.200.255.111/24"},
  "relay": {"mgmt_address": "10.200.255.112/24", "server_segment": {"bridge": "lab-br-t-rsv"}}}}
JSON

run() {
	local case=$1
	shift
	mkdir -p "$tmp/$case"
	: >"$tmp/$case/calls"
	env "$@" PATH="$tmp/bin:$PATH" CALLS="$tmp/$case/calls" RESOLVED_FILE="$tmp/resolved.json" \
		"$fake/scripts/run-cell.sh" t-relay "$tmp/$case/work" "$tmp/$case/evidence" >"$tmp/$case/out" 2>&1
}

if run probe-fails PROBE_RC=1; then
	echo "run-cell-relay-test: FAIL -- run-cell exited 0 after a failed relay probe" >&2
	fail=1
fi
if grep -q '^run ' "$tmp/probe-fails/calls"; then
	echo "run-cell-relay-test: FAIL -- a shape ran after a failed relay probe" >&2
	fail=1
fi
for f in t-relay.pcap t-relay-server.pcap; do
	[ -s "$tmp/probe-fails/evidence/$f" ] || {
		echo "run-cell-relay-test: FAIL -- $f was not kept after a failed probe" >&2
		fail=1
	}
done

run probe-passes PROBE_RC=0 || {
	echo "run-cell-relay-test: FAIL -- run-cell failed with a passing probe" >&2
	cat "$tmp/probe-passes/out" >&2
	fail=1
}
if [ "$(head -1 "$tmp/probe-passes/calls")" != probe ] || [ "$(grep -c '^run ' "$tmp/probe-passes/calls")" -ne 5 ]; then
	echo "run-cell-relay-test: FAIL -- want the probe first, then five shapes" >&2
	cat "$tmp/probe-passes/calls" >&2
	fail=1
fi
if [ "$(cat "$tmp/probe-passes/evidence/t-relay-server.pcap" 2>/dev/null)" != t-relay-srv ]; then
	echo "run-cell-relay-test: FAIL -- the server pcap is not the t-relay-srv observer's" >&2
	fail=1
fi
[ "$fail" -eq 0 ] && echo "run-cell-relay-test: PASS"
exit "$fail"
