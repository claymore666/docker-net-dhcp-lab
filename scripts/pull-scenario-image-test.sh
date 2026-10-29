#!/bin/bash
# pull-scenario-image.sh and its place in up-cell.sh (lab #93): the pull
# retries a bounded number of times and fails loudly, the tag is the one
# internal/scenario runs, and up-cell.sh calls it unconditionally after the
# Docker host is up and before any relay or source. ssh and sleep are stubs;
# network-free.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
bad() {
	echo "pull-scenario-image-test: $*" >&2
	fail=1
}

mkdir -p "$tmp/bin"
cat >"$tmp/bin/ssh" <<'STUB'
#!/bin/bash
echo "$*" >>"$SSH_LOG"
n=$(wc -l <"$SSH_LOG")
[ "$n" -gt "${SSH_FAIL_FIRST:-0}" ]
STUB
cat >"$tmp/bin/sleep" <<'STUB'
#!/bin/bash
echo "$*" >>"$SLEEP_LOG"
STUB
chmod +x "$tmp/bin/ssh" "$tmp/bin/sleep"

# run FAIL_FIRST: the script against the stubs; rc, SSH_LOG and err are
# left for the case.
run() {
	: >"$tmp/ssh.log"
	: >"$tmp/sleep.log"
	set +e
	SSH_FAIL_FIRST=$1 SSH_LOG="$tmp/ssh.log" SLEEP_LOG="$tmp/sleep.log" LAB_PULL_ATTEMPTS=3 PATH="$tmp/bin:$PATH" \
		./scripts/pull-scenario-image.sh 10.200.0.7 "$tmp/known_hosts" >"$tmp/out" 2>"$tmp/err"
	rc=$?
	set -e
}

image=$(sed -n 's/^SCENARIO_IMAGE=//p' scripts/pull-scenario-image.sh)

run 0
[ "$rc" -eq 0 ] || bad "a pull that works exited $rc"
[ "$(wc -l <"$tmp/ssh.log")" -eq 1 ] || bad "a pull that works made $(wc -l <"$tmp/ssh.log") remote calls"
grep -q "lab@10.200.0.7 sudo docker pull -q $image" "$tmp/ssh.log" || bad "the remote did not run 'sudo docker pull $image' on the host: $(cat "$tmp/ssh.log")"
grep -q "UserKnownHostsFile=$tmp/known_hosts" "$tmp/ssh.log" || bad "the per-cell known_hosts was not used"

run 2
{ [ "$rc" -eq 0 ] && [ "$(wc -l <"$tmp/ssh.log")" -eq 3 ]; } || bad "two failures then a pull: exit $rc, $(wc -l <"$tmp/ssh.log") calls, want exit 0 after 3"

run 99
[ "$rc" -ne 0 ] || bad "a pull that never works exited 0"
[ "$(wc -l <"$tmp/ssh.log")" -eq 3 ] || bad "the retry is not bounded by LAB_PULL_ATTEMPTS: $(wc -l <"$tmp/ssh.log") calls"
grep -q 'could not be pulled' "$tmp/err" || bad "a failed pull did not say so on stderr"

# The tag the scenarios run, from the non-test code, is the tag pulled.
code=$(for f in internal/scenario/*.go; do case $f in *_test.go) ;; *) grep -hoE 'alpine:[0-9][0-9a-z.-]*' "$f" ;; esac; done | sort -u)
[ -n "$code" ] || bad "no alpine tag found in internal/scenario: the drift check sees nothing"
[ "$code" = "$image" ] || bad "internal/scenario runs [$code] but the pull script fetches $image"

# up-cell.sh: an unconditional top-level call, after the wait for the
# Docker host and before the relay and source bring-up.
# shellcheck disable=SC2016  # the patterns match up-cell.sh's literal text
call=$(grep -nE '^"\$REPO_ROOT/scripts/pull-scenario-image\.sh" "\$mgmt_ip" "\$known_hosts"$' scripts/up-cell.sh | cut -d: -f1 || true)
# shellcheck disable=SC2016
wait_end=$(grep -nF '[ "$ok" -eq 1 ]' scripts/up-cell.sh | head -1 | cut -d: -f1 || true)
relay=$(grep -nF 'scripts/up-relay.sh' scripts/up-cell.sh | head -1 | cut -d: -f1 || true)
source=$(grep -nF 'scripts/up-source.sh' scripts/up-cell.sh | head -1 | cut -d: -f1 || true)
if [ -z "$call" ] || [ "$(wc -w <<<"$call")" -ne 1 ]; then
	bad "up-cell.sh has no single top-level call to pull-scenario-image.sh"
elif [ -z "$wait_end" ] || [ "$call" -le "$wait_end" ] || [ "$call" -ge "$relay" ] || [ "$call" -ge "$source" ]; then
	bad "the pull (line $call) is not between the Docker host wait (line ${wait_end:-?}) and the relay/source (lines ${relay:-?}/${source:-?})"
fi

[ "$fail" -eq 0 ]
echo "pull-scenario-image-test: PASS"
