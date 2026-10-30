#!/bin/bash
# seed-chr.sh (#9) against a stub guest agent and a stub ssh: a seeded
# CHR is left alone, a stock one gets the mgmt script, the three files and
# one admin import, a run stopped after the admin line is finished, and
# each failure maps to its exit code (1 poll again, 2 stop). No VM.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/seed"
for f in lab-mgmt.rsc lab-baseline.rsc lab-seed.rsc; do echo "# $f" >"$tmp/seed/$f"; done
echo 'ssh-ed25519 AAAAC3NzaSeedTest lab-controller' >"$tmp/seed/lab.pub"

# The agent: STUB_IDENTITY is what guest-exec prints first, STUB_ADMIN
# second (admin disabled, lab users, lab keys), STUB_PING=no
# leaves guest-ping unanswered. Every request lands in $STUB_LOG.
cat >"$tmp/bin/sudo" <<'STUB'
#!/bin/bash
req=${*: -1}
printf '%s\n' "$req" >>"$STUB_LOG"
case "$req" in
*guest-ping*) [ "${STUB_PING:-yes}" = yes ] && echo '{"return":{}}' ;;
*'"guest-exec"'*)
	# STUB_EXEC_FAIL=N: the Nth guest-exec gets no answer (virsh timeout, rc 1);
	# STUB_EXEC_EMPTY=N: it gets an empty reply (the socat path's timeout).
	n=$(grep -c '"guest-exec"' "$STUB_LOG")
	[ "${STUB_EXEC_FAIL:-0}" = "$n" ] && exit 1
	[ "${STUB_EXEC_EMPTY:-0}" = "$n" ] && exit 0
	echo '{"return":{"pid":7}}'
	;;
*guest-exec-status*)
	n=$(grep -c '"guest-exec"' "$STUB_LOG")
	# STUB_STATUS_FAIL=N: the status of the Nth script times out (rc 1);
	# STUB_HANG=N: it never reports exited (lab #130).
	[ "${STUB_STATUS_FAIL:-0}" = "$n" ] && exit 1
	if [ "${STUB_HANG:-0}" = "$n" ]; then
		echo '{"return":{"exited":false}}'
		exit 0
	fi
	case "$n" in 1) o=$STUB_IDENTITY ;; 2) o=${STUB_ADMIN:-false,0,0} ;; *) o='' ;; esac
	printf '{"return":{"exitcode":0,"exited":true,"out-data":"%s"}}\n' "$(printf '%s\r\n' "$o" | base64 -w0)"
	;;
*guest-file-open*) echo '{"return":1000}' ;;
*guest-file-write*)
	b=$(sed 's/.*"buf-b64":"\([^"]*\)".*/\1/' <<<"$req")
	printf '{"return":{"count":%d,"eof":false}}\n' "$(base64 -d <<<"$b" | wc -c)"
	;;
*) echo '{"return":{}}' ;;
esac
STUB
cat >"$tmp/bin/ssh" <<'STUB'
#!/bin/bash
{ printf 'SSH'; printf ' %q' "$@"; echo; } >>"$STUB_LOG"
printf '%s\r\n' "$STUB_IMPORT"
exit "${STUB_SSH_RC:-0}"
STUB
cat >"$tmp/bin/sleep" <<'STUB'
#!/bin/bash
STUB
chmod +x "$tmp"/bin/*

fail=0
bad() {
	echo "seed-chr-test: $*" >&2
	fail=1
}
# run NAME WANT_RC [VAR=value ...]: seed-chr.sh under the stubs.
run() {
	local name=$1 want=$2 rc=0
	shift 2
	: >"$tmp/log"
	env STUB_LOG="$tmp/log" STUB_IDENTITY=CHR STUB_IMPORT='Script file loaded and executed successfully' \
		PATH="$tmp/bin:$PATH" "$@" "$REPO_ROOT/scripts/seed-chr.sh" lab-chr-source "$tmp/seed" 10.200.255.141 "$tmp/kh" >"$tmp/out" 2>&1 || rc=$?
	[ "$rc" = "$want" ] || bad "$name: exit $rc, want $want: $(cat "$tmp/out")"
}

run seeded 0 STUB_IDENTITY=lab-ready
[ "$(grep -c '"guest-exec"' "$tmp/log")" = 1 ] || bad "seeded: ran more than the identity read"
grep -q 'guest-file-open\|^SSH' "$tmp/log" && bad "seeded: wrote files or logged in again"

run stock 0
[ "$(grep -c '"guest-exec"' "$tmp/log")" = 3 ] || bad "stock: the mgmt script did not run once"
grep -q "$(base64 -w0 <"$tmp/seed/lab-mgmt.rsc")" "$tmp/log" || bad "stock: guest-exec did not carry lab-mgmt.rsc"
for f in lab.pub lab-baseline.rsc lab-seed.rsc; do
	grep -qF "\"path\":\"$f\"" "$tmp/log" || bad "stock: $f was not written"
done
login=$(grep '^SSH' "$tmp/log" || true)
[ "$(wc -l <<<"$login")" = 1 ] || bad "stock: not exactly one login: $login"
for want in "UserKnownHostsFile=$tmp/kh" 'PubkeyAuthentication=no' 'admin@10.200.255.141' '/import\ file-name=lab-seed.rsc'; do
	grep -qF -- "$want" <<<"$login" || bad "stock: the login lacks $want: $login"
done

run resume 0 STUB_ADMIN=true,1,1
[ "$(grep -c '"guest-exec"' "$tmp/log")" = 3 ] || bad "resume: not one identity set after the admin read"
grep -q "$(printf '%s\n' '/system identity set name=lab-ready' | base64 -w0)" "$tmp/log" || bad "resume: the identity was not set"
grep -q 'guest-file-open\|^SSH' "$tmp/log" && bad "resume: wrote files or logged in"
run half-seeded 2 STUB_ADMIN=true,0,0
grep -q '^SSH' "$tmp/log" && bad "half-seeded: logged in"
# lab #130: an agent that pings but is slow is a poll again (1), never a
# refusal (2); a mgmt script that did not finish must not run twice (2).
run exec-timeout 1 STUB_EXEC_FAIL=1
grep -q 'timeout\|did not answer guest-exec' "$tmp/out" || bad "exec-timeout: no named reason: $(cat "$tmp/out")"
run exec-empty 1 STUB_EXEC_EMPTY=1
run status-timeout 1 STUB_STATUS_FAIL=1
grep -q 'did not answer guest-exec-status' "$tmp/out" || bad "status-timeout: no named reason: $(cat "$tmp/out")"
run identity-hangs 1 STUB_HANG=1
grep -q 'has not finished' "$tmp/out" || bad "identity-hangs: no named reason: $(cat "$tmp/out")"
run admin-read-hangs 1 STUB_HANG=2
run exec-timeout-late 1 STUB_EXEC_FAIL=2
run mgmt-hangs 2 STUB_HANG=3
grep -q 'TIMEOUT -- lab-mgmt.rsc had not finished' "$tmp/out" || bad "mgmt-hangs: no named timeout: $(cat "$tmp/out")"
grep -q 'REFUSED' "$tmp/out" && bad "mgmt-hangs: a timeout reported as a refusal"
grep -q 'guest-file-open\|^SSH' "$tmp/log" && bad "mgmt-hangs: went on after an unfinished mgmt script"
run no-agent 1 STUB_PING=no
grep -q 'guest-exec' "$tmp/log" && bad "no-agent: went on past the ping"
run no-sshd 1 STUB_SSH_RC=255 STUB_IMPORT='Connection refused'
run denied 2 STUB_IMPORT='not enough permissions (9)'
run parse-error 2 STUB_IMPORT='expected end of command (line 3 column 1)'
run silent 2 STUB_IMPORT=''
run script-error 2 STUB_SSH_RC=1 STUB_IMPORT='failure: already have such user'
rm -f "$tmp/seed/lab.pub"
run no-key 2
grep -q . "$tmp/log" && bad "no-key: talked to the agent without the key"

[ "$fail" -eq 0 ] && echo "seed-chr-test: PASS"
exit "$fail"
