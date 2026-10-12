#!/bin/bash
# Seed a MikroTik CHR source VM (lab #9). guest-exec scripts run with a
# policy that may write config but not users or keys (M3), so the guest
# agent runs lab-mgmt.rsc (vendor export, mgmt address) and pushes lab.pub,
# lab-baseline.rsc and lab-seed.rsc with guest-file-write; the stock admin
# (blank password, once) then imports lab-seed.rsc over the mgmt address,
# and that script disables admin. up-source.sh's ready_qga calls this until
# the identity reads lab-ready. Exit 0: seeded; exit 1: not there yet,
# poll again; exit 2: refused, stop.
set -euo pipefail

usage='usage: seed-chr.sh <domain> <seed-dir> <mgmt-ip> <known-hosts>'
DOMAIN=${1:?$usage}
SEED_DIR=${2:?$usage}
MGMT_IP=${3:?$usage}
KNOWN_HOSTS=${4:?$usage}
for f in lab.pub lab-mgmt.rsc lab-baseline.rsc lab-seed.rsc; do
	[ -s "$SEED_DIR/$f" ] || {
		echo "seed-chr: REFUSED -- $SEED_DIR/$f is missing or empty" >&2
		exit 2
	}
done

# libvirt holds the agent channel's one connection, so on the lab host
# every request goes through virsh. QGA_SOCKET names a bare qemu chardev
# socket instead (a local qemu run): guest-sync with a fresh id first, as
# replies to earlier requests can still sit in that channel (M3, lab #9).
qga() {
	if [ -z "${QGA_SOCKET:-}" ]; then
		sudo -n virsh qemu-agent-command "$DOMAIN" --timeout 30 "$1"
		return
	fi
	local id=$((RANDOM * 32768 + RANDOM))
	{
		printf '{"execute":"guest-sync","arguments":{"id":%d}}\n' "$id"
		sleep 1
		printf '%s\n' "$1"
		sleep 2
	} | timeout 30 socat - UNIX-CONNECT:"$QGA_SOCKET" |
		awk -v id="$id" 'f { print; exit } $0 == "{\"return\":" id "}" { f = 1 }'
}

# field NAME JSON: one scalar member of a one-line agent reply.
field() { sed -n "s/.*\"$1\":\"\{0,1\}\([^\",}]*\).*/\1/p" <<<"$2"; }

# ros SCRIPT: run RouterOS script text through guest-exec; sets out and
# code (-1 on a script error, M3).
ros() {
	local r pid s=''
	r=$(qga "{\"execute\":\"guest-exec\",\"arguments\":{\"input-data\":\"$(printf '%s\n' "$1" | base64 -w0)\",\"capture-output\":true}}")
	pid=$(field pid "$r")
	[ -n "$pid" ] || {
		echo "seed-chr: REFUSED -- guest-exec answered: $r" >&2
		exit 2
	}
	for _ in $(seq 1 30); do
		s=$(qga "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":$pid}}")
		[ "$(field exited "$s")" = true ] && break
		sleep 1
	done
	out=$(field out-data "$s" | base64 -d 2>/dev/null | tr -d '\r' || true)
	code=$(field exitcode "$s")
}

if ! qga '{"execute":"guest-ping"}' 2>/dev/null | grep -q '"return"'; then
	echo "seed-chr: the guest agent of $DOMAIN does not answer yet" >&2
	exit 1
fi

ros ':put [/system identity get name]'
[ "$code" = 0 ] || {
	echo "seed-chr: REFUSED -- the identity read exited ${code:-without an exit code}: $out" >&2
	exit 2
}
if [ "$out" = lab-ready ]; then
	echo "seed-chr: $DOMAIN is seeded"
	exit 0
fi

# A run killed between lab-seed.rsc's admin line and its identity line
# leaves admin disabled, so no login can finish it. lab and its key show
# the lines before ran; guest-exec may set the identity (M3, lab #9).
ros ':put ([/user get admin disabled] . "," . [:len [/user find name=lab]] . "," . [:len [/user ssh-keys find user=lab]])'
case "$code:$out" in
0:false,*) ;;
0:true,1,1)
	ros '/system identity set name=lab-ready'
	[ "$code" = 0 ] || {
		echo "seed-chr: REFUSED -- the identity set exited ${code:-without an exit code}: $out" >&2
		exit 2
	}
	echo "seed-chr: $DOMAIN seeded (resumed after admin was disabled)"
	exit 0
	;;
*)
	echo "seed-chr: REFUSED -- admin is disabled but the seed is not complete, or the read failed (exit ${code:-none}): $out" >&2
	exit 2
	;;
esac

ros "$(cat "$SEED_DIR/lab-mgmt.rsc")"
[ "$code" = 0 ] || {
	echo "seed-chr: REFUSED -- lab-mgmt.rsc exited ${code:-without an exit code}: $out" >&2
	exit 2
}

for f in lab.pub lab-baseline.rsc lab-seed.rsc; do
	r=$(qga "{\"execute\":\"guest-file-open\",\"arguments\":{\"path\":\"$f\",\"mode\":\"w\"}}")
	handle=$(field return "$r")
	case "$handle" in '' | *[!0-9]*)
		echo "seed-chr: REFUSED -- guest-file-open $f answered: $r" >&2
		exit 2
		;;
	esac
	r=$(qga "{\"execute\":\"guest-file-write\",\"arguments\":{\"handle\":$handle,\"buf-b64\":\"$(base64 -w0 <"$SEED_DIR/$f")\"}}")
	qga "{\"execute\":\"guest-file-close\",\"arguments\":{\"handle\":$handle}}" >/dev/null
	if [ "$(field count "$r")" != "$(stat -c %s "$SEED_DIR/$f")" ]; then
		echo "seed-chr: REFUSED -- guest-file-write $f answered: $r" >&2
		exit 2
	fi
done

# SSH_ASKPASS=/bin/true answers the password prompt with the stock blank
# password; a parse error still exits 0 (M3), so the import's own success
# line is what counts. 255 is the login itself: sshd not up yet (admin
# disabled by an earlier run is ruled out above).
rc=0
out=$(SSH_ASKPASS=/bin/true SSH_ASKPASS_REQUIRE=force ssh -p "${SEED_SSH_PORT:-22}" -o UserKnownHostsFile="$KNOWN_HOSTS" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -o ControlMaster=no -o ControlPath=none -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive "admin@$MGMT_IP" '/import file-name=lab-seed.rsc' </dev/null 2>&1) || rc=$?
out=$(tr -d '\r' <<<"$out")
if [ "$rc" = 255 ]; then
	echo "seed-chr: the admin login to $DOMAIN failed: $out" >&2
	exit 1
fi
if [ "$rc" != 0 ] || ! grep -q 'executed successfully' <<<"$out" || grep -qiE 'error|failure|bad command|expected|missing value|not enough permissions' <<<"$out"; then
	echo "seed-chr: REFUSED -- lab-seed.rsc answered (exit $rc): $out" >&2
	exit 2
fi
echo "seed-chr: $DOMAIN seeded"
