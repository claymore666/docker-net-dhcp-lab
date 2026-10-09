#!/bin/bash
# relay-probe.sh (#11): the ACK match against a client pcap measured in a
# netns (Kea behind dhcrelay, relay leg 02:11:00:00:00:01, client
# 02:11:00:00:00:10), and the probe's refusals with stubbed ssh/sudo.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/relay-probe.sh
. "$REPO_ROOT/scripts/relay-probe.sh"
FIX="$REPO_ROOT/scripts/testdata/relay-probe-client.tcpdump.txt"
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

C=02:11:00:00:00:10
ack_from 02:11:00:00:00:01 "$C" <"$FIX" || { echo "relay-probe-test: FAIL -- the relay's ACK was not found" >&2; fail=1; }
if ack_from 02:11:00:00:00:10 "$C" <"$FIX"; then
	echo "relay-probe-test: FAIL -- an ACK was credited to the client's own MAC" >&2
	fail=1
fi
if grep -v 'length 1: ACK$' "$FIX" | ack_from 02:11:00:00:00:01 "$C"; then
	echo "relay-probe-test: FAIL -- an OFFER alone passed as an ACK" >&2
	fail=1
fi
if ack_from 02:11:00:00:00:01 02:11:00:00:00:77 <"$FIX"; then
	echo "relay-probe-test: FAIL -- an ACK to another client passed" >&2
	fail=1
fi
if grep -v 'Gateway-IP' "$FIX" | ack_from 02:11:00:00:00:01 "$C"; then
	echo "relay-probe-test: FAIL -- a routed ACK (giaddr 0) passed as the relay's delivery" >&2
	fail=1
fi
if sed 's/Gateway-IP 10.200.10.1/Gateway-IP 0.0.0.0/' "$FIX" | ack_from 02:11:00:00:00:01 "$C"; then
	echo "relay-probe-test: FAIL -- an ACK with giaddr 0.0.0.0 passed" >&2
	fail=1
fi

# Stubs: ssh answers by target, sudo runs the observer read from $FRAMES.
cat >"$tmp/ssh" <<'STUB'
#!/bin/bash
cmd=${*: -1}
case "$cmd" in
*/sys/class/net/eth1/address*)
	case "$*" in
	*lab@10.200.255.112*) echo "${RELAY_MAC-02:11:00:00:00:01}" ;;
	*) echo "${CLIENT_MAC-02:11:00:00:00:10}" ;;
	esac
	;;
*udhcpc*) exit "${UDHCPC_RC:-0}" ;;
esac
STUB
cat >"$tmp/sudo" <<'STUB'
#!/bin/bash
cat "$FRAMES"
STUB
chmod +x "$tmp/ssh" "$tmp/sudo"
run() { PATH="$tmp:$PATH" FRAMES="${FRAMES:-$FIX}" "$REPO_ROOT/scripts/relay-probe.sh" c 10.200.255.110 10.200.255.112 "$tmp" >/dev/null 2>&1; }
run || { echo "relay-probe-test: FAIL -- a healthy relay failed the probe" >&2; fail=1; }
if UDHCPC_RC=1 run; then
	echo "relay-probe-test: FAIL -- a probe without a lease passed" >&2
	fail=1
fi
if RELAY_MAC=02:11:00:00:00:99 run; then
	echo "relay-probe-test: FAIL -- an ACK from another MAC passed" >&2
	fail=1
fi
if RELAY_MAC="" run; then
	echo "relay-probe-test: FAIL -- an unreadable relay MAC passed" >&2
	fail=1
fi
if CLIENT_MAC=02:11:00:00:00:66 run; then
	echo "relay-probe-test: FAIL -- an ACK to another client's MAC passed" >&2
	fail=1
fi
if out=$(CLIENT_MAC="" PATH="$tmp:$PATH" FRAMES="$FIX" "$REPO_ROOT/scripts/relay-probe.sh" c 10.200.255.110 10.200.255.112 "$tmp" 2>&1) ||
	[[ $out != *"Docker host segment NIC MAC unreadable"* ]]; then
	echo "relay-probe-test: FAIL -- an unreadable Docker host MAC was not refused as one: $out" >&2
	fail=1
fi
[ "$fail" -eq 0 ] && echo "relay-probe-test: PASS"
exit "$fail"
