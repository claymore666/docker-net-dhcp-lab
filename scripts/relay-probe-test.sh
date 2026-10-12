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

# Stubs: ssh answers by target, sudo runs the observer read from $FRAMES,
# or from $SRV_FRAMES for the server segment's observer.
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
case "$*" in
*" lab-observer-c-srv "*) cat "$SRV_FRAMES" ;;
*) cat "$FRAMES" ;;
esac
STUB
chmod +x "$tmp/ssh" "$tmp/sudo"
RUN_C="$REPO_ROOT/scripts/testdata/relay-probe-run-client.tcpdump.txt"
RUN_S="$REPO_ROOT/scripts/testdata/relay-probe-run-server.tcpdump.txt"
run() { PATH="$tmp:$PATH" FRAMES="${FRAMES:-$FIX}" SRV_FRAMES="${SRV_FRAMES:-$RUN_S}" "$REPO_ROOT/scripts/relay-probe.sh" c 10.200.255.110 10.200.255.112 "$tmp" >/dev/null 2>&1; }
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
# The v0.2.0 host run's kea-relay cell (#76), as the observer's own
# tcpdump (alpine 3.20, 4.99.4) prints its two captures. Client frames
# start at lines 7 (Discover), 19 (Offer), 32 (Request), 46 (ACK); server
# frames at 15, 30, 45 (Request), 62 (ACK).
cut_to() { sed -n "1,$2p" "$1" >"$tmp/$3"; }
probe() {
	env RELAY_MAC=52:54:00:5f:7b:2c CLIENT_MAC=52:54:00:6f:e3:c7 "$@" PATH="$tmp:$PATH" \
		"$REPO_ROOT/scripts/relay-probe.sh" c 10.200.255.110 10.200.255.112 "$tmp" 2>&1
}
if ! out=$(probe FRAMES="$RUN_C" SRV_FRAMES="$RUN_S") || [[ $out != *"ACK from 52:54:00:5f:7b:2c on the client segment"* ]]; then
	echo "relay-probe-test: FAIL -- the host run's own captures fail the probe: $out" >&2
	fail=1
fi
cut_to "$RUN_C" 6 c-none
cut_to "$RUN_C" 31 c-offer
cut_to "$RUN_C" 45 c-noack
cut_to "$RUN_S" 44 s-noreq
cut_to "$RUN_S" 61 s-noack
# want <case> <client> <server> <text>: the probe fails and says <text>.
want() {
	if out=$(probe FRAMES="$tmp/$2" SRV_FRAMES="$3") || [[ $out != *"$4"* ]]; then
		echo "relay-probe-test: FAIL -- $1: want \"$4\", got: $out" >&2
		fail=1
	fi
}
# miss <case> <client> <server> <lacks>: a lease with no ACK in the client
# file is the capture's miss, never a hop, and <lacks> ends the line (#76).
miss() {
	want "$1" "$2" "$3" "lost in the capture, not at a hop: udhcpc got a lease, so the ACK reached 52:54:00:6f:e3:c7, but the client observer holds none; client observer lacks: $4"
	if [[ $out == *"at hop "* || $out != *"$4" ]]; then
		echo "relay-probe-test: FAIL -- $1: a capture miss named a hop or ran on: $out" >&2
		fail=1
	fi
}
miss "read before the observer wrote the exchange" c-none "$RUN_S" "DHCPREQUEST from 52:54:00:6f:e3:c7, DHCPACK; server observer lacks: nothing"
miss "read after the Offer only" c-offer "$RUN_S" "DHCPREQUEST from 52:54:00:6f:e3:c7, DHCPACK; server observer lacks: nothing"
miss "read between the Request and the ACK" c-noack "$RUN_S" "DHCPACK; server observer lacks: nothing"
miss "server file ends before the relayed Request" c-noack "$tmp/s-noreq" "DHCPACK; server observer lacks: relayed DHCPREQUEST, DHCPACK to giaddr"
miss "server file ends before the ACK" c-noack "$tmp/s-noack" "DHCPACK; server observer lacks: DHCPACK to giaddr"
# Each qualifier: the Request on the client segment is the Docker host
# NIC's own, and both server-segment messages carry a giaddr.
sed '32s/^\([0-9:.]*\) 52:54:00:6f:e3:c7 /\1 02:11:00:00:00:42 /' "$tmp/c-noack" >"$tmp/c-foreign-req"
miss "Request from another NIC" c-foreign-req "$RUN_S" "DHCPREQUEST from 52:54:00:6f:e3:c7, DHCPACK; server observer lacks: nothing"
sed '45,61{/Gateway-IP/d;}' "$RUN_S" >"$tmp/s-routed-req"
miss "unrelayed Request on the server segment" c-noack "$tmp/s-routed-req" "DHCPACK; server observer lacks: relayed DHCPREQUEST"
sed '62,${/Gateway-IP/d;}' "$RUN_S" >"$tmp/s-routed-ack"
miss "server ACK without giaddr" c-noack "$tmp/s-routed-ack" "DHCPACK; server observer lacks: DHCPACK to giaddr"
# An ACK that reached the client off the relay is the one hop fault the
# client file can prove.
sed '46,${/Gateway-IP/d;}' "$RUN_C" >"$tmp/c-routed-ack"
want "client ACK without giaddr" c-routed-ack "$RUN_S" "lost at hop 4 (relay to Docker host NIC): the client observer holds no DHCPACK from 52:54:00:5f:7b:2c with giaddr set; its ACKs for 52:54:00:6f:e3:c7: 52:54:00:5f:7b:2c giaddr 0.0.0.0"
if out=$(probe FRAMES="$RUN_C" SRV_FRAMES="$RUN_S" RELAY_MAC=02:11:00:00:00:99) ||
	[[ $out != *"lost at hop 4 "*"its ACKs for 52:54:00:6f:e3:c7: 52:54:00:5f:7b:2c giaddr 10.200.10.1" ]]; then
	echo "relay-probe-test: FAIL -- an ACK from another MAC is not named at hop 4: $out" >&2
	fail=1
fi
[ "$fail" -eq 0 ] && echo "relay-probe-test: PASS"
exit "$fail"
