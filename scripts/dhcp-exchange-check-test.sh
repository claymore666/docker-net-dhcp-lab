#!/bin/bash
# Offline cases for dhcp-exchange-check.sh (issue #2),
# against real pcap fixtures (scripts/testdata/, built by
# gen-dhcp-fixtures.py) -- not synthetic decoded text. Case A is the
# positive control: a genuine four-message exchange must pass.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DATA="$REPO_ROOT/scripts/testdata"
# shellcheck source=scripts/dhcp-exchange-check.sh
. "$REPO_ROOT/scripts/dhcp-exchange-check.sh"

MAC=da:b6:45:5b:ef:fe
fail=0

expect_ok() {
	local name=$1 pcap=$2 mac=$3 got
	got=$(dhcp_exchange_reason "$pcap" "$mac")
	if [ -n "$got" ]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: expected a clean pass, got \"$got\"" >&2
		fail=1
	fi
}

expect_fail() {
	local name=$1 pcap=$2 mac=$3 want_substr=$4 got
	got=$(dhcp_exchange_reason "$pcap" "$mac")
	if [ -z "$got" ]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: expected a failure mentioning \"$want_substr\", got a clean pass" >&2
		fail=1
	elif [[ "$got" != *"$want_substr"* ]]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: expected a failure mentioning \"$want_substr\", got \"$got\"" >&2
		fail=1
	fi
}

expect_err() {
	local name=$1 pcap=$2 mac=$3 want_substr=$4 got rc=0
	got=$(dhcp_exchange_reason "$pcap" "$mac") || rc=$?
	if [ "$rc" -eq 0 ]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: expected a non-zero exit, got 0 (\"$got\")" >&2
		fail=1
	elif [[ "$got" != *"$want_substr"* ]]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: expected an error mentioning \"$want_substr\", got \"$got\"" >&2
		fail=1
	elif [[ "$got" == *"no single xid"* ]]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: a missing capture read as a disagreement, not a capture error" >&2
		fail=1
	fi
}

expect_ok "case A (real four-message exchange)" "$DATA/dhcp-good.pcap" "$MAC"
expect_fail "case B (stops after OFFER)" "$DATA/dhcp-stops-after-offer.pcap" "$MAC" "no single xid"
expect_fail "case C (ends in a NAK)" "$DATA/dhcp-ends-in-nak.pcap" "$MAC" "NAK"
expect_fail "case D (exchange belongs to another MAC)" "$DATA/dhcp-wrong-mac.pcap" "$MAC" "no single xid"
# A pcap that has not been written yet (issue #8: the whole-cell capture
# is not on disk while a scenario runs) must read as a capture error,
# never as a disagreement -- the two have different causes and the
# evidence text must not conflate them.
expect_err "case E (pcap does not exist yet)" "$DATA/does-not-exist.pcap" "$MAC" "capture unreadable"

# dhcp_message_log (group C, #23): the per-identity message sequence,
# compared as "type@time" so a wrong identity tie or a lost timestamp
# both show.
expect_log() {
	local name=$1 pcap=$2 ident=$3 want=$4 got
	got=$(dhcp_message_log "$pcap" "$ident" | awk '{printf "%s%s@%s", (NR > 1 ? " " : ""), $2, $1}')
	if [ "$got" != "$want" ]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: got \"$got\", want \"$want\"" >&2
		fail=1
	fi
}

expect_field() {
	local name=$1 pcap=$2 ident=$3 row=$4 col=$5 want=$6 got
	got=$(dhcp_message_log "$pcap" "$ident" | awk -v r="$row" -v c="$col" 'NR == r {print $c}')
	if [ "$got" != "$want" ]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: row $row field $col = \"$got\", want \"$want\"" >&2
		fail=1
	fi
}

CID=00:01:02:03:04:05:06:07:08
expect_log "log F (client id behind a shared MAC, replies tied by xid)" "$DATA/dhcp-c-retransmit.pcap" "$CID" \
	"DISCOVER@100.000000 DISCOVER@104.200000 DISCOVER@112.100000 OFFER@114.300000 REQUEST@114.400000 ACK@114.500000"
expect_log "log G (MAC identity, unanswered unicast renewal)" "$DATA/dhcp-c-unanswered-request.pcap" "DA:B6:45:5B:EF:FE" \
	"DISCOVER@1000.000000 OFFER@1000.200000 REQUEST@1000.300000 ACK@1000.500000 REQUEST@1060.000000 REQUEST@1105.000000 ACK@1105.100000"
expect_field "log G renewal ciaddr" "$DATA/dhcp-c-unanswered-request.pcap" "$MAC" 5 8 10.200.1.100
expect_field "log G renewal dst" "$DATA/dhcp-c-unanswered-request.pcap" "$MAC" 5 11 10.200.1.2
expect_log "log H (two servers, DECLINE, NAK)" "$DATA/dhcp-c-decline-nak.pcap" "$MAC" \
	"DISCOVER@10.000000 OFFER@10.100000 OFFER@10.200000 REQUEST@10.300000 ACK@10.400000 DECLINE@11.500000 REQUEST@12.000000 NAK@12.100000"
expect_field "log H rogue server id" "$DATA/dhcp-c-decline-nak.pcap" "$MAC" 3 6 10.200.1.240
expect_field "log H decline requested address" "$DATA/dhcp-c-decline-nak.pcap" "$MAC" 6 7 10.200.1.100
expect_log "log I (another identity sees nothing)" "$DATA/dhcp-c-retransmit.pcap" "$MAC" ""
expect_log "log J (partial last record dropped)" "$DATA/dhcp-c-partial.pcap" "$MAC" \
	"DISCOVER@0.000000 OFFER@0.000000 REQUEST@0.000000"
expect_log "log L (\"*\" prints every identity)" "$DATA/dhcp-c-retransmit.pcap" "*" \
	"DISCOVER@100.000000 DISCOVER@101.000000 DISCOVER@104.200000 DISCOVER@112.100000 OFFER@114.300000 REQUEST@114.400000 ACK@114.500000"
# A Kea HA pair's T2 rebind (lab #12), captured on a local pair: the
# unicast T1 renewal to the dead primary goes unanswered, the broadcast
# rebind (secs 3) is ACKed by the partner with option 51 = 40 s.
HAMAC=ce:26:ae:11:40:98
HAPCAP="$DATA/dhcp-c5-kea-ha-rebind.pcap"
expect_log "log M (Kea HA rebind to the partner)" "$HAPCAP" "$HAMAC" \
	"DISCOVER@1791571234.398347 OFFER@1791571234.398865 REQUEST@1791571234.474303 ACK@1791571234.475340 REQUEST@1791571254.578337 REQUEST@1791571257.674251 ACK@1791571257.674791 REQUEST@1791571277.802297 ACK@1791571277.803316"
expect_field "log M renewal dst (unicast to the primary)" "$HAPCAP" "$HAMAC" 5 11 10.200.8.2
expect_field "log M rebind secs" "$HAPCAP" "$HAMAC" 6 12 3
expect_field "log M renewal secs" "$HAPCAP" "$HAMAC" 5 12 0
expect_field "log M rebind ACK server id" "$HAPCAP" "$HAMAC" 7 6 10.200.8.3
got=$(dhcp_message_log "$HAPCAP" "$HAMAC" 51 | awk 'NR == 7 {print $13}')
if [ "$got" != 0x00000028 ]; then
	echo "dhcp-exchange-check-test: FAIL -- log M rebind ACK option 51 = \"$got\", want 0x00000028" >&2
	fail=1
fi
rc=0
(dhcp_message_log "$DATA/does-not-exist.pcap" "$MAC" >/dev/null 2>&1) || rc=$?
if [ "$rc" -eq 0 ]; then
	echo "dhcp-exchange-check-test: FAIL -- log K: a missing capture read as an empty log" >&2
	fail=1
fi

# dhcp_option_bytes (group F, #20): option bytes by CODE. tcpdump prints
# 80 as SLP-NA and 77, 108 and type 9 as other names, so every case
# expects bytes, never a printed name.
expect_opts() {
	local name=$1 pcap=$2 ident=$3 codes=$4 want=$5 got
	got=$(dhcp_option_bytes "$pcap" "$ident" "$codes" | awk '{ $1 = ""; printf "%s%s", (NR > 1 ? " | " : ""), substr($0, 2) }')
	if [ "$got" != "$want" ]; then
		echo "dhcp-exchange-check-test: FAIL -- $name: got \"$got\", want \"$want\"" >&2
		fail=1
	fi
}

FMAC=02:f1:00:00:00:01
FOTHER=02:f1:00:00:00:02
UC_HEX=0x096c61622d75632d6631 # RFC 3004: length 9, then "lab-uc-f1"
expect_opts "opts M (77 in DISCOVER and REQUEST only, other client none)" "$DATA/dhcp-f1-userclass.pcap" "$FMAC" 77 \
	"DISCOVER 0f100001 $UC_HEX | OFFER 0f100001 - | REQUEST 0f100001 $UC_HEX | ACK 0f100001 -"
expect_opts "opts N (a client that sends no class)" "$DATA/dhcp-f1-userclass.pcap" "$FOTHER" 77 \
	"DISCOVER 0f100002 - | OFFER 0f100002 -"
expect_opts "opts O (108 in OFFER and ACK, PRL without it)" "$DATA/dhcp-f2-forced108.pcap" "$FMAC" 108,55 \
	"DISCOVER 0f200001 - 0x010306 | OFFER 0f200001 0x00000708 - | REQUEST 0f200001 - 0x010306 | ACK 0f200001 0x00000708 -"
expect_opts "opts P (another identity gets no 108)" "$DATA/dhcp-f2-forced108.pcap" "$FOTHER" 108 \
	"DISCOVER 0f200002 - | OFFER 0f200002 -"
expect_opts "opts Q (108 asked for in the PRL)" "$DATA/dhcp-f2-asked108.pcap" "$FMAC" 55 \
	"DISCOVER 0f200003 0x0103066c | OFFER 0f200003 -"
expect_opts "opts R (80 is present with no data: 0x, not -)" "$DATA/dhcp-f3-rapid-commit.pcap" "$FMAC" 80 \
	"DISCOVER 0f300001 0x | ACK 0f300001 0x"
expect_opts "opts S (fallback: 80 in DISCOVER only, four messages)" "$DATA/dhcp-f3-fallback.pcap" "$FMAC" 80 \
	"DISCOVER 0f300002 0x | OFFER 0f300002 - | REQUEST 0f300002 - | ACK 0f300002 -"
expect_opts "opts T (a plain exchange carries no 80)" "$DATA/dhcp-good.pcap" "$MAC" 80 \
	"DISCOVER 6623f715 - | OFFER 6623f715 - | REQUEST 6623f715 - | ACK 6623f715 -"
got=$(dhcp_message_log "$DATA/dhcp-f-forcerenew.pcap" "$FMAC" | awk '{print $2}')
if [ "$got" != "FORCERENEW" ]; then
	echo "dhcp-exchange-check-test: FAIL -- opts U: message type 9 read as \"$got\", want FORCERENEW" >&2
	fail=1
fi
rc=0
(dhcp_option_bytes "$DATA/dhcp-good.pcap" "$MAC" "" >/dev/null 2>&1) || rc=$?
[ "$rc" -ne 0 ] || { echo "dhcp-exchange-check-test: FAIL -- opts V: an empty code list was accepted" >&2; fail=1; }
rc=0
(dhcp_option_bytes "$DATA/dhcp-good.pcap" "$MAC" "80,x" >/dev/null 2>&1) || rc=$?
[ "$rc" -ne 0 ] || { echo "dhcp-exchange-check-test: FAIL -- opts W: a non-numeric code was accepted" >&2; fail=1; }
rc=0
(dhcp_option_bytes "$DATA/does-not-exist.pcap" "$MAC" 80 >/dev/null 2>&1) || rc=$?
[ "$rc" -ne 0 ] || { echo "dhcp-exchange-check-test: FAIL -- opts X: a missing capture read as no options" >&2; fail=1; }

# dhcp6_message_log (#23 group D), against real captures (v6/*.pcap,
# kea 2.6.3, dhcpd 4.4.3-P1, dnsmasq 2.91, radvd 2.20) and built
# frame sets (v6/synth-*.pcap) for what they do not hold.
V6="$DATA/v6"
DUID6=00:03:00:01:02:00:00:00:23:d1
expect6() {
	local name=$1 pcap=$2 ident=$3 want=$4 got
	got=$(dhcp6_message_log "$pcap" "$ident" | cut -d' ' -f2-)
	if [ "$got" != "$want" ]; then
		printf 'dhcp-exchange-check-test: FAIL -- v6 %s:\n got: %s\nwant: %s\n' "$name" "$got" "$want" >&2
		fail=1
	fi
}
expect6 "kea rapid commit, no IA_TA granted" "$V6/kea-rapid-ta.pcap" fe80::ff:fe00:23d1 "SOLICIT 3375cc $DUID6 - 1 1|-|-|- 2|-|-|- - fe80::ff:fe00:23d1 ff02::1:2
REPLY 3375cc $DUID6 00:01:00:01:32:5b:e6:f1:d6:8c:f2:55:4c:fb 1 1|fd42:200:0:100::100|3600|7200 - - fe80::d48c:f2ff:fe55:4cfb fe80::ff:fe00:23d1
RA fe80::d48c:f2ff:fe55:4cfb 1 0 0 fd42:200:0:100::/64|1|7200|3600 -"
expect6 "isc rapid commit with IA_TA" "$V6/isc-rapid-ta.pcap" "$DUID6" "RA fe80::acd0:bdff:fe25:28a8 1 0 1800 fd42:200:0:200::/64|1|7200|3600 -
SOLICIT 7a75a6 $DUID6 - 1 1|-|-|- 2|-|-|- - fe80::ff:fe00:23d1 ff02::1:2
REPLY 7a75a6 $DUID6 00:01:00:01:32:5b:e7:61:ae:d0:bd:25:28:a8 1 1|fd42:200:0:200::1aa|3600|7200 2|fd42:200:0:200::22f|3600|7200 - fe80::acd0:bdff:fe25:28a8 fe80::ff:fe00:23d1
RA fe80::acd0:bdff:fe25:28a8 1 0 0 fd42:200:0:200::/64|1|7200|3600 -"
expect6 "radvd four messages, Request on a new xid" "$V6/radvd-m1a1.pcap" 02:00:00:00:23:d1 "RA fe80::c03e:49ff:fe99:b0b 1 0 1800 fd42:200:0:100::/64|1|7200|3600 -
RA fe80::c03e:49ff:fe99:b0b 1 0 1800 fd42:200:0:100::/64|1|7200|3600 -
SOLICIT d031a3 $DUID6 - 0 1|-|-|- - - fe80::ff:fe00:23d1 ff02::1:2
ADVERTISE d031a3 $DUID6 00:01:00:01:32:5b:e7:0a:c2:3e:49:99:0b:0b 0 1|fd42:200:0:100::100|3600|7200 - - fe80::c03e:49ff:fe99:b0b fe80::ff:fe00:23d1
REQUEST 878a02 $DUID6 00:01:00:01:32:5b:e7:0a:c2:3e:49:99:0b:0b 0 1|-|-|- - - fe80::ff:fe00:23d1 ff02::1:2
REPLY 878a02 $DUID6 00:01:00:01:32:5b:e7:0a:c2:3e:49:99:0b:0b 0 1|fd42:200:0:100::101|3600|7200 - - fe80::c03e:49ff:fe99:b0b fe80::ff:fe00:23d1
RA fe80::c03e:49ff:fe99:b0b 1 0 0 fd42:200:0:100::/64|1|7200|3600 -"
got=$(dhcp6_message_log "$V6/dnsmasq-slaac-ra.pcap" "$DUID6" | awk '$2 == "RA" {print $6, $7}')
[ "$got" = "1800 fd42:200:0:300::/64|1|7200|7200
1800 fd42:200:0:300::/64|1|7190|7190" ] || { echo "dhcp-exchange-check-test: FAIL -- v6 dnsmasq slaac RA read \"$got\"" >&2; fail=1; }
got=$(dhcp6_message_log "$V6/dnsmasq-ta.pcap" "$DUID6" | awk '$2 == "REPLY" {print $8}')
[ "$got" = "2|fd42:200:0:300::12d|7200|7200" ] || { echo "dhcp-exchange-check-test: FAIL -- v6 dnsmasq IA_TA read \"$got\"" >&2; fail=1; }
SYN="$V6/synth-mixed.pcap"
SDUID6=00:03:00:01:02:00:00:00:06:01
RA6="RA fe80::6:1 1 1 1800 fd42:200:0:900::/64|1|7200|3600,fd42:200:0:901::/64|0|600|300 64:ff9b::/96|600"
A6="SOLICIT 0a0001 00:03:00:01:02:00:00:00:06:02 - 1 1|-|-|- 2|-|-|- 3|-|-|- fe80::6:2 ff02::1:2
REPLY 0a0001 00:03:00:01:02:00:00:00:06:02 $SDUID6 1 1|fd42:200:0:900::1a|3600|7200 2|-|-|- 3|fd42:200:0:9f0::/60|1800|3600 fe80::6:1 fe80::6:2"
B6="SOLICIT 0b0001 00:03:00:01:02:00:00:00:06:ff - 0 7|-|-|- - - fe80::6:3 ff02::1:2
REPLY 0b0001 00:03:00:01:02:00:00:00:06:ff $SDUID6 0 7|fd42:200:0:900::1b|3600|7200 - - fe80::6:1 fe80::6:3"
expect6 "synthetic, link-local ident" "$SYN" fe80::6:2 "$RA6
$A6"
expect6 "synthetic, DUID ident (upper case)" "$SYN" 00:03:00:01:02:00:00:00:06:02 "$RA6
$A6"
expect6 "synthetic, shared MAC matches both" "$SYN" 02:00:00:00:06:02 "$RA6
$B6
$A6"
expect6 "synthetic, ident set" "$SYN" "nomatch,FE80::6:3" "$RA6
$B6"
expect6 "synthetic, star skips hop-by-hop and relay" "$SYN" '*' "$RA6
$B6
$A6
REPLY 0c0001 - $SDUID6 0 - - - fe80::6:1 fe80::6:2"
expect6 "synthetic, Reply without a client DUID matched by xid" "$V6/synth-xid.pcap" fe80::6:2 "INFORMATION-REQUEST 0a0003 00:03:00:01:02:00:00:00:06:02 - 0 - - - fe80::6:2 ff02::1:2
REPLY 0a0003 - $SDUID6 0 - - - fe80::6:1 fe80::6:2"
tr6=$(mktemp)
head -c "$(($(stat -c %s "$V6/radvd-m1a1.pcap") - 20))" "$V6/radvd-m1a1.pcap" >"$tr6"
got=$(dhcp6_message_log "$tr6" '*' | awk '{print $2}' | tr '\n' ' ')
rm -f "$tr6"
[ "$got" = "RA RA SOLICIT ADVERTISE REQUEST REPLY " ] || { echo "dhcp-exchange-check-test: FAIL -- v6 truncated capture read \"$got\"" >&2; fail=1; }
rc=0
(dhcp6_message_log "$DATA/does-not-exist.pcap" '*' >/dev/null 2>&1) || rc=$?
[ "$rc" -ne 0 ] || { echo "dhcp-exchange-check-test: FAIL -- v6 a missing capture read as no messages" >&2; fail=1; }

# dhcp_relay_log (lab #11): the v4 fields plus giaddr flags ethsrc ethdst
# o82, against hand-built frames (gen-dhcp-fixtures.py) and real
# dhcrelay/Kea captures (testdata/relay/real-*.pcap).
expect_rlog() {
	local name=$1 pcap=$2 ident=$3 want=$4 got
	got=$(dhcp_relay_log "$pcap" "$ident" | cut -d' ' -f2-)
	if [ "$got" != "$want" ]; then
		printf 'dhcp-exchange-check-test: FAIL -- relay %s:\n got: %s\nwant: %s\n' "$name" "$got" "$want" >&2
		fail=1
	fi
}
expect_rfield() {
	local name=$1 pcap=$2 ident=$3 row=$4 col=$5 want=$6 got
	got=$(dhcp_relay_log "$pcap" "$ident" | awk -v r="$row" -v c="$col" 'NR == r {print $c}')
	if [ "$got" != "$want" ]; then
		echo "dhcp-exchange-check-test: FAIL -- relay $name: row $row field $col = \"$got\", want \"$want\"" >&2
		fail=1
	fi
}
RMAC=02:11:00:00:00:10
O82=0x0104657468310203726c79 # circuit-id "eth1", remote-id "rly"
expect_rlog "relayed DISCOVER and OFFER (option 82 echoed, giaddr, MACs)" "$DATA/dhcp-relay-server-leg.pcap" "$RMAC" \
	"DISCOVER 5a5a0001 $RMAC - - - - - 10.200.11.1 10.200.11.2 0 10.200.10.1 0x0000 02:11:00:00:00:02 02:11:00:00:00:20 $O82
OFFER 5a5a0001 $RMAC - 10.200.11.2 - - 10.200.10.100 10.200.11.2 10.200.10.1 0 10.200.10.1 0x0000 02:11:00:00:00:20 02:11:00:00:00:02 $O82"
expect_rfield "relayed DISCOVER without -a prints a dash" "$DATA/dhcp-relay-no82.pcap" "$RMAC" 1 17 -
expect_rlog "delivery by broadcast (flag set) and by unicast to chaddr (flag clear)" "$DATA/dhcp-relay-deliver.pcap" "$RMAC" \
	"OFFER 5a5a0001 $RMAC - 10.200.11.2 - - 10.200.10.100 10.200.10.1 255.255.255.255 0 - 0x8000 02:11:00:00:00:01 ff:ff:ff:ff:ff:ff -
OFFER 5a5a0002 $RMAC - 10.200.11.2 - - 10.200.10.100 10.200.10.1 10.200.10.100 0 - 0x0000 02:11:00:00:00:01 $RMAC -"
expect_rlog "T1 renewal then T2 rebind (secs 3, broadcast)" "$DATA/dhcp-relay-rebind.pcap" "$RMAC" \
	"REQUEST 5a5a0003 $RMAC - - - 10.200.10.100 - 10.200.10.100 10.200.11.2 0 - 0x0000 $RMAC 02:11:00:00:00:01 -
REQUEST 5a5a0004 $RMAC - - - 10.200.10.100 - 10.200.10.100 255.255.255.255 3 - 0x0000 $RMAC ff:ff:ff:ff:ff:ff -"
expect_rlog "unicast renewal, its routed copy and the relayed copy; another client's same xid is not ours" "$DATA/dhcp-relay-renewal.pcap" "$RMAC" \
	"REQUEST 5a5a0005 $RMAC - - - 10.200.10.100 - 10.200.10.100 10.200.11.2 0 - 0x0000 $RMAC 02:11:00:00:00:01 -
REQUEST 5a5a0005 $RMAC - - - 10.200.10.100 - 10.200.10.100 10.200.11.2 0 - 0x0000 02:11:00:00:00:02 02:11:00:00:00:20 -
REQUEST 5a5a0005 $RMAC - - - 10.200.10.100 - 10.200.11.1 10.200.11.2 0 10.200.10.1 0x0000 02:11:00:00:00:02 02:11:00:00:00:20 $O82"
expect_rlog "an identity that is not in the capture" "$DATA/dhcp-relay-renewal.pcap" 02:11:00:00:00:99 ""
expect_rfield "client-id ident" "$DATA/relay/real-bs-kea-b.pcap" 01:02:11:00:00:00:10 1 3 bc26c51c
# Real captures: a relayed exchange with the broadcast flag set, one with
# it clear, and the unicast renewal that dhcrelay also relays a copy of.
RD=$DATA/relay
expect_rfield "real server leg, giaddr" "$RD/real-bs-kea-b.pcap" "$RMAC" 1 13 10.200.10.1
expect_rfield "real server leg, flag set" "$RD/real-bs-kea-b.pcap" "$RMAC" 1 14 0x8000
expect_rfield "real server leg, option 82 circuit-id eth1" "$RD/real-bs-kea-b.pcap" "$RMAC" 1 17 0x010465746831
expect_rfield "real server leg, OFFER echoes option 82" "$RD/real-bs-kea-b.pcap" "$RMAC" 2 17 0x010465746831
expect_rfield "real client leg, flag set, delivered by broadcast" "$RD/real-bc-kea-b.pcap" "$RMAC" 2 16 ff:ff:ff:ff:ff:ff
expect_rfield "real client leg, flag set" "$RD/real-bc-kea-b.pcap" "$RMAC" 2 14 0x8000
expect_rfield "real client leg, flag clear" "$RD/real-bc-kea-nob.pcap" "$RMAC" 2 14 0x0000
expect_rfield "real client leg, flag clear, delivered unicast to chaddr" "$RD/real-bc-kea-nob.pcap" "$RMAC" 2 16 "$RMAC"
expect_rfield "real client leg, OFFER from the relay MAC" "$RD/real-bc-kea-nob.pcap" "$RMAC" 2 15 02:11:00:00:00:01
expect_rfield "real client leg, no option 82 after the relay" "$RD/real-bc-kea-nob.pcap" "$RMAC" 2 17 -
expect_rfield "real renewal, ciaddr" "$RD/real-bc-kea-renew.pcap" "$RMAC" 5 8 10.200.10.100
expect_rfield "real renewal, eth dst is the relay client leg" "$RD/real-bc-kea-renew.pcap" "$RMAC" 5 16 02:11:00:00:00:01
expect_rfield "real renewal, routed copy giaddr 0" "$RD/real-bs-kea-renew.pcap" "$RMAC" 5 13 -
expect_rfield "real renewal, relayed copy giaddr set" "$RD/real-bs-kea-renew.pcap" "$RMAC" 6 13 10.200.10.1
expect_rfield "real renewal, relayed copy carries option 82" "$RD/real-bs-kea-renew.pcap" "$RMAC" 6 17 0x010465746831
rc=0
(dhcp_relay_log "$DATA/does-not-exist.pcap" "$RMAC" >/dev/null 2>&1) || rc=$?
[ "$rc" -ne 0 ] || { echo "dhcp-exchange-check-test: FAIL -- relay: a missing capture read as an empty log" >&2; fail=1; }

# Group D part 2 captures (#23): wire M/A per RA, PIO order as sent
# (dnsmasq lists the second prefix first), PREF64, a zero-lifetime PIO
# and IA_PD Replies from Kea pd-pools and ISC prefix6.
ra6() { dhcp6_message_log "$1" '*' | awk '$2 == "RA" && $6 != 0 {print $4, $5, $7, $8; exit}'; }
check6() {
	[ "$2" = "$3" ] || { printf 'dhcp-exchange-check-test: FAIL -- v6 %s:\n got: %s\nwant: %s\n' "$1" "$2" "$3" >&2; fail=1; }
}
check6 "radvd M=1 A=0" "$(ra6 "$V6/radvd-m1a0.pcap")" "1 0 fd42:200:0:100::/64|0|7200|3600 -"
check6 "radvd two PIOs and PREF64" "$(ra6 "$V6/radvd-two-pio-pref64.pcap")" "1 0 fd42:200:0:100::/64|1|7200|3600,fd42:200:0:101::/64|1|7200|3600 fd42:200:0:164::/96|1800"
check6 "radvd second PIO expired" "$(ra6 "$V6/radvd-second-expired.pcap")" "1 0 fd42:200:0:100::/64|1|7200|3600,fd42:200:0:101::/64|1|0|0 -"
check6 "dnsmasq two PIOs, second first" "$(ra6 "$V6/dnsmasq-two-pio.pcap")" "1 1 fd42:200:0:101::/64|1|7200|7200,fd42:200:0:100::/64|1|7200|7200 -"
got=$(dhcp6_message_log "$V6/dnsmasq-pio-order-flips.pcap" '*' | awk '$2 == "RA" {split($7, p, "|"); print $4, $5, p[1]}' | tr '\n' ' ')
check6 "dnsmasq M=0 PIO order flips between RAs" "$got" "0 0 fd42:200:0:101::/64 0 0 fd42:200:0:100::/64 "
PD6=00:03:00:01:02:00:00:00:23:d2
check6 "kea IA_PD Reply" "$(dhcp6_message_log "$V6/kea-pd.pcap" "$PD6" | awk '$2 == "REPLY" {print $7, $9}')" "1|fd42:200:0:100::101|3600|7200 3|fd42:200:0:181::/64|3600|7200,3|fd42:200:0:181::/64|3600|7200"
check6 "isc IA_PD Reply" "$(dhcp6_message_log "$V6/isc-pd.pcap" "$PD6" | awk '$2 == "REPLY" {print $7, $9}')" "1|fd42:200:0:100::1c5|3600|7200 3|fd42:200:0:1ff::/64|3600|7200,3|fd42:200:0:1ff::/64|3600|7200"

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "dhcp-exchange-check-test: PASS"
