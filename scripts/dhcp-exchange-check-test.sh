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

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "dhcp-exchange-check-test: PASS"
