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

expect_ok "case A (real four-message exchange)" "$DATA/dhcp-good.pcap" "$MAC"
expect_fail "case B (stops after OFFER)" "$DATA/dhcp-stops-after-offer.pcap" "$MAC" "no single xid"
expect_fail "case C (ends in a NAK)" "$DATA/dhcp-ends-in-nak.pcap" "$MAC" "NAK"
expect_fail "case D (exchange belongs to another MAC)" "$DATA/dhcp-wrong-mac.pcap" "$MAC" "no single xid"

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "dhcp-exchange-check-test: PASS"
