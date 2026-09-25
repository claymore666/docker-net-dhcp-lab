#!/bin/bash
# Shared library, sourced never executed (issue #2): was
# demo-source-cell.sh's own inline loop, which matched all four message
# names anywhere in the whole decode, including the BOOTP header's own
# "Request from <mac>" text, with no tie to one xid or one MAC, and
# "ACK" substring-matching "NACK" too. dhcp_exchange_reason prints
# nothing (and the caller sees "") when one xid ties Discover, Offer,
# Request and ACK -- identified only by the DHCP-Message (53) option
# line -- to the given MAC; otherwise it prints why.
dhcp_exchange_reason() {
	local pcap=$1 mac=$2
	tcpdump -n -v -r "$pcap" 'udp port 67 or udp port 68' 2>/dev/null | awk -v want="$mac" '
	BEGIN { IGNORECASE = 1 }
	/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/ { xid = ""; cmac = "" }
	/xid 0x/ {
		match($0, /xid 0x[0-9a-fA-F]+/)
		xid = substr($0, RSTART + 4, RLENGTH - 4)
	}
	/Client-Ethernet-Address/ {
		cmac = $2
		sub(/,$/, "", cmac)
	}
	/DHCP-Message \(53\), length 1:/ {
		if (xid == "" || tolower(cmac) != tolower(want)) next
		line = $0
		sub(/.*DHCP-Message \(53\), length 1: */, "", line)
		gsub(/^[ \t]+|[ \t]+$/, "", line)
		if (line == "NACK") { nak_xid = xid; next }
		have[xid, line] = 1
		xids[xid] = 1
	}
	END {
		if (nak_xid != "") {
			print "source sent a NAK to " want " (xid " nak_xid ")"
			exit
		}
		for (x in xids) {
			if ((x, "Discover") in have && (x, "Offer") in have && \
			    (x, "Request") in have && (x, "ACK") in have) {
				exit
			}
		}
		print "no single xid ties Discover+Offer+Request+ACK to " want
	}
	'
}
