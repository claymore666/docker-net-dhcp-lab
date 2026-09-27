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
	local pcap=$1 mac=$2 out rc outfile
	outfile=$(mktemp)
	# The pipe runs as a bare statement, never inside $(...) (issue #8):
	# a command substitution runs in its own subshell, so PIPESTATUS read
	# back in the caller reflects that subshell's last-run command, not
	# tcpdump. set +e/-e brackets it instead of `|| true`, because `||
	# true` is itself a second pipeline once the first one has already
	# failed under pipefail, and running it clobbers PIPESTATUS before
	# this function can read it.
	set +e
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
	' >"$outfile"
	rc=${PIPESTATUS[0]}
	set -e
	out=$(cat "$outfile")
	rm -f "$outfile"
	if [ "$rc" -ne 0 ]; then
		echo "capture unreadable: tcpdump exited $rc reading $pcap"
		return 1
	fi
	echo "$out"
}

# dhcp_exchange_mac_seen prints 1 if any packet in the capture carries
# the given mac as its Client-Ethernet-Address, 0 otherwise (issue #8):
# dhcp_exchange_reason's "no single xid ties ..." text covers both a
# mac that appears but never completes the four messages and a mac
# that never appears at all -- a resumed run's capture only covers the
# shapes being re-run, so a deferred check's mac from an earlier run
# can fall in the second case. The caller must have already confirmed
# the capture itself is readable (dhcp_exchange_reason's own rc).
dhcp_exchange_mac_seen() {
	local pcap=$1 mac=$2 outfile
	outfile=$(mktemp)
	set +e
	tcpdump -n -v -r "$pcap" 'udp port 67 or udp port 68' 2>/dev/null | awk -v want="$mac" '
	/Client-Ethernet-Address/ {
		cmac = $2
		sub(/,$/, "", cmac)
		if (tolower(cmac) == tolower(want)) { print 1; exit }
	}
	' >"$outfile"
	set -e
	if [ -s "$outfile" ]; then
		echo 1
	else
		echo 0
	fi
	rm -f "$outfile"
}
