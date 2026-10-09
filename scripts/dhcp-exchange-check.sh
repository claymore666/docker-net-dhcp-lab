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

# dhcp_message_log prints one line per DHCP message for one identity
# (group C, #23): "ts type xid chaddr cid server req ciaddr yiaddr src
# dst", "-" for an empty field, ts in epoch seconds from the capture.
# A client message matches on chaddr or option 61 (ipvlan shares the
# parent MAC); a server reply matches on chaddr, option 61, or the xid
# of a matched client message, since a reply need not echo option 61.
# "*" prints every message (C10 waits on a sender not yet known).
# The decode reads tcpdump's hex, not its text, and uses no gawk-only
# builtin: Debian's default awk is mawk. A capture copied while tcpdump
# was writing may end in a partial record; that one record is dropped.
# A third argument, a comma list of option codes, appends one field per
# code to every line: "0x<hex of the option's data>" ("0x" alone for a
# zero-length option such as 80), "-" when the message lacks it.
dhcp_message_log() {
	local pcap=$1 want errfile outfile rc codes=${3:-}
	want=$(printf '%s' "$2" | tr 'A-F' 'a-f')
	errfile=$(mktemp)
	outfile=$(mktemp)
	set +e
	tcpdump -n -tt -x -r "$pcap" 'udp port 67 or udp port 68' 2>"$errfile" | awk -v want="$want" -v codes="$codes" '
	function hv(c) { return index("0123456789abcdef", c) - 1 }
	function b(i) { return hv(substr(h, 2 * i + 1, 1)) * 16 + hv(substr(h, 2 * i + 2, 1)) }
	function hx(i, n,   s, k) { s = ""; for (k = 0; k < n; k++) s = s substr(h, 2 * (i + k) + 1, 2); return s }
	function ip(i) { return b(i) "." b(i + 1) "." b(i + 2) "." b(i + 3) }
	function colon(i, n,   s, k) { s = ""; for (k = 0; k < n; k++) s = s (k ? ":" : "") substr(h, 2 * (i + k) + 1, 2); return s }
	function nz(v) { return (v == "" || v == "0.0.0.0") ? "-" : v }
	function flush(   ihl, o, op, xid, ch, ci, yi, cid, srv, req, ty, p, code, len, line, k) {
		if (h == "" || ts == "") return
		ihl = (b(0) % 16) * 4
		o = ihl + 8
		if (length(h) < 2 * (o + 240) || hx(o + 236, 4) != "63825363") { h = ""; return }
		op = b(o); xid = hx(o + 4, 4); ci = ip(o + 12); yi = ip(o + 16); ch = colon(o + 28, 6)
		cid = ""; srv = ""; req = ""; ty = ""
		delete ov
		p = o + 240
		while (2 * p < length(h)) {
			code = b(p)
			if (code == 255) break
			if (code == 0) { p++; continue }
			len = b(p + 1)
			if (code == 53) ty = b(p + 2)
			else if (code == 54 && len == 4) srv = ip(p + 2)
			else if (code == 50 && len == 4) req = ip(p + 2)
			else if (code == 61) cid = colon(p + 2, len)
			if (code in wc) ov[code] = "0x" hx(p + 2, len)
			p += 2 + len
		}
		line = ts " " (ty in tn ? tn[ty] : "TYPE" ty) " " xid " " ch " " nz(cid) " " nz(srv) " " nz(req) " " nz(ci) " " nz(yi) " " ip(12) " " ip(16)
		for (k = 1; k <= nwc; k++) line = line " " ((wl[k] in ov) ? ov[wl[k]] : "-")
		h = ""
		if (want == "*") matched[xid] = 1
		else if (op == 1 && (ch == want || cid == want)) matched[xid] = 1
		else if (!(op == 2 && (ch == want || cid == want || (xid in matched)))) return
		print line
	}
	BEGIN {
		split("DISCOVER OFFER REQUEST DECLINE ACK NAK RELEASE INFORM FORCERENEW", n, " ")
		for (i = 1; i <= 9; i++) tn[i] = n[i]
		nwc = (codes == "") ? 0 : split(codes, wl, ",")
		for (i = 1; i <= nwc; i++) wc[wl[i] + 0] = 1
	}
	$1 ~ /^[0-9]+\.[0-9]+$/ { flush(); ts = $1; next }
	$1 ~ /^0x[0-9a-f]+:$/ { for (i = 2; i <= NF; i++) h = h $i; next }
	END { flush() }
	' >"$outfile"
	rc=${PIPESTATUS[0]}
	set -e
	if [ "$rc" -ne 0 ] && ! grep -q 'truncated dump file' "$errfile"; then
		echo "capture unreadable: tcpdump exited $rc reading $pcap: $(head -c 300 "$errfile")" >&2
		rm -f "$errfile" "$outfile"
		return 1
	fi
	cat "$outfile"
	rm -f "$errfile" "$outfile"
}

# dhcp_option_bytes <pcap> <ident> <code[,code...]> prints, per message of
# one identity, "ts TYPE xid" and then one field per option code
# (group F, #20). It keys on the option CODE read from the hex, never on
# tcpdump's printed names, which are wrong for the codes F needs: 80 prints
# as SLP-NA and 77, 108 and message type 9 as Unknown.
dhcp_option_bytes() {
	local pcap=$1 ident=$2 codes=$3 c log
	[ -n "$codes" ] || { echo "dhcp_option_bytes: no option code given" >&2; return 2; }
	for c in ${codes//,/ }; do
		case "$c" in
		'' | *[!0-9]*) echo "dhcp_option_bytes: bad option code \"$c\"" >&2; return 2 ;;
		esac
		if [ "$c" -lt 1 ] || [ "$c" -gt 254 ]; then
			echo "dhcp_option_bytes: option code $c out of range" >&2
			return 2
		fi
	done
	log=$(dhcp_message_log "$pcap" "$ident" "$codes") || return 1
	[ -n "$log" ] || return 0
	awk '{ printf "%s %s %s", $1, $2, $3; for (i = 12; i <= NF; i++) printf " %s", $i; printf "\n" }' <<<"$log"
}
