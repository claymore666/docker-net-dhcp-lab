#!/bin/bash
# Shared address patterns for hygiene-check.sh and pack.sh (issue #4):
# one file, sourced by both, so "what counts as a disallowed address"
# never drifts into two copies. Data and functions only -- it sets
# nothing else and never runs on its own; a sourcing script keeps its
# own set -euo pipefail.

# Everything the lab may publish: its /16, its ULA /48 fd42:200::/48
# exactly (third group zero or elided, so fd42:2001:: and fd42:200:1::
# stay refused, #23 group D; a bare "fd42:200" is what the candidate
# match leaves of "fd42:200::/48"), loopback, link-local, the RFC 5737 /
# RFC 3849 documentation ranges, Docker's default bridge pools
# 172.17.0.0/16 to 172.31.0.0/16 (172.16.0.0/16 is not one and stays
# refused) and Kea's stock sample subnet 10.1.1.0/24. 192.168.0.0/16 is
# LAN detail here and stays refused.
HYGIENE_ALLOWED_RE='^(10\.200\.|10\.1\.1\.|127\.|169\.254\.|172\.(1[7-9]|2[0-9]|3[01])\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|fd42:200(:(0{1,4}:|:)|$))'

# RFC1918 and link-local candidates only; a public IP is not house detail.
HYGIENE_ADDR_CANDIDATE_RE='\b(10(\.[0-9]{1,3}){3}|192\.168(\.[0-9]{1,3}){2}|172\.(1[6-9]|2[0-9]|3[01])(\.[0-9]{1,3}){2}|169\.254(\.[0-9]{1,3}){2}|fd[0-9a-f]{2}:[0-9a-f:]+)\b'

# hygiene_address_candidates prints every address-shaped substring on
# line $1, one per line (none, if there aren't any).
hygiene_address_candidates() {
	grep -oE "$HYGIENE_ADDR_CANDIDATE_RE" <<<"$1" || true
}

# hygiene_address_disallowed prints every address-shaped substring on
# line $1 that HYGIENE_ALLOWED_RE does not cover, one per line -- the
# one check hygiene-check.sh (tracked files) and pack.sh (a bundle's own
# files) both call, so a caller never re-derives "disallowed" itself.
hygiene_address_disallowed() {
	local line=$1 m
	while IFS= read -r m; do
		[ -z "$m" ] && continue
		if ! [[ "$m" =~ $HYGIENE_ALLOWED_RE ]]; then
			echo "$m"
		fi
	done < <(hygiene_address_candidates "$line")
}
