#!/bin/bash
# Lab-owned firewall allow rule for bridged traffic that stays fully
# inside a lab segment bridge (issue #1). This fixes a real blocker, not
# just an observer visibility gap: Docker's DOCKER-USER hook intercepts
# bridged IPv4 frames between two ordinary ports of any bridge (via
# br_netfilter) and drops them by default -- measured live, a lab
# segment's own DHCP traffic was silently dropped the same way a real
# source VM and a Docker host VM sharing a segment would lose it
# (issue #2). This never touches DOCKER-USER's, FORWARD's or CI-DMZ-*'s
# own content, RETURN, or policy: it only reads the DMZ script's jump
# position in each protocol and inserts or removes its own single,
# comment-tagged jump right after it.
#
# IPv4 hooks into iptables DOCKER-USER, right after the DMZ script's own
# jump there. IPv6 hooks into ip6tables FORWARD directly, right after
# the DMZ script's own jump there -- never into an ip6 DOCKER-USER chain,
# which does not exist today (Docker's IPv6 iptables support is off) and
# which Docker, not this script, would own once that support is on.
#
# Idempotent: safe to re-run at every bring-up. Both protocols refuse
# outright if the DMZ script's own jump is not where this script expects
# it -- never guessing a position.
set -euo pipefail

IPT=${LAB_SEG_IPTABLES:-iptables}
IPT6=${LAB_SEG_IP6TABLES:-ip6tables}
DMZ_COMMENT="CI DMZ containment"
LAB_COMMENT="lab segments"

build_chain() {
	local ipt=$1
	"$ipt" -N LAB-SEG 2>/dev/null || true
	if ! "$ipt" -C LAB-SEG -m physdev --physdev-is-bridged -i lab-br+ -o lab-br+ -j ACCEPT 2>/dev/null; then
		# An accept here skips Docker's inter-network isolation, which is
		# harmless because lab bridges are never Docker networks.
		"$ipt" -A LAB-SEG -m physdev --physdev-is-bridged -i lab-br+ -o lab-br+ -j ACCEPT
	fi
}

# Deletes every jump carrying our own comment from $chain, so a re-run
# never stacks a second one. Matches on the comment only, never on
# position -- deleting by position would risk the DMZ script's own jump
# if the two ever moved relative to each other.
delete_own_jump() {
	local ipt=$1 chain=$2
	while "$ipt" -D "$chain" -m comment --comment "$LAB_COMMENT" -j LAB-SEG 2>/dev/null; do :; done
}

# Prints the 1-based line number of the first rule in $chain whose text
# contains $comment, or nothing if there is none.
jump_line() {
	local ipt=$1 chain=$2 comment=$3
	"$ipt" -L "$chain" -n --line-numbers 2>/dev/null | awk -v c="$comment" '$0 ~ c {print $1; exit}'
}

hook_after_dmz() {
	local ipt=$1 chain=$2 proto=$3
	build_chain "$ipt"

	# Checked explicitly and first, never folded into the jump_line lookup
	# below: a chain that does not exist at all must refuse loudly, not
	# just come back with an empty (and therefore ambiguous) jump line.
	if ! "$ipt" -L "$chain" -n >/dev/null 2>&1; then
		echo "lab-seg-firewall: REFUSED -- $proto chain $chain does not exist; refusing to guess a position" >&2
		exit 1
	fi

	local dmz_line
	dmz_line=$(jump_line "$ipt" "$chain" "$DMZ_COMMENT")
	if [ -z "$dmz_line" ]; then
		echo "lab-seg-firewall: REFUSED -- no \"$DMZ_COMMENT\" jump in $proto $chain; refusing to guess a position" >&2
		exit 1
	fi
	delete_own_jump "$ipt" "$chain"
	"$ipt" -I "$chain" "$((dmz_line + 1))" -m comment --comment "$LAB_COMMENT" -j LAB-SEG

	# Re-read the chain after inserting: exiting 0 on the insert command
	# alone proved nothing about whether the jump actually landed where it
	# was asked to, or whether some earlier unconditional RETURN in the
	# same chain makes it dead on arrival either way.
	local final_line return_line
	final_line=$(jump_line "$ipt" "$chain" "$LAB_COMMENT")
	if [ -z "$final_line" ] || [ "$final_line" -ne "$((dmz_line + 1))" ]; then
		echo "lab-seg-firewall: REFUSED -- $proto LAB-SEG jump landed at line ${final_line:-none} in $chain, not $((dmz_line + 1)) as inserted" >&2
		exit 1
	fi
	return_line=$("$ipt" -L "$chain" -n --line-numbers 2>/dev/null | awk -v l="$final_line" '$0 ~ /-j[[:space:]]+RETURN([[:space:]]|$)/ && $1 < l {print $1; exit}')
	if [ -n "$return_line" ]; then
		echo "lab-seg-firewall: REFUSED -- $proto LAB-SEG jump at line $final_line in $chain sits after a RETURN at line $return_line; it would never run" >&2
		exit 1
	fi
	echo "lab-seg-firewall: $proto LAB-SEG jump installed in $chain after \"$DMZ_COMMENT\" (line $dmz_line)"
}

### ---------- IPv4: DOCKER-USER ----------
hook_after_dmz "$IPT" DOCKER-USER iptables

### ---------- IPv6: FORWARD directly, never DOCKER-USER ----------
# The DMZ script hooks its own v6 jump into FORWARD, not DOCKER-USER,
# because Docker only creates an ip6 DOCKER-USER chain once its IPv6
# iptables support is switched on -- true today and unconditionally, so
# this script does the same, and never creates or touches DOCKER-USER
# under ip6tables. If Docker's v6 support switches on later, Docker
# starts owning ip6 DOCKER-USER; this rule stays in FORWARD, where it
# keeps working either way, and this script still never touches that
# chain.
hook_after_dmz "$IPT6" FORWARD ip6tables
