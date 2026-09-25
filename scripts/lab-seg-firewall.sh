#!/bin/bash
# Lab-owned firewall allow rule for bridged lab-segment traffic (issue
# #1): DOCKER-USER drops bridged frames between two bridge ports by
# default (br_netfilter) -- measured live, lab DHCP traffic was lost
# the same way a real source VM would lose it (issue #2). Reads the
# DMZ script's jump position in each protocol and inserts or removes
# only its own single, comment-tagged jump right after it; never
# touches DOCKER-USER's, FORWARD's or CI-DMZ-*'s own rules, RETURN, or
# policy. IPv4 hooks DOCKER-USER; IPv6 hooks FORWARD directly (no ip6
# DOCKER-USER chain while Docker's v6 iptables support is off).
# Idempotent; refuses outright if the DMZ jump is not where expected.
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
		# harmless because lab bridges are never Docker networks. Checked
		# explicitly, never left to set -e: the caller can run this inside
		# a subshell whose own -e is off (see the top-level calls below).
		if ! "$ipt" -A LAB-SEG -m physdev --physdev-is-bridged -i lab-br+ -o lab-br+ -j ACCEPT; then
			echo "lab-seg-firewall: REFUSED -- could not add the LAB-SEG rule body" >&2
			return 1
		fi
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
	if ! build_chain "$ipt"; then
		return 1
	fi

	# Checked explicitly and first, never folded into the jump_line lookup
	# below: a chain that does not exist at all must refuse loudly, not
	# just come back with an empty (and therefore ambiguous) jump line.
	# Nothing has been written yet, so a plain return is enough here.
	if ! "$ipt" -L "$chain" -n >/dev/null 2>&1; then
		echo "lab-seg-firewall: REFUSED -- $proto chain $chain does not exist; refusing to guess a position" >&2
		return 1
	fi

	# delete_own_jump runs before the first real read of dmz_line: a stray
	# LAB-SEG jump sitting above the DMZ jump (leftover state, a hand
	# edit) shifts every line below it once removed, so a position read
	# before that removal is already stale by the time it is used.
	delete_own_jump "$ipt" "$chain"

	local dmz_line
	dmz_line=$(jump_line "$ipt" "$chain" "$DMZ_COMMENT")
	if [ -z "$dmz_line" ]; then
		echo "lab-seg-firewall: REFUSED -- no \"$DMZ_COMMENT\" jump in $proto $chain; refusing to guess a position" >&2
		return 1
	fi
	# Checked explicitly for the same reason as build_chain's -A above:
	# this can run with the caller's own -e off.
	if ! "$ipt" -I "$chain" "$((dmz_line + 1))" -m comment --comment "$LAB_COMMENT" -j LAB-SEG; then
		echo "lab-seg-firewall: REFUSED -- $proto could not insert the LAB-SEG jump into $chain" >&2
		return 1
	fi

	# Re-read the chain after inserting, both positions fresh: exiting 0
	# on the insert alone proves nothing, and comparing the re-read jump
	# line back against $dmz_line (the value used to place it) would only
	# ever agree with itself. Read the DMZ jump's line again too, and
	# compare two independent post-insert reads against each other.
	local final_dmz_line final_line return_line
	final_dmz_line=$(jump_line "$ipt" "$chain" "$DMZ_COMMENT")
	final_line=$(jump_line "$ipt" "$chain" "$LAB_COMMENT")
	if [ -z "$final_dmz_line" ] || [ -z "$final_line" ] || [ "$final_line" -ne "$((final_dmz_line + 1))" ]; then
		echo "lab-seg-firewall: REFUSED -- $proto LAB-SEG jump landed at line ${final_line:-none} in $chain, DMZ jump now at line ${final_dmz_line:-none}" >&2
		# The jump just landed wrong; undo it rather than leave this
		# protocol half-applied on a refusal.
		delete_own_jump "$ipt" "$chain"
		return 1
	fi
	# The target name is its own column in real -L -n --line-numbers
	# output ("RETURN"), never a "-j RETURN" flag pair -- that syntax
	# only appears in -S/rule-spec output. Match column 2 by position,
	# not a substring search across the whole line.
	return_line=$("$ipt" -L "$chain" -n --line-numbers 2>/dev/null | awk -v l="$final_line" '$1 ~ /^[0-9]+$/ && $2 == "RETURN" && $1 < l {print $1; exit}')
	if [ -n "$return_line" ]; then
		# Refuses either way, conditional or not: this script cannot prove
		# lab traffic can never match a RETURN ahead of its own jump.
		echo "lab-seg-firewall: REFUSED -- $proto: a RETURN rule precedes the DMZ jump; refusing" >&2
		delete_own_jump "$ipt" "$chain"
		return 1
	fi
	echo "lab-seg-firewall: $proto LAB-SEG jump installed in $chain after \"$DMZ_COMMENT\" (line $final_dmz_line)"
}

### ---------- IPv4: DOCKER-USER ----------
# Run in a subshell so testing its exit status here (`if ! (...)`) does
# not abort this script mid-function on the first failure -- but that
# same wrapping also turns off -e inside the subshell for the whole call,
# in both bash and POSIX shells, so hook_after_dmz and build_chain check
# every command that writes a rule explicitly and return 1 themselves;
# neither relies on -e to catch a failed add.
if ! (hook_after_dmz "$IPT" DOCKER-USER iptables); then
	exit 1
fi

### ---------- IPv6: FORWARD directly, never DOCKER-USER ----------
# The DMZ script hooks its own v6 jump into FORWARD, not DOCKER-USER:
# Docker only creates an ip6 DOCKER-USER chain once its v6 iptables
# support is on, which is off today, so this rule lives in FORWARD and
# never touches DOCKER-USER under ip6tables either way, before or after
# that switches. If v6 refuses, the v4 jump above already landed; take
# it back out so a v6-only problem never leaves v4 half-applied, all or
# nothing across both protocols.
if ! (hook_after_dmz "$IPT6" FORWARD ip6tables); then
	echo "lab-seg-firewall: rolling back the IPv4 jump because IPv6 refused" >&2
	delete_own_jump "$IPT" DOCKER-USER
	exit 1
fi
