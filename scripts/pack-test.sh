#!/bin/bash
# Fixture tests for pack.sh (issue #4): a throwaway bundle directory per
# case, never the real evidence dir, so a planted violation is never
# itself published.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT="$REPO_ROOT/scripts/pack.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail=0

# An empty denylist file: every "ok" case below packs against this one,
# so each exercises the real, required denylist path rather than an
# empty argument standing in for "no check".
deny="$tmp/denylist.txt"
printf '%s\n' "some-other-plugin-name" >"$deny"

# run_case builds bundle_dir/<name> ($5, default note.txt) from $2, runs
# pack.sh against it with $4 as the denylist file (default: the
# empty-hit one above; a $4 explicitly passed as "" stays empty rather
# than falling back, so the no-denylist case below can actually ask for
# that), and checks the exit against want ($3: ok | fail). "${4-$deny}"
# (no colon) is deliberate: bash's ":-" also substitutes on an explicit
# empty string, which would make that case impossible to write.
run_case() {
	local desc=$1 content=$2 want=$3 denylist=${4-$deny} name=${5:-note.txt}
	local case_dir out
	case_dir=$(mktemp -d "$tmp/case-XXXXXX")
	mkdir -p "$case_dir/bundle"
	printf '%s' "$content" >"$case_dir/bundle/$name"
	out="$case_dir/out.tar.gz"
	if "$SCRIPT" "$case_dir/bundle" "$out" "$denylist" >/dev/null 2>&1; then
		got=ok
	else
		got=fail
	fi
	if [ "$got" != "$want" ]; then
		echo "pack-test: FAIL -- $desc: wanted $want, got $got" >&2
		return 1
	fi
	if [ "$want" = "ok" ] && [ ! -f "$out" ]; then
		echo "pack-test: FAIL -- $desc: wanted a tarball, none written" >&2
		return 1
	fi
	if [ "$want" = "fail" ] && [ -f "$out" ]; then
		echo "pack-test: FAIL -- $desc: refused case still wrote a tarball" >&2
		return 1
	fi
}

# A clean fixture: no address, no non-lab hostname, packs.
run_case "clean fixture packs" \
	$'result: PASS\nreason: lease confirmed\n' ok || fail=1

# A planted disallowed address must refuse, same range hygiene-check.sh
# itself refuses on -- reused via scripts/hygiene-patterns.sh, not a
# second copy of the pattern.
run_case "planted 192.168.x address refused" \
	$'observed gateway 192.168.7.1\n' fail || fail=1

# A lab-range address must still pass.
run_case "lab-range address, still packs" \
	$'observed gateway 10.200.1.1\n' ok || fail=1

# Docker's own default bridge range and Kea's stock example config
# range are both harmless noise, never LAN detail, and must still pack.
run_case "docker bridge address, still packs" \
	$'two networks: 172.18.0.2 plus the lease\n' ok || fail=1
run_case "kea stock example config address, still packs" \
	$'"data": "10.1.1.202, 10.1.1.203"\n' ok || fail=1

# A journalctl-shaped line whose hostname is not lab-*, the shape a
# plugin journal capture with a real machine name would have.
run_case "non-lab hostname in a journal-shaped line refused" \
	$'Sep 27 10:00:01 realbox dockerd[123]: plugin=abc123 lease granted\n' fail || fail=1

# The same shape, with a lab-generated hostname, must pack.
run_case "lab hostname in a journal-shaped line packs" \
	$'Sep 27 10:00:01 lab-docker-host dockerd[123]: plugin=abc123 lease granted\n' ok || fail=1

# A denylist hit refuses, even with no address and a lab hostname.
run_case "denylist hit refused" \
	$'note: tested against some-other-plugin-name for comparison\n' fail || fail=1
# The same denylist, no hit, still packs.
run_case "denylist configured, no hit, still packs" \
	$'note: nothing of interest here\n' ok || fail=1

# No denylist at all -- neither a third argument nor LAB_PACK_DENYLIST
# -- must refuse: a release pack never passes with that check missing.
run_case "no denylist given refuses" \
	$'note: nothing of interest here\n' fail "" || fail=1

# A denylist path that names no real file must refuse the same way, not
# silently skip the check as though none had been given.
run_case "denylist path that does not exist refuses" \
	$'note: nothing of interest here\n' fail "$tmp/does-not-exist.txt" || fail=1

# A denylist file that exists but names no real entry -- empty, or
# comments and blank lines only -- checks nothing, the same gap as no
# denylist at all, and must refuse the same way.
empty_deny="$tmp/denylist-empty.txt"
: >"$empty_deny"
comment_deny="$tmp/denylist-comment-only.txt"
printf '%s\n' "# only a comment" "" >"$comment_deny"
run_case "empty denylist file refuses" \
	$'note: nothing of interest here\n' fail "$empty_deny" || fail=1
run_case "comment-only denylist file refuses" \
	$'note: nothing of interest here\n' fail "$comment_deny" || fail=1

# An evidence line already relative to the bundle is left alone and
# still packs; one naming a real path elsewhere on the filesystem
# (never inside this bundle) is a leak of the host's own layout and
# refuses the whole pack. Written into a *.verdict-named file: the
# rewrite pack.sh does only reads that file shape, same as a real run.
run_case "relative evidence path packs" \
	$'evidence.leases_after: leases.txt\n' ok "$deny" "test.verdict" || fail=1
run_case "evidence path outside the bundle refused" \
	$'evidence.leases_after: /elsewhere/leases.txt\n' fail "$deny" "test.verdict" || fail=1

# ---- config diffs (#32, #46) -----------------------------------------
# Stock fixtures: excerpts, verbatim, of the pinned packages' own stock config
# text (Debian 13 amd64, unpacked with dpkg-deb -x). The dnsmasq and ISC ones
# carry example addresses in comment lines, the defect of #32 and #46; the
# Kea ones carry none the check refuses and exercise the "//" comment style.
# Source of each is the comment above its function.

# dnsmasq 2.91-1+deb13u2, /etc/dnsmasq.conf lines 62-67, 160-167, 236-238.
stock_dnsmasq() {
	cat <<'FIXTURE_EOF'
#no-poll

# Add other name servers here, with domain specs if they are for
# non-public domains.
#server=/localnet/192.168.0.1

#domain=reserved.thekelleys.org.uk,192.68.3.100,192.168.3.200

# Uncomment this to enable the integrated DHCP server, you need
# to supply the range of addresses available for lease and optionally
# a lease time. If you have more than one network, you will need to
# repeat this for each network on which you want to supply DHCP
# service.
#dhcp-range=192.168.0.50,192.168.0.150,12h
# Always allocate the host with Ethernet address 11:22:33:44:55:66
# The IP address 192.168.0.60
#dhcp-host=11:22:33:44:55:66,192.168.0.60
FIXTURE_EOF
}

# isc-dhcp-server 4.4.3-P1-8, /etc/dhcp/dhcpd.conf lines 1-24, 30-55.
stock_isc() {
	cat <<'FIXTURE_EOF'
# dhcpd.conf
#
# Sample configuration file for ISC dhcpd
#

# option definitions common to all supported networks...
option domain-name "example.org";
option domain-name-servers ns1.example.org, ns2.example.org;

default-lease-time 600;
max-lease-time 7200;

# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ('none', since DHCP v2 didn't
# have support for DDNS.)
ddns-update-style none;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
#authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
#subnet 10.152.187.0 netmask 255.255.255.0 {
#}

# This is a very basic subnet declaration.

#subnet 10.254.239.0 netmask 255.255.255.224 {
#  range 10.254.239.10 10.254.239.20;
#  option routers rtr-239-0-1.example.org, rtr-239-0-2.example.org;
#}

# This declaration allows BOOTP clients to get dynamic addresses,
# which we don't really recommend.

#subnet 10.254.239.32 netmask 255.255.255.224 {
#  range dynamic-bootp 10.254.239.40 10.254.239.60;
#  option broadcast-address 10.254.239.31;
#  option routers rtr-239-32-1.example.org;
#}

# A slightly different configuration for an internal subnet.
#subnet 10.5.5.0 netmask 255.255.255.224 {
#  range 10.5.5.26 10.5.5.30;
#  option domain-name-servers ns1.internal.example.org;
#  option domain-name "internal.example.org";
#  option routers 10.5.5.1;
#  option broadcast-address 10.5.5.31;
FIXTURE_EOF
}

# kea-dhcp4-server 2.6.3-1+deb13u1, /etc/kea/kea-dhcp4.conf lines 1-5, 22-33, 41-52, 357-364.
stock_kea() {
	cat <<'FIXTURE_EOF'
// This is a basic configuration for the Kea DHCPv4 server. Subnet declarations
// are mostly commented out and no interfaces are listed. Therefore, the servers
// will not listen or respond to any queries.
// The basic configuration must be extended to specify interfaces on which
// the servers should listen. There are a number of example options defined.
// If configurations for other Kea services are also included in this file they
// are ignored by the DHCPv4 server.
{

// DHCPv4 configuration starts here. This section will be read by DHCPv4 server
// and will be ignored by other components.
"Dhcp4": {
    // Add names of your network interfaces to listen on.
    "interfaces-config": {
        // See section 8.2.4 for more details. You probably want to add just
        // interface name (e.g. "eth0" or specific IPv4 address on that
        // interface name (e.g. "eth0/192.0.2.1").
        // "dhcp-socket-type": "udp"
    },

    // Kea supports control channel, which is a way to receive management
    // commands while the server is running. This is a Unix domain socket that
    // receives commands formatted in JSON, e.g. config-set (which sets new
    // configuration), config-reload (which tells Kea to reload its
    // configuration from file), statistic-get (to retrieve statistics) and many
    // more. For detailed description, see Sections 8.8, 16 and 15.
    "control-socket": {
        "socket-type": "unix",
        "socket-name": "kea4-ctrl-socket"
                    "ip-address": "192.0.2.203",
                    "option-data": [ {
                        "name": "domain-name-servers",
                        "data": "10.1.1.202, 10.1.1.203"
                    } ]
                },

                // The fourth reservation is based on circuit-id. This is an option
FIXTURE_EOF
}

# kea-ctrl-agent 2.6.3-1+deb13u1, /etc/kea/kea-ctrl-agent.conf lines 1-16.
stock_kea_ctrl() {
	cat <<'FIXTURE_EOF'
// This is a basic configuration for the Kea Control Agent.
//
// This is just a very basic configuration. Kea comes with large suite (over 30)
// of configuration examples and extensive Kea User's Guide. Please refer to
// those materials to get better understanding of what this software is able to
// do. Comments in this configuration file sometimes refer to sections for more
// details. These are section numbers in Kea User's Guide. The version matching
// your software should come with your Kea package, but it is also available
// in ISC's Knowledgebase (https://kea.readthedocs.io; the direct link for
// the stable version is https://kea.readthedocs.io/).
//
// This configuration file contains only Control Agent's configuration.
// If configurations for other Kea services are also included in this file they
// are ignored by the Control Agent.
{

FIXTURE_EOF
}

# isc-dhcp-server 4.4.3-P1-8, the /etc/default/isc-dhcp-server its postinst writes (postinst lines 37-54).
stock_isc_default() {
	cat <<'FIXTURE_EOF'
# Defaults for isc-dhcp-server (sourced by /etc/init.d/isc-dhcp-server)

# Path to dhcpd's config file (default: /etc/dhcp/dhcpd.conf).
#DHCPDv4_CONF=/etc/dhcp/dhcpd.conf
#DHCPDv6_CONF=/etc/dhcp/dhcpd6.conf

# Path to dhcpd's PID file (default: /var/run/dhcpd.pid).
#DHCPDv4_PID=/var/run/dhcpd.pid
#DHCPDv6_PID=/var/run/dhcpd6.pid

# Additional options to start dhcpd with.
#	Don't use options -cf or -pf here; use DHCPD_CONF/ DHCPD_PID instead
#OPTIONS=""

# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?
#	Separate multiple interfaces with spaces, e.g. "eth0 eth1".
INTERFACESv4=""
INTERFACESv6=""
FIXTURE_EOF
}

# udhcpd 1:1.37.0-6, /etc/udhcpd.conf lines 1-9, 48-49, 60-77. Its code lines
# carry vendor example addresses (start, end, opt dns, ...), the defect of
# DESIGN-910 5.8; the capture masks them for this type only.
stock_udhcpd() {
	cat <<'FIXTURE_EOF'
# Sample udhcpd configuration file (/etc/udhcpd.conf)
# Values shown are defaults

# The start and end of the IP lease block
start		192.168.0.20
end		192.168.0.254

# The interface that udhcpd will use
interface	eth0
# next server to use in bootstrap
#siaddr		192.168.0.22	# default: 0.0.0.0 (none)
# Static leases map
#static_lease 00:60:08:11:CE:4E 192.168.0.54
#static_lease 00:60:08:11:CE:3E 192.168.0.44 optional_hostname

# The remainder of options are DHCP options and can be specified with the
# keyword 'opt' or 'option'. If an option can take multiple items, such
# as the dns option, they can be listed on the same line, or multiple
# lines.
# Examples:
opt	dns	192.168.10.2 192.168.10.10
option	subnet	255.255.255.0
opt	router	192.168.10.2
opt	wins	192.168.10.10
option	dns	129.219.13.81	# appended to above DNS servers for a total of 3
option	domain	local
option	lease	864000		# default: 10 days
option	msstaticroutes	10.0.0.0/8 10.127.0.1		# single static route
option	staticroutes	10.0.0.0/8 10.127.0.1, 10.11.12.0/24 10.11.12.1
FIXTURE_EOF
}

# live_from_template FILE N prints the Nth heredoc of a cloud-init template
# (the config the cell writes), placeholders replaced by lab addresses.
live_from_template() {
	awk -v want="$2" '
	inh { t = $0; sub(/^[ ]+/, "", t)
	      if (t == delim) { inh = 0; if (n == want) exit }
	      else if (n == want) { sub(/^    /, ""); print }
	      next }
	/<<.[A-Z]+.$/ { n++; delim = $0; sub(/^.*<<./, "", delim); sub(/.$/, "", delim); inh = 1 }
	' "$1" | sed -E 's/__[A-Z_]+__/10.200.1.1/g'
}

# The capture script reaches the cell with `ssh ... "sudo cat <path>"`; the
# stub answers from a directory tree that mirrors the cell's filesystem.
stubbin="$tmp/stubbin"
mkdir -p "$stubbin"
cat >"$stubbin/ssh" <<'STUB_EOF'
#!/bin/bash
cmd=${!#}
case "$cmd" in
'sudo cat /'*) cat "$LAB_TEST_FIX${cmd#sudo cat }" ;;
*) exit 99 ;;
esac
STUB_EOF
chmod +x "$stubbin/ssh"

# source_tree TYPE DIR lays out the cell's stock backups and live files.
source_tree() {
	local type=$1 d=$2 t="$REPO_ROOT/cloud-init"
	mkdir -p "$d/root/lab-stock-config" "$d/etc/kea" "$d/etc/dhcp" "$d/etc/default"
	case "$type" in
	kea)
		stock_kea >"$d/root/lab-stock-config/kea-dhcp4.conf.stock"
		stock_kea_ctrl >"$d/root/lab-stock-config/kea-ctrl-agent.conf.stock"
		live_from_template "$t/kea-user-data.tmpl.yaml" 1 >"$d/etc/kea/kea-dhcp4.conf"
		live_from_template "$t/kea-user-data.tmpl.yaml" 2 >"$d/etc/kea/kea-ctrl-agent.conf"
		;;
	isc-dhcp)
		stock_isc >"$d/root/lab-stock-config/dhcpd.conf.stock"
		stock_isc_default >"$d/root/lab-stock-config/isc-dhcp-server.stock"
		live_from_template "$t/isc-dhcp-user-data.tmpl.yaml" 1 >"$d/etc/dhcp/dhcpd.conf"
		live_from_template "$t/isc-dhcp-user-data.tmpl.yaml" 2 >"$d/etc/default/isc-dhcp-server"
		;;
	dnsmasq)
		stock_dnsmasq >"$d/root/lab-stock-config/dnsmasq.conf.stock"
		live_from_template "$t/dnsmasq-user-data.tmpl.yaml" 1 >"$d/etc/dnsmasq.conf"
		;;
	udhcpd)
		stock_udhcpd >"$d/root/lab-stock-config/udhcpd.conf.stock"
		live_from_template "$t/udhcpd-user-data.tmpl.yaml" 1 >"$d/etc/udhcpd.conf"
		;;
	esac
}

# run_capture TYPE TREE EVIDENCE runs the real capture script against the stub.
run_capture() {
	mkdir -p "$tmp/work"
	PATH="$stubbin:$PATH" LAB_TEST_FIX="$2" \
		"$REPO_ROOT/scripts/capture-source-config-diff.sh" "cell-$1" "$1" 10.200.0.2 "$tmp/work" "$3" >/dev/null 2>"$tmp/capture.err"
}

# pack_ok / pack_refused DESC EVIDENCE-DIR [MESSAGE-FRAGMENT]
cfg_n=0
pack_dir() { cfg_n=$((cfg_n + 1)); "$SCRIPT" "$1" "$tmp/cfg-out-$cfg_n.tar.gz" "$deny" >/dev/null 2>"$tmp/pack.err"; }
expect_pack() {
	local desc=$1 want=$2 dir=$3 frag=${4:-} got
	if pack_dir "$dir"; then got=ok; else got=fail; fi
	if [ "$got" != "$want" ]; then
		echo "pack-test: FAIL -- $desc: wanted $want, got $got" >&2
		return 1
	fi
	if [ -n "$frag" ] && ! grep -qF -- "$frag" "$tmp/pack.err"; then
		echo "pack-test: FAIL -- $desc: refusal did not say '$frag'" >&2
		return 1
	fi
}
new_dir() { mktemp -d "$tmp/ev-XXXXXX"; }

# effective TEXT-FILE: the independent spelling of the strip (comment and
# blank lines out), used to judge what the rendered diff must carry.
effective() { grep -vE '^[[:space:]]*(#|//|$)' "$1" || true; }

# side_of SECTION-FILE stock|live: one side rebuilt from a rendered section.
side_of() { # section file, stock|live
	local pat='^[ +]'
	[ "$2" = stock ] && pat='^[ -]'
	{ grep -vE '^(# effective-config:|--- stock$|\+\+\+ live$|@@ )' "$1" | grep -E "$pat" | cut -c2-; } || true
}

# old_capture OUT-FILE STOCK LIVE PATH writes what capture wrote before this
# change: plain `diff -u` of the raw files (3 lines of context, fd labels).
old_capture() {
	{
		echo "# config diff for cell old (test), commit 0123456789abcdef, captured 20260927T000000Z"
		echo "## $4"
		diff -u --label /dev/fd/63 --label /dev/fd/62 "$2" "$3" || true
	} >"$1"
}

# packed_vs_files DESC TARBALL STOCK-FILE LIVE-FILE PATH pulls the config diff
# out of what pack wrote and compares the section for PATH with the stock and
# live files themselves (#32): the bundle's content, not capture's output.
packed_vs_files() {
	local desc=$1 tgz=$2 sf=$3 lf=$4 pth=$5 member
	member=$(tar -tzf "$tgz" 2>/dev/null | grep -E -- '-config-diff-[^/]*\.txt$' | head -1 || true)
	if [ -z "$member" ]; then
		echo "pack-test: FAIL -- $desc: the tarball carries no config diff" >&2
		return 1
	fi
	tar -xzOf "$tgz" "$member" >"$tmp/packed.txt"
	if ! head -1 "$tmp/packed.txt" | grep -q '^# config diff for cell '; then
		echo "pack-test: FAIL -- $desc: the packed config diff lost its header line" >&2
		return 1
	fi
	awk -v want="## $pth" '$0 == want { on = 1; next } /^## / { on = 0 } on' "$tmp/packed.txt" >"$tmp/packed-sec.txt"
	if ! grep -q '^# effective-config: ' "$tmp/packed-sec.txt"; then
		echo "pack-test: FAIL -- $desc: no re-rendered section for $pth in the tarball" >&2
		return 1
	fi
	effective "$sf" >"$tmp/pk-want-stock"
	effective "$lf" >"$tmp/pk-want-live"
	side_of "$tmp/packed-sec.txt" stock >"$tmp/pk-got-stock"
	side_of "$tmp/packed-sec.txt" live >"$tmp/pk-got-live"
	if ! cmp -s "$tmp/pk-want-stock" "$tmp/pk-got-stock"; then
		echo "pack-test: FAIL -- $desc: the packed stock side of $pth is not the stock file's effective config" >&2
		return 1
	fi
	if ! cmp -s "$tmp/pk-want-live" "$tmp/pk-got-live"; then
		echo "pack-test: FAIL -- $desc: the packed live side of $pth is not the live file's effective config" >&2
		return 1
	fi
}

# new_capture OUT-DIR TYPE: lays out a tree and runs the real capture.
cfg_types="kea isc-dhcp dnsmasq"
for ty in $cfg_types; do
	tree="$tmp/tree-$ty"
	source_tree "$ty" "$tree"
	ev="$tmp/ev-$ty"
	mkdir -p "$ev"
	if ! run_capture "$ty" "$tree" "$ev"; then
		echo "pack-test: FAIL -- source-$ty: capture exited non-zero: $(head -c 300 "$tmp/capture.err")" >&2
		fail=1
		continue
	fi
	expect_pack "source-$ty: captured diff packs" ok "$ev" || fail=1
	src_tgz="$tmp/cfg-out-$cfg_n.tar.gz"
	cdf=$(ls "$ev"/cell-"$ty"-config-diff-*.txt)
	# Every section: stock side == stock without comment/blank lines, live
	# side == live without them. An independent rebuild, not the lib's.
	awk -v dir="$tmp/sec-$ty" 'BEGIN { system("mkdir -p " dir) } /^## / { n++; f = dir "/" n ".txt"; print substr($0, 4) > (dir "/" n ".path"); next } n { print > f }' "$cdf"
	for sec in "$tmp/sec-$ty"/*.txt; do
		n=$(basename "$sec" .txt)
		p=$(cat "$tmp/sec-$ty/$n.path")
		case "$ty:$p" in
		kea:/etc/kea/kea-dhcp4.conf) sf="$tree/root/lab-stock-config/kea-dhcp4.conf.stock" ;;
		kea:/etc/kea/kea-ctrl-agent.conf) sf="$tree/root/lab-stock-config/kea-ctrl-agent.conf.stock" ;;
		isc-dhcp:/etc/dhcp/dhcpd.conf) sf="$tree/root/lab-stock-config/dhcpd.conf.stock" ;;
		isc-dhcp:/etc/default/isc-dhcp-server) sf="$tree/root/lab-stock-config/isc-dhcp-server.stock" ;;
		dnsmasq:/etc/dnsmasq.conf) sf="$tree/root/lab-stock-config/dnsmasq.conf.stock" ;;
		esac
		effective "$sf" >"$tmp/want-stock"
		effective "$tree$p" >"$tmp/want-live"
		side_of "$sec" stock >"$tmp/got-stock"
		side_of "$sec" live >"$tmp/got-live"
		if ! cmp -s "$tmp/want-stock" "$tmp/got-stock" || ! cmp -s "$tmp/want-live" "$tmp/got-live"; then
			echo "pack-test: FAIL -- source-$ty: section $p does not render the stock and live effective config" >&2
			fail=1
		fi
		packed_vs_files "source-$ty" "$src_tgz" "$sf" "$tree$p" "$p" || fail=1
		if grep -qE '^[ +-][[:space:]]*(#|//)' "$sec"; then
			echo "pack-test: FAIL -- source-$ty: section $p still carries a comment line" >&2
			fail=1
		fi
	done
	# Control: the raw stock text of ISC and dnsmasq, in a plain file, is
	# still refused, so the passes above are the strip's doing.
	case "$ty" in
	isc-dhcp | dnsmasq)
		ctl=$(new_dir)
		cat "$tree"/root/lab-stock-config/*.stock >"$ctl/stock-text.txt"
		expect_pack "source-$ty: control, raw stock text in a plain file refuses" fail "$ctl" || fail=1
		;;
	esac
done

# Old stored format (a plain `diff -u` of the raw files) packs when the diff
# covers both whole files, and the bundle on disk is not rewritten.
for pair in "dnsmasq:root/lab-stock-config/dnsmasq.conf.stock:etc/dnsmasq.conf:/etc/dnsmasq.conf" \
	"isc-dhcp:root/lab-stock-config/dhcpd.conf.stock:etc/dhcp/dhcpd.conf:/etc/dhcp/dhcpd.conf" \
	"isc-dhcp:root/lab-stock-config/isc-dhcp-server.stock:etc/default/isc-dhcp-server:/etc/default/isc-dhcp-server"; do
	IFS=: read -r ty sf lf pth <<<"$pair"
	ev=$(new_dir)
	old_capture "$ev/cell-old-config-diff-20260927T000000Z.txt" "$tmp/tree-$ty/$sf" "$tmp/tree-$ty/$lf" "$pth"
	cp "$ev/cell-old-config-diff-20260927T000000Z.txt" "$tmp/old-before.txt"
	expect_pack "old-format-diff-rerendered ($pth)" ok "$ev" || fail=1
	cmp -s "$tmp/old-before.txt" "$ev/cell-old-config-diff-20260927T000000Z.txt" || { echo "pack-test: FAIL -- old-format-diff-rerendered ($pth): pack rewrote the bundle on disk" >&2; fail=1; }
	packed_vs_files "old-format-diff-rerendered ($pth)" "$tmp/cfg-out-$cfg_n.tar.gz" "$tmp/tree-$ty/$sf" "$tmp/tree-$ty/$lf" "$pth" || fail=1
done

# Files with no newline at the end: diff writes "\ No newline at end of
# file" markers, and the rebuilt sides must not lose or gain a line (#32).
ev=$(new_dir)
printf 'keep=1\n# comment\nold=2' >"$tmp/nonl-stock"
printf 'keep=1\nnew=2' >"$tmp/nonl-live"
old_capture "$ev/cell-nonl-config-diff-20260927T000000Z.txt" "$tmp/nonl-stock" "$tmp/nonl-live" /etc/nonl.conf
expect_pack "old-format-no-newline-at-end" ok "$ev" || fail=1
packed_vs_files "old-format-no-newline-at-end" "$tmp/cfg-out-$cfg_n.tar.gz" "$tmp/nonl-stock" "$tmp/nonl-live" /etc/nonl.conf || fail=1

# put_cd DIR NAME PATH, body on stdin: a hand-built section.
put_cd() {
	{
		echo "# config diff for cell hand (test), commit 0123456789abcdef, captured 20260927T000000Z"
		echo "## $3"
		cat
	} >"$1/hand-config-diff-$2.txt"
}

# live-comment-address-refused: a real address in a comment on the LIVE side
# must still refuse, at capture and at pack, in both stored formats.
tree="$tmp/tree-live-comment"
source_tree dnsmasq "$tree"
printf '%s\n' '# upstream 192.168.7.9' >>"$tree/etc/dnsmasq.conf"
ev=$(new_dir)
if run_capture dnsmasq "$tree" "$ev"; then
	echo "pack-test: FAIL -- live-comment-address-refused-by-capture: capture exited 0" >&2
	fail=1
fi
if ls "$ev"/*-config-diff-* >/dev/null 2>&1; then
	echo "pack-test: FAIL -- live-comment-address-refused-by-capture: a diff was written" >&2
	fail=1
fi
ev=$(new_dir)
old_capture "$ev/cell-old-config-diff-20260927T000000Z.txt" "$tmp/tree-dnsmasq/root/lab-stock-config/dnsmasq.conf.stock" "$tree/etc/dnsmasq.conf" /etc/dnsmasq.conf
expect_pack "live-comment-address-refused-by-pack-old-format" fail "$ev" || fail=1
ev=$(new_dir)
put_cd "$ev" new /etc/dnsmasq.conf <<'DIFF_EOF'
# effective-config: comment and blank lines removed; stock 1 lines, live 2 lines
--- stock
+++ live
@@ -1 +1,2 @@
 interface=eth1
+# upstream 192.168.7.9
DIFF_EOF
expect_pack "live-comment-address-refused-by-pack-new-format" fail "$ev" || fail=1

# stock-code-address-refused: a stock line that is not a comment keeps its
# address in the diff and refuses.
tree="$tmp/tree-stock-code"
source_tree dnsmasq "$tree"
printf '%s\n' 'server=192.168.7.9' >>"$tree/root/lab-stock-config/dnsmasq.conf.stock"
ev=$(new_dir)
run_capture dnsmasq "$tree" "$ev" || { echo "pack-test: FAIL -- stock-code-address-refused: capture failed" >&2; fail=1; }
expect_pack "stock-code-address-refused" fail "$ev" || fail=1

# udhcpd-stock-example-addresses-masked (#10, DESIGN-910 5.8): the stock
# udhcpd.conf has vendor example addresses in CODE lines. The capture masks
# them on the stock side for this type only, the packed diff carries the
# placeholder, and the live side is untouched and still checked strictly.
tree="$tmp/tree-udhcpd"
source_tree udhcpd "$tree"
ev=$(new_dir)
run_capture udhcpd "$tree" "$ev" || { echo "pack-test: FAIL -- udhcpd-stock-example-addresses-masked: capture failed: $(head -c 300 "$tmp/capture.err")" >&2; fail=1; }
expect_pack "udhcpd-stock-example-addresses-masked" ok "$ev" || fail=1
tar -xzOf "$tmp/cfg-out-$cfg_n.tar.gz" >"$tmp/udhcpd-packed.txt"
grep -qF '<vendor-example-address>' "$tmp/udhcpd-packed.txt" || { echo "pack-test: FAIL -- udhcpd-stock-example-addresses-masked: no placeholder in the packed diff" >&2; fail=1; }
if grep -qE '192\.168\.|(^|[^0-9.])10\.(0|11|127)\.' "$tmp/udhcpd-packed.txt"; then
	echo "pack-test: FAIL -- udhcpd-stock-example-addresses-masked: a vendor address is in the packed diff" >&2
	fail=1
fi
# The masked stock side is what an independent sed makes of the stock file.
effective "$tree/root/lab-stock-config/udhcpd.conf.stock" |
	sed -E 's/192\.168(\.[0-9]{1,3}){2}|10(\.[0-9]{1,3}){3}/<vendor-example-address>/g' >"$tmp/udhcpd-want-stock"
cdf=$(ls "$ev"/cell-udhcpd-config-diff-*.txt)
awk '/^## /{on=1;next} on' "$cdf" >"$tmp/udhcpd-sec.txt"
side_of "$tmp/udhcpd-sec.txt" stock >"$tmp/udhcpd-got-stock"
side_of "$tmp/udhcpd-sec.txt" live >"$tmp/udhcpd-got-live"
cmp -s "$tmp/udhcpd-want-stock" "$tmp/udhcpd-got-stock" || { echo "pack-test: FAIL -- udhcpd-stock-example-addresses-masked: the stock side is not the masked effective stock config" >&2; fail=1; }
effective "$tree/etc/udhcpd.conf" | cmp -s - "$tmp/udhcpd-got-live" || { echo "pack-test: FAIL -- udhcpd-stock-example-addresses-masked: the live side was altered" >&2; fail=1; }
# Live side stays strict for this type: a code line or a comment, refused.
for live_line in 'dns 192.168.7.9' '# upstream 192.168.7.9'; do
	tree="$tmp/tree-udhcpd-live"
	rm -rf "$tree"
	source_tree udhcpd "$tree"
	printf '%s\n' "$live_line" >>"$tree/etc/udhcpd.conf"
	ev=$(new_dir)
	if run_capture udhcpd "$tree" "$ev"; then
		echo "pack-test: FAIL -- udhcpd-live-address-refused: capture exited 0 for '$live_line'" >&2
		fail=1
	fi
	if ls "$ev"/*-config-diff-* >/dev/null 2>&1; then
		echo "pack-test: FAIL -- udhcpd-live-address-refused: a diff was written for '$live_line'" >&2
		fail=1
	fi
done

# blank-only-change-empty-diff: stock and live differ in blank and comment
# lines only, the diff is empty and still packs.
tree="$tmp/tree-blank"
mkdir -p "$tree/root/lab-stock-config" "$tree/etc"
printf '%s\n' 'interface=eth1' '' '' '# a note' 'bind-interfaces' >"$tree/root/lab-stock-config/dnsmasq.conf.stock"
printf '%s\n' 'interface=eth1' 'bind-interfaces' >"$tree/etc/dnsmasq.conf"
ev=$(new_dir)
run_capture dnsmasq "$tree" "$ev" || { echo "pack-test: FAIL -- blank-only-change-empty-diff: capture failed" >&2; fail=1; }
if sed -n '3,$p' "$ev"/cell-dnsmasq-config-diff-*.txt | grep -vE '^#' | grep -qE '^[-+@]'; then
	echo "pack-test: FAIL -- blank-only-change-empty-diff: the diff is not empty" >&2
	fail=1
fi
expect_pack "blank-only-change-empty-diff" ok "$ev" || fail=1

# dashes-lookalike-line: a config line that renders as "--- " or "+++ " in
# a diff must not end the parse early.
tree="$tmp/tree-dashes"
mkdir -p "$tree/root/lab-stock-config" "$tree/etc"
printf '%s\n' '-- one' 'keep' >"$tree/root/lab-stock-config/dnsmasq.conf.stock"
printf '%s\n' '++ two' 'keep' >"$tree/etc/dnsmasq.conf"
ev=$(new_dir)
run_capture dnsmasq "$tree" "$ev" || { echo "pack-test: FAIL -- dashes-lookalike-line: capture failed" >&2; fail=1; }
expect_pack "dashes-lookalike-line" ok "$ev" || fail=1
tar -xzOf "$tmp/cfg-out-$cfg_n.tar.gz" | grep -qxF -- '--- one' || { echo "pack-test: FAIL -- dashes-lookalike-line: rendered diff lost the line" >&2; fail=1; }

# capture-ssh-failure-refused: a cell that cannot answer for a file ends
# the capture, it does not diff against nothing.
tree="$tmp/tree-missing"
source_tree dnsmasq "$tree"
rm -f "$tree/root/lab-stock-config/dnsmasq.conf.stock"
ev=$(new_dir)
if run_capture dnsmasq "$tree" "$ev"; then
	echo "pack-test: FAIL -- capture-ssh-failure-refused: missing stock file, capture exited 0" >&2
	fail=1
fi
tree="$tmp/tree-empty-live"
source_tree dnsmasq "$tree"
: >"$tree/etc/dnsmasq.conf"
ev=$(new_dir)
if run_capture dnsmasq "$tree" "$ev"; then
	echo "pack-test: FAIL -- capture-ssh-failure-refused: empty live file, capture exited 0" >&2
	fail=1
fi

# partial-*: a diff that does not cover both whole files is refused, with the
# fix named. Built from numbered files so the hunk shapes are certain.
partial_dir() { # sed expression applied to the live copy, line count
	local d
	d=$(new_dir)
	seq -f "line %g" 1 "$2" >"$tmp/p-stock"
	sed "$1" "$tmp/p-stock" >"$tmp/p-live"
	old_capture "$d/cell-old-config-diff-20260927T000000Z.txt" "$tmp/p-stock" "$tmp/p-live" /etc/dnsmasq.conf
	echo "$d"
}
d=$(partial_dir 's/^line 2$/changed 2/;s/^line 28$/changed 28/' 30)
expect_pack "partial-two-hunks" fail "$d" "more than one hunk" || fail=1
d=$(partial_dir 's/^line 28$/changed 28/' 30)
expect_pack "partial-first-hunk-not-at-line-1" fail "$d" "does not start at line 1" || fail=1
d=$(partial_dir 's/^line 2$/changed 2/' 30)
expect_pack "partial-end-of-file-unproven" fail "$d" "capture-source-config-diff.sh" || fail=1
d=$(partial_dir 's/^line 3$/changed 3/' 5)
expect_pack "whole-file-in-one-hunk-packs" ok "$d" || fail=1
d=$(partial_dir 's/^line 3$/changed 3/' 4)
f=$(ls "$d"/*-config-diff-*)
head -n -2 "$f" >"$f.cut"
mv "$f.cut" "$f"
expect_pack "partial-truncated-hunk" fail "$d" "capture-source-config-diff.sh" || fail=1

# capture-one-hunk-for-the-whole-file: two changes far apart still render as
# one hunk, the shape pack needs to prove both files are whole.
tree="$tmp/tree-far"
mkdir -p "$tree/root/lab-stock-config" "$tree/etc"
seq -f "opt %g" 1 30 >"$tree/root/lab-stock-config/dnsmasq.conf.stock"
seq -f "opt %g" 1 30 | sed 's/^opt 2$/changed 2/;s/^opt 28$/changed 28/' >"$tree/etc/dnsmasq.conf"
ev=$(new_dir)
run_capture dnsmasq "$tree" "$ev" || { echo "pack-test: FAIL -- capture-one-hunk-for-the-whole-file: capture failed" >&2; fail=1; }
hunks=$(grep -c '^@@ ' "$ev"/cell-dnsmasq-config-diff-*.txt || true)
[ "$hunks" = 1 ] || { echo "pack-test: FAIL -- capture-one-hunk-for-the-whole-file: $hunks hunks" >&2; fail=1; }
expect_pack "capture-one-hunk-for-the-whole-file" ok "$ev" || fail=1

# new format: the marker's counts are the proof of the whole file.
good_new() { # dir, stock-count, live-count
	put_cd "$1" new /etc/dnsmasq.conf <<DIFF_EOF
# effective-config: comment and blank lines removed; stock $2 lines, live $3 lines
--- stock
+++ live
@@ -1,2 +1,2 @@
 interface=eth1
-bind-interfaces
+bind-dynamic
DIFF_EOF
}
ev=$(new_dir)
good_new "$ev" 2 2
expect_pack "new-format-counts-match-packs" ok "$ev" || fail=1
ev=$(new_dir)
good_new "$ev" 3 2
expect_pack "partial-new-format-stock-count-disagrees" fail "$ev" "capture-source-config-diff.sh" || fail=1
ev=$(new_dir)
good_new "$ev" 2 5
expect_pack "partial-new-format-live-count-disagrees" fail "$ev" "capture-source-config-diff.sh" || fail=1
ev=$(new_dir)
put_cd "$ev" new /etc/dnsmasq.conf <<'DIFF_EOF'
# effective-config: comment and blank lines removed; stock 4 lines, live 5 lines
DIFF_EOF
expect_pack "partial-new-format-empty-body-unequal-counts" fail "$ev" "capture-source-config-diff.sh" || fail=1
ev=$(new_dir)
put_cd "$ev" new /etc/dnsmasq.conf <<'DIFF_EOF'
# effective-config: comment and blank lines removed; stock 4 lines, live 4 lines
DIFF_EOF
expect_pack "empty-body-equal-counts-packs" ok "$ev" || fail=1
ev=$(new_dir)
printf '%s\n' '# config diff for cell hand (test), commit 0123456789abcdef, captured 20260927T000000Z' >"$ev/hand-config-diff-none.txt"
expect_pack "config-diff-file-without-a-section-refused" fail "$ev" || fail=1

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "pack-test: PASS -- all cases behaved as expected"
