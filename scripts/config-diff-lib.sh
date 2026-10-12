#!/bin/bash
# Config-diff helpers shared by capture-source-config-diff.sh and pack.sh
# (issues #32, #46): one definition of the "effective configuration" (a
# config file without comment and blank lines) and of what makes a stored
# diff cover a whole file. Functions only; the sourcing script keeps its own
# set -euo pipefail. A section of a config-diff file is `## <live path>`,
# a marker line with the line counts of both stripped sides, then a unified
# diff with unbounded context (one hunk spans both files). An older capture
# wrote a plain `diff -u` of the raw files, 3 context lines, no marker; it
# is accepted only when its one hunk provably spans both files.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/scripts/hygiene-patterns.sh"

CONFIG_DIFF_FIX="re-run scripts/capture-source-config-diff.sh against the cell to get a whole-file diff"

# config_effective prints stdin without comment lines ("#" and "//", the
# two styles of ISC, dnsmasq and Kea) and blank lines.
config_effective() {
	grep -vE '^[[:space:]]*(#|//|$)' || true
}

# config_live_disallowed_lines FILE prints the number of every line that
# carries a disallowed address, comment or not. Never prints the address.
config_live_disallowed_lines() {
	local n=0 line
	while IFS= read -r line || [ -n "$line" ]; do
		n=$((n + 1))
		if [ -n "$(hygiene_address_disallowed "$line")" ]; then
			echo "$n"
		fi
	done <"$1"
}

# config_mask_vendor_examples FILE rewrites FILE in place, replacing every
# disallowed address with <vendor-example-address>. For the stock side of a
# type whose package ships example addresses in code lines (busybox
# udhcpd.conf, DESIGN-910 section 5.8, lab #10); the live side is never
# masked and HYGIENE_ALLOWED_RE is not widened. Longest address first, so an
# address that begins another one is not cut short. Status 1 if one survives.
config_mask_vendor_examples() {
	local out line a left=0
	out=$(mktemp)
	while IFS= read -r line || [ -n "$line" ]; do
		while IFS= read -r a; do
			[ -n "$a" ] && line=${line//"$a"/<vendor-example-address>}
		done < <(hygiene_address_disallowed "$line" | awk '{ print length, $0 }' | sort -rn | cut -d' ' -f2-)
		[ -z "$(hygiene_address_disallowed "$line")" ] || left=1
		printf '%s\n' "$line" >>"$out"
	done <"$1"
	cat "$out" >"$1"
	rm -f "$out"
	return "$left"
}

# config_diff_render STOCK LIVE prints a section body for two raw files.
config_diff_render() {
	local d s l
	d=$(mktemp -d)
	config_effective <"$1" >"$d/s"
	config_effective <"$2" >"$d/l"
	s=$(wc -l <"$d/s" | tr -d ' ')
	l=$(wc -l <"$d/l" | tr -d ' ')
	printf '# effective-config: comment and blank lines removed; stock %s lines, live %s lines\n' "$s" "$l"
	diff -U 1000000 --label stock --label live "$d/s" "$d/l" || [ $? -eq 1 ]
	rm -rf "$d"
}

# config_diff_sides BODY STOCK-OUT LIVE-OUT rebuilds both raw sides from a
# section body. Status 1, reason on stderr, when the body is not a diff
# that spans both whole files: more than one hunk, a hunk shorter than it
# declares, a first hunk past line 1, marker counts that disagree with the
# hunk, or (no marker) a hunk ending in 3 context lines, where the diff
# cannot show whether the file goes on.
config_diff_sides() {
	awk -v stock_out="$2" -v live_out="$3" '
	function bail(m) { print m > "/dev/stderr"; failed = 1; exit 1 }
	BEGIN { printf "" > stock_out; printf "" > live_out; st = 0; cn = -1; cm = -1; ctx = 0; seen_marker = 0 }
	{
		if (st == 0) {
			if ($0 ~ /^# effective-config: /) {
				if (seen_marker++) bail("a second marker line")
				if (!match($0, /stock [0-9]+ lines, live [0-9]+ lines/)) bail("a marker line without line counts")
				split(substr($0, RSTART, RLENGTH), w, " ")
				cn = w[2] + 0; cm = w[5] + 0
				next
			}
			if ($0 ~ /^--- /) { st = 1; next }
			bail("text where the diff header was expected")
		}
		if (st == 1) {
			if ($0 ~ /^\+\+\+ /) { st = 2; next }
			bail("the --- header line has no +++ line")
		}
		if (st == 2) {
			if ($0 !~ /^@@ -[0-9]+(,[0-9]+)? \+[0-9]+(,[0-9]+)? @@/) bail("no hunk header after the file headers")
			s = $0; sub(/^@@ -/, "", s)
			split(s, p, " ")
			n = split(p[1], o, ","); a = o[1] + 0; b = (n > 1) ? o[2] + 0 : 1
			sub(/^\+/, "", p[2]); n = split(p[2], q, ","); c = q[1] + 0; d = (n > 1) ? q[2] + 0 : 1
			orem = b; nrem = d; st = 3
			next
		}
		if (st == 3) {
			t = substr($0, 1, 1); rest = substr($0, 2)
			if (t == "\\") next
			if (t == " ") {
				if (orem < 1 || nrem < 1) bail("a context line past the declared hunk length")
				print rest > stock_out; print rest > live_out; orem--; nrem--; ctx++
			} else if (t == "-") {
				if (orem < 1) bail("a removed line past the declared hunk length")
				print rest > stock_out; orem--; ctx = 0
			} else if (t == "+") {
				if (nrem < 1) bail("an added line past the declared hunk length")
				print rest > live_out; nrem--; ctx = 0
			} else bail("a line that is not diff text inside a hunk")
			if (orem == 0 && nrem == 0) st = 4
			next
		}
		if ($0 ~ /^\\/) next
		if ($0 ~ /^@@/) bail("more than one hunk: the lines between them are not in the diff")
		bail("text after the hunk")
	}
	END {
		if (failed) exit 1
		if (st == 0) {
			if (cn >= 0 && cn != cm) bail("an empty diff for sides of " cn " and " cm " lines")
			exit 0
		}
		if (st < 3) bail("a diff header without a hunk")
		if (st == 3) bail("the hunk ends before its declared length")
		if ((b > 0 ? a != 1 : a != 0) || (d > 0 ? c != 1 : c != 0)) bail("the hunk does not start at line 1 of the files")
		if (cn >= 0) {
			if (b != cn || d != cm) bail("the hunk covers " b " and " d " lines, the marker says " cn " and " cm)
		} else if (ctx >= 3) bail("the diff ends in context lines and cannot show whether the files go on")
		exit 0
	}' "$1"
}

# config_diff_rerender_file IN OUT re-renders every section of a stored
# config-diff file: the sides are rebuilt from the diff, the live side is
# checked as it was written (comments included, so a comment cannot hide a
# disallowed address), and both are rendered again without comment and
# blank lines. Writes OUT only on success; on refusal prints each reason on
# stderr and returns 1.
config_diff_rerender_file() {
	local in=$1 out=$2 d line sec="" have_sec=0 sections=0 bad=0 err lines
	d=$(mktemp -d)
	: >"$d/out"
	: >"$d/body"
	_cd_flush() {
		[ "$have_sec" -eq 1 ] || return 0
		sections=$((sections + 1))
		if ! err=$(config_diff_sides "$d/body" "$d/stock" "$d/live" 2>&1); then
			echo "section $sec: $err; $CONFIG_DIFF_FIX" >&2
			bad=1
		elif lines=$(config_live_disallowed_lines "$d/live" | tr '\n' ' '); [ -n "$lines" ]; then
			echo "section $sec: the live side carries a disallowed address at live line(s) ${lines% }, comments included" >&2
			bad=1
		else
			{
				printf '## %s\n' "$sec"
				config_diff_render "$d/stock" "$d/live"
			} >>"$d/out"
		fi
		: >"$d/body"
	}
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		'## '*)
			_cd_flush
			sec=${line#\#\# }
			have_sec=1
			;;
		*)
			if [ "$have_sec" -eq 1 ]; then
				printf '%s\n' "$line" >>"$d/body"
			else
				printf '%s\n' "$line" >>"$d/out"
			fi
			;;
		esac
	done <"$in"
	_cd_flush
	if [ "$sections" -eq 0 ]; then
		echo "no '## <path>' section in the file" >&2
		bad=1
	fi
	if [ "$bad" -eq 0 ]; then
		cat "$d/out" >"$out"
	fi
	rm -rf "$d"
	return "$bad"
}
