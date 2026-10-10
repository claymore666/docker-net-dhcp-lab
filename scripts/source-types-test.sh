#!/bin/bash
# source-types.sh (#9): the five Debian types keep the version command,
# the stock and live reads and udhcpd's stock mask that run-cell.sh and
# capture-source-config-diff.sh used before the table, an unknown type
# is refused by every function, and every type the schema accepts has an
# arm.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/scripts/source-types.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail=0
bad() {
	echo "source-types-test: $*" >&2
	fail=1
}

declare -A want_pairs=(
	[kea]='kea-dhcp4.conf.stock:/etc/kea/kea-dhcp4.conf kea-ctrl-agent.conf.stock:/etc/kea/kea-ctrl-agent.conf'
	[isc-dhcp]='dhcpd.conf.stock:/etc/dhcp/dhcpd.conf isc-dhcp-server.stock:/etc/default/isc-dhcp-server'
	[dnsmasq]='dnsmasq.conf.stock:/etc/dnsmasq.conf'
	[udhcpd]='udhcpd.conf.stock:/etc/udhcpd.conf'
	[pihole]='pihole.toml.stock:/etc/pihole/pihole.toml'
	[openwrt]='network.stock:/etc/config/network dhcp.stock:/etc/config/dhcp dnsmasq.conf.stock:/etc/dnsmasq.conf'
)
declare -A want_mask=([kea]=0 [isc-dhcp]=0 [dnsmasq]=0 [udhcpd]=1 [pihole]=0 [openwrt]=1)
for t in kea isc-dhcp dnsmasq udhcpd pihole openwrt; do
	want_version=$'kernel\tuname -r'
	[ "$t" != openwrt ] || want_version=$'openwrt\t'"$openwrt_version"
	[ "$(source_version_cmd "$t")" = "$want_version" ] || bad "$t: version $(source_version_cmd "$t")"
	got=$(source_config_pairs "$t" | tr '\n' ' ')
	[ "$got" = "${want_pairs[$t]} " ] || bad "$t: pairs $got"
	[ "$(source_stock_cmd "$t" x.stock)" = "sudo cat /root/lab-stock-config/x.stock" ] || bad "$t: stock read"
	[ "$(source_live_cmd "$t" /etc/x.conf)" = "sudo cat /etc/x.conf" ] || bad "$t: live read"
	[ "$(source_stock_mask "$t")" = "${want_mask[$t]}" ] || bad "$t: stock mask $(source_stock_mask "$t")"
done

for f in source_version_cmd source_config_pairs source_stock_mask source_stock_cmd source_live_cmd; do
	if out=$("$f" not-a-type x 2>/dev/null) || [ -n "$out" ]; then
		bad "$f accepted an unknown type"
	fi
done

# The schema's sourceTypes map, read out of schema.go.
types=$(awk '/^var sourceTypes = /,/}/' "$REPO_ROOT/internal/labyaml/schema.go" | grep -oE '"[a-z0-9-]+": *true' | cut -d'"' -f2)
[ -n "$types" ] || bad "no source types read from schema.go"
for t in $types; do
	for f in source_version_cmd source_config_pairs source_stock_mask source_stock_cmd source_live_cmd; do
		if ! out=$("$f" "$t" x 2>/dev/null) || [ -z "$out" ]; then
			bad "source type $t has no $f arm in source-types.sh"
		fi
	done
done

# capture-source-config-diff.sh end to end with ssh stubbed: the reads it
# sends per type are the ones it sent before the table.
mkdir -p "$tmp/bin"
cat >"$tmp/bin/ssh" <<'STUB'
#!/bin/bash
echo "${!#}" >>"$SSH_LOG"
echo "option=1"
STUB
chmod +x "$tmp/bin/ssh"
for t in kea isc-dhcp dnsmasq udhcpd pihole openwrt; do
	: >"$tmp/ssh.log"
	want=""
	for p in ${want_pairs[$t]}; do
		want+="sudo cat /root/lab-stock-config/${p%%:*}"$'\n'"sudo cat ${p##*:}"$'\n'
	done
	SSH_LOG="$tmp/ssh.log" PATH="$tmp/bin:$PATH" \
		"$REPO_ROOT/scripts/capture-source-config-diff.sh" "c-$t" "$t" 192.0.2.1 "$tmp" "$tmp/ev" >/dev/null ||
		bad "$t: capture failed"
	[ "$(cat "$tmp/ssh.log")"$'\n' = "$want" ] || bad "$t: capture read $(tr '\n' '|' <"$tmp/ssh.log")"
done
if SSH_LOG="$tmp/ssh.log" PATH="$tmp/bin:$PATH" \
	"$REPO_ROOT/scripts/capture-source-config-diff.sh" c-x not-a-type 192.0.2.1 "$tmp" "$tmp/ev" >/dev/null 2>&1; then
	bad "capture accepted an unknown type"
fi

# routeros (#9): RouterOS CLI reads, no shell. The capture sends them as
# they are and drops the CR the CLI ends each line in.
[ "$(source_version_cmd routeros)" = $'routeros\t:put [/system resource get version]' ] || bad "routeros: version $(source_version_cmd routeros)"
[ "$(source_config_pairs routeros)" = lab-stock.rsc:/export ] || bad "routeros: pairs $(source_config_pairs routeros)"
[ "$(source_stock_mask routeros)" = 0 ] || bad "routeros: stock mask"
cat >"$tmp/bin/ssh" <<'STUB'
#!/bin/bash
echo "${!#}" >>"$SSH_LOG"
printf '# 2026-10-10 by RouterOS\r\n/ip pool\r\nadd name=lab\r\n'
[ "${!#}" != /export ] || printf '/system identity\r\nset name=lab-ready\r\n'
STUB
: >"$tmp/ssh.log"
SSH_LOG="$tmp/ssh.log" PATH="$tmp/bin:$PATH" \
	"$REPO_ROOT/scripts/capture-source-config-diff.sh" c-ros routeros 192.0.2.1 "$tmp" "$tmp/ev-ros" >/dev/null ||
	bad "routeros: capture failed"
[ "$(tr '\n' '|' <"$tmp/ssh.log")" = ':put [/file get lab-stock.rsc contents]|/export|' ] || bad "routeros: capture read $(tr '\n' '|' <"$tmp/ssh.log")"
grep -q $'\r' "$tmp"/ev-ros/* && bad "routeros: the diff kept a CR"
{ grep -qx ' add name=lab' "$tmp"/ev-ros/* && grep -qx '+set name=lab-ready' "$tmp"/ev-ros/*; } ||
	bad "routeros: the diff is not stock against live: $(cat "$tmp"/ev-ros/*)"
cat >"$tmp/bin/ssh" <<'STUB'
#!/bin/bash
echo "${!#}" >>"$SSH_LOG"
echo "option=1"
STUB

# A type with pairs and a mask but a stock or live read that is missing (#9)
# or prints nothing: the capture refuses before any ssh and writes no
# diff file. Run against a
# copy of scripts/ whose source-types.sh ends in overrides for a sixth
# type; the real arms still refuse it everywhere else.
mkdir -p "$tmp/repo"
cp -r "$REPO_ROOT/scripts" "$tmp/repo/scripts"
printf '#!/bin/bash\necho 0000000\n' >"$tmp/bin/git"
chmod +x "$tmp/bin/git"
for c in no-stock empty-stock no-live empty-live; do
	{
		cat "$REPO_ROOT/scripts/source-types.sh"
		echo 'source_config_pairs() { echo sixth.conf.stock:/etc/sixth.conf; }'
		echo 'source_stock_mask() { echo 0; }'
		case "$c" in
		no-stock) ;;
		empty-stock) echo 'source_stock_cmd() { :; }' ;;
		*)
			# shellcheck disable=SC2016 # $2 is the override's own argument, read when the copy runs
			echo 'source_stock_cmd() { echo "sudo cat /root/lab-stock-config/$2"; }'
			;;
		esac
		[ "$c" != empty-live ] || echo 'source_live_cmd() { :; }'
	} >"$tmp/repo/scripts/source-types.sh"
	: >"$tmp/ssh.log"
	rm -rf "$tmp/ev6"
	if SSH_LOG="$tmp/ssh.log" PATH="$tmp/bin:$PATH" \
		"$tmp/repo/scripts/capture-source-config-diff.sh" c-six sixth 192.0.2.1 "$tmp" "$tmp/ev6" >/dev/null 2>"$tmp/six.err"; then
		bad "$c: capture accepted a type with a missing read arm"
	fi
	arm=${c#*-}
	grep -q "REFUSED -- source type sixth has no source_${arm}_cmd arm" "$tmp/six.err" ||
		bad "$c: want the missing-arm refusal, got $(tr '\n' '|' <"$tmp/six.err")"
	[ ! -s "$tmp/ssh.log" ] || bad "$c: capture sent reads before refusing: $(tr '\n' '|' <"$tmp/ssh.log")"
	[ -z "$(ls -A "$tmp/ev6" 2>/dev/null)" ] || bad "$c: capture wrote a diff file"
done

[ "$fail" -eq 0 ]
echo "source-types-test: PASS"
