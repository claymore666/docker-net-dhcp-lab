#!/bin/bash
# up-source.sh's IPv6 gate is driven by the source type (lab #10, #23): a
# type that serves DHCPv6 is refused without its v6 fields, a v4-only type
# (udhcpd, pihole) passes without them and renders no v6 address. UP_SOURCE_RENDER_ONLY
# stops the script after the seed files, so no VM, image or key is touched.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

# Case 1: each v4-only cell (udhcpd, pihole) passes and its network-config
# has no v6 address. The placeholder up-source.sh hands the renderer for the
# dropped item (the literal none) must never reach an address: no code line
# contains it, and eth1's address list is exactly one IPv4 item.
for typ in udhcpd pihole; do
	w="$tmp/w1-$typ"
	if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh "$typ" "$w" 2>&1); then
		echo "up-source-test: $typ cell refused: $out" >&2
		fail=1
		continue
	fi
	nc="$w/seed-source/network-config"
	if grep -q '::\|SEG_ADDR6\|""' "$nc"; then
		echo "up-source-test: $typ network-config carries a v6 address" >&2
		cat "$nc" >&2
		fail=1
	fi
	if grep -v '^[[:space:]]*#' "$nc" | grep -qw 'none'; then
		echo "up-source-test: $typ network-config carries the literal none" >&2
		cat "$nc" >&2
		fail=1
	fi
	eth1_addrs=$(awk '/set-name: eth1/{on=1;next} on && /addresses:/{print;exit}' "$nc")
	if ! grep -qE '^[[:space:]]+addresses: \[[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}\]$' <<<"$eth1_addrs"; then
		echo "up-source-test: $typ eth1 addresses is not exactly one IPv4 item: $eth1_addrs" >&2
		fail=1
	fi
done

# Case 2: the kea cell with its v6 fields passes and keeps the v6 address.
if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh kea "$tmp/w2" 2>&1); then
	echo "up-source-test: kea cell refused: $out" >&2
	fail=1
elif ! grep -q 'fd42:200:0:100::2/64' "$tmp/w2/seed-source/network-config"; then
	echo "up-source-test: kea network-config lost its v6 address" >&2
	fail=1
fi

# Case 3: the kea cell without its v6 block (the schema allows it; the
# script must not) is refused, naming the missing field.
awk '
/^  - name: /{ inkea = ($3 == "kea") }
inkea && /^[[:space:]]+(subnet6|seg_address6|pool6_start|pool6_end|temp6_pool):/ { next }
{ print }' lab.yaml >"$tmp/nov6.yaml"
if out=$(LAB_YAML="$tmp/nov6.yaml" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh kea "$tmp/w3" 2>&1); then
	echo "up-source-test: kea cell without v6 was accepted" >&2
	fail=1
elif ! grep -q 'has no seg_subnet6' <<<"$out"; then
	echo "up-source-test: kea refusal does not name the missing field: $out" >&2
	fail=1
fi

# Case 4: the kea-ha partner (#12) renders into its own seed dir with its
# own hostname and the HA template, inside the seed hook (#9).
w4="$tmp/w4"
if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh kea-ha "$w4" partner 2>&1); then
	echo "up-source-test: kea-ha partner refused: $out" >&2
	fail=1
elif [ -e "$w4/seed-source" ] || ! grep -qx 'local-hostname: lab-kea-partner' "$w4/seed-partner/meta-data" ||
	! grep -q '^hostname: lab-kea-partner$' "$w4/seed-partner/user-data" ||
	! grep -q 'fd42:200:0:800::3/64' "$w4/seed-partner/network-config"; then
	echo "up-source-test: kea-ha partner seed is not its own: $(ls "$w4")" >&2
	fail=1
fi

# Case 4b: the isc-failover pair (#12). The partner renders the secondary
# role with mclt and split commented out (dhcpd.conf(5) refuses them there)
# and the primary keeps both, each peer pointing at the other.
w4b="$tmp/w4b"
for peer in primary partner; do
	arg=
	[ "$peer" != partner ] || arg=partner
	if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh isc-failover "$w4b" $arg 2>&1); then
		echo "up-source-test: isc-failover $peer refused: $out" >&2
		fail=1
		continue
	fi
	[ "$peer" = partner ] && ud="$w4b/seed-partner/user-data" || ud="$w4b/seed-source/user-data"
	if grep -q '__FO_\|__HA_' "$ud"; then
		echo "up-source-test: isc-failover $peer keeps a placeholder" >&2
		fail=1
	fi
	if [ "$peer" = partner ]; then
		for want in 'secondary;' 'address 10.200.9.3;' 'peer address 10.200.9.2;' '# mclt 60;' '# split 128;'; do
			grep -qF "$want" "$ud" || { echo "up-source-test: isc-failover partner lacks $want" >&2; fail=1; }
		done
		grep -qE '^ +mclt 60;|^ +split 128;' "$ud" && { echo "up-source-test: isc-failover partner keeps mclt or split" >&2; fail=1; }
	else
		for want in ' primary;' 'address 10.200.9.2;' 'peer address 10.200.9.3;' ' mclt 60;' ' split 128;'; do
			grep -qF "$want" "$ud" || { echo "up-source-test: isc-failover primary lacks $want" >&2; fail=1; }
		done
		grep -qE '# (mclt|split)' "$ud" && { echo "up-source-test: isc-failover primary comments mclt or split out" >&2; fail=1; }
	fi
done

# Case 5: the chr cell (#9) renders its three RouterOS scripts and the key
# with every placeholder filled, and the seed script disables the stock
# admin and sets the identity ready_qga waits for as its last line.
w5="$tmp/w5"
if ! out=$(UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh chr "$w5" 2>&1); then
	echo "up-source-test: chr cell refused: $out" >&2
	fail=1
else
	d="$w5/seed-source"
	if grep -l '__' "$d"/*.rsc >&2; then
		echo "up-source-test: chr seed keeps a placeholder" >&2
		fail=1
	fi
	grep -qx 'ssh-ed25519 AAAA render-only' "$d/lab.pub" || {
		echo "up-source-test: chr lab.pub is not the key" >&2
		fail=1
	}
	for want in 'lab-mgmt.rsc:address=10.200.255.141/24}' 'lab-mgmt.rsc:gateway=10.200.255.1}' \
		'lab-baseline.rsc:address=10.200.14.2/24$' 'lab-baseline.rsc:ranges=10.200.14.100-10.200.14.200}' \
		'lab-baseline.rsc:ranges=10.200.14.221-10.200.14.230}' 'lab-baseline.rsc:gateway=10.200.14.2$' \
		'lab-seed.rsc:^/user set \[find name=admin\] disabled=yes$'; do
		grep -q "${want#*:}" "$d/${want%%:*}" || {
			echo "up-source-test: chr ${want%%:*} lacks ${want#*:}" >&2
			fail=1
		}
	done
	[ "$(grep -v '^#' "$d/lab-mgmt.rsc" | head -1)" = ':if ([:len [/file find name=lab-stock.rsc]] = 0) do={/export file=lab-stock}' ] || {
		echo "up-source-test: chr lab-mgmt.rsc does not keep the vendor export before its first change" >&2
		fail=1
	}
	# printf keeps the service name off the ssh-call gate in verify.sh (lab #9).
	[ "$(grep -v '^#' "$d/lab-mgmt.rsc" | sed -n 2,3p | tr '\n' '|')" = "$(printf '/ip service disable [find name!=%s dynamic=no]|/ipv6 settings set disable-ipv6=yes|' "ssh")" ] || {
		echo "up-source-test: chr lab-mgmt.rsc does not close the stock services and IPv6 right after the export" >&2
		fail=1
	}
	[ "$(grep -v '^#' "$d/lab-seed.rsc" | tail -1)" = '/system identity set name=lab-ready' ] || {
		echo "up-source-test: chr lab-seed.rsc does not end on the identity" >&2
		fail=1
	}
fi

# Case 6: the baked seed (#9) passes only when the cache's build id is
# the one the build script derives from the cell as lab.yaml has it now;
# a pool edit after the build is refused (defeat N2).
cache="$tmp/cache"
mkdir -p "$cache"
LAB_PUBKEY="ssh-ed25519 AAAA render-only" ./scripts/build-openwrt-image.sh --id openwrt >"$cache/openwrt-25.12.5-x86-64.build-id"
if ! out=$(LAB_IMAGE_CACHE="$cache" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh openwrt "$tmp/w6" 2>&1); then
	echo "up-source-test: openwrt refused a current build id: $out" >&2
	fail=1
fi
sed '/^  - name: openwrt$/,$ s/pool_end: 10\.200\.15\.200/pool_end: 10.200.15.199/' lab.yaml >"$tmp/stale.yaml"
if cmp -s lab.yaml "$tmp/stale.yaml"; then
	echo "up-source-test: the openwrt pool edit did not apply" >&2
	fail=1
elif out=$(LAB_YAML="$tmp/stale.yaml" LAB_IMAGE_CACHE="$cache" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh openwrt "$tmp/w6b" 2>&1) ||
	! grep -q 'run scripts/build-openwrt-image.sh openwrt' <<<"$out"; then
	echo "up-source-test: openwrt accepted a stale image: $out" >&2
	fail=1
fi

# Case 7: the windows seed (#14) is baked the same way: the cache's build
# id must be the one build-windows-image.sh derives from the cell now, and
# the run path is no longer refused for the kind.
wid=$(LAB_PUBKEY="ssh-ed25519 AAAA render-only" ./scripts/build-windows-image.sh --id windows)
printf '%s\n' "$wid" >"$cache/windows-2025-eval.build-id"
if ! out=$(LAB_IMAGE_CACHE="$cache" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh windows "$tmp/w7" 2>&1); then
	echo "up-source-test: windows refused a current build id: $out" >&2
	fail=1
fi
echo "an-older-id" >"$cache/windows-2025-eval.build-id"
if out=$(LAB_IMAGE_CACHE="$cache" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh windows "$tmp/w7b" 2>&1) ||
	! grep -q 'run scripts/build-windows-image.sh windows' <<<"$out"; then
	echo "up-source-test: windows accepted a stale image: $out" >&2
	fail=1
fi
rm -f "$cache/windows-2025-eval.build-id"
if out=$(LAB_IMAGE_CACHE="$cache" UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh windows "$tmp/w7c" 2>&1) ||
	! grep -q "holds 'nothing'" <<<"$out"; then
	echo "up-source-test: windows accepted a missing build id: $out" >&2
	fail=1
fi

# Case 8: the windows run path with stubbed virsh, virt-install, qemu-img,
# sudo, sleep and ssh. ready_windows is ready only when ssh answers AND the
# marker read through powershell holds exactly the cell's id; the bound is
# a variable and defaults to 60 tries.
w8="$tmp/w8"
mkdir -p "$w8/bin" "$w8/home/.ssh" "$w8/cache"
ssh-keygen -q -t ed25519 -N '' -f "$w8/home/.ssh/id_ed25519_lab" -C test
cat >"$w8/bin/sudo" <<'STUB'
#!/bin/bash
[ "$1" = -n ] && shift
exec "$@"
STUB
cat >"$w8/bin/virsh" <<'STUB'
#!/bin/bash
[ "$1" = dominfo ] && exit 1
exit 0
STUB
cat >"$w8/bin/virt-install" <<'STUB'
#!/bin/bash
echo "$*" >>"$STUB_DIR/virt-install.log"
STUB
cat >"$w8/bin/qemu-img" <<'STUB'
#!/bin/bash
exit 0
STUB
cat >"$w8/bin/sleep" <<'STUB'
#!/bin/bash
echo "$1" >>"$STUB_DIR/sleep.log"
STUB
cat >"$w8/bin/ssh" <<'STUB'
#!/bin/bash
echo "$*" >>"$STUB_DIR/ssh.log"
n=$(wc -l <"$STUB_DIR/ssh.log")
if [ "$n" -le "${STUB_SSH_FAIL_FIRST:-0}" ] || [ -n "${STUB_SSH_DOWN:-}" ]; then exit 255; fi
printf '%s' "${@: -1}" | base64 -d | iconv -f UTF-16LE -t UTF-8 >>"$STUB_DIR/ps.log"
printf '\n' >>"$STUB_DIR/ps.log"
printf '%s' "$STUB_MARKER"
STUB
chmod +x "$w8"/bin/*
touch -d '2 minutes ago' "$w8/cache/windows-2025-eval.qcow2"
wid8=$(LAB_PUBKEY=$(cat "$w8/home/.ssh/id_ed25519_lab.pub") ./scripts/build-windows-image.sh --id windows)
printf '%s\n' "$wid8" >"$w8/cache/windows-2025-eval.build-id"
realgo=$(command -v go)
gocache=$("$realgo" env GOCACHE)
gomod=$("$realgo" env GOMODCACHE)

run8() { # run8 NAME [VAR=value ...]: one up-source.sh windows run in a fresh work dir
	local name=$1
	shift
	rm -rf "$w8/work-$name" "$w8/stub-$name"
	mkdir -p "$w8/stub-$name" "$w8/work-$name"
	: >"$w8/stub-$name/ssh.log"
	touch "$w8/work-$name/lab-windows-source.qcow2"
	env "$@" PATH="$w8/bin:$PATH" HOME="$w8/home" GOCACHE="$gocache" GOMODCACHE="$gomod" \
		LAB_IMAGE_CACHE="$w8/cache" STUB_DIR="$w8/stub-$name" \
		./scripts/up-source.sh windows "$w8/work-$name" >"$w8/out-$name" 2>&1
}
calls() { wc -l <"$w8/stub-$1/ssh.log"; }

if ! run8 ok STUB_MARKER="$wid8"$'\r\n' UP_SOURCE_READY_TRIES=3 UP_SOURCE_READY_TICK=0; then
	echo "up-source-test: windows with the current marker did not come up: $(cat "$w8/out-ok")" >&2
	fail=1
elif ! grep -q 'ready at 10.200.255.161' "$w8/out-ok" ||
	! grep -q 'lab@10.200.255.161 powershell -NonInteractive -EncodedCommand' "$w8/stub-ok/ssh.log" ||
	! grep -qF 'C:\ProgramData\lab\bootstrap-done' "$w8/stub-ok/ps.log" ||
	! grep -q -- '--os-variant win2k25' "$w8/stub-ok/virt-install.log"; then
	echo "up-source-test: windows ready run lacks its ssh/powershell/virt-install evidence: $(cat "$w8/out-ok")" >&2
	fail=1
fi

# Unreachable: the bound is the number of tries, then a loud refusal.
if run8 down STUB_SSH_DOWN=1 UP_SOURCE_READY_TRIES=3 UP_SOURCE_READY_TICK=0 ||
	! grep -q 'windows did not finish inside the bound' "$w8/out-down" || [ "$(calls down)" -ne 3 ]; then
	echo "up-source-test: unreachable windows source: rc/message/tries wrong ($(calls down) probes): $(cat "$w8/out-down")" >&2
	fail=1
fi

# Reachable but the marker is another build's: not ready (defeat: ssh alone).
for bad in "an-older-id" "${wid8}x" "x${wid8}" ""; do
	if run8 stale STUB_MARKER="$bad" UP_SOURCE_READY_TRIES=3 UP_SOURCE_READY_TICK=0 ||
		! grep -q 'windows did not finish inside the bound' "$w8/out-stale" || [ "$(calls stale)" -ne 3 ]; then
		echo "up-source-test: windows with marker '$bad' counted as ready: $(cat "$w8/out-stale")" >&2
		fail=1
	fi
done

# Slow to come up: two unreachable tries, then ready.
if ! run8 slow STUB_SSH_FAIL_FIRST=2 STUB_MARKER="$wid8" UP_SOURCE_READY_TRIES=5 UP_SOURCE_READY_TICK=0 ||
	[ "$(calls slow)" -ne 3 ]; then
	echo "up-source-test: windows that answers on the third try: $(calls slow) calls: $(cat "$w8/out-slow")" >&2
	fail=1
fi

# The default bound is 60 tries of 10 s.
if run8 dflt STUB_SSH_DOWN=1 ||
	[ "$(calls dflt)" -ne 60 ] || [ "$(sort -u "$w8/stub-dflt/sleep.log")" != 10 ]; then
	echo "up-source-test: default bound is not 60 x 10 s ($(calls dflt) calls, sleeps '$(sort -u "$w8/stub-dflt/sleep.log" | tr '\n' ' ')')" >&2
	fail=1
fi

# A custom tick is the sleep between tries, not a constant (lab #14).
if run8 tick STUB_SSH_DOWN=1 UP_SOURCE_READY_TRIES=4 UP_SOURCE_READY_TICK=7 ||
	[ "$(calls tick)" -ne 4 ] || [ "$(sort -u "$w8/stub-tick/sleep.log")" != 7 ]; then
	echo "up-source-test: UP_SOURCE_READY_TICK=7 did not give 4 tries of 7 s" >&2
	fail=1
fi

# A bad bound is refused before any VM is created.
for bad in "UP_SOURCE_READY_TRIES=0" "UP_SOURCE_READY_TRIES=x" "UP_SOURCE_READY_TICK=-1"; do
	if run8 badb "$bad" STUB_MARKER="$wid8" ||
		! grep -q 'must be whole numbers' "$w8/out-badb" || [ -e "$w8/stub-badb/virt-install.log" ]; then
		echo "up-source-test: bound '$bad' was not refused up front: $(cat "$w8/out-badb")" >&2
		fail=1
	fi
done

# A stale build id is refused on the run path too, before any VM exists.
echo "an-older-id" >"$w8/cache/windows-2025-eval.build-id"
if run8 oldid STUB_MARKER="$wid8" UP_SOURCE_READY_TRIES=3 UP_SOURCE_READY_TICK=0 ||
	! grep -q 'run scripts/build-windows-image.sh windows' "$w8/out-oldid" || [ -e "$w8/stub-oldid/virt-install.log" ]; then
	echo "up-source-test: a stale windows image reached virt-install: $(cat "$w8/out-oldid")" >&2
	fail=1
fi

[ "$fail" -eq 0 ] && echo "up-source-test: ok"
exit "$fail"
