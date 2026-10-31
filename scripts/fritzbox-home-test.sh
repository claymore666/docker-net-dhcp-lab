#!/bin/bash
# Self-test for the home Fritz.Box cell (lab #13): the wire reader and judges on synthetic captures, every env
# refusal of fritzbox-home-run.sh before any docker call, and a rendered bundle that labctl matrix accepts.
set -euo pipefail
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
WIRE=$REPO/scripts/fritzbox-wire.py
RUN=$REPO/scripts/fritzbox-home-run.sh
fails=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got [$2] want [$3]"; fails=$((fails + 1)); fi; }

python3 - "$T" <<'EOF'
import socket, struct, sys
T = sys.argv[1]
R, S = "00:00:5e:00:53:01", "192.0.2.1"
M1, M2, M3 = "02:fd:4b:00:13:01", "02:fd:4b:00:13:02", "02:fd:4b:00:13:03"
mb = lambda s: bytes(int(x, 16) for x in s.split(":"))
def frame(op, esrc, edst, sip, dip, chaddr, xid, ciaddr, yiaddr, opts):
    b = struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0) + socket.inet_aton(ciaddr) + socket.inet_aton(yiaddr)
    b += b"\0" * 8 + mb(chaddr) + b"\0" * 10 + b"\0" * 192 + bytes([99, 130, 83, 99])
    for c, v in opts:
        b += bytes([c, len(v)]) + v
    b += b"\xff"
    sp, dp = (68, 67) if op == 1 else (67, 68)
    u = struct.pack("!HHHH", sp, dp, 8 + len(b), 0) + b
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0, socket.inet_aton(sip), socket.inet_aton(dip))
    return mb(edst) + mb(esrc) + b"\x08\x00" + ip + u
def cl(t, mac, xid, typ, ciaddr="0.0.0.0", unicast=False, extra=(), host="lab-fb-1"):
    o = [(53, bytes([typ])), (61, b"\x01" + mb(mac)), (12, host.encode())] + list(extra)
    if unicast:
        return t, frame(1, mac, R, ciaddr, S, mac, xid, ciaddr, "0.0.0.0", o)
    return t, frame(1, mac, "ff:ff:ff:ff:ff:ff", "0.0.0.0" if ciaddr == "0.0.0.0" else ciaddr, "255.255.255.255", mac, xid, ciaddr, "0.0.0.0", o)
def sv(t, mac, xid, typ, yi):
    o = [(53, bytes([typ])), (54, socket.inet_aton(S)), (51, struct.pack("!I", 86400))]
    return t, frame(2, R, mac, S, "255.255.255.255", mac, xid, "0.0.0.0", yi, o)
def write(name, frames):
    with open(T + "/" + name, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, fr in frames:
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(fr), len(fr)) + fr)
        f.write(b"\x01\x02\x03")  # a truncated record tail, as a live tcpdump -U file can end
ip10, ip11, ip12 = "192.0.2.10", "192.0.2.11", "192.0.2.12"
good = [cl(100, M1, 1, 1, extra=[(80, b"")]), sv(100.1, M1, 1, 5, ip10),
        cl(101, M2, 2, 1, host="lab-fb-2"), sv(101.1, M2, 2, 2, ip11),
        cl(101.2, M2, 2, 3, extra=[(54, socket.inet_aton(S)), (50, socket.inet_aton(ip11))], host="lab-fb-2"), sv(101.3, M2, 2, 5, ip11),
        cl(150, M2, 3, 7, ciaddr=ip11, unicast=True, host="lab-fb-2"),
        cl(200, M1, 4, 3, ciaddr=ip10, unicast=True), sv(200.1, M1, 4, 5, ip10),
        cl(210, M3, 5, 3, extra=[(50, socket.inet_aton(ip12))], host="lab-fb-3"), sv(210.1, M3, 5, 6, "0.0.0.0"),
        cl(220, "02:42:ac:11:00:05", 6, 1, host="someone-else")]
write("good.pcap", good)
write("bad.pcap", [cl(300, "02:42:ac:11:00:06", 7, 1, host="lab-fb-2"), cl(301, M1, 8, 4, extra=[(50, socket.inet_aton(ip10))])])
# E1: bound, renew, then the one RELEASE of release_lease=on_stop.
write("e1.pcap", good[:2] + good[7:9] + [cl(230, M1, 9, 7, ciaddr=ip10, unicast=True)])
EOF

W() { python3 "$WIRE" "$@"; }
MACS=02:fd:4b:00:13:01,02:fd:4b:00:13:02,02:fd:4b:00:13:03
check "ledger: M2 released, M3 NAKed, M1 held with the cid from its own frame" \
	"$(W ledger "$T/good.pcap" --macs "$MACS" --server 192.0.2.1)" "02:fd:4b:00:13:01 192.0.2.10 0102fd4b001301"
check "acked: every address the box ACKed, last holder" \
	"$(W acked "$T/good.pcap" --macs "$MACS" --server 192.0.2.1 | tr '\n' ';')" "192.0.2.10 02:fd:4b:00:13:01;192.0.2.11 02:fd:4b:00:13:02;"
check "exchanges: rapid 2-message, then a unicast renewal" \
	"$(W exchanges "$T/good.pcap" --mac 02:fd:4b:00:13:01 --server 192.0.2.1 | tr '\n' ';')" \
	"discover ACK 192.0.2.10 rapid offers=0 -;renew ACK 192.0.2.10 - offers=0 -;"
check "exchanges: 4-message select counts the OFFER" \
	"$(W exchanges "$T/good.pcap" --mac 02:fd:4b:00:13:02 --server 192.0.2.1 | head -1)" "discover ACK 192.0.2.11 - offers=1 -"
check "exchanges: --since drops the earlier exchange" \
	"$(W exchanges "$T/good.pcap" --mac 02:fd:4b:00:13:01 --server 192.0.2.1 --since 150 | wc -l | tr -d ' ')" "1"
check "exchanges: INIT-REBOOT answered by NAK" \
	"$(W exchanges "$T/good.pcap" --mac 02:fd:4b:00:13:03 --server 192.0.2.1 | awk '{print $1, $2}')" "init-reboot NAK"
rc=0
out=$(W guard "$T/good.pcap" --macs "$MACS" --host-mac 00:00:5e:00:53:99 2>"$T/foreign") || rc=$?
check "guard: a foreign container's DISCOVER is not ours (exit 0, no problem line)" "$rc:$out" "0:"
check "guard: the foreign frame is reported apart" "$(cat "$T/foreign")" "foreign client frame from 02:42:ac:11:00:05 (DISCOVER)"
rc=0
out=$(W guard "$T/bad.pcap" --macs "$MACS" --host-mac 00:00:5e:00:53:99 2>/dev/null) || rc=$?
check "guard: a lab-fb hostname under a Docker MAC, and our DECLINE, abort" "$rc:$(echo "$out" | tr '\n' ';')" \
	"1:DECLINE from 02:fd:4b:00:13:01 for 192.0.2.10;client frame from 02:42:ac:11:00:06 outside the MAC budget (DISCOVER);"

metrics() {
	for n in leases_obtained leases_renewed releases_sent naks_received dhcp_timeouts renewals_unanswered lease_changed; do
		v=0
		case " $* " in *" $n="*) v=$(echo " $* " | sed "s/.* $n=\([0-9]*\) .*/\1/") ;; esac
		echo "net_dhcp_${n}_total{family=\"ipv4\"} $v"
		echo "net_dhcp_${n}_total{family=\"ipv6\"} 0"
	done
}
metrics >"$T/m0"
metrics leases_obtained=1 leases_renewed=1 >"$T/m1"
echo '{"leases_obtained":1,"leases_obtained_v4":1,"leases_obtained_v6":0,"leases_renewed":1,"leases_renewed_v4":1,"leases_renewed_v6":0,"releases_sent":0,"releases_sent_v4":0,"releases_sent_v6":0,"naks_received":0,"naks_received_v4":0,"naks_received_v6":0,"dhcp_timeouts":0,"dhcp_timeouts_v4":0,"dhcp_timeouts_v6":0,"renewals_unanswered":0,"renewals_unanswered_v4":0,"renewals_unanswered_v6":0,"lease_changed":0,"lease_changed_v4":0,"lease_changed_v6":0}' >"$T/h1"
e2() { W e2 --pcap "$T/good.pcap" --mac 02:fd:4b:00:13:01 --server 192.0.2.1 --before "$T/m0" --after "$1" --health "$2" --address "${3:-192.0.2.10}" | head -1; }
check "e2: deltas match the wire, health agrees" "$(e2 "$T/m1" "$T/h1")" PASS
metrics leases_obtained=2 leases_renewed=1 >"$T/m2"
check "e2: an obtained count the wire does not show fails" "$(e2 "$T/m2" "$T/h1")" FAIL
check "e2: an ACK for another address than the container's fails" "$(e2 "$T/m1" "$T/h1" 192.0.2.99)" FAIL
sed 's/"lease_changed_v4":0/"lease_changed_v4":1/' "$T/h1" >"$T/h2"
check "e2: /Plugin.Health disagreeing with /metrics fails" "$(e2 "$T/m1" "$T/h2")" FAIL
check "e2: a missing series is BLOCKED, not PASS" "$(e2 /dev/null "$T/h1")" BLOCKED

metrics leases_obtained=1 leases_renewed=1 releases_sent=1 >"$T/m3"
N=0123456789abcdef
printf '{"kind":"bound","network":"%s","ip":"192.0.2.10"}\n{"kind":"renew","network":"%s","ip":"192.0.2.10"}\n{"kind":"stopped","network":"%s"}\n{"kind":"bound","network":"ffff","ip":"192.0.2.77"}\n' "$N" "$N" "$N" >"$T/l1"
e1() { W e1 --pcap "$T/e1.pcap" --mac 02:fd:4b:00:13:01 --server 192.0.2.1 --before "$T/m0" --after "$2" --ledger "$1" --network "$N" | head -1; }
check "e1: ledger bound+renew equals the wire, one RELEASE equals releases_sent_v4" "$(e1 "$T/l1" "$T/m3")" PASS
check "e1: a RELEASE the counter did not count fails" "$(e1 "$T/l1" "$T/m1")" FAIL
head -1 "$T/l1" >"$T/l2"
check "e1: a renewal missing from the ledger fails" "$(e1 "$T/l2" "$T/m3")" FAIL
{ cat "$T/l1"; printf '{"kind":"rebound","network":"%s","ip":"192.0.2.10"}\n' "$N"; } >"$T/l3"
check "e1: an unknown ledger kind is BLOCKED" "$(e1 "$T/l3" "$T/m3")" BLOCKED

check "redact: live prefix and MACs, not a longer number" \
	"$(echo 'got 10.1.7.5 via 00:11:22:33:44:55 host AA:BB:CC:DD:EE:FF not 110.1.7.5' |
		FB_PREFIX=10.1.7. FB_ROUTER_MAC=00:11:22:33:44:55 FB_HOST_MAC=aa:bb:cc:dd:ee:ff W redact)" \
	"got 192.0.2.5 via box-mac host host-mac not 110.1.7.5"

# Refusals: each exits 2 before any docker call (a docker stub on PATH records a call).
mkdir -p "$T/bin"
printf '#!/bin/sh\necho called >>"%s/docker-called"\necho 26.1.5\n' "$T" >"$T/bin/docker"
chmod +x "$T/bin/docker"
refuse() {
	local name=$1 want=$2
	shift 2
	local rc=0
	env -i PATH="$T/bin:/usr/bin:/bin" "$@" bash "$RUN" "${ARG:-run}" >/dev/null 2>"$T/err" || rc=$?
	check "refuse: $name" "$rc:$([ -e "$T/docker-called" ] && echo docker || echo none):$(grep -cF "$want" "$T/err")" "2:none:1"
}
ok=(FB_CONFIRM=home-fritzbox-nondisruptive FB_OUT="$T/out" FB_PARENT=lo)
C=FB_CONFIRM=home-fritzbox-nondisruptive
ARG=bogus refuse "unknown subcommand" "usage:" "${ok[@]}"
refuse "no FB_CONFIRM" "FB_CONFIRM must be" FB_OUT="$T/out" FB_PARENT=lo
refuse "wrong FB_CONFIRM" "FB_CONFIRM must be" FB_CONFIRM=yes FB_OUT="$T/out" FB_PARENT=lo
refuse "no FB_OUT" "FB_OUT is not set" "$C" FB_PARENT=lo
refuse "relative FB_OUT" "must be an absolute path" "$C" FB_OUT=out FB_PARENT=lo
refuse "FB_OUT inside the repo" "outside the repo" "$C" FB_OUT="$REPO/results/x" FB_PARENT=lab-fb-nope0
refuse "no FB_PARENT" "FB_PARENT is not set" "$C" FB_OUT="$T/out"
refuse "FB_PARENT not a link" "is not a link" "$C" FB_OUT="$T/out" FB_PARENT=lab-fb-nope0
ARG=cleanup refuse "cleanup without FB_CONFIRM" "FB_CONFIRM must be" FB_OUT="$T/out" FB_PARENT=lo

# Render: a finished run's results become a bundle labctl matrix accepts, redacted, one verdict per catalog row
# and shape.
O=$T/run
mkdir -p "$O/ev/macvlan/A1"
printf 'ROUTER=10.1.7.1\nPREFIX=10.1.7.\nROUTER_MAC=00:11:22:33:44:55\nHOST_MAC=aa:bb:cc:dd:ee:ff\n' >"$O/lan.env"
printf 'macvlan\tA1\tPASS\t2026-10-31T12:00:00Z\tgot 10.1.7.23 from 00:11:22:33:44:55\nmacvlan-ipam\tA1\tFAIL\t2026-10-31T12:01:00Z\tno ACK\n' >"$O/results.tsv"
echo 'discover ACK 10.1.7.23 - offers=1 -' >"$O/ev/macvlan/A1/exchanges-1.txt"
PATH="$T/bin:$PATH" FB_CONFIRM=home-fritzbox-nondisruptive FB_OUT="$O" bash "$RUN" render >/dev/null
B=$O/bundle
want=$(($(grep -cE '^\s*Name[A-Za-z0-9]+\s*= "' "$REPO/internal/scenario/catalog.go") * 2))
check "render: one verdict per catalog row and shape" "$(find "$B" -name '*.verdict' | wc -l | tr -d ' ')" "$want"
check "render: PASS carries its redacted evidence" "$(cat "$B/evidence/macvlan/A1-first-lease/exchanges-1.txt")" "discover ACK 192.0.2.23 - offers=1 -"
check "render: no live prefix or MAC anywhere in the bundle" "$(grep -rlE '10\.1\.7\.|00:11:22:33:44:55|aa:bb:cc:dd:ee:ff' "$B" | wc -l | tr -d ' ')" "0"
check "render: a row outside the plan is N/A with the plan's reason" \
	"$(sed -n 's/^reason: //p' "$B/fritzbox-home-macvlan-C7-rogue-server.verdict")" \
	"home router, non-disruptive cell: needs a router config change, stopping or disturbing the router, a rogue or squatting host, or weeks of run time"
(cd "$REPO" && go run ./cmd/labctl matrix --root "$B" --out "$T/page.md" "$B") >/dev/null
check "render: labctl matrix reads the bundle (1 PASS, 1 FAIL)" \
	"$(grep -oF '[PASS](' "$T/page.md" | wc -l | tr -d ' ')/$(grep -oF '[FAIL](' "$T/page.md" | wc -l | tr -d ' ')" "1/1"

# docker compose 2.26.1 on engine API 1.45 drops a service-level mac_address and keeps the per-network key (measured
# on the session box, lab #13 run 1 aborted on it); A3's compose file must pin the MAC under the network.
a3=$(sed -n '/^s_A3() {/,/^EOF$/p' "$RUN")
check "A3 compose pins the MAC under its network, not at service level" \
	"$(echo "$a3" | grep -cE '^        mac_address: ')/$(echo "$a3" | grep -cE '^    mac_address: ')" "1/0"

[ "$fails" -eq 0 ] || { echo "fritzbox-home-test.sh: $fails failed" >&2; exit 1; }
echo "fritzbox-home-test.sh: all passed"
