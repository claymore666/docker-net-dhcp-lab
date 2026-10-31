#!/bin/bash
# shellcheck disable=SC2015 # every 'a && b || fail' here means: fail when either step fails
# Home Fritz.Box cell (lab #13): the approved non-disruptive scenarios against a home router, from a Docker host
# on its LAN. The LAN (subnet, router, MACs) is read from the host at run time, so no home detail enters the repo;
# the box's lease table needs a login, so verdicts rest on its own frames in the capture.
#   fritzbox-home-run.sh run       scenarios, then cleanup (also on abort)
#   fritzbox-home-run.sh cleanup   idempotent cleanup alone, e.g. after a power cut
#   fritzbox-home-run.sh render    redacted verdict bundle from a finished run
# Env: FB_PARENT (host NIC on the LAN), FB_OUT (absolute, outside the repo), FB_CONFIRM=home-fritzbox-nondisruptive;
# optional FB_PLUGIN_TAG (v2.7.0), FB_PREV_TAG (v2.6.1), FB_DEADLINE_MIN (95).
set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CMD=${1:-}
TAG=${FB_PLUGIN_TAG:-v2.7.0}
PREV=${FB_PREV_TAG:-v2.6.1}
DEADLINE_MIN=${FB_DEADLINE_MIN:-95}
IMAGE_REPO=ghcr.io/claymore666/docker-net-dhcp
CERT_ID='^https://github.com/claymore666/docker-net-dhcp/.github/workflows/release.yml@'
CERT_ISSUER=https://token.actions.githubusercontent.com
COSIGN=${FB_COSIGN:-cosign}
IMG=lab-fb-tools:1
HELPER=lab-fb-helper
ALIAS=lab-fb-dhcp:$TAG
UPALIAS=lab-fb-dhcp-up:latest
# Each alias keeps its own STATE_DIR under the host bind mount, so the host's other plugins' state is never shared.
MAIN_STATE=/var/lib/net-dhcp/lab-fb-main
UP_STATE=/var/lib/net-dhcp/lab-fb-up
MACS=(02:fd:4b:00:13:01 02:fd:4b:00:13:02 02:fd:4b:00:13:03 02:fd:4b:00:13:04 02:fd:4b:00:13:05 02:fd:4b:00:13:06)
MACLIST=$(IFS=,; echo "${MACS[*]}")
CELL=fritzbox-home
ROUTER="" PREFIX="" ROUTER_MAC="" HOST_MAC="" BASE_ADDR="" BASE_ROUTE="" T0=0
SCENARIOS=(A1 A2 A3 A6 A8 A9 A10 A11 A12 A13 A16 B3 B4 B7 B8 F3-rapid-commit-v4 E1 E2)

die() { echo "fritzbox-home-run.sh: $*" >&2; exit 2; }

check_env() {
	case "$CMD" in run | cleanup | render) ;; *) die "usage: $0 run|cleanup|render" ;; esac
	[ "${FB_CONFIRM:-}" = home-fritzbox-nondisruptive ] || die "FB_CONFIRM must be home-fritzbox-nondisruptive"
	[ -n "${FB_OUT:-}" ] || die "FB_OUT is not set"
	case "$FB_OUT" in /*) ;; *) die "FB_OUT must be an absolute path" ;; esac
	case "$FB_OUT/" in "$REPO"/*) die "FB_OUT must be outside the repo: pcaps are never published" ;; esac
	[ "$CMD" = render ] && return 0
	[ -n "${FB_PARENT:-}" ] || die "FB_PARENT is not set"
	[ -e "/sys/class/net/$FB_PARENT" ] || die "FB_PARENT $FB_PARENT is not a link on this host"
}

OUT=${FB_OUT:-}
LOG=$OUT/run.log
RES=$OUT/results.tsv
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

# lan reads the LAN once and keeps it in FB_OUT, so a cleanup after a power cut uses the run's own values.
lan() {
	if [ -s "$OUT/lan.env" ]; then
		# shellcheck disable=SC1091
		. "$OUT/lan.env"
		return 0
	fi
	local cidr router rmac hmac
	cidr=$(ip -4 -o addr show dev "$FB_PARENT" scope global | awk '{print $4; exit}')
	[ -n "$cidr" ] || die "$FB_PARENT carries no IPv4 address"
	[ "${cidr#*/}" = 24 ] || die "$FB_PARENT is on a /${cidr#*/}; this run handles a /24 only"
	router=$(ip -4 route show default dev "$FB_PARENT" | awk '{print $3; exit}')
	[ -n "$router" ] || die "no default route via $FB_PARENT"
	ping -c1 -W2 "$router" >/dev/null 2>&1 || die "the router does not answer ping"
	rmac=$(ip neigh show "$router" dev "$FB_PARENT" | awk '{for (i = 1; i < NF; i++) if ($i == "lladdr") print $(i + 1)}')
	[ -n "$rmac" ] || die "no neighbour entry for the router"
	hmac=$(cat "/sys/class/net/$FB_PARENT/address")
	{
		echo "ROUTER=$router"
		echo "PREFIX=${cidr%.*/*}."
		echo "ROUTER_MAC=$rmac"
		echo "HOST_MAC=$hmac"
		echo "BASE_ADDR='$cidr'"
		echo "BASE_ROUTE='$(ip -4 route show default | tr '\n' ' ')'"
		echo "T0=$(date +%s)"
	} >"$OUT/lan.env"
	# shellcheck disable=SC1091
	. "$OUT/lan.env"
}

H() { docker exec "$HELPER" "$@"; }
W() { docker exec -e FB_PREFIX="$PREFIX" -e FB_ROUTER_MAC="$ROUTER_MAC" -e FB_HOST_MAC="$HOST_MAC" "$HELPER" python3 /s/fritzbox-wire.py "$@"; }

build_image() {
	docker image inspect "$IMG" >/dev/null 2>&1 && return 0
	log "building $IMG"
	printf '%s\n' 'FROM debian:13' \
		'RUN apt-get update && apt-get install -y --no-install-recommends python3 tcpdump iproute2 iputils-ping arping dnsutils curl procps && rm -rf /var/lib/apt/lists/*' |
		docker build -q -t "$IMG" - >>"$LOG" 2>&1
}

helper_up() {
	if [ "$(docker inspect -f '{{.State.Running}}' "$HELPER" 2>/dev/null)" = true ]; then return 0; fi
	docker rm -f "$HELPER" >/dev/null 2>&1
	build_image || return 1
	mkdir -p "$OUT/cap"
	docker run -d --name "$HELPER" --net host --pid host --privileged \
		-v "$OUT:/w" -v "$REPO/scripts:/s:ro" -v /var/lib/net-dhcp:/state -v /run/docker/plugins:/rdp:ro \
		--entrypoint sleep "$IMG" infinity >/dev/null
}

# Captures: full = every frame of the six MACs, the box's DHCP replies and the host's own DHCP frames (the plugin sends
# release_lease RELEASEs from the parent's address); out = every DHCP client frame leaving
# the parent, which the guard reads for MACs outside the budget.
# cap_alive is true only for our own tcpdump writing that file: a pid file left by a power cut may name a reused pid.
cap_alive() {
	H sh -c "p=\$(cat /w/cap/$1.pid 2>/dev/null) && tr '\\0' ' ' </proc/\$p/cmdline 2>/dev/null | grep -q 'tcpdump .*/w/cap/$1.pcap'"
}

cap_start() {
	local name=$1 filter=$2 extra=${3:-}
	cap_alive "$name" && return 0
	docker exec -d "$HELPER" sh -c "echo \$\$ > /w/cap/$name.pid; exec tcpdump -p -U $extra -i $FB_PARENT -n -s0 -w /w/cap/$name.pcap '$filter' 2> /w/cap/$name.err"
	sleep 2
}

# A capture restarted after a power cut writes new files, so the run's own pcaps are never overwritten.
SUF=""
captures_start() {
	local f="" m n
	n=$(find "$OUT/cap" -name 'full*.pcap' 2>/dev/null | wc -l)
	for m in "${MACS[@]}"; do f="$f${f:+ or }ether host $m"; done
	SUF=""
	[ "$n" -gt 0 ] && ! cap_alive full && SUF=$n
	cap_start "full$SUF" "($f) or (ether src $ROUTER_MAC and udp src port 67) or (ether src $HOST_MAC and udp dst port 67)"
	cap_start "out$SUF" 'udp dst port 67' '-Q out'
}

pcaps() { find "$OUT/cap" -name 'full*.pcap' -printf '/w/cap/%f\n' | sort; }
lastcap() { pcaps | tail -1; }

captures_stop() {
	local p n
	for p in "$OUT"/cap/*.pid; do
		[ -e "$p" ] || continue
		n=$(basename "$p" .pid)
		cap_alive "$n" && H sh -c "kill -INT \$(cat /w/cap/$n.pid)"
		H rm -f "/w/cap/$n.pid"
	done
	sleep 2
}

drops() { cat "$OUT"/cap/*.err 2>/dev/null | awk '/dropped by kernel/ {s += $1} END {print s + 0}'; }

held() {
	local -a p
	mapfile -t p < <(pcaps)
	W ledger "${p[@]}" --macs "$MACLIST" --server "$ROUTER"
}

# release_held hands back every address the box ACKed to one of our MACs and nobody released since, with the client
# id from our own REQUEST (the box honours chaddr + cid + ciaddr, measured P4 in the keep measurement).
release_held() {
	local mac ip cid
	sleep 1
	held | while read -r mac ip cid; do
		[ -n "$ip" ] || continue
		[ "$cid" = - ] && cid=""
		log "release $ip held by $mac"
		W release --iface "$FB_PARENT" --mac "$mac" --ip "$ip" --server "$ROUTER" --smac "$ROUTER_MAC" --cid "$cid" >>"$LOG"
	done
	sleep 1
}

ABORT=""
abort() { ABORT=$1; log "ABORT: $1"; exit 3; }

# between is the containment check run before every scenario and after every container start.
between() {
	local g
	g=$(W guard /w/cap/out.pcap --macs "$MACLIST" --host-mac "$HOST_MAC" 2>>"$OUT/foreign.txt") || abort "guard: $g"
	[ "$(ip -4 -o addr show dev "$FB_PARENT" scope global | awk '{print $4; exit}')" = "$BASE_ADDR" ] || abort "the host's own address on $FB_PARENT changed"
	[ "$(ip -4 route show default | tr '\n' ' ')" = "$BASE_ROUTE" ] || abort "the host's default route changed"
	ping -c2 -W2 "$ROUTER" >/dev/null 2>&1 || abort "the router stopped answering the host's ping"
	[ "$(held | wc -l)" -le 4 ] || abort "more than four leases held"
	[ "$(($(date +%s) - T0))" -lt "$((DEADLINE_MIN * 60))" ] || abort "scenario deadline of $DEADLINE_MIN min reached"
}

# --- Docker objects. Everything is named lab-fb-*, and only exact names from these lists are ever removed. ---
ours() { docker "$1" ls -a --format '{{.Names}}' 2>/dev/null | grep -E '^lab-fb-' | grep -vx "$HELPER"; }
our_nets() { docker network ls --format '{{.Name}}' | grep -E '^lab-fb-'; }

teardown_objects() {
	local c n
	for c in $(ours container); do docker rm -f "$c" >/dev/null 2>&1; done
	for n in $(our_nets); do docker network rm "$n" >/dev/null 2>&1 || log "network rm $n failed"; done
}

digest_of() {
	local tag=$1 out
	out=$("$COSIGN" verify "$IMAGE_REPO:$tag" --certificate-identity-regexp "$CERT_ID" --certificate-oidc-issuer "$CERT_ISSUER" 2>>"$LOG") || return 1
	echo "$out" | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["critical"]["image"]["docker-manifest-digest"])'
}

# install_alias verifies the release signature, installs that digest disabled, checks the reference, then enables.
install_alias() {
	local alias=$1 tag=$2 state=$3 dg ref
	dg=$(digest_of "$tag") || { log "cosign verify $tag failed"; return 1; }
	log "install $alias from $tag ($dg)"
	docker plugin install --alias "$alias" --grant-all-permissions --disable "$IMAGE_REPO@$dg" "STATE_DIR=$state" >>"$LOG" 2>&1 || return 1
	ref=$(docker plugin inspect -f '{{.PluginReference}}' "$alias")
	[ "$ref" = "$IMAGE_REPO@$dg" ] || { log "reference $ref is not $IMAGE_REPO@$dg"; return 1; }
	docker plugin inspect -f '{{range .Settings.Env}}{{println .}}{{end}}' "$alias" | grep -qx "STATE_DIR=$state" || { log "$alias lacks STATE_DIR=$state"; return 1; }
	docker plugin enable "$alias" >>"$LOG" 2>&1
}

plugin_rm() { docker plugin inspect "$1" >/dev/null 2>&1 && docker plugin rm -f "$1" >/dev/null 2>&1; }

sock_get() { H curl -sf --unix-socket "/rdp/$(docker plugin inspect -f '{{.Id}}' "$1")/net-dhcp.sock" "http://localhost$2"; }

# --- scenario helpers ---
S="" SHAPE="" EVD="" SINCE=0 R="" WHY=""
pass() { R=PASS WHY=$1; }
fail() { R=FAIL WHY=$1; }
blocked() { R=BLOCKED WHY=$1; }
note() { echo "$*" >>"$EVD/steps.txt"; }

mknet() {
	local net=$1 drv=$2
	shift 2
	local ipam=null
	[ "$SHAPE" = macvlan-ipam ] && ipam=$drv
	docker network create -d "$drv" --ipam-driver "$ipam" -o mode=macvlan -o parent="$FB_PARENT" "$@" "$net" >/dev/null 2>>"$EVD/steps.txt"
}

# ccreate creates a container pinned to MAC number n and refuses to start it unless Docker carries that MAC.
ccreate() {
	local name=$1 net=$2 n=$3
	shift 3
	local mac=${MACS[$((n - 1))]} got
	docker create --name "$name" --hostname "lab-fb-$n" --init --network "name=$net,mac-address=$mac" "$@" "$IMG" sleep infinity >/dev/null 2>>"$EVD/steps.txt" || return 1
	got=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").MacAddress}}" "$name")
	if [ "$got" != "$mac" ]; then
		docker rm -f "$name" >/dev/null 2>&1
		abort "container $name would start with MAC '$got', not $mac"
	fi
}

cstart() { docker start "$1" >/dev/null 2>>"$EVD/steps.txt"; }
crun() { ccreate "$@" && cstart "$1"; }

addr_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1" 2>/dev/null; }
dev_of() { docker exec "$1" ip -o -4 addr show | awk -v a="$2/" 'index($4, a) == 1 {print $2; exit}'; }

xch() { W exchanges "$(lastcap)" --mac "$1" --server "$ROUTER" --since "${2:-$SINCE}"; }

reach() {
	local c=$1 a=$2 d i
	for i in 1 2 3 4 5 6 7 8; do
		d=$(dev_of "$c" "$a")
		[ -n "$d" ] && docker exec "$c" ping -c1 -W2 -I "$d" "$ROUTER" >/dev/null 2>&1 && return 0
		sleep 2
	done
	return 1
}

# leased: container c on net with MAC number n holds an address the box ACKed to that MAC, and the box answers its
# ping. Sets ADDR, or WHY on failure.
ADDR=""
leased() {
	local c=$1 net=$2 n=$3 mac=${MACS[$(($3 - 1))]} i
	ADDR=$(addr_of "$c" "$net")
	between
	if [ -z "$ADDR" ]; then WHY="$c has no address on $net"; return 1; fi
	case "$ADDR" in "$PREFIX"*) ;; *) WHY="$c holds $ADDR, outside the router's subnet"; return 1 ;; esac
	for i in 1 2 3; do
		xch "$mac" | grep -q " ACK $ADDR " && break
		sleep 2
	done
	xch "$mac" >>"$EVD/exchanges-$n.txt"
	if ! xch "$mac" | grep -q " ACK $ADDR "; then WHY="no ACK from the box for $ADDR to $mac in the capture"; return 1; fi
	note "$c mac $mac address $ADDR, ACKed by the box"
	if ! reach "$c" "$ADDR"; then WHY="the box did not answer $c's ping from $ADDR"; return 1; fi
	note "$c reaches the box from $ADDR"
}

no_nak() { ! xch "$1" "$2" | grep -q ' NAK '; }

silent() {
	! H ping -c2 -W1 "$1" >/dev/null 2>&1 && ! H arping -c2 -w3 -I "$FB_PARENT" "$1" >/dev/null 2>&1
}

wire_count() { W events "$(lastcap)" --mac "$1" --since "$2" | grep -c "\"type\": \"$3\""; }

# --- scenarios (semantics copied from internal/scenario; the box's frames stand in for its lease table) ---
s_A1() {
	local c=lab-fb-$S-a1 net=lab-fb-$S-a1
	mknet "$net" "$ALIAS" && crun "$c" "$net" 1 || { fail "container did not start: $(tail -1 "$EVD/steps.txt")"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	if [ "$S" = m ] && [ "$(W events /w/cap/out.pcap --mac "${MACS[0]}" | grep -c DISCOVER)" -eq 0 ]; then
		abort "guard blind: the outbound capture has no DISCOVER from ${MACS[0]}"
	fi
	pass "container mac ${MACS[0]} got address $ADDR, ACKed by the box (server id = the box), the box answers its ping"
}

s_A2() {
	local c=lab-fb-$S-a2 net=lab-fb-$S-a2 a1 t
	mknet "$net" "$ALIAS" && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	a1=$ADDR t=$(date +%s.%N)
	docker restart -t 2 "$c" >/dev/null || { fail "docker restart failed"; return; }
	leased "$c" "$net" 1 || { fail "after restart: $WHY"; return; }
	[ "$ADDR" = "$a1" ] || { fail "address changed across restart: $a1 -> $ADDR"; return; }
	no_nak "${MACS[0]}" "$t" || { fail "the box NAKed after the restart"; return; }
	pass "container restarted, kept address $a1, ACKed by the box, reachable after the restart; exchanges after restart: $(xch "${MACS[0]}" "$t" | tr '\n' ';')"
}

s_A3() {
	local net=lab-fb-$S-a3 f=$OUT/compose-a3.yml c=lab-fb-$S-a3-1 a1 reuse
	# docker compose 2.26.1 on engine API 1.45 drops a service-level mac_address and keeps the per-network key
	# (measured 2026-10-31, lab #13), so the MAC is pinned under the network.
	cat >"$f" <<EOF
name: lab-fb-a3
services:
  c:
    image: $IMG
    container_name: $c
    hostname: lab-fb-1
    init: true
    command: ["sleep", "infinity"]
    networks:
      $net:
        mac_address: ${MACS[0]}
networks:
  $net:
    external: true
EOF
	mknet "$net" "$ALIAS" || { fail "network create failed"; return; }
	compose_up() {
		docker compose -f "$f" create >/dev/null 2>>"$EVD/steps.txt" || return 1
		[ "$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").MacAddress}}" "$c")" = "${MACS[0]}" ] ||
			{ docker compose -f "$f" down >/dev/null 2>&1; abort "compose would start $c without ${MACS[0]}"; }
		docker compose -f "$f" start >/dev/null 2>>"$EVD/steps.txt"
	}
	compose_up || { fail "compose up (down phase) failed"; return; }
	leased "$c" "$net" 1 || { fail "before down: $WHY"; return; }
	a1=$ADDR
	docker compose -f "$f" down >/dev/null 2>>"$EVD/steps.txt" || { fail "compose down failed"; return; }
	compose_up || { fail "compose up after down failed"; return; }
	leased "$c" "$net" 1 || { fail "after down/up: $WHY"; docker compose -f "$f" down >/dev/null 2>&1; return; }
	reuse="same address as before the down"
	[ "$ADDR" = "$a1" ] || reuse="new address, previous $a1"
	docker compose -f "$f" down >/dev/null 2>&1
	pass "fresh container after compose down/up got address $ADDR, ACKed by the box ($reuse), reachable"
}

s_A6() {
	local c=lab-fb-$S-a6 net=lab-fb-$S-a6 dg a1 t how=disable ref
	plugin_rm "$UPALIAS"
	# The second shape's A6 starts from an empty state dir: an older plugin never reads a newer one's files.
	H rm -rf /state/lab-fb-up
	install_alias "$UPALIAS" "$PREV" "$UP_STATE" || { blocked "could not install the verified previous tag $PREV"; return; }
	mknet "$net" "$UPALIAS" && crun "$c" "$net" 1 || { fail "container did not start under $PREV"; return; }
	leased "$c" "$net" 1 || { fail "under $PREV: $WHY"; return; }
	a1=$ADDR
	dg=$(digest_of "$TAG") || { blocked "cosign verify $TAG failed"; return; }
	t=$(date +%s.%N)
	if ! docker plugin disable "$UPALIAS" >>"$EVD/steps.txt" 2>&1; then
		how="disable -f (plain disable refused: in use)"
		docker plugin disable -f "$UPALIAS" >>"$EVD/steps.txt" 2>&1 || { fail "disable before upgrade failed"; return; }
	fi
	docker plugin upgrade "$UPALIAS" "$IMAGE_REPO@$dg" --grant-all-permissions --skip-remote-check >>"$EVD/steps.txt" 2>&1 || { fail "upgrade to $TAG failed"; return; }
	if ! docker plugin inspect -f '{{range .Settings.Env}}{{println .}}{{end}}' "$UPALIAS" | grep -qx "STATE_DIR=$UP_STATE"; then
		note "upgrade dropped STATE_DIR; set again before enable"
		docker plugin set "$UPALIAS" "STATE_DIR=$UP_STATE" || { blocked "could not keep STATE_DIR across the upgrade"; return; }
	fi
	docker plugin enable "$UPALIAS" >>"$EVD/steps.txt" 2>&1 || { fail "enable after upgrade failed"; return; }
	ref=$(docker plugin inspect -f '{{.PluginReference}}' "$UPALIAS")
	[ "$ref" = "$IMAGE_REPO@$dg" ] || { fail "installed reference after upgrade is $ref, not $TAG's digest"; return; }
	note "upgraded $PREV -> $TAG by $how; reference $TAG's verified digest"
	sleep 5
	[ "$(docker inspect -f '{{.State.Running}}' "$c")" = true ] || { fail "the container stopped across the upgrade"; return; }
	reach "$c" "$a1" || { fail "after the upgrade the box does not answer the container's ping from $a1"; return; }
	no_nak "${MACS[0]}" "$t" || { fail "the box NAKed after the upgrade"; return; }
	xch "${MACS[0]}" "$t" >"$EVD/exchanges-after-upgrade.txt"
	pass "upgraded $PREV -> $TAG ($how), the running container kept $a1 and the box answers its ping; no NAK; exchanges after the upgrade: $(tr '\n' ';' <"$EVD/exchanges-after-upgrade.txt")"
}

s_A8() {
	local net=lab-fb-$S-a8 i a seen=" " n=0 notes=""
	mknet "$net" "$ALIAS" || { fail "network create failed"; return; }
	for i in 1 2 3 4; do ccreate "lab-fb-$S-a8-$i" "$net" "$i" || { fail "create $i failed"; return; }; done
	for i in 1 2 3 4; do cstart "lab-fb-$S-a8-$i" & done
	wait
	for i in 1 2 3 4; do
		leased "lab-fb-$S-a8-$i" "$net" "$i" || { fail "container $i: $WHY"; return; }
		case "$seen" in *" $ADDR "*) fail "two containers share $ADDR"; return ;; esac
		seen="$seen$ADDR " n=$((n + 1)) notes="$notes ${MACS[$((i - 1))]}=$ADDR"
	done
	pass "burst reduced to 4 (home router limit): $n containers started at once, $n distinct addresses ACKed by the box, each reachable:$notes"
}

s_A9() {
	local c=lab-fb-$S-a9 net=lab-fb-$S-a9 a1 t
	mknet "$net" "$ALIAS" && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	a1=$ADDR t=$(date +%s.%N)
	docker stop -t 2 "$c" >/dev/null && sleep 5 && cstart "$c" || { fail "stop/start failed"; return; }
	leased "$c" "$net" 1 || { fail "after stop/wait/start: $WHY"; return; }
	[ "$ADDR" = "$a1" ] || { fail "address changed across stop, 5 s, start: $a1 -> $ADDR"; return; }
	no_nak "${MACS[0]}" "$t" || { fail "the box NAKed after the start"; return; }
	pass "stopped, waited 5 s, started: kept $a1, reachable; exchanges after the start: $(xch "${MACS[0]}" "$t" | tr '\n' ';')"
}

s_A10() {
	local c=lab-fb-$S-a10 net=lab-fb-$S-a10 a1 t0 pid i
	mknet "$net" "$ALIAS" && crun "$c" "$net" 1 --restart unless-stopped || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	a1=$ADDR t0=$(docker inspect -f '{{.State.StartedAt}}' "$c") pid=$(docker inspect -f '{{.State.Pid}}' "$c")
	# SIGKILL from outside: docker kill counts as a manual stop, which unless-stopped does not restart.
	H kill -9 "$pid" || { blocked "could not kill the container's main process"; return; }
	for i in $(seq 1 30); do
		[ "$(docker inspect -f '{{.State.Running}} {{.State.StartedAt}}' "$c")" != "true $t0" ] &&
			[ "$(docker inspect -f '{{.State.Running}}' "$c")" = true ] && break
		sleep 1
	done
	[ "$(docker inspect -f '{{.State.StartedAt}}' "$c")" != "$t0" ] || { fail "the restart policy did not restart the killed container in 30 s"; return; }
	leased "$c" "$net" 1 || { fail "after the policy restart: $WHY"; return; }
	[ "$ADDR" = "$a1" ] || { fail "address changed across the crash: $a1 -> $ADDR"; return; }
	pass "container's main process killed, restart policy recovered it, kept $a1, reachable"
}

s_A11() {
	local c=lab-fb-$S-a11 net=lab-fb-$S-a11 a1 t
	mknet "$net" "$ALIAS" && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	a1=$ADDR t=$(date +%s.%N)
	docker pause "$c" >/dev/null && sleep 5 && docker unpause "$c" >/dev/null || { fail "pause/unpause failed"; return; }
	reach "$c" "$a1" || { fail "after unpause the box does not answer from $a1"; return; }
	[ "$(addr_of "$c" "$net")" = "$a1" ] || { fail "address changed across pause"; return; }
	[ "$(xch "${MACS[0]}" "$t" | wc -l)" -eq 0 ] || { fail "pause/unpause started a DHCP exchange: $(xch "${MACS[0]}" "$t" | tr '\n' ';')"; return; }
	pass "paused 5 s then unpaused: kept $a1, no DHCP exchange on the wire, reachable"
}

s_A12() { R=N/A WHY="the Docker host's engine (26) does not carry a MAC on docker network connect of a running container, so the reconnect would lease under a MAC outside this run's six; the MAC set is the hard limit on a home router"; }

s_A13() {
	local c=lab-fb-$S-a13 net=lab-fb-$S-a13 plain=lab-fb-plain gw ia
	docker network create --internal "$plain" >/dev/null 2>>"$EVD/steps.txt" || { fail "internal network create failed"; return; }
	mknet "$net" "$ALIAS" && ccreate "$c" "$net" 1 || { fail "container create failed"; return; }
	docker network connect "$plain" "$c" 2>>"$EVD/steps.txt" || { fail "connect of the internal network failed"; return; }
	cstart "$c" || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	gw=$(docker exec "$c" ip -4 route show default | awk '{print $3; exit}')
	ia=$(addr_of "$c" "$plain")
	[ "$gw" = "$ROUTER" ] || { fail "default route via '$gw', not the lease's gateway"; return; }
	[ -n "$ia" ] || { fail "no address on the internal network"; return; }
	pass "plugin network address $ADDR (ACKed, reachable, default route via the lease's gateway) plus an internal Docker network address $ia, on one container"
}

s_A16() {
	local c=lab-fb-$S-a16 net=lab-fb-$S-a16 id t
	mknet "$net" "$ALIAS" && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	id=$(docker inspect -f '{{.Id}}' "$c") t=$(date +%s.%N)
	docker rm -f "$c" >/dev/null || { fail "docker rm -f failed"; return; }
	sleep 5
	docker network inspect -f '{{range $k, $v := .Containers}}{{$k}} {{end}}' "$net" | grep -q "$id" && { fail "the network still lists the removed container"; return; }
	[ "$(wire_count "${MACS[0]}" "$t" RELEASE)" -eq 0 ] || { fail "a RELEASE went out although release_lease is never"; return; }
	pass "forced remove of a running container: the network no longer lists it, and no RELEASE went on the wire for $ADDR, as release_lease=never documents"
}

s_B3() {
	local c=lab-fb-$S-b3 net=lab-fb-$S-b3 i name ans=""
	mknet "$net" "$ALIAS" -o register_dns=true && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	W events "$(lastcap)" --mac "${MACS[0]}" --since "$SINCE" | grep -q '"fqdn": true' || note "no option 81 seen in our frames"
	for i in $(seq 1 10); do
		for name in lab-fb-1 lab-fb-1.fritz.box; do
			ans=$(H dig +short +time=2 +tries=1 "@$ROUTER" "$name" A | head -1)
			[ "$ans" = "$ADDR" ] && break 2
		done
		sleep 3
	done
	note "dig $name -> '$ans'"
	[ "$ans" = "$ADDR" ] || { fail "the box's DNS does not answer lab-fb-1 with $ADDR within 30 s (last answer '$ans')"; return; }
	pass "the box's DNS answers $name with the leased address $ADDR"
}

s_B4() {
	local net=lab-fb-$S-b4 a1 n
	mknet "$net" "$ALIAS" && crun "lab-fb-$S-b4-1" "$net" 1 || { fail "first container did not start"; return; }
	leased "lab-fb-$S-b4-1" "$net" 1 || { fail "first container: $WHY"; return; }
	a1=$ADDR
	docker rm -f "lab-fb-$S-b4-1" >/dev/null
	silent "$a1" || { blocked "$a1 still answers ping or ARP after the remove; not asking for it"; return; }
	crun "lab-fb-$S-b4-2" "$net" 1 || { fail "second container did not start"; return; }
	leased "lab-fb-$S-b4-2" "$net" 1 || { fail "second container: $WHY"; return; }
	[ "$ADDR" = "$a1" ] || { fail "mac ${MACS[0]} had $a1, the second container with the same mac got $ADDR"; return; }
	n=$(held | awk -v m="${MACS[0]}" '$1 == m' | wc -l)
	[ "$n" -eq 1 ] || { fail "the box holds $n ACKed addresses for ${MACS[0]}, want exactly 1"; return; }
	pass "mac ${MACS[0]} kept $a1 across a remove and a new container; one ACKed address for the mac on the wire"
}

s_B7() {
	local c=lab-fb-$S-b7 net=lab-fb-$S-b7 a1 t rt="" i
	mknet "$net" "$ALIAS" -o release_lease=on_remove && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	a1=$ADDR t=$(date +%s.%N)
	docker stop -t 2 "$c" >/dev/null && docker rm "$c" >/dev/null || { fail "stop/rm failed"; return; }
	for i in $(seq 1 50); do
		rt=$(W events "$(lastcap)" --mac "${MACS[0]}" --since "$t" | python3 -c 'import json, sys
for l in sys.stdin:
    e = json.loads(l)
    if e["type"] == "RELEASE" and e["ciaddr"] == sys.argv[1]:
        print(e["t"]); break' "$a1")
		[ -n "$rt" ] && break
		sleep 2
	done
	[ -n "$rt" ] || { fail "no RELEASE for $a1 on the wire within 100 s of the stop (documented 65-80 s)"; return; }
	note "RELEASE for $a1 on the wire $(python3 -c "print(round($rt - $t))") s after the stop"
	sleep 3
	silent "$a1" || { blocked "$a1 answers ping or ARP after the release; not asking for it"; return; }
	if W offer --iface "$FB_PARENT" --mac "${MACS[4]}" --ip "$a1" >>"$EVD/steps.txt"; then
		pass "release_lease=on_remove: RELEASE for $a1 $(python3 -c "print(round($rt - $t))") s after the stop, and the box then offers $a1 to another MAC"
	else
		fail "the RELEASE went out but the box does not offer $a1 to another MAC: $(tail -1 "$EVD/steps.txt")"
	fi
}

s_B8() {
	local net=lab-fb-$S-b8 i seen=" " notes=""
	mknet "$net" "$ALIAS" || { fail "network create failed"; return; }
	for i in 1 2 3; do ccreate "lab-fb-$S-b8-$i" "$net" "$i" || { fail "create $i failed"; return; }; done
	for i in 1 2 3; do cstart "lab-fb-$S-b8-$i" & done
	wait
	for i in 1 2 3; do
		leased "lab-fb-$S-b8-$i" "$net" "$i" || { fail "container $i: $WHY"; return; }
		case "$seen" in *" $ADDR "*) fail "two containers share $ADDR"; return ;; esac
		seen="$seen$ADDR " notes="$notes ${MACS[$((i - 1))]}=$ADDR"
	done
	pass "3 containers hold 3 distinct leases on 3 distinct macs, each ACKed by the box:$notes"
}

s_F3() {
	local c=lab-fb-$S-f3 net=lab-fb-$S-f3 row
	mknet "$net" "$ALIAS" -o rapid_commit=true && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	row=$(xch "${MACS[0]}" | awk -v a="$ADDR" '$1 == "discover" && $2 == "ACK" && $3 == a' | head -1)
	[ -n "$row" ] || { fail "no DISCOVER-started exchange ended in the ACK for $ADDR"; return; }
	case "$row" in *" rapid "*) ;; *) fail "the DISCOVER carried no option 80"; return ;; esac
	case "$row" in
	*" offers=0 "*) pass "rapid_commit=true: the box answered the DISCOVER (option 80) with an ACK, a 2-message lease for $ADDR" ;;
	*) pass "rapid_commit=true: the box ignored option 80 and answered OFFER, the 4-message exchange continued, lease $ADDR ($row)" ;;
	esac
}

s_E1() {
	local c=lab-fb-$S-e1 net=lab-fb-$S-e1 id i out
	sock_get "$ALIAS" /metrics >"$EVD/metrics-before.txt" || { blocked "could not read /metrics"; return; }
	mknet "$net" "$ALIAS" -o audit_log=true -o release_lease=on_stop && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	id=$(docker network inspect -f '{{.Id}}' "$net")
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	docker stop -t 2 "$c" >/dev/null
	for i in 1 2 3 4 5; do [ "$(wire_count "${MACS[0]}" "$SINCE" RELEASE)" -gt 0 ] && break; sleep 2; done
	sock_get "$ALIAS" /metrics >"$EVD/metrics-after.txt" || { blocked "could not read /metrics"; return; }
	H cat "/state/lab-fb-main/leases.jsonl" >"$EVD/ledger-all.jsonl" 2>/dev/null
	grep -F "$id" "$EVD/ledger-all.jsonl" >"$EVD/ledger.jsonl"
	out=$(W e1 --pcap "$(lastcap)" --mac "${MACS[0]}" --server "$ROUTER" --since "$SINCE" --ledger "/w/ev/$SHAPE/E1/ledger.jsonl" \
		--network "$id" --before "/w/ev/$SHAPE/E1/metrics-before.txt" --after "/w/ev/$SHAPE/E1/metrics-after.txt")
	R=$(echo "$out" | head -1) WHY=$(echo "$out" | sed -n 2p)
}

s_E2() {
	local c=lab-fb-$S-e2 net=lab-fb-$S-e2 out
	sock_get "$ALIAS" /metrics >"$EVD/metrics-before.txt" || { blocked "could not read /metrics"; return; }
	mknet "$net" "$ALIAS" && crun "$c" "$net" 1 || { fail "container did not start"; return; }
	leased "$c" "$net" 1 || { fail "$WHY"; return; }
	sleep 3
	sock_get "$ALIAS" /metrics >"$EVD/metrics-after.txt" && sock_get "$ALIAS" /Plugin.Health >"$EVD/health.json" || { blocked "could not read /metrics or /Plugin.Health"; return; }
	out=$(W e2 --pcap "$(lastcap)" --mac "${MACS[0]}" --server "$ROUTER" --since "$SINCE" --address "$ADDR" \
		--before "/w/ev/$SHAPE/E2/metrics-before.txt" --after "/w/ev/$SHAPE/E2/metrics-after.txt" --health "/w/ev/$SHAPE/E2/health.json")
	R=$(echo "$out" | head -1) WHY=$(echo "$out" | sed -n 2p)
}

run_scenario() {
	local id=${1%%-*}
	EVD=$OUT/ev/$SHAPE/$id
	mkdir -p "$EVD"
	between
	R="" WHY="" SINCE=$(date +%s.%N)
	log "$SHAPE $id start"
	"s_$id"
	[ -n "$R" ] || { R=FAIL WHY="scenario ended without a verdict"; }
	teardown_objects
	[ "$id" = A6 ] && plugin_rm "$UPALIAS"
	release_held
	printf '%s\t%s\t%s\t%s\t%s\n' "$SHAPE" "$id" "$R" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$WHY" >>"$RES"
	log "$SHAPE $id $R: $WHY"
}

# --- cleanup: idempotent, runs on every exit of run, re-runnable alone ---
cleanup() {
	trap '' TERM INT
	local proof=$OUT/cleanup-proof.txt ip mac ok bad=0 macs extra
	log "cleanup start${ABORT:+ (abort: $ABORT)}"
	: >"$proof"
	teardown_objects
	plugin_rm "$ALIAS"
	plugin_rm "$UPALIAS"
	if ! helper_up; then
		echo "FAIL helper could not start: no release or verify possible" >>"$proof"
		bad=1
	else
		captures_start
		if [ -n "$(pcaps)" ]; then
			extra=$(for o in "$OUT"/cap/out*.pcap; do W guard "/w/cap/$(basename "$o")" --macs "$MACLIST" --host-mac "$HOST_MAC" 2>>"$OUT/foreign.txt"; done |
				awk '/outside the MAC budget/ {print $4}' | sort -u | tr '\n' ',')
			macs=$MACLIST${extra:+,${extra%,}}
			MACLIST=$macs release_held
			sleep 3
			local -a p
			mapfile -t p < <(pcaps)
			W acked "${p[@]}" --macs "$macs" --server "$ROUTER" >"$OUT/acked.txt"
			while read -r ip mac; do
				ok=0
				for v in "${MACS[5]}" "${MACS[4]}"; do
					W offer --iface "$FB_PARENT" --mac "$v" --ip "$ip" >>"$OUT/offer-verify.txt" && { ok=1; break; }
					sleep 3
				done
				if [ "$ok" = 1 ]; then echo "PASS $ip (last held by $mac) offered back to another MAC" >>"$proof"; else
					echo "FAIL $ip (last held by $mac) not offered back" >>"$proof"
					bad=1
				fi
			done <"$OUT/acked.txt"
			MACLIST=$macs held >"$OUT/held-after.txt"
			[ -s "$OUT/held-after.txt" ] && { echo "FAIL ledger still shows held: $(tr '\n' ';' <"$OUT/held-after.txt")" >>"$proof"; bad=1; }
		fi
		H rm -rf /state/lab-fb-main /state/lab-fb-up
		captures_stop
	fi
	echo "INFO capture drops: $(drops)" >>"$proof"
	ip -o link | grep -qi '02:fd:4b:00:13' && { echo "FAIL a host link still carries one of the six MACs" >>"$proof"; bad=1; }
	docker rm -f "$HELPER" >/dev/null 2>&1
	docker image rm "$IMG" >/dev/null 2>&1
	! docker ps -a --format '{{.Names}}' | grep -qE '^lab-fb-' || { echo "FAIL lab-fb containers left" >>"$proof"; bad=1; }
	[ -z "$(our_nets)" ] || { echo "FAIL lab-fb networks left" >>"$proof"; bad=1; }
	! docker plugin ls --format '{{.Name}}' | grep -qE '^lab-fb-' || { echo "FAIL lab-fb plugin aliases left" >>"$proof"; bad=1; }
	! docker images --format '{{.Repository}}' | grep -qE '^lab-fb-' || { echo "FAIL lab-fb image left" >>"$proof"; bad=1; }
	[ "$(ip -4 -o addr show dev "$FB_PARENT" scope global | awk '{print $4; exit}')" = "$BASE_ADDR" ] || { echo "FAIL host address on the parent changed" >>"$proof"; bad=1; }
	[ "$(ip -4 route show default | tr '\n' ' ')" = "$BASE_ROUTE" ] || { echo "FAIL host default route changed" >>"$proof"; bad=1; }
	[ "$bad" = 0 ] && echo "CLEAN all checks passed" >>"$proof"
	log "cleanup done: $(tail -1 "$proof")"
	return "$bad"
}

run() {
	local shape id
	mkdir -p "$OUT/cap" "$OUT/ev"
	[ -e "$RES" ] && die "$RES exists: one run per FB_OUT"
	lan
	trap 'cleanup' EXIT
	trap 'abort "signal"' TERM INT
	helper_up || abort "helper did not start"
	captures_start
	H sh -c 'test -s /w/cap/full.pcap' || abort "capture did not start"
	W arp-probe --iface "$FB_PARENT" --mac "${MACS[5]}" --target "$ROUTER" >>"$LOG" || abort "precheck: the box does not answer an RFC 5227 probe"
	install_alias "$ALIAS" "$TAG" "$MAIN_STATE" || abort "could not install the verified $TAG"
	for shape in macvlan macvlan-ipam; do
		SHAPE=$shape S=m
		[ "$shape" = macvlan-ipam ] && S=i
		for id in "${SCENARIOS[@]}"; do run_scenario "$id"; done
	done
	log "scenarios done; drops so far $(drops)"
}

# render writes the redacted bundle: verdicts, evidence text, the resolved cell. Pcaps stay in FB_OUT.
render() {
	local b=$OUT/bundle sha host_distro host_kernel dv shape id r ts why f rel
	# shellcheck disable=SC1091
	. "$OUT/lan.env"
	sha=$(git -C "$REPO" rev-parse HEAD)
	# shellcheck disable=SC1091
	host_distro=$(. /etc/os-release && echo "$PRETTY_NAME")
	host_kernel=$(uname -r)
	dv=$(docker version -f '{{.Server.Version}}')
	rm -rf "${b:?}"
	mkdir -p "$b"
	redact() { FB_PREFIX=$PREFIX FB_ROUTER_MAC=$ROUTER_MAC FB_HOST_MAC=$HOST_MAC python3 "$REPO/scripts/fritzbox-wire.py" redact; }
	printf '{"cell":{"name":"%s","docker_host":{"plugin_tag":"%s","previous_plugin_tag":"%s"}}}\n' \
		"$CELL" "$IMAGE_REPO:$TAG" "$IMAGE_REPO:$PREV" >"$b/$CELL-resolved-lab.json"
	while IFS=$'\t' read -r shape id r ts why; do
		local full
		full=$(grep -oE "\"$id-[a-z0-9-]+\"" "$REPO/internal/scenario/catalog.go" | head -1 | tr -d '"')
		f=$b/$CELL-$shape-$full.verdict
		{
			echo "scenario: $full"
			echo "cell: $CELL"
			echo "shape: $shape"
			echo "result: $r"
			echo "reason: $(echo "$why" | redact)"
			echo "git_sha: $sha"
			echo "host.distro: $host_distro"
			echo "host.kernel: $host_kernel"
			echo "host.docker_version: $dv"
			echo "timestamp: $ts"
		} >"$f"
		if [ "$r" = PASS ] || [ "$r" = FAIL ]; then
			mkdir -p "$b/evidence/$shape/$full"
			for e in "$OUT/ev/$shape/$id"/*.txt "$OUT/ev/$shape/$id"/*.json "$OUT/ev/$shape/$id"/*.jsonl; do
				[ -s "$e" ] || continue
				[ "$(basename "$e")" = ledger-all.jsonl ] && continue
				rel=evidence/$shape/$full/$(basename "$e")
				redact <"$e" >"$b/$rel"
				echo "evidence.$(basename "${e%.*}"): $rel" >>"$f"
			done
		fi
	done <"$RES"
	for full in $(grep -oE '^\s*Name[A-Za-z0-9]+\s*= "[^"]+"' "$REPO/internal/scenario/catalog.go" | grep -oE '"[^"]+"' | tr -d '"'); do
		for shape in macvlan macvlan-ipam; do
			f=$b/$CELL-$shape-$full.verdict
			[ -e "$f" ] && continue
			printf 'scenario: %s\ncell: %s\nshape: %s\nresult: N/A\nreason: %s\ngit_sha: %s\n' \
				"$full" "$CELL" "$shape" "$(na_reason "$full")" "$sha" >"$f"
		done
	done
	echo "$b"
}

# na_reason is the approved plan's reason for every row this cell does not run (lab #13 phase 2 plan).
na_reason() {
	# Group F rows are named in full: the publication hygiene gate reads a bare F<n> as a review citation (lab #20).
	case "$1" in
	F1-user-class-pool | F2a-option-108-not-asked | F2b-option-108-forced | F8-forcerenew) set -- B1 ;;
	F4-rapid-commit-v6 | F5-temporary-address | F6-prefix-delegation | F7-pref64) set -- D ;;
	*) set -- "${1%%-*}" ;;
	esac
	case "$1" in
	B1 | B2 | B5 | B6 | C1 | C2 | C3 | C4 | C5 | C5b | C5c | C5d | C6 | C6b | C7 | C8 | C9 | C10 | C11 | C12 | C12b | E5)
		echo "home router, non-disruptive cell: needs a router config change, stopping or disturbing the router, a rogue or squatting host, or weeks of run time" ;;
	A4 | A5 | A5b | A7) echo "restarts the Docker host's shared daemon, reboots it or kills a root process; the Docker host is shared and is not restarted" ;;
	A15) echo "compose scale gives replicas Docker-generated MACs, outside this run's six" ;;
	A14) echo "the home router's lease is 24 h, so T1 is 12 h; one run is bounded to 2 h" ;;
	D*) echo "the home LAN has no IPv6" ;;
	E3a | E3b) echo "the home LAN has no VLAN and the host's link names are not changed" ;;
	*) echo "not in this cell's approved scenario list" ;;
	esac
}

check_env
case "$CMD" in
run) run ;;
cleanup) lan && trap '' TERM INT && cleanup ;;
render) render ;;
esac
