#!/bin/bash
# The relay cell's end-to-end probe (#11), run once before any shape: a
# throwaway udhcpc on the Docker host's segment NIC must get a lease, and
# the client observer must hold the relay's ACK to that NIC. Anything
# else is a lab error; run-cell.sh runs no shape then.
set -euo pipefail

# dhcp_frames reads `tcpdump -nn -e -v` text on stdin and prints one line
# per DHCPv4 message: eth-src chaddr giaddr type. tcpdump prints no
# Gateway-IP line for giaddr 0.0.0.0.
dhcp_frames() {
	awk '
		function emit() { if (type != "") print src, chaddr, giaddr, type; type = "" }
		/^[0-9]/ { emit(); src = $2; chaddr = "-"; giaddr = "0.0.0.0" }
		/^[ \t]*Gateway-IP / { giaddr = $2 }
		/^[ \t]*Client-Ethernet-Address / { chaddr = $2 }
		/DHCP-Message \(53\), length 1: / { type = $NF }
		END { emit() }'
}

# seen <frames> <eth-src|any> <chaddr> <giaddr: set|any> <type> succeeds
# on a dhcp_frames line that matches all four.
seen() {
	awk -v src="$2" -v ch="$3" -v gi="$4" -v type="$5" '
		(src == "any" || $1 == src) && $2 == ch && (gi == "any" || $3 != "0.0.0.0") && $4 == type { found = 1 }
		END { exit !found }' <<<"$1"
}

# ack_from <relay-mac> <client-mac> reads `tcpdump -nn -e -v` text on
# stdin and succeeds on a DHCPACK sent from <relay-mac>, for chaddr
# <client-mac>, with a giaddr set: the relay's own delivery to this
# probe, not a routed ACK to another client (#11).
ack_from() {
	seen "$(dhcp_frames)" "$1" "$2" set ACK
}

# lost_hop <client-frames> <server-frames> <relay-mac> <client-mac> says
# where the relayed ACK went (#76). udhcpc holds a lease, so every hop
# delivered: only an ACK that reached the client off the relay names a
# hop; a frame missing from a file is the capture's, listed per observer.
lost_hop() {
	local cf=$1 sf=$2 relay=$3 client=$4 acks cl="" sl=""
	acks=$(awk -v c="$client" '$2 == c && $4 == "ACK" { printf "%s%s giaddr %s", sep, $1, $3; sep = ", " }' <<<"$cf")
	if [ -n "$acks" ]; then
		echo "lost at hop 4 (relay to Docker host NIC): the client observer holds no DHCPACK from $relay with giaddr set; its ACKs for $client: $acks"
		return
	fi
	seen "$cf" "$client" "$client" any Request || cl="DHCPREQUEST from $client, "
	seen "$sf" any "$client" set Request || sl="relayed DHCPREQUEST, "
	seen "$sf" any "$client" set ACK || sl+="DHCPACK to giaddr, "
	sl=${sl%, }
	echo "lost in the capture, not at a hop: udhcpc got a lease, so the ACK reached $client, but the client observer holds none; client observer lacks: ${cl}DHCPACK; server observer lacks: ${sl:-nothing}"
}

# A live capture can end mid-frame, and tcpdump then exits non-zero
# after printing every whole frame; the frames are what is judged.
observer_frames() {
	sudo -n docker exec "$1" tcpdump -nn -e -v -r /tmp/obs.pcap 2>/dev/null || true
}

main() {
	local cell=${1:?usage: relay-probe.sh <cell> <docker-host-ip> <relay-ip> <work-dir>}
	local host_ip=${2:?} relay_ip=${3:?} work=${4:?}
	local known_hosts="$work/known_hosts" relay_mac client_mac
	ssh_run() {
		ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
			-o StrictHostKeyChecking=accept-new -o ControlMaster=no -o ControlPath=none \
			-i ~/.ssh/id_ed25519_lab lab@"$1" "$2"
	}
	relay_mac=$(ssh_run "$relay_ip" 'cat /sys/class/net/eth1/address')
	if ! [[ $relay_mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; then
		echo "relay-probe: FAIL -- relay client leg MAC unreadable: '$relay_mac'" >&2
		return 1
	fi
	client_mac=$(ssh_run "$host_ip" 'cat /sys/class/net/eth1/address')
	if ! [[ $client_mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; then
		echo "relay-probe: FAIL -- Docker host segment NIC MAC unreadable: '$client_mac'" >&2
		return 1
	fi
	# No -R: a release is unicast to the source, and the Docker host's
	# segment NIC has no address, so it would leave by the management
	# NIC. ResetLeases clears the lease before the first shape.
	if ! ssh_run "$host_ip" 'sudo docker run --rm --net host --cap-add NET_RAW --cap-add NET_ADMIN alpine:3.20 udhcpc -i eth1 -n -q -s /bin/true -t 5'; then
		echo "relay-probe: FAIL -- no lease through the relay on the Docker host's segment NIC" >&2
		return 1
	fi
	local frames hop
	frames=$(observer_frames "lab-observer-$cell")
	if ! ack_from "$relay_mac" "$client_mac" <<<"$frames"; then
		hop=$(lost_hop "$(dhcp_frames <<<"$frames")" "$(observer_frames "lab-observer-$cell-srv" | dhcp_frames)" "$relay_mac" "$client_mac")
		echo "relay-probe: FAIL -- no relayed ACK from $relay_mac to $client_mac on the client segment; $hop" >&2
		return 1
	fi
	echo "relay-probe: lease through the relay, ACK from $relay_mac on the client segment"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
