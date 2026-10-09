#!/bin/bash
# The relay cell's end-to-end probe (#11), run once before any shape: a
# throwaway udhcpc on the Docker host's segment NIC must get a lease, and
# the client observer must hold the relay's ACK to that NIC. Anything
# else is a lab error; run-cell.sh runs no shape then.
set -euo pipefail

# ack_from <relay-mac> <client-mac> reads `tcpdump -nn -e -v` text on
# stdin and succeeds on a DHCPACK sent from <relay-mac>, for chaddr
# <client-mac>, with a giaddr set: the relay's own delivery to this
# probe, not a routed ACK to another client (#11).
ack_from() {
	awk -v mac="$1" -v client="$2" '
		/^[0-9]/ { src = $2; chaddr = ""; relayed = 0 }
		/^[ \t]*Gateway-IP / { relayed = ($2 != "0.0.0.0") }
		/^[ \t]*Client-Ethernet-Address / { chaddr = $2 }
		/DHCP-Message \(53\), length 1: ACK$/ && src == mac && chaddr == client && relayed { found = 1 }
		END { exit !found }'
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
	# A live capture can end mid-frame, and tcpdump then exits non-zero
	# after printing every whole frame; the frames are what is judged.
	local frames
	frames=$(sudo -n docker exec "lab-observer-$cell" tcpdump -nn -e -v -r /tmp/obs.pcap 2>/dev/null || true)
	if ! ack_from "$relay_mac" "$client_mac" <<<"$frames"; then
		echo "relay-probe: FAIL -- the client observer holds no relayed ACK from $relay_mac to $client_mac" >&2
		return 1
	fi
	echo "relay-probe: lease through the relay, ACK from $relay_mac on the client segment"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	main "$@"
fi
