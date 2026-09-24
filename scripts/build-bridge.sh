#!/bin/bash
# Create (or check) one lab segment bridge, and refuse if it, or the port
# being added, would carry anything but the lab's own devices (issue #1,
# track file "lab0 is the lab NIC"). Never touches eth0: that name is
# refused outright, never matched against the allowlist below.
#
# Usage:
#   build-bridge.sh <bridge-name>                 # create/check, no port
#   build-bridge.sh <bridge-name> --add-port <if>  # create/check, then add
set -euo pipefail

# A lab bridge may enslave: a libvirt VM tap (vnetN), an observer veth
# (veth-obs-*), or lab0 itself / a VLAN sub-interface of it (lab0, lab0.N).
# Nothing else, ever -- and "eth0" (or any other real uplink) is refused
# even if a future rename made it match one of these patterns by accident,
# because the check below runs on the literal name first.
is_allowed_port() {
	local ifname=$1
	case "$ifname" in
	eth0 | eth1 | eth[0-9]*) return 1 ;; # never a physical uplink, whatever it's called
	vnet* | veth-obs-* | lab0 | lab0.[0-9]*) return 0 ;;
	*) return 1 ;;
	esac
}

bridge=${1:?bridge name required}
shift || true
add_port=""
if [ "${1:-}" = "--add-port" ]; then
	add_port=${2:?--add-port needs an interface name}
fi

if [ ! -d "/sys/class/net/$bridge" ]; then
	ip link add name "$bridge" type bridge
	ip link set "$bridge" up
elif [ ! -d "/sys/class/net/$bridge/bridge" ]; then
	echo "build-bridge: $bridge exists and is not a bridge" >&2
	exit 1
fi

# Refuse on what is ALREADY enslaved, before considering any new port: a
# bridge a previous run polluted must not be used silently.
bad=0
if [ -d "/sys/class/net/$bridge/brif" ]; then
	for port in /sys/class/net/"$bridge"/brif/*; do
		[ -e "$port" ] || continue
		name=$(basename "$port")
		if ! is_allowed_port "$name"; then
			echo "build-bridge: REFUSED -- $bridge already enslaves $name, not a lab device" >&2
			bad=1
		fi
	done
fi
[ "$bad" -eq 0 ] || exit 1

if [ -n "$add_port" ]; then
	if ! is_allowed_port "$add_port"; then
		echo "build-bridge: REFUSED -- $add_port is not a lab device, will not enslave it to $bridge" >&2
		exit 1
	fi
	ip link set "$add_port" master "$bridge"
	ip link set "$add_port" up
fi

echo "build-bridge: $bridge ok"
