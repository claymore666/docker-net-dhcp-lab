#!/bin/bash
# Render the source VM's network-config (#2) to stdout. With a route
# (#11, a relay cell) eth1 gains one route to the client segment via the
# relay's server leg; without one the placeholder line is dropped, so a
# cell with no relay renders exactly as before.
set -euo pipefail
usage="usage: render-source-network-config.sh <template> <mgmt-addr> <mgmt-gw> <mgmt-mac> <seg-mac> <seg-addr> <seg-addr6> [<route-to> <route-via>]"
TMPL=${1:?$usage}
MGMT_ADDR=${2:?$usage}
MGMT_GW=${3:?$usage}
MGMT_MAC=${4:?$usage}
SEG_MAC=${5:?$usage}
SEG_ADDR=${6:?$usage}
SEG_ADDR6=${7:?$usage}
ROUTE_TO=${8:-}
ROUTE_VIA=${9:-}

if [ -n "$ROUTE_TO" ] && [ -n "$ROUTE_VIA" ]; then
	routes=(-e "s#^\([[:space:]]*\)\# __SEG_ROUTES__\$#\1routes: [{to: \"$ROUTE_TO\", via: \"$ROUTE_VIA\"}]#")
elif [ -z "$ROUTE_TO" ] && [ -z "$ROUTE_VIA" ]; then
	routes=(-e '/__SEG_ROUTES__/d')
else
	echo "render-source-network-config: a route needs both <route-to> and <route-via>" >&2
	exit 2
fi
sed -e "s#__MGMT_ADDR__#$MGMT_ADDR#" -e "s#__MGMT_GW__#$MGMT_GW#g" \
	-e "s#__MGMT_MAC__#$MGMT_MAC#" -e "s#__SEG_MAC__#$SEG_MAC#" \
	-e "s#__SEG_ADDR__#$SEG_ADDR#" -e "s#__SEG_ADDR6__#$SEG_ADDR6#" "${routes[@]}" "$TMPL"
