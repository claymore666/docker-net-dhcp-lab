#!/bin/bash
# Per source type (#9): the version line run-cell.sh records and the
# stock and live config reads capture-source-config-diff.sh diffs. A
# type with no arm here is refused, never read with another type's
# commands; source-types-test.sh fails while a type lab.yaml accepts
# has no arm. Sourced, never run.

# source_version_cmd TYPE: prints "<label><TAB><command to run on it>".
# OpenWrt's release and its dnsmasq on one line, run by the image's ash.
# shellcheck disable=SC2016 # expanded on the source, not here (lab #9)
openwrt_version='. /etc/openwrt_release && printf "%s, " "$DISTRIB_DESCRIPTION" && /usr/sbin/dnsmasq --version | head -n1'
source_version_cmd() {
	case "$1" in
	kea | isc-dhcp | dnsmasq | udhcpd | pihole) printf 'kernel\tuname -r\n' ;;
	routeros) printf 'routeros\t:put [/system resource get version]\n' ;;
	openwrt) printf '%s\t%s\n' openwrt "$openwrt_version" ;;
	*) source_type_unknown "$1" ;;
	esac
}

# source_config_pairs TYPE: prints one "<stock name>:<live path>" per
# config file the type's seed backs up before writing its own.
source_config_pairs() {
	case "$1" in
	kea) printf '%s\n' kea-dhcp4.conf.stock:/etc/kea/kea-dhcp4.conf kea-ctrl-agent.conf.stock:/etc/kea/kea-ctrl-agent.conf ;;
	isc-dhcp) printf '%s\n' dhcpd.conf.stock:/etc/dhcp/dhcpd.conf isc-dhcp-server.stock:/etc/default/isc-dhcp-server ;;
	dnsmasq) printf '%s\n' dnsmasq.conf.stock:/etc/dnsmasq.conf ;;
	udhcpd) printf '%s\n' udhcpd.conf.stock:/etc/udhcpd.conf ;;
	pihole) printf '%s\n' pihole.toml.stock:/etc/pihole/pihole.toml ;;
	routeros) printf '%s\n' lab-stock.rsc:/export ;;
	openwrt) printf '%s\n' network.stock:/etc/config/network dhcp.stock:/etc/config/dhcp dnsmasq.conf.stock:/etc/dnsmasq.conf ;;
	*) source_type_unknown "$1" ;;
	esac
}

# source_stock_mask TYPE: prints 1 when the stock side's vendor example
# addresses are masked before the diff (busybox udhcpd.conf, DESIGN-910
# 5.8, lab #10; the network file OpenWrt generates, lab #9), 0 when
# a stock code line with an address is refused.
source_stock_mask() {
	case "$1" in
	udhcpd) echo 1 ;;
	kea | isc-dhcp | dnsmasq | pihole | routeros) echo 0 ;;
	openwrt) echo 1 ;;
	*) source_type_unknown "$1" ;;
	esac
}

# source_stock_cmd TYPE NAME and source_live_cmd TYPE PATH: the command
# that prints that side over ssh. RouterOS (#9) has no shell: the stock
# side is the export the seed wrote before its first change, the live
# side the command /export itself.
source_stock_cmd() {
	case "$1" in
	kea | isc-dhcp | dnsmasq | udhcpd | pihole | openwrt) printf 'sudo cat /root/lab-stock-config/%s\n' "$2" ;;
	routeros) printf ':put [/file get %s contents]\n' "$2" ;;
	*) source_type_unknown "$1" ;;
	esac
}
source_live_cmd() {
	case "$1" in
	kea | isc-dhcp | dnsmasq | udhcpd | pihole | openwrt) printf 'sudo cat %s\n' "$2" ;;
	routeros) printf '%s\n' "$2" ;;
	*) source_type_unknown "$1" ;;
	esac
}

source_type_unknown() {
	echo "source-types: unknown source type $1" >&2
	return 1
}
