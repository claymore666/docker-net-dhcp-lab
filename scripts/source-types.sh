#!/bin/bash
# Per source type (#9): the version line run-cell.sh records and the
# stock and live config reads capture-source-config-diff.sh diffs. A
# type with no arm here is refused, never read with another type's
# commands; source-types-test.sh fails while a type lab.yaml accepts
# has no arm. Sourced, never run.

# source_version_cmd TYPE: prints "<label><TAB><command to run on it>".
source_version_cmd() {
	case "$1" in
	kea | isc-dhcp | dnsmasq | udhcpd | pihole) printf 'kernel\tuname -r\n' ;;
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
	*) source_type_unknown "$1" ;;
	esac
}

# source_stock_mask TYPE: prints 1 when the stock side's vendor example
# addresses are masked before the diff (busybox udhcpd.conf, DESIGN-910
# 5.8, lab #10), 0 when a stock code line with an address is refused.
source_stock_mask() {
	case "$1" in
	udhcpd) echo 1 ;;
	kea | isc-dhcp | dnsmasq | pihole) echo 0 ;;
	*) source_type_unknown "$1" ;;
	esac
}

# source_stock_cmd TYPE NAME and source_live_cmd TYPE PATH: the command
# that prints that side over ssh.
source_stock_cmd() {
	case "$1" in
	kea | isc-dhcp | dnsmasq | udhcpd | pihole) printf 'sudo cat /root/lab-stock-config/%s\n' "$2" ;;
	*) source_type_unknown "$1" ;;
	esac
}
source_live_cmd() {
	case "$1" in
	kea | isc-dhcp | dnsmasq | udhcpd | pihole) printf 'sudo cat %s\n' "$2" ;;
	*) source_type_unknown "$1" ;;
	esac
}

source_type_unknown() {
	echo "source-types: unknown source type $1" >&2
	return 1
}
