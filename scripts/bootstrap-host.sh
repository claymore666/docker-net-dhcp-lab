#!/bin/bash
# One-time (idempotent) setup of the lab host: packages, a pinned Go
# toolchain, and the management network nested VMs use for apt/image
# pulls. Never touches eth0, ci-dmz-firewall.service or any netplan file.
# Run as root (the lab host gives passwordless sudo).
set -euo pipefail

GO_VERSION=go1.27.0
GO_TARBALL="${GO_VERSION}.linux-amd64.tar.gz"

echo "== packages =="
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
	qemu-system-x86 qemu-utils libvirt-daemon-system libvirt-clients \
	virtinst ovmf swtpm genisoimage cloud-image-utils \
	docker.io tcpdump jq curl ca-certificates

# libvirt's default network runs its own dnsmasq DHCP server bridged to
# the host: it must not exist here, at all, ever -- a second DHCP server
# on the lab host is exactly what this lab must never create.
if virsh net-info default >/dev/null 2>&1; then
	virsh net-destroy default 2>/dev/null || true
	virsh net-undefine default
fi

echo "== management network (net-mgmt, NAT, no DHCP) =="
if ! virsh net-info net-mgmt >/dev/null 2>&1; then
	tmp=$(mktemp)
	trap 'rm -f "$tmp"' EXIT
	cat >"$tmp" <<'EOF'
<network>
  <name>net-mgmt</name>
  <forward mode="nat"/>
  <bridge name="virbr-mgmt" stp="on" delay="0"/>
  <ip address="10.200.255.1" netmask="255.255.255.0"/>
</network>
EOF
	# Deliberately no <dhcp> element: nested VMs get a static address from
	# their own cloud-init network-config, rendered by labctl resolve.
	virsh net-define "$tmp"
	virsh net-autostart net-mgmt
	virsh net-start net-mgmt
fi

echo "== Go ${GO_VERSION} (pinned) =="
if ! command -v go >/dev/null || [ "$(go version 2>/dev/null | awk '{print $3}')" != "$GO_VERSION" ]; then
	tmp=$(mktemp -d)
	curl -fsSL -o "$tmp/$GO_TARBALL" "https://go.dev/dl/$GO_TARBALL"
	rm -rf /usr/local/go
	tar -C /usr/local -xzf "$tmp/$GO_TARBALL"
	rm -rf "$tmp"
	ln -sf /usr/local/go/bin/go /usr/local/bin/go
	ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
fi
go version

echo "bootstrap-host: done. Run dmz-probe.sh next -- required after anything that touches netfilter."
