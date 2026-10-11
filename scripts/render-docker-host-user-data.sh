#!/bin/bash
# Render cloud-init/docker-host-user-data.tmpl.yaml for one cell: reads the
# `labctl resolve` JSON on stdin, takes the SSH public key as $1, writes the
# user-data to stdout. up-cell.sh and cloud-init-docker-host-test.sh both go
# through this one script, so the test renders what a bring-up renders
# (issue #27).
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
pubkey=${1:?usage: render-docker-host-user-data.sh <ssh-pubkey> < resolved.json}
RESOLVED=$(cat)

plugin_tag=$(jq -r '.cell.docker_host.plugin_tag' <<<"$RESOLVED")
engine_version=$(jq -r '.cell.docker_host.engine_version // empty' <<<"$RESOLVED")
image_distro=$(jq -r '.docker_host_image.distro' <<<"$RESOLVED")
image_suite=$(jq -r '.docker_host_image.suite' <<<"$RESOLVED")
apt_sources_fix=$(jq -r '.docker_host_image.apt_sources_fix // empty' <<<"$RESOLVED")
seg_nic_setup=$(jq -r '.docker_host_seg_nic_setup // empty' <<<"$RESOLVED")
# An image whose own network stack keeps the segment NIC up has no setup
# line, and its user-data stays as it was before lab #70.
seg_nic_sed="s#__SEG_NIC_SETUP__#$seg_nic_setup#g"
[ -n "$seg_nic_setup" ] || seg_nic_sed='/__SEG_NIC_SETUP__/d'

sed -e "s#__PLUGIN_TAG__#$plugin_tag#g" -e "s#__SSH_PUBKEY__#$pubkey#" \
	-e "s#__DOCKER_APT_DISTRO__#$image_distro#g" -e "s#__DOCKER_APT_SUITE__#$image_suite#g" \
	-e "s#__DOCKER_ENGINE_PACKAGE__#${engine_version:+=$engine_version}#g" \
	-e "s#__APT_SOURCES_FIX__#$apt_sources_fix#g" -e "$seg_nic_sed" \
	"$REPO_ROOT/cloud-init/docker-host-user-data.tmpl.yaml"
