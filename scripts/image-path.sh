#!/bin/bash
# Where a base image lives on the host: the one definition
# fetch-base-image.sh (which writes it) and run-cells.sh (which asks
# whether a built one is there) both read, so the two cannot disagree on
# the path (lab #14). Sourced, never run.

# image_cache_dir: LAB_IMAGE_CACHE, else the lab host's data disk.
image_cache_dir() {
	printf '%s\n' "${LAB_IMAGE_CACHE:-/srv/lab/images}"
}

# base_image_path NAME: the qcow2 a cell's overlay is backed by.
base_image_path() {
	printf '%s/%s.qcow2\n' "$(image_cache_dir)" "$1"
}
