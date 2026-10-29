#!/bin/bash
# Lab #91: the relay VM has no sysctl binary, so its first-boot runcmd must
# turn forwarding on by writing the proc file, and keep the sysctl.d file
# so a reboot restores it. The write is also run for real against a temp
# file, with no sysctl on the PATH.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"
t=cloud-init/relay-user-data.tmpl.yaml
proc=/proc/sys/net/ipv4/ip_forward
fail=0
bad() { echo "relay-user-data-test: $*" >&2; fail=1; }

cmds=$(grep -E '^[[:space:]]+- ' "$t" || true)
sysctl_lines=$(printf '%s\n' "$cmds" | grep -E '(^|[^_a-zA-Z.])sysctl[[:space:]]' || true)
[ -z "$sysctl_lines" ] || bad "a runcmd step calls the sysctl binary: $sysctl_lines"

write=$(printf '%s\n' "$cmds" | grep -F "$proc" || true)
[ "$(printf '%s\n' "$write" | grep -c .)" -eq 1 ] || bad "expected exactly one runcmd step writing $proc, got: $write"
grep -qE '^  - echo 1 >'"$proc"'$' "$t" || bad "the proc write is not 'echo 1 >$proc'"
grep -qF 'echo net.ipv4.ip_forward=1 >/etc/sysctl.d/90-lab-relay.conf' "$t" || bad "the sysctl.d file for reboots is gone"

w=$(grep -nF "$proc" "$t" | head -1 | cut -d: -f1)
r=$(grep -nF 'systemctl restart nftables isc-dhcp-relay' "$t" | head -1 | cut -d: -f1)
{ [ -n "$w" ] && [ -n "$r" ] && [ "$w" -lt "$r" ]; } || bad "forwarding is not on before the relay restarts"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
for b in bash echo cat; do ln -s "$(command -v "$b")" "$tmp/bin/$b"; done
step=$(grep -E "^  - echo 1 >$proc\$" "$t" | sed -e 's/^  - //' -e "s#$proc#$tmp/ip_forward#")
PATH="$tmp/bin" bash -c "$step" || bad "the write step failed without sysctl on the PATH"
[ "$(cat "$tmp/ip_forward" 2>/dev/null)" = 1 ] || bad "the write step did not leave 1 in the file"

[ "$fail" -eq 0 ] || exit 1
echo "relay-user-data-test: PASS"
