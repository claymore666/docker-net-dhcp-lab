#!/bin/bash
# Proves the per-cell known_hosts fix (issue #1, live run 2026-09-25):
# up-cell.sh's wait loop must survive a rebuilt VM presenting a new host
# key at the same static mgmt address. Runs a real sshd on loopback, never
# touches the personal ~/.ssh/known_hosts, and never touches libvirt or
# the lab network -- CI-safe, same shape as build-bridge-test.sh's
# unshare-gated FAIL-under-CI/SKIP-elsewhere rule.
set -euo pipefail

if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
	if [ "${CI:-}" = "true" ]; then
		echo "lab-known-hosts-test: FAIL -- sshd not available in CI; a gate never goes quietly green" >&2
		exit 1
	fi
	echo "lab-known-hosts-test: SKIP -- sshd not available here (not CI)" >&2
	exit 0
fi
SSHD=$(command -v sshd || echo /usr/sbin/sshd)

tmp=$(mktemp -d)
pid=""
cleanup() {
	if [ -n "$pid" ]; then
		kill "$pid" >/dev/null 2>&1 || true
	fi
	rm -rf "$tmp"
}
trap cleanup EXIT

port=$((20000 + (RANDOM % 20000)))
known_hosts="$tmp/known_hosts"

ssh-keygen -t ed25519 -N '' -f "$tmp/host_key_a" -q
ssh-keygen -t ed25519 -N '' -f "$tmp/host_key_b" -q
ssh-keygen -t ed25519 -N '' -f "$tmp/client_key" -q -C lab-known-hosts-test
cp "$tmp/client_key.pub" "$tmp/authorized_keys"

start_sshd() {
	local hostkey=$1
	cat >"$tmp/sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $hostkey
AuthorizedKeysFile $tmp/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
UseDNS no
PidFile $tmp/sshd.pid
EOF
	"$SSHD" -f "$tmp/sshd_config" -D -e >"$tmp/sshd.log" 2>&1 &
	pid=$!
	local waited=0
	while ! ss -ltn "sport = :$port" 2>/dev/null | grep -q "$port"; do
		waited=$((waited + 1))
		if [ "$waited" -ge 50 ]; then
			echo "lab-known-hosts-test: FAIL -- sshd (key $hostkey) did not open port $port inside the bound" >&2
			cat "$tmp/sshd.log" >&2 || true
			exit 1
		fi
		sleep 0.1
	done
}

stop_sshd() {
	if [ -n "$pid" ]; then
		kill "$pid" >/dev/null 2>&1 || true
	fi
	local waited=0
	while [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; do
		waited=$((waited + 1))
		if [ "$waited" -ge 50 ]; then
			echo "lab-known-hosts-test: FAIL -- sshd (pid $pid) did not exit inside the bound" >&2
			exit 1
		fi
		sleep 0.1
	done
	pid=""
}

# Exactly up-cell.sh's own options (scripts/up-cell.sh's wait loop and
# scripts/run-dhcpdiscover-test.sh's ssh_run()), against 127.0.0.1 instead
# of a lab VM's mgmt address. ControlMaster/ControlPath matter here as
# much as in production: without them, an operator's own multiplexing
# ssh config (a `Host *` ControlMaster/ControlPersist block, discovered
# live while writing this test) silently reuses this test's own first
# connection for the second one and skips host-key checking on it,
# which would make phase 3 below pass for the wrong reason.
lab_ssh() {
	ssh -o "UserKnownHostsFile=$known_hosts" -o GlobalKnownHostsFile=/dev/null \
		-o StrictHostKeyChecking=accept-new -o ConnectTimeout=3 \
		-o ControlMaster=no -o ControlPath=none \
		-i "$tmp/client_key" -p "$port" 127.0.0.1 "$@"
}

fail=0

# Phase 1: first bring-up. known_hosts starts empty, as up-cell.sh's own
# ": >$known_hosts" does. accept-new then writes key A's entry into it,
# same as a real bring-up would -- keep that copy for phase 3 below.
: >"$known_hosts"
start_sshd "$tmp/host_key_a"
if ! out1=$(lab_ssh true 2>&1); then
	echo "lab-known-hosts-test: FAIL -- phase 1 (first bring-up, key A, empty known_hosts) was refused:" >&2
	echo "$out1" >&2
	fail=1
fi
cp "$known_hosts" "$tmp/known_hosts.after_a"
stop_sshd

# Phase 2: the rebuild this fix exists for. Same address (127.0.0.1, same
# port), a new host key (B), and known_hosts reset exactly the way
# up-cell.sh resets it on every bring-up. Must succeed -- this is the
# literal "second bring-up at the same address with a new host key gets
# past the wait".
: >"$known_hosts"
start_sshd "$tmp/host_key_b"
if ! out2=$(lab_ssh true 2>&1); then
	echo "lab-known-hosts-test: FAIL -- phase 2 (rebuilt VM, key B, reset known_hosts) was refused:" >&2
	echo "$out2" >&2
	fail=1
fi
stop_sshd

# Phase 3: negative control, proving this test is actually sensitive to
# the bug it exists to catch. known_hosts is restored to phase 1's
# post-connect state (key A's entry, standing in for a stale personal
# ~/.ssh/known_hosts) and NOT reset before hitting the same address now
# serving key B. Must be refused, specifically for a host-key reason --
# this is the exact failure the 2026-09-25 live run hit, reproduced here
# without ever touching a real lab VM or the personal known_hosts file.
cp "$tmp/known_hosts.after_a" "$known_hosts"
start_sshd "$tmp/host_key_b"
if out3=$(lab_ssh true 2>&1); then
	echo "lab-known-hosts-test: FAIL -- phase 3 (negative control) was accepted although known_hosts was not reset; this test is not sensitive to the bug it exists to catch" >&2
	fail=1
else
	if ! grep -qi 'host key' <<<"$out3"; then
		echo "lab-known-hosts-test: FAIL -- phase 3 was refused, but not for a host-key reason:" >&2
		echo "$out3" >&2
		fail=1
	fi
fi
stop_sshd

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "lab-known-hosts-test: PASS -- first bring-up, rebuilt-VM reset, and the negative control all behaved as expected"
