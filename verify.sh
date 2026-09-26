#!/bin/bash
# The lab repo's arbiter: run at the repo root, on the untouched head,
# never a subset. CI-safe: it never touches the lab host, libvirt or the
# network. What only the lab host can prove (a real bring-up, a capture)
# is evidence recorded separately instead.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$REPO_ROOT"

echo "== go build =="
go build ./...

echo "== go vet =="
go vet ./...

echo "== gofmt =="
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "gofmt: not formatted:" >&2
	echo "$unformatted" >&2
	exit 1
fi

echo "== go test =="
go test ./...

echo "== shellcheck =="
if command -v shellcheck >/dev/null; then
	shellcheck scripts/*.sh
else
	echo "verify.sh: shellcheck not installed, skipping" >&2
fi

echo "== schema self-check =="
go run ./cmd/labctl validate lab.yaml

# unreachable_reason and its evasion detectors live in wiring-check.sh,
# shared with wiring-check-test.sh's mutation cases below
# so the same code path that gates up-cell.sh is what gets mutated.
. "$REPO_ROOT/scripts/wiring-check.sh"

echo "== containment preflight refusal tests =="
./scripts/containment-preflight-test.sh

echo "== wiring-check catches every evasion it guards against (mutation-tested) =="
./scripts/wiring-check-test.sh

echo "== containment preflight is wired into up-cell.sh =="
# An exact, anchored line match: not a bare substring grep, so a neutered
# call (a leading ":", a trailing "|| true", commenting the line out)
# fails this just as much as deleting the call outright.
preflight_line=$(grep -nE '^[[:space:]]*sudo[[:space:]]+-n[[:space:]]+"\$REPO_ROOT/scripts/containment-preflight\.sh"[[:space:]]*$' scripts/up-cell.sh | head -1 | cut -d: -f1)
if [ -z "$preflight_line" ]; then
	echo "verify.sh: up-cell.sh does not call containment-preflight.sh as its own, unmodified command" >&2
	exit 1
fi
preflight_reason=$(unreachable_reason scripts/up-cell.sh "$preflight_line")
if [ -n "$preflight_reason" ]; then
	echo "verify.sh: containment-preflight.sh's call in up-cell.sh (line $preflight_line) $preflight_reason; it must be unconditional and reachable" >&2
	exit 1
fi

# Every virt-install/virsh start call must itself run under sudo -n:
# net-mgmt and the segment bridge live under qemu:///system, and an
# unprefixed call would silently reach the empty per-user
# qemu:///session instead of failing loudly (same reasoning as the
# preflight call above). Catch a call missing the prefix anywhere in
# the file, not just the first one.
unprivileged_start=$(grep -nE '^[[:space:]]*(virt-install\b|virsh start\b)' scripts/up-cell.sh || true)
if [ -n "$unprivileged_start" ]; then
	echo "verify.sh: up-cell.sh calls virt-install/virsh start without sudo -n:" >&2
	echo "$unprivileged_start" >&2
	exit 1
fi

# The preflight call must also run before the VM is ever started -- a
# passing call after virt-install/virsh start already touched libvirt is
# too late to refuse anything. Whichever of the two starts the VM comes
# first in the file is the one that matters.
start_line=$(grep -nE '^[[:space:]]*sudo[[:space:]]+-n[[:space:]]+(virt-install\b|virsh start\b)' scripts/up-cell.sh | head -1 | cut -d: -f1)
if [ -z "$start_line" ]; then
	echo "verify.sh: up-cell.sh has no sudo -n virt-install/virsh start call to order the preflight against" >&2
	exit 1
fi
if [ "$preflight_line" -ge "$start_line" ]; then
	echo "verify.sh: containment-preflight.sh (line $preflight_line) does not run before the VM start (line $start_line)" >&2
	exit 1
fi

# lab-seg-firewall.sh must run unconditionally in up-cell.sh (never
# behind a flag there -- that gate belongs to build-bridge.sh's own,
# separate, CI-safe call), after the preflight and before the VM ever
# starts: applied too late, a real bring-up's segment traffic (and #2's
# server-to-host traffic) is silently dropped until the next re-run.
firewall_line=$(grep -nE '^[[:space:]]*sudo[[:space:]]+-n[[:space:]]+"\$REPO_ROOT/scripts/lab-seg-firewall\.sh"[[:space:]]*$' scripts/up-cell.sh | head -1 | cut -d: -f1)
if [ -z "$firewall_line" ]; then
	echo "verify.sh: up-cell.sh does not call lab-seg-firewall.sh as its own, unmodified, unconditional command" >&2
	exit 1
fi
firewall_reason=$(unreachable_reason scripts/up-cell.sh "$firewall_line")
if [ -n "$firewall_reason" ]; then
	echo "verify.sh: lab-seg-firewall.sh's call in up-cell.sh (line $firewall_line) $firewall_reason; it must be unconditional and reachable" >&2
	exit 1
fi
if [ "$firewall_line" -le "$preflight_line" ]; then
	echo "verify.sh: lab-seg-firewall.sh (line $firewall_line) does not run after the preflight (line $preflight_line)" >&2
	exit 1
fi
if [ "$firewall_line" -ge "$start_line" ]; then
	echo "verify.sh: lab-seg-firewall.sh (line $firewall_line) does not run before the VM start (line $start_line)" >&2
	exit 1
fi

echo "== segment bridge refusal tests =="
./scripts/build-bridge-test.sh

echo "== build-bridge-test fails loudly (never skips) under CI when unshare is unavailable =="
# A failing unshare stub under CI=true must make build-bridge-test.sh
# exit non-zero, never a quiet skip.
ci_stub=$(mktemp -d)
trap 'rm -rf "$ci_stub"' EXIT
cat >"$ci_stub/unshare" <<'EOF'
#!/bin/bash
exit 1
EOF
chmod +x "$ci_stub/unshare"
if CI=true PATH="$ci_stub:$PATH" ./scripts/build-bridge-test.sh >/dev/null 2>&1; then
	echo "verify.sh: build-bridge-test.sh must fail under CI=true when unshare is unavailable, but it exited 0" >&2
	exit 1
fi
rm -rf "$ci_stub"
trap - EXIT

echo "== lab segment firewall refusal/idempotency tests =="
./scripts/lab-seg-firewall-test.sh

echo "== down-cell refusal and pcap-preservation tests =="
./scripts/down-cell-test.sh

echo "== capture-start/capture-stop orchestration and sudo -n tests =="
./scripts/capture-lifecycle-test.sh

echo "== DHCP four-message check, against real pcap fixtures =="
if command -v tcpdump >/dev/null; then
	./scripts/dhcp-exchange-check-test.sh
else
	echo "verify.sh: tcpdump not installed, skipping" >&2
fi

echo "== per-cell known_hosts survives a rebuilt VM's new host key =="
./scripts/lab-known-hosts-test.sh

echo "== containment probe refusal and pass-path tests =="
./scripts/containment-probe-test.sh

echo "== no host-side script calls bare docker =="
# A host-side call (one this repo's own scripts run directly on the lab
# host, not a string handed to ssh_run for the VM to run) must go through
# sudo -n, same reasoning as the preflight/firewall calls above: the
# operator running these scripts is deliberately not in the docker group,
# since docker-group membership is root-equivalent on the host (issue
# #1/#3 direction). Matched only at true statement-start or immediately
# after a command substitution's "$(" -- the in-VM "sudo docker ..."
# strings passed to ssh_run start with ssh_run, not docker, so they never
# match this and are correctly left alone.
offenders=$(grep -nE '(^[[:space:]]*docker[[:space:]]|\$\(docker[[:space:]])' scripts/*.sh \
	| grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' || true)
if [ -n "$offenders" ]; then
	echo "verify.sh: host-side docker call(s) without sudo -n:" >&2
	echo "$offenders" >&2
	exit 1
fi

echo "== no host-side script calls other privileged commands bare =="
# Same reasoning and shape as the docker check above, for every other
# command needing CAP_NET_ADMIN/CAP_SYS_ADMIN or root here. Excluded by
# name: build-bridge.sh/lab-seg-firewall.sh/containment-preflight.sh run
# already-elevated under a caller's own sudo -n wrap (up-cell.sh) and
# unprivileged inside their *-test.sh's unshare -rnm or PATH-stubbed
# fakes, where sudo -n would break the CI-safe path; bootstrap-host.sh
# is a documented one-time root setup script, never invoked here; every
# *-test.sh runs against a fake or a namespace, never the real host.
priv_targets=()
for f in scripts/*.sh; do
	case "$f" in
	*-test.sh | scripts/build-bridge.sh | scripts/lab-seg-firewall.sh | scripts/containment-preflight.sh | scripts/bootstrap-host.sh) ;;
	*) priv_targets+=("$f") ;;
	esac
done
offenders=$(grep -nE '(^[[:space:]]*(ip|nsenter|tc|bridge|sysctl|virsh|nft|virt-install|modprobe|mount|umount)[[:space:]]|\$\((ip|nsenter|tc|bridge|sysctl|virsh|nft|virt-install|modprobe|mount|umount)[[:space:]])' "${priv_targets[@]}" \
	| grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' || true)
if [ -n "$offenders" ]; then
	echo "verify.sh: host-side privileged call(s) without sudo -n:" >&2
	echo "$offenders" >&2
	exit 1
fi

echo "== no host-side script live-captures with tcpdump bare =="
# tcpdump -r (reading a saved pcap back, as demo-ref-cell.sh does at its
# own final check) needs no privilege at all and is deliberately not
# flagged. tcpdump -i/-w (a live capture on a real interface) does, but
# observe-segment.sh's own live capture already runs inside the container
# through sudo -n docker exec (the container's own root, not this host),
# so the same file exclusions as the check above apply here too.
offenders=$(grep -nE '(^[[:space:]]*tcpdump[[:space:]]|\$\(tcpdump[[:space:]])' "${priv_targets[@]}" \
	| grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' \
	| grep -E ' -[iw]([[:space:]]|$)|--interface|--write' \
	| grep -v 'sudo -n' || true)
if [ -n "$offenders" ]; then
	echo "verify.sh: host-side tcpdump live-capture call(s) without sudo -n:" >&2
	echo "$offenders" >&2
	exit 1
fi

echo "== every lab ssh/scp call carries the per-cell known_hosts option =="
# Every real invocation line, not a function definition (ssh_run() {) or a
# call to one (ssh_run "..."), which the (^|[^_a-zA-Z]) alternation and the
# required trailing space both rule out. Every one of these reaches a lab
# VM at a static, reused mgmt address (issue #1): without
# UserKnownHostsFile pointed at the per-cell file, a rebuilt VM's new host
# key at the same address hits the same refusal that broke the 2026-09-25
# live run, indistinguishable from "not ready yet".
offenders=$(grep -nE '(^|[^_a-zA-Z])(ssh|scp)[[:space:]]' scripts/*.sh \
	| grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' \
	| grep -v 'UserKnownHostsFile' || true)
if [ -n "$offenders" ]; then
	echo "verify.sh: ssh/scp call(s) missing UserKnownHostsFile:" >&2
	echo "$offenders" >&2
	exit 1
fi

echo "== build-bridge.sh never touches real iptables unless explicitly enabled =="
# Stub iptables/ip6tables that fail loudly if called at all; a default,
# unprivileged build-bridge.sh run (LAB_SEG_APPLY_FIREWALL unset) must
# never invoke them.
gate_stub=$(mktemp -d)
trap 'rm -rf "$gate_stub"' EXIT
for bin in iptables ip6tables; do
	cat >"$gate_stub/$bin" <<EOF
#!/bin/bash
echo "gate-stub: $bin was called with LAB_SEG_APPLY_FIREWALL unset/0 -- gate is broken" >&2
exit 1
EOF
	chmod +x "$gate_stub/$bin"
done
if ! unshare -rnm true 2>/dev/null; then
	if [ "${CI:-}" = "true" ]; then
		echo "verify.sh: FAIL -- unshare -rnm not available in CI for the build-bridge gate check" >&2
		exit 1
	fi
	echo "verify.sh: SKIP -- unshare -rnm not available here (not CI), skipping the build-bridge gate check" >&2
else
	gate_inner='
set -euo pipefail
mount -t sysfs sysfs /sys
ip link set lo up
"$1" gate-bridge >/dev/null
echo "verify.sh: build-bridge.sh left iptables/ip6tables untouched with the gate off"
'
	unshare -rnm env PATH="$gate_stub:$PATH" bash -c "$gate_inner" bash "$REPO_ROOT/scripts/build-bridge.sh"
fi
rm -rf "$gate_stub"
trap - EXIT

echo "== comment blocks in tracked shell scripts stay <=10 lines =="
# Comment blocks in tracked shell scripts stay at 10 lines or fewer (#1).
comment_max=10
comment_offenders=""
while IFS= read -r f; do
	over=$(awk -v max="$comment_max" -v file="$f" '
		NR==1 && /^#!/ { next }
		/^[[:space:]]*#/ { if (count==0) start=NR; count++; next }
		{ if (count>max) print file":"start": comment block of "count" lines (max "max")"; count=0 }
		END { if (count>max) print file":"start": comment block of "count" lines (max "max")" }
	' "$f")
	[ -n "$over" ] && comment_offenders="$comment_offenders
$over"
done < <(git ls-files '*.sh')
if [ -n "$comment_offenders" ]; then
	echo "verify.sh: comment block(s) over $comment_max lines:" >&2
	echo "$comment_offenders" >&2
	exit 1
fi

echo "== hygiene fixture tests =="
./scripts/hygiene-check-test.sh

echo "== no AI attribution =="
if git rev-parse --verify origin/dev >/dev/null 2>&1; then
	range="origin/dev..HEAD"
else
	range="HEAD"
fi
attributed=$(git log "$range" --format='%an <%ae>%n%cn <%ce>%n%B' 2>/dev/null | grep -iE 'claude|anthropic|co-authored|generated with' || true)
if [ -n "$attributed" ]; then
	echo "verify.sh: AI attribution found in commit metadata" >&2
	exit 1
fi

echo "== no process/role words in commit messages =="
# Same range as the AI-attribution scan above: how this project is
# worked on (who staffs it, work-tracking tags, review rounds) never
# belongs in a commit that ships. Subjects and bodies only -- author/
# committer identity is real and is not in scope here.
processy=$(git log "$range" --format='%B' 2>/dev/null | grep -inE '\b(lead|coordinator|maintainer|reviewer|lab-(impl|rev)-[a-zA-Z0-9]+|exchange-[0-9]+)\b' || true) # hygiene: pattern literal, not prose
if [ -n "$processy" ]; then
	echo "verify.sh: process/role word found in a commit message:" >&2
	echo "$processy" >&2
	exit 1
fi

echo "== source daemons bind eth1 only =="
./scripts/source-bind-check.sh

echo "== publication hygiene =="
./scripts/hygiene-check.sh

echo "verify.sh: PASS"
