#!/bin/bash
# The lab repo's arbiter (track file: "verify.sh at the repo root, on the
# untouched head, never a subset"). CI-safe: it never touches the lab
# host, libvirt or the network. What only the lab host can prove (a real
# bring-up, a capture) is evidence attached to the handover instead.
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

# Prints the if/for/while/until/case nesting depth in effect immediately
# before $line in $file, relying on this repo's own style convention of
# putting control keywords and their closing keywords on their own line
# with zero leading whitespace for every top-level statement. A line at
# depth 0 is unconditional; depth > 0 means some call was wrapped in an
# "if" (or similar) without changing the matched line's own text, which
# an anchored grep alone cannot tell apart from a truly unconditional call.
depth_at_line() {
	local file=$1 line=$2
	awk -v target="$line" '
	NR>=target { exit }
	{
		l = $0
		sub(/^[[:space:]]+/, "", l)
		if (l ~ /^(if|for|while|until|case)([[:space:]]|\()/) depth++
		else if (l ~ /^(fi|done|esac)([[:space:];]|$)/) depth--
	}
	END { print depth + 0 }
	' "$file"
}

echo "== containment preflight refusal tests =="
./scripts/containment-preflight-test.sh

echo "== containment preflight is wired into up-cell.sh =="
# An exact, anchored line match: not a bare substring grep, so a neutered
# call (a leading ":", a trailing "|| true", commenting the line out)
# fails this just as much as deleting the call outright.
preflight_line=$(grep -nE '^[[:space:]]*sudo[[:space:]]+-n[[:space:]]+"\$REPO_ROOT/scripts/containment-preflight\.sh"[[:space:]]*$' scripts/up-cell.sh | head -1 | cut -d: -f1)
if [ -z "$preflight_line" ]; then
	echo "verify.sh: up-cell.sh does not call containment-preflight.sh as its own, unmodified command" >&2
	exit 1
fi
preflight_depth=$(depth_at_line scripts/up-cell.sh "$preflight_line")
if [ "$preflight_depth" -ne 0 ]; then
	echo "verify.sh: containment-preflight.sh's call in up-cell.sh (line $preflight_line) sits inside a conditional block (depth $preflight_depth); it must be unconditional" >&2
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
firewall_depth=$(depth_at_line scripts/up-cell.sh "$firewall_line")
if [ "$firewall_depth" -ne 0 ]; then
	echo "verify.sh: lab-seg-firewall.sh's call in up-cell.sh (line $firewall_line) sits inside a conditional block (depth $firewall_depth); it must be unconditional" >&2
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
processy=$(git log "$range" --format='%B' 2>/dev/null | grep -inE '\b(lead|coordinator|maintainer|reviewer|lab-(impl|rev)-[a-zA-Z0-9]+|exchange-[0-9]+)\b' || true)
if [ -n "$processy" ]; then
	echo "verify.sh: process/role word found in a commit message:" >&2
	echo "$processy" >&2
	exit 1
fi

echo "== publication hygiene =="
./scripts/hygiene-check.sh

echo "verify.sh: PASS"
