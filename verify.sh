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

echo "== containment preflight refusal tests =="
./scripts/containment-preflight-test.sh

echo "== containment preflight is wired into up-cell.sh =="
# An exact, anchored line match: not a bare substring grep, so a neutered
# call (a leading ":", a trailing "|| true", commenting the line out)
# fails this just as much as deleting the call outright.
preflight_line=$(grep -nE '^[[:space:]]*"\$REPO_ROOT/scripts/containment-preflight\.sh"[[:space:]]*$' scripts/up-cell.sh | head -1 | cut -d: -f1)
if [ -z "$preflight_line" ]; then
	echo "verify.sh: up-cell.sh does not call containment-preflight.sh as its own, unmodified command" >&2
	exit 1
fi

# The call must also run before the VM is ever started -- a passing call
# after virt-install/virsh start already touched libvirt is too late to
# refuse anything. Whichever of the two starts the VM comes first in the
# file is the one that matters.
start_line=$(grep -nE '^\s*(virt-install\b|virsh start\b)' scripts/up-cell.sh | head -1 | cut -d: -f1)
if [ -z "$start_line" ]; then
	echo "verify.sh: up-cell.sh has no virt-install/virsh start call to order the preflight against" >&2
	exit 1
fi
if [ "$preflight_line" -ge "$start_line" ]; then
	echo "verify.sh: containment-preflight.sh (line $preflight_line) does not run before the VM start (line $start_line)" >&2
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

echo "== publication hygiene =="
./scripts/hygiene-check.sh

echo "verify.sh: PASS"
