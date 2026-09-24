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
if ! grep -q 'containment-preflight.sh' scripts/up-cell.sh; then
	echo "verify.sh: up-cell.sh no longer calls containment-preflight.sh" >&2
	exit 1
fi

echo "== segment bridge refusal tests =="
./scripts/build-bridge-test.sh

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
