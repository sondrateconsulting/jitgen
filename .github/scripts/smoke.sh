#!/usr/bin/env bash
# Pre-publish smoke test for a built jitgen artifact.
#
# Runs the two offline, non-executing checks the release pipeline gates publishing on:
#   1. `jitgen --version`            — the binary loads and prints its version + data-contract.
#   2. `jitgen analyze` on a fixture — diff intake + planning works end to end. `analyze` is
#      non-executing (no sandbox, no network, no toolchains), so it is the right safe smoke check.
#
# Used two ways (see .github/workflows/release.yml):
#   - against a freshly built binary:   .github/scripts/smoke.sh target/release/jitgen
#   - inside the freshly built image:   docker run --rm -i --entrypoint bash <image> -s jitgen < smoke.sh
#
# Portable to macOS's bash 3.2 and Debian's bash. Exits non-zero on the first failure (set -e), so a
# failing smoke fails the build job and the publish step (gated on `needs:`) never runs.
set -euo pipefail

BIN="${1:-jitgen}"

# The fixture step `cd`s into a temp dir, so a *relative* binary path (e.g. target/release/jitgen) must
# be absolutized first. A bare command name (e.g. `jitgen` on PATH, as inside the image) is left as-is.
case "$BIN" in
  */*) BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" ;;
esac

echo "== jitgen --version =="
version_out="$("$BIN" --version)"
echo "$version_out"
case "$version_out" in
  *jitgen*data-contract*) ;;
  *) echo "smoke FAIL: unexpected --version output" >&2; exit 1 ;;
esac

echo
echo "== jitgen analyze on a one-commit-diff fixture repo (offline, non-executing) =="
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

git init -q
git config user.email "smoke@jitgen.test"
git config user.name "jitgen smoke"
git config commit.gpgsign false

mkdir -p src
printf 'pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n' > src/lib.rs
git add -A
git commit -q -m "base"

# A single-line change is the minimal diff jitgen plans against.
printf 'pub fn add(a: i32, b: i32) -> i32 {\n    a - b\n}\n' > src/lib.rs
git commit -q -a -m "head: flip + to -"

"$BIN" analyze --repo . --base HEAD~1 --head HEAD --format json

echo
echo "smoke OK"
