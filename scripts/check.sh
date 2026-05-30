#!/usr/bin/env bash
# jitgen repository check: format, lint, test, build.
#
# Cargo is the always-working dev build; Bazel (Bzlmod) is the canonical build (ADR-0001) and is
# exercised when available. Run from anywhere; resolves the repo root itself.
set -euo pipefail

cd "$(dirname "$0")/.."

section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

section "cargo fmt --check"
cargo fmt --all -- --check

section "cargo clippy (-D warnings)"
cargo clippy --locked --workspace --all-targets -- -D warnings

section "cargo test --workspace"
cargo test --locked --workspace

section "cargo build --workspace --release"
cargo build --locked --workspace --release

# Resolve a Bazel runner: prefer `bazel`, fall back to `bazelisk` (a host may have only the latter).
BAZEL="$(command -v bazel || command -v bazelisk || true)"
if [ -n "$BAZEL" ]; then
  section "bazel build //... ($BAZEL)"
  "$BAZEL" build --lockfile_mode=error //...
  section "bazel test //..."
  # Capture bazel's real exit code (NOT the status of a negation). Exit 4 == "no tests found",
  # treated as non-fatal; anything else propagates.
  code=0
  "$BAZEL" test --lockfile_mode=error //... || code=$?
  if [ "$code" -eq 4 ]; then
    echo "(bazel: no test targets matched — ok)"
  elif [ "$code" -ne 0 ]; then
    exit "$code"
  fi
else
  echo
  echo "NOTE: neither bazel nor bazelisk found on PATH; skipped the canonical Bazel build."
  echo "      See docs/implementation-status.md for provisioning (F1 installs bazelisk)."
fi

echo
echo "All checks passed."
