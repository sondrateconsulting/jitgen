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

section "rustc pin parity (Cargo vs Bazel)"
# The Cargo dev build (rust-toolchain.toml) and the Bazel toolchain pin (MODULE.bazel) must name the
# same rustc, or a future rules_rust bump (or a hand edit to one file) can leave Bazel compiling on a
# different compiler than Cargo — stale cross-build cache entries and subtle build-result drift. This
# compares the two DECLARED pins (no Bazel needed, so it runs even when Bazel is absent); when Bazel is
# available the build section below additionally asserts the rustc Bazel actually RESOLVES (a literal
# match here does not by itself prove the resolved toolchain). The MODULE.bazel parse is scoped to the
# `rust.toolchain( ... )` stanza via a sed address range, so a `versions = [...]` belonging to some
# other extension can't be misread; comment lines are stripped and the first match taken. An empty
# parse (missing/renamed attribute) is caught by the -z guard below — fail closed.
cargo_rustc="$(sed -nE '/^[[:space:]]*#/d; s/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n1)"
bazel_rustc="$(sed -nE '/rust\.toolchain\(/,/\)/ { /^[[:space:]]*#/d; s/.*versions[[:space:]]*=[[:space:]]*\[[[:space:]]*"([^"]+)".*/\1/p; }' MODULE.bazel | head -n1)"
if [ -z "$cargo_rustc" ] || [ -z "$bazel_rustc" ]; then
  echo "ERROR: could not parse the rustc pin (rust-toolchain.toml='$cargo_rustc', MODULE.bazel='$bazel_rustc')." >&2
  exit 1
fi
if [ "$cargo_rustc" != "$bazel_rustc" ]; then
  echo "ERROR: rustc pin drift — rust-toolchain.toml=$cargo_rustc, MODULE.bazel=$bazel_rustc." >&2
  echo "       Set channel in rust-toolchain.toml and rust.toolchain(versions=...) in MODULE.bazel to the same value." >&2
  exit 1
fi
echo "Cargo and Bazel declare the same rustc ($cargo_rustc)."

# Resolve a Bazel runner: prefer `bazel`, fall back to `bazelisk` (a host may have only the latter).
BAZEL="$(command -v bazel || command -v bazelisk || true)"
if [ -n "$BAZEL" ]; then
  section "bazel build //... ($BAZEL)"
  "$BAZEL" build --lockfile_mode=error //...

  section "bazel resolved rustc == pin"
  # Assert the rustc Bazel actually RESOLVES matches the declared pin — catches a rules_rust default
  # that drifted from the pin, which the text comparison above cannot see. `current_rustc_files` is the
  # documented alias for the active toolchain's rustc; resolve its path (relative to the workspace, so
  # it runs via the bazel-out symlink) and ask the binary directly. Each probe ends in `|| true` so a
  # renamed-upstream target or a probe miss can't trip `set -euo pipefail` — we then degrade to the
  # declared-pin check above (the NOTE branch) rather than abort the gate. A real version MISMATCH
  # (non-empty and different) still hard-fails below.
  resolved_rustc_bin="$("$BAZEL" cquery @rules_rust//rust/toolchain:current_rustc_files --output=files 2>/dev/null | grep -E '/rustc$' | head -n1 || true)"
  resolved_rustc=""
  if [ -n "$resolved_rustc_bin" ] && [ -x "$resolved_rustc_bin" ]; then
    resolved_rustc="$("$resolved_rustc_bin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
  fi
  if [ -z "$resolved_rustc" ]; then
    echo "NOTE: could not determine the Bazel-resolved rustc; relied on the declared-pin check above."
  elif [ "$resolved_rustc" != "$cargo_rustc" ]; then
    echo "ERROR: Bazel resolves rustc $resolved_rustc but the pin is $cargo_rustc (rules_rust default drift?)." >&2
    exit 1
  else
    echo "Bazel resolves rustc $resolved_rustc (matches the pin)."
  fi

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

  section "test-cache policy (fail-closed remote caching)"
  bash scripts/check-test-cache-policy.sh
else
  echo
  echo "NOTE: neither bazel nor bazelisk found on PATH; skipped the canonical Bazel build."
  echo "      See docs/implementation-status.md for provisioning (F1 installs bazelisk)."
fi

echo
echo "All checks passed."
