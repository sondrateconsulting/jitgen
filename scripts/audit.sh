#!/usr/bin/env bash
# jitgen supply-chain audit: CVE scan (cargo-audit) + advisories/licenses/bans/sources (cargo-deny).
#
# Kept SEPARATE from scripts/check.sh on purpose: both tools fetch the RustSec advisory database over
# the network, while check.sh is the always-offline fmt/clippy/test/build gate. cargo-audit and
# cargo-deny are DEV/CI tools, NOT crate dependencies (no Cargo.toml/BUILD.bazel entry, no Bazel
# crate_universe repin). Config lives in deny.toml. Run from anywhere; resolves the repo root itself.
#
# Install (one-time): cargo install cargo-audit cargo-deny
set -euo pipefail

cd "$(dirname "$0")/.."

section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

missing=0
command -v cargo-audit >/dev/null 2>&1 || { echo "NOTE: cargo-audit not installed (cargo install cargo-audit)"; missing=1; }
command -v cargo-deny  >/dev/null 2>&1 || { echo "NOTE: cargo-deny not installed (cargo install cargo-deny)"; missing=1; }
if [ "$missing" -ne 0 ]; then
  echo "Install the missing tool(s) above, then re-run. (These are dev/CI tools, not crate deps.)"
  exit 127
fi

section "cargo audit (RustSec CVE scan)"
cargo audit

section "cargo deny check (advisories + licenses + bans + sources)"
cargo deny check

echo
echo "Supply-chain audit passed."
