"""Shared jitgen Bazel helpers.

A single source for the crate version plus thin wrappers around rules_rust that set the edition and
`version` (so `CARGO_PKG_VERSION` matches the Cargo build — see F1/T1 review #2) and attach a unit
`rust_test` to every crate. Keeps per-crate BUILD.bazel files to one line and prevents drift.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

# Single source of the Bazel-side crate version. Keep in sync with [workspace.package].version in
# Cargo.toml (a version-parity check is added in F10 hardening).
JITGEN_VERSION = "0.2.1"

# Remote test-result caching policy (FAIL-CLOSED). Bazel can cache a test's pass/fail keyed on its
# inputs, but a test that reads host state (git config, $HOME, TZ, locale, network, /tmp, ...) can
# then serve a stale FALSE PASS from the cache — a silent failure with no user-visible error. So
# every jitgen rust_test is NON-remote-cacheable BY DEFAULT (local_only); a crate opts in only after
# a per-crate hermeticity audit (Phase 3 / T6) by passing test_cache = "remote_ok". This gates ONLY
# the remote cache; local caching and --cache_test_results are unaffected.
TEST_CACHE_LOCAL_ONLY = "local_only"
TEST_CACHE_REMOTE_OK = "remote_ok"

def _test_tags(test_cache):
    """Translate a test_cache policy into rust_test tags. Fail-closed: an unknown value errors."""
    if test_cache == TEST_CACHE_REMOTE_OK:
        return []  # eligible for remote test-result caching (only after a hermeticity audit)
    if test_cache == TEST_CACHE_LOCAL_ONLY:
        return ["no-remote-cache"]  # default: never serve/store this test's result via the remote cache
    fail("test_cache must be %r or %r, got: %r" % (TEST_CACHE_LOCAL_ONLY, TEST_CACHE_REMOTE_OK, test_cache))

def jitgen_rust_library(name, deps = [], test_cache = TEST_CACHE_LOCAL_ONLY, **kwargs):
    """A jitgen library crate (edition 2021, versioned) + its unit test target.

    test_cache: remote-cache policy for the generated <name>_test (default fail-closed local_only).
    """
    rust_library(
        name = name,
        srcs = native.glob(["src/**/*.rs"]),
        edition = "2021",
        version = JITGEN_VERSION,
        deps = deps,
        visibility = ["//visibility:public"],
        **kwargs
    )
    rust_test(
        name = name + "_test",
        crate = ":" + name,
        tags = _test_tags(test_cache),
    )

def jitgen_rust_binary(name, deps = [], test_cache = TEST_CACHE_LOCAL_ONLY, **kwargs):
    """A jitgen binary crate (edition 2021, versioned) + its unit test target.

    test_cache: remote-cache policy for the generated <name>_test (default fail-closed local_only).
    """
    rust_binary(
        name = name,
        srcs = native.glob(["src/**/*.rs"]),
        edition = "2021",
        version = JITGEN_VERSION,
        deps = deps,
        visibility = ["//visibility:public"],
        **kwargs
    )
    rust_test(
        name = name + "_test",
        crate = ":" + name,
        tags = _test_tags(test_cache),
    )
