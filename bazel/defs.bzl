"""Shared jitgen Bazel helpers.

A single source for the crate version plus thin wrappers around rules_rust that set the edition and
`version` (so `CARGO_PKG_VERSION` matches the Cargo build — see F1/T1 review #2) and attach a unit
`rust_test` to every crate. Keeps per-crate BUILD.bazel files to one line and prevents drift.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")

# Single source of the Bazel-side crate version. Keep in sync with [workspace.package].version in
# Cargo.toml (a version-parity check is added in F10 hardening).
JITGEN_VERSION = "0.2.0"

def jitgen_rust_library(name, deps = [], **kwargs):
    """A jitgen library crate (edition 2021, versioned) + its unit test target."""
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
    )

def jitgen_rust_binary(name, deps = [], **kwargs):
    """A jitgen binary crate (edition 2021, versioned) + its unit test target."""
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
    )
