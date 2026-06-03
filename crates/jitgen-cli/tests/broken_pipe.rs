//! Integration test: a closed stdout pipe must not make jitgen panic.
//!
//! `main()` resets SIGPIPE to its default disposition (via the `sigpipe` crate). Without that, Rust
//! leaves SIGPIPE ignored and `print!`/`println!` panic when the reader goes away
//! (`jitgen analyze … | head`), exiting 101. With it, a broken-pipe write ends the process via
//! SIGPIPE (exit 141) — the Unix-standard behavior. SIGPIPE is Unix-only, so this file is too.
//!
//! Cargo-only (like the other `tests/` integration tests in this workspace): it spawns the built
//! binary via `CARGO_BIN_EXE_jitgen`, which Bazel's per-crate unit `rust_test` does not provide.
#![cfg(unix)]

use os_pipe::pipe;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

/// Repo to analyze: the workspace root (this crate is `crates/jitgen-cli`). It is a git working tree
/// in a normal checkout and as a nested Claude worktree, both of which jitgen's git intake accepts.
const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

#[test]
fn stdout_broken_pipe_terminates_cleanly_without_panicking() {
    let bin = env!("CARGO_BIN_EXE_jitgen");

    // Create the pipe and close the read end *before* spawning, then hand the child only the write
    // end. The child therefore has no stdout reader for its entire lifetime, so its first write (the
    // `println!` of the JSON plan) deterministically faults with EPIPE — independent of scheduling,
    // pipe-buffer size, and how long git intake takes. (Closing the read end *after* spawn would race
    // the child's first write; this closes it first, so there is no race.)
    let (reader, writer) = pipe().expect("create pipe");
    drop(reader);

    // `analyze --format json` writes its plan to stdout with `println!` — the print path the global
    // SIGPIPE reset guards (unlike `completions`, it has no per-command broken-pipe handling). base ==
    // head == HEAD is an empty diff: valid, needs no history beyond HEAD, still emits a JSON report.
    // stderr is captured (not discarded) so that if `analyze` ever exits *before* its first stdout
    // write — e.g. a git `safe.directory` rejection in a locked-down CI container — the assertions
    // below report *why* (the error text) instead of a bare exit code with no SIGPIPE.
    let mut child = Command::new(bin)
        .args([
            "analyze", "--repo", REPO, "--base", "HEAD", "--head", "HEAD", "--format", "json",
        ])
        .stdout(writer)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn jitgen");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr is piped")
        .read_to_string(&mut stderr)
        .expect("read child stderr");
    let status = child.wait().expect("wait for jitgen");

    // The regression this guards: `print!`/`println!` panic on EPIPE -> exit 101.
    assert_ne!(
        status.code(),
        Some(101),
        "a broken stdout pipe must not panic; got {status:?}\n--- stderr ---\n{stderr}"
    );
    // With SIGPIPE reset to SIG_DFL, the broken-pipe write terminates the process via SIGPIPE. The
    // binary is spawned directly (no shell), so that is reported as signal 13 — not exit code 141,
    // which is the shell's 128+signal convention.
    assert_eq!(
        status.signal(),
        Some(13),
        "expected termination by SIGPIPE (13); got {status:?}\n--- stderr ---\n{stderr}"
    );
}
